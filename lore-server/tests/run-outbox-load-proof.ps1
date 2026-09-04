# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs WP-119 Phase 8's admission-limit load test and WP-109 Phase 5's Postgres
and relay capacity proof against live local infrastructure.

.DESCRIPTION
Brings up what `lore-server/tests/outbox_load_proof.rs` needs -- one disposable
Postgres database, the private notification gateway with real mTLS material,
and the cell's JetStream streams -- runs each case in its own cargo invocation,
and reports PASS, FAIL and NOT RUN distinctly against a fixed expected
inventory, followed by the measurement tables the cases printed.

Unlike WP-109 Phase 3's two-process runner this needs NO MinIO bucket and no
`loreserver` binary: every case drives the relay in-process against a real
gateway, so the object store is never touched.

Reuses existing local infrastructure rather than standing up its own: the
`lorehub-dataplane-test` Postgres and the dev NATS. Those are long-lived
developer services, so this runner never starts, stops or removes one, and
refuses to run if it cannot see them. It creates and removes only the database
it named itself, and starts and stops only its own gateway process.

It deliberately LEAVES the cell's three JetStream streams behind
(`ensureCellStreams` is idempotent and the local broker is budgeted for a fixed
set of cell slots).

WHAT IT PUBLISHES. A full run publishes roughly `2 * Rows` messages at each of
1 KiB, 16 KiB and 64 KiB plus `2 * Rows` more at 1 KiB into the cell's DURABLE
stream -- around 170 MiB at the default Rows. The stream is long-lived, so a
developer running this repeatedly may want `nats stream purge DURABLE-<cell>`.
This runner does not purge a shared broker resource on its own; pass
-PurgeStreamBefore to opt in.

Every seeded row carries a fresh per-run idempotency salt, so a second run is
published rather than answered from the broker's dedupe window. Without that
salt the measured rate would be the rate of deduplication.

.PARAMETER Rows
Rows seeded per size. The default matches the test's own default.

.PARAMETER Case
Run only the named cases (the short keys, e.g. -Case drain-sizes). Default: all.

.PARAMETER Release
Build and run the cases in release. A debug build under-states every rate; the
results table records which profile produced the numbers.

.PARAMETER KeepOnFailure
Leave the case database and the gateway log behind when a case fails.

.EXAMPLE
pwsh lore-server/tests/run-outbox-load-proof.ps1

.EXAMPLE
pwsh lore-server/tests/run-outbox-load-proof.ps1 -Release -Rows 5000
#>

[CmdletBinding()]
param(
    [int]$Rows = 2000,
    [string[]]$Case,
    [switch]$Release,
    [switch]$KeepOnFailure,
    [switch]$PurgeStreamBefore,
    [int]$PortBase = 41500,
    [string]$CellId = 'sfo3-cell-a',
    [string]$PostgresContainer = 'lorehub-dataplane-test-postgres-1',
    [string]$PostgresHostPort = '11832',
    [string]$PostgresRole = 'lorehub',
    [string]$NatsUrl = 'nats://127.0.0.1:4222'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$workspaceRoot = Split-Path -Parent $loreRoot
$lorehubRoot = Join-Path $workspaceRoot 'lorehub'
$gatewayRoot = Join-Path $lorehubRoot 'apps/notification-gateway'

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$runRoot = Join-Path ([IO.Path]::GetTempPath()) "wp119-load-$runId"
$certDir = Join-Path $runRoot 'certs'
$profileName = if ($Release) { 'release' } else { 'debug' }

# Each case runs in its own cargo invocation so one case's FAILURE cannot hide
# another case's result. Not a hang: there is no timeout on the cargo call, and
# a wedged case would stall the whole run. Each case carries its own internal
# drain deadline instead, which bounds every path except a hang inside a single
# database call.
#
# `NeedsGateway` records which environment half a case needs. It is deliberately
# not enforced here: a case that needs the gateway and cannot see one must
# report NOT RUN from inside the test, so the absence is visible in the test's
# own output rather than inferred by this runner.
$caseCatalog = @(
    [pscustomobject]@{
        Key = 'drain-sizes'; NeedsGateway = $true; Ignored = $true
        Test = 'measure_drain_rate_and_gateway_latency_at_three_event_sizes'
        Expected = 'MEASURED'
    }
    [pscustomobject]@{
        Key = 'two-workers'; NeedsGateway = $true; Ignored = $true
        Test = 'measure_two_workers_draining_one_backlog_without_publishing_a_row_twice'
        Expected = 'MEASURED'
    }
    [pscustomobject]@{
        Key = 'readiness-threshold'; NeedsGateway = $false; Ignored = $true
        Test = 'readiness_flips_at_the_thirty_second_oldest_unpublished_threshold'
        Expected = 'MEASURED'
    }
    [pscustomobject]@{
        Key = 'admission-limits'; NeedsGateway = $false; Ignored = $true
        Test = 'admission_closes_and_reopens_as_the_backlog_crosses_each_limit'
        Expected = 'MEASURED'
    }
    [pscustomobject]@{
        Key = 'client-retry-budget'; NeedsGateway = $false; Ignored = $false
        Test = 'measure_the_real_lore_client_resource_exhausted_retry_budget'
        Expected = 'MEASURED'
    }
    [pscustomobject]@{
        Key = 'receiver-lag'; NeedsGateway = $false; Ignored = $true
        Test = 'receiver_checkpoint_lag_under_load_is_not_run_here'
        Expected = 'NOT RUN'
    }
)

$selected = if ($Case) {
    $wanted = @($Case | ForEach-Object { $_.ToLowerInvariant() })
    $unknown = @($wanted | Where-Object { $_ -notin $caseCatalog.Key })
    if ($unknown.Count -ne 0) { throw "unknown case key(s): $($unknown -join ', ')" }
    @($caseCatalog | Where-Object { $_.Key -in $wanted })
}
else { $caseCatalog }

$results = @(
    foreach ($entry in $selected) {
        [pscustomobject]@{
            Case     = $entry.Key
            Expected = $entry.Expected
            Status   = 'NOT RUN'
            Note     = 'not reached'
        }
    }
)

$measurements = New-Object System.Collections.Generic.List[string]
$commandLog = New-Object System.Collections.Generic.List[string]
$gatewayProcess = $null
$gatewayEnv = $null
$database = "wp119_load_$runId"
$databaseCreated = $false
$setupError = $null

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)
    $commandLog.Add(("{0} {1}" -f $FilePath, ($ArgumentList -join ' ')))
    $output = & $FilePath @ArgumentList 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "$FilePath exited with $LASTEXITCODE`n$output" }
    return $output
}

# The cert generator is a bash script shelling out to a NATIVE Windows
# `openssl`, written for Git Bash: it takes a Windows-style output directory,
# which WSL's `/bin/bash` (usually first on PATH) cannot open at all, failing as
# a bare "No such file or directory" naming a path that plainly exists. Resolve
# Git's own bash from the `git` executable rather than trusting PATH order.
function Resolve-GitBash {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        $gitRoot = Split-Path (Split-Path $git.Source -Parent) -Parent
        foreach ($candidate in @((Join-Path $gitRoot 'bin/bash.exe'), (Join-Path $gitRoot 'usr/bin/bash.exe'))) {
            if (Test-Path $candidate) { return $candidate }
        }
    }
    $fallback = Get-Command bash -ErrorAction SilentlyContinue
    if ($null -eq $fallback) { throw 'no bash found; Git for Windows supplies the one this needs' }
    Write-Warning "falling back to $($fallback.Source); the cert generator expects Git Bash"
    return $fallback.Source
}

function Assert-ContainerRunning {
    param([Parameter(Mandatory)][string]$Name)
    $state = & docker inspect --format '{{.State.Running}}' $Name 2>&1
    if ($LASTEXITCODE -ne 0 -or ($state | Out-String).Trim() -ne 'true') {
        throw "container '$Name' is not running. Bring the local stack up first; this runner " +
        'creates only the database it names itself and never starts shared services.'
    }
}

function Assert-Listening {
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][int]$Port)
    $probe = Test-NetConnection -ComputerName '127.0.0.1' -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $probe) { throw "$Label is not listening on 127.0.0.1:$Port" }
}

try {
    # -- preflight ---------------------------------------------------------
    Write-Host '== preflight =='
    Assert-ContainerRunning -Name $PostgresContainer
    Assert-Listening -Label 'NATS (compose profile "notifications")' -Port 4222
    foreach ($tool in @('docker', 'cargo', 'bun', 'git')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not on PATH" }
    }
    if ($CellId -ne 'sfo3-cell-a') {
        throw "dev-certs.sh mints its relay leaf for cell 'sfo3-cell-a', and the gateway takes the " +
        "cell from the CERTIFICATE rather than the envelope; -CellId '$CellId' would be refused " +
        'as SCOPE_MISMATCH. It must also equal the test harness''s own TEST_CELL_ID.'
    }
    # The test enforces the same floor and panics below it. Refusing here too
    # means an operator finds out before a gateway and three streams are stood
    # up, and it keeps the runner from ever reporting MEASURED over a backlog
    # too small to measure anything.
    if ($Rows -lt 500) { throw "-Rows $Rows is below the 500-row floor; that backlog produces noise, not a measurement" }
    $bash = Resolve-GitBash
    New-Item -ItemType Directory -Force $runRoot | Out-Null

    # -- build -------------------------------------------------------------
    # Built ONCE here, then each case invokes the produced binary directly.
    #
    # Not a micro-optimisation. `cargo` takes an exclusive lock on the shared
    # `target/` directory, and in this workspace other sessions rebuild
    # `lore-server` continuously; a runner that shelled out to `cargo` once per
    # case queued behind those rebuilds and stalled for tens of minutes between
    # cases, with no output to say why. Invoking the binary skips the lock
    # entirely, and it also guarantees every case ran the SAME build -- which a
    # per-case `cargo test` does not, if a sibling lane lands a change midway
    # through the run.
    Write-Host "== building the load-proof test target ($profileName) =="
    Push-Location $loreRoot
    try {
        $buildArgs = @(
            'test', '-p', 'lore-server', '--test', 'outbox_load_proof', '--no-run', '-j', '4',
            '--message-format', 'json'
        )
        if ($Release) { $buildArgs += '--release' }
        $buildJson = Invoke-Checked cargo $buildArgs
    }
    finally { Pop-Location }

    $testBin = $null
    foreach ($line in ($buildJson -split "`r?`n")) {
        if ($line -notmatch '^\s*\{') { continue }
        try { $record = $line | ConvertFrom-Json } catch { continue }
        if ($record.reason -eq 'compiler-artifact' -and $record.target.name -eq 'outbox_load_proof' -and $record.executable) {
            $testBin = $record.executable
        }
    }
    if (-not $testBin -or -not (Test-Path $testBin)) {
        throw "cargo did not report an executable for the outbox_load_proof test target"
    }
    Write-Host "   built $testBin"

    # -- gateway trust material and streams --------------------------------
    Write-Host '== provisioning the private gateway =='
    $certScript = (Join-Path $gatewayRoot 'scripts/dev-certs.sh') -replace '\\', '/'
    Invoke-Checked $bash @($certScript, ($certDir -replace '\\', '/')) | Out-Null

    # Invoked directly rather than through `bun run --filter`, which does not
    # forward trailing arguments to the package script: the cell would silently
    # default and the streams this run publishes to would never be created.
    Push-Location $gatewayRoot
    try {
        $provisionOutput = Invoke-Checked bun @('scripts/provision-streams.ts', '--cell', $CellId, '--url', $NatsUrl)
    }
    finally { Pop-Location }
    $streamIdentity = "DURABLE-$CellId"
    Write-Host "   streams provisioned for $CellId (publishing into $streamIdentity)"

    # Capacity note, not a gate. A full run publishes roughly 170 MiB at the
    # default Rows into a stream this runner does not own and will not resize;
    # printing what the broker says it holds lets an operator decide whether to
    # purge before rather than discover a discard policy afterwards.
    $capacityMatch = [regex]::Match(
        $provisionOutput,
        ('(?m)^\s*' + [regex]::Escape($streamIdentity) + '\s.*?discard=(?<discard>\S+)\s+max_msgs=(?<msgs>\S+)\s+max_bytes=(?<bytes>\S+)\s+messages=(?<held>\S+)')
    )
    if ($capacityMatch.Success) {
        Write-Host ("   {0} currently holds {1} message(s); limits max_msgs={2} max_bytes={3} discard={4}" -f
            $streamIdentity, $capacityMatch.Groups['held'].Value, $capacityMatch.Groups['msgs'].Value,
            $capacityMatch.Groups['bytes'].Value, $capacityMatch.Groups['discard'].Value)
        Write-Host "   this run will add about $($Rows * 8) messages and roughly $([math]::Round($Rows * 83 / 1024)) MiB"
    }
    else {
        Write-Warning "   could not read $streamIdentity's capacity from the provisioner output; publishing anyway"
    }

    if ($PurgeStreamBefore) {
        if (Get-Command nats -ErrorAction SilentlyContinue) {
            Invoke-Checked nats @('stream', 'purge', $streamIdentity, '--force', '--server', $NatsUrl) | Out-Null
            Write-Host "   purged $streamIdentity on request"
        }
        else { Write-Warning '   -PurgeStreamBefore was passed but the `nats` CLI is not on PATH; skipping' }
    }

    $gatewayPrivatePort = $PortBase
    $gatewayAdminPort = $PortBase + 1
    # `-AsArray` is load-bearing: `ConvertTo-Json` collapses a one-element array
    # to a bare object, and the gateway refuses a placement that is not a JSON
    # array. `placement_epoch` must equal the test harness's own
    # TEST_PLACEMENT_EPOCH, or every envelope is refused as a scope mismatch.
    $placement = @{
        region_id          = 'sfo3'
        cell_id            = $CellId
        shard_id           = 'shard-local'
        placement_epoch    = 12
        placement_revision = 1
        state              = 'active'
        contract_version   = 1
        credential_version = 1
        residency_tags     = @()
        account            = 'CELL_LOCAL'
    } | ConvertTo-Json -Compress -Depth 5 -AsArray
    $shards = @{ shard_id = 'shard-local'; servers = @($NatsUrl); members = 1 } |
        ConvertTo-Json -Compress -Depth 5 -AsArray

    $gatewayLog = Join-Path $runRoot 'gateway.log'
    $gatewayEnv = @{
        LH_GATEWAY_ENV          = 'development'
        LH_GATEWAY_REGION       = 'sfo3'
        LH_GATEWAY_PLACEMENT    = $placement
        LH_GATEWAY_SHARDS       = $shards
        LH_GATEWAY_PRIVATE_HOST = '127.0.0.1'
        LH_GATEWAY_PRIVATE_PORT = "$gatewayPrivatePort"
        LH_GATEWAY_ADMIN_HOST   = '127.0.0.1'
        LH_GATEWAY_ADMIN_PORT   = "$gatewayAdminPort"
        LH_GATEWAY_TLS_CERT     = (Join-Path $certDir 'server.crt')
        LH_GATEWAY_TLS_KEY      = (Join-Path $certDir 'server.key')
        LH_GATEWAY_CLIENT_CA    = (Join-Path $certDir 'ca.crt')
    }
    foreach ($pair in $gatewayEnv.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process')
    }
    $commandLog.Add("bun src/index.ts   # cwd=$gatewayRoot, private=$gatewayPrivatePort admin=$gatewayAdminPort")
    $gatewayProcess = Start-Process -FilePath 'bun' -ArgumentList 'src/index.ts' `
        -WorkingDirectory $gatewayRoot -PassThru -NoNewWindow `
        -RedirectStandardOutput $gatewayLog -RedirectStandardError "$gatewayLog.err"

    $gatewayReady = $false
    foreach ($attempt in 1..60) {
        try {
            $health = Invoke-WebRequest -Uri "http://127.0.0.1:$gatewayAdminPort/healthz" -TimeoutSec 2 -UseBasicParsing
            if ($health.StatusCode -eq 200) { $gatewayReady = $true; break }
        }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $gatewayReady) {
        $tail = if (Test-Path $gatewayLog) { Get-Content $gatewayLog -Tail 40 | Out-String } else { '(no log)' }
        $errTail = if (Test-Path "$gatewayLog.err") { Get-Content "$gatewayLog.err" -Tail 40 | Out-String } else { '' }
        throw "the notification gateway never became healthy on 127.0.0.1:$gatewayAdminPort`n$tail`n$errTail"
    }
    Write-Host "   gateway healthy on 127.0.0.1:$gatewayAdminPort (private mTLS on $gatewayPrivatePort)"

    # -- one database for the run; each case takes its own schema ----------
    Invoke-Checked docker @(
        'exec', $PostgresContainer, 'psql', '-v', 'ON_ERROR_STOP=1',
        '-U', $PostgresRole, '-d', 'postgres', '-c', "CREATE DATABASE $database;"
    ) | Out-Null
    $databaseCreated = $true
    Write-Host "   database $database created"

    $baseEnv = @{
        LORE_TEST_PG_URL       = "postgresql://$PostgresRole`:$PostgresRole@127.0.0.1:$PostgresHostPort/$database"
        LORE_LOAD_ROWS         = "$Rows"
        LORE_LOAD_GATEWAY_URI  = "https://localhost:$gatewayPrivatePort"
        LORE_LOAD_CLIENT_CERT  = (Join-Path $certDir 'relay.crt')
        LORE_LOAD_CLIENT_KEY   = (Join-Path $certDir 'relay.key')
        LORE_LOAD_TRUST_ROOTS  = (Join-Path $certDir 'ca.crt')
    }

    # -- cases -------------------------------------------------------------
    foreach ($result in $results) {
        $entry = $caseCatalog | Where-Object { $_.Key -eq $result.Case }
        Write-Host ''
        Write-Host "== case $($result.Case): $($entry.Test) =="

        foreach ($pair in $baseEnv.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process')
        }

        Push-Location $loreRoot
        try {
            $testArgs = @('--exact', $entry.Test, '--nocapture', '--test-threads=1')
            if ($entry.Ignored) { $testArgs += '--ignored' }
            $commandLog.Add("$testBin $($testArgs -join ' ')   # db=$database rows=$Rows profile=$profileName")
            $output = & $testBin @testArgs 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
            foreach ($key in $baseEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
        }

        $ran = 0
        $passed = 0
        $failed = 0
        $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
        $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
        if ($runningMatch.Success) { $ran = [int]$runningMatch.Groups[1].Value }
        if ($resultMatch.Success) {
            $passed = [int]$resultMatch.Groups[1].Value
            $failed = [int]$resultMatch.Groups[2].Value
        }

        $notRunMarker = [regex]::Match($output, '\[\[NOTRUN\]\]\s*(?<case>\S+)\s*::\s*(?<why>.+)')
        $measuredMarker = $output -match '\[\[MEASURED\]\]'

        # Three-way, and a body that returned early is NOT RUN even though cargo
        # reports it green. That distinction is the whole point of the markers:
        # a case whose prerequisites were absent produced no evidence, and
        # counting it as a pass is exactly the failure mode CR-032's "load-test
        # those limits" requirement cannot survive.
        # A non-zero exit is checked FIRST. A test binary that aborts -- a stack
        # overflow, a killed process -- prints no `test result:` line at all, so
        # the "nothing executed" branch below would otherwise claim it as NOT
        # RUN and hide a crash behind a missing prerequisite.
        if ($exitCode -ne 0 -or $failed -ne 0) {
            $result.Status = 'FAIL'
            $result.Note = if ($resultMatch.Success) { 'see output above' } else { 'aborted without reporting a result' }
            Write-Warning "   FAIL`n$output"
        }
        elseif ($ran -eq 0 -or ($failed -eq 0 -and $passed -eq 0)) {
            $result.Status = 'NOT RUN'
            $result.Note = 'no test executed (filter matched nothing)'
        }
        elseif ($notRunMarker.Success) {
            $result.Status = 'NOT RUN'
            $result.Note = $notRunMarker.Groups['why'].Value.Trim()
        }
        elseif ($measuredMarker) {
            $result.Status = 'MEASURED'
            $result.Note = ''
        }
        else {
            $result.Status = 'NOT RUN'
            $result.Note = 'the case passed but emitted no [[MEASURED]] marker'
        }

        if ($result.Status -eq 'MEASURED') { Write-Host '   MEASURED' }
        elseif ($result.Status -eq 'NOT RUN') { Write-Warning "   NOT RUN: $($result.Note)" }

        # Keep the measurement block for the final table: everything the case
        # printed between its own banner and the markers.
        $measurements.Add("--- $($result.Case) [$($result.Status)] ---")
        foreach ($line in ($output -split "`r?`n")) {
            if ($line -match '^\s*(===|\[\[|test result:)') { continue }
            if ($line -match '^\s*(warning:|Compiling|Finished|Running|running \d|test \S+ \.\.\.)') { continue }
            if ($line.Trim().Length -eq 0) { continue }
            if ($line -match '^\s*case namespace') { continue }
            $measurements.Add("  $line")
        }
    }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    if ($null -ne $gatewayProcess -and -not $gatewayProcess.HasExited) {
        Stop-Process -Id $gatewayProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $gatewayEnv) {
        foreach ($key in @($gatewayEnv.Keys)) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
    }
    $anyBad = @($results | Where-Object { $_.Status -ne $_.Expected }).Count -ne 0
    if ($databaseCreated -and -not ($KeepOnFailure -and $anyBad)) {
        & docker exec $PostgresContainer psql -v ON_ERROR_STOP=1 -U $PostgresRole -d postgres `
            -c "DROP DATABASE IF EXISTS $database WITH (FORCE);" *> $null
    }
    if ($KeepOnFailure -and $anyBad) { Write-Warning "run artefacts kept under $runRoot (database $database)" }
    elseif (Test-Path $runRoot) { Remove-Item -Recurse -Force $runRoot -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host '== measurements =='
Write-Host "   environment: PostgreSQL in $PostgresContainer on 127.0.0.1:$PostgresHostPort; NATS $NatsUrl;"
Write-Host "                gateway from lorehub/apps/notification-gateway; cell $CellId;"
Write-Host "                cargo profile $profileName; rows/size $Rows; all on one machine."
foreach ($line in $measurements) { Write-Host $line }

Write-Host ''
Write-Host '== commands =='
foreach ($line in $commandLog) { Write-Host "   $line" }

Write-Host ''
$results | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
$okCount = @($results | Where-Object { $_.Status -eq $_.Expected }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($results | Where-Object { $_.Status -eq 'NOT RUN' -and $_.Expected -ne 'NOT RUN' }).Count
Write-Host "Summary: AS EXPECTED=$okCount FAIL=$failCount UNEXPECTED NOT RUN=$notRunCount EXPECTED=$($results.Count)"
Write-Host ''
Write-Host 'Scope this run does NOT cover:'
Write-Host '  - Two real loreserver PROCESSES. "Two workers" here is two EventRelayWorkers over one'
Write-Host '    pool. Process-level exactly-once is WP-109 Phase 3 cases B, D and E:'
Write-Host '    lore-integration-tests/tests/run-active-active-two-process-live.ps1.'
Write-Host '  - Receiver checkpoint lag under load. Reported NOT RUN by its own case, which names'
Write-Host '    the missing bring-up.'
Write-Host '  - The 1,000,000-row and 5 GiB admission limits at their SHIPPED values. Crossing is'
Write-Host '    proven at scaled limits; the probe cost at the shipped limits is extrapolated and'
Write-Host '    labelled as such. The 300-second AGE limit IS crossed at its shipped value.'

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
    exit 1
}
if ($failCount -ne 0 -or $notRunCount -ne 0) { exit 1 }
exit 0
