# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs WP-109 Phase 3's two-process shared-backend proof against live infrastructure.

.DESCRIPTION
Brings up everything two real loreserver processes need to share one cell
Postgres database and one MinIO bucket while publishing through the private
notification gateway, then runs each Rust case in its OWN disposable database
and its OWN bucket, and reports PASS, FAIL, and NOT RUN distinctly against a
fixed expected inventory.

The per-case database and bucket are not tidiness. WP-109 requires every real
service run and case to have a unique namespace, and rejects `#[serial]` as a
substitute; the two processes of ONE case deliberately share that case's
namespace, which is the whole point of the proof, and nothing else does.

Reuses existing local infrastructure rather than standing up its own: the
`lorehub-dataplane-test` Postgres, the dev MinIO, and the dev NATS. Those are
long-lived developer services, so this runner never starts, stops, or removes
one, and refuses to run if it cannot see them. It creates and removes the
per-case database and bucket it named itself.

Two things it touches on a shared service and deliberately LEAVES behind, both
idempotent: the three JetStream streams for the cell (`ensureCellStreams` is
idempotent, and the local broker is budgeted for a fixed set of cell slots, so
churning them costs more than keeping them), and MinIO's `local` `mc` alias,
which it sets to the same endpoint and credentials the compose `minio-init`
one-shot already uses.

It also leaves behind one durable CONSUMER per receiver generation, because
every receiver identity is namespaced to the run (see `LORE_AA2P_RUN_ID` below)
and consumer names are derived from it. That is deliberate: reusing an identity
across runs attaches to the previous run's consumer and gaps the new receiver's
frontier permanently. The cost is a slowly growing consumer list on the local
broker, which is a developer's own `nats consumer rm` to prune; this runner does
not delete broker resources it cannot prove it created.

.PARAMETER KeepOnFailure
Leave the case database, the bucket, and the process logs behind when a case
fails, for debugging.

.PARAMETER Case
Run only the named cases (the short letters, e.g. -Case a,b). Default: all.

.PARAMETER PortBase
First loopback port of the first case's five-port band. Each case takes ten.

.EXAMPLE
pwsh lore-integration-tests/tests/run-active-active-two-process-live.ps1
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [string[]]$Case,
    [int]$PortBase = 41400,
    [string]$CellId = 'sfo3-cell-a',
    [string]$PostgresContainer = 'lorehub-dataplane-test-postgres-1',
    [string]$MinioContainer = 'lorehub-dataplane-minio-1',
    [string]$PostgresHostPort = '11832',
    [string]$PostgresRole = 'lorehub',
    [string]$MinioEndpoint = 'http://127.0.0.1:9000',
    [string]$NatsUrl = 'nats://127.0.0.1:4222'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$workspaceRoot = Split-Path -Parent $loreRoot
$lorehubRoot = Join-Path $workspaceRoot 'lorehub'
$gatewayRoot = Join-Path $lorehubRoot 'apps/notification-gateway'
$fixtures = Join-Path $lorehubRoot 'docker/test-fixtures'

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$runRoot = Join-Path ([IO.Path]::GetTempPath()) "wp109-aa2p-$runId"
$certDir = Join-Path $runRoot 'certs'

# The module path a `--exact` filter needs: `integration.rs` declares
# `mod active_active_two_process_test`, whose file declares
# `mod active_active_two_process_tests`.
$testPrefix = 'active_active_two_process_test::active_active_two_process_tests'

$caseCatalog = @(
    [pscustomobject]@{ Key = 'a'; Test = "$testPrefix::case_a_both_processes_serve_reads_of_a_repository_created_through_a" }
    [pscustomobject]@{ Key = 'b'; Test = "$testPrefix::case_b_simultaneous_pushes_leave_one_winner_one_branch_and_one_outbox_row" }
    [pscustomobject]@{ Key = 'c'; Test = "$testPrefix::case_c_a_lock_held_through_one_process_is_refused_through_the_other" }
    [pscustomobject]@{ Key = 'd'; Test = "$testPrefix::case_d_a_kill_before_the_relay_claim_relays_the_row_exactly_once_after_restart" }
    [pscustomobject]@{ Key = 'e'; Test = "$testPrefix::case_e_a_lost_relay_worker_is_reclaimed_by_the_other_process" }
    [pscustomobject]@{ Key = 'f'; Test = "$testPrefix::case_f_an_obliterate_through_one_process_is_seen_by_the_other" }
    [pscustomobject]@{ Key = 'g'; Test = "$testPrefix::case_g_both_processes_report_their_event_plane_facets_at_rest" }
    [pscustomobject]@{ Key = 'h'; Test = "$testPrefix::case_h_a_lock_acquired_through_one_process_is_released_through_the_other_only_with_its_token" }
    [pscustomobject]@{ Key = 'i'; Test = "$testPrefix::case_i_a_released_client_push_through_a_is_reconciled_through_b_by_attempt_id" }
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
            Case   = $entry.Key
            Test   = $entry.Test
            Status = 'NOT RUN'
            Ran    = 0
            Passed = 0
            Failed = 0
            Note   = ''
        }
    }
)

$gatewayProcess = $null
$gatewayEnv = $null
$createdDatabases = @()
$createdBuckets = @()
$setupError = $null
$commandLog = New-Object System.Collections.Generic.List[string]

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)
    $commandLog.Add(("{0} {1}" -f $FilePath, ($ArgumentList -join ' ')))
    $output = & $FilePath @ArgumentList 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with $LASTEXITCODE`n$output"
    }
    return $output
}

# The cert generator is a bash script that shells out to a NATIVE Windows
# `openssl` and is written for Git Bash: it sets `MSYS2_ARG_CONV_EXCL` and takes
# a Windows-style output directory. WSL's `/bin/bash` is usually first on PATH
# and cannot open `D:/...` at all, which fails as a bare "No such file or
# directory" naming a path that plainly exists. Resolve Git's own bash from the
# `git` executable rather than trusting PATH order.
function Resolve-GitBash {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        $gitRoot = Split-Path (Split-Path $git.Source -Parent) -Parent
        foreach ($candidate in @(
                (Join-Path $gitRoot 'bin/bash.exe'),
                (Join-Path $gitRoot 'usr/bin/bash.exe')
            )) {
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
        'creates only the database and bucket it names itself and never starts shared services.'
    }
}

function Assert-Listening {
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][int]$Port)
    $probe = Test-NetConnection -ComputerName '127.0.0.1' -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $probe) { throw "$Label is not listening on 127.0.0.1:$Port" }
}

function New-CaseDatabase {
    param([Parameter(Mandatory)][string]$Name)
    Invoke-Checked docker @(
        'exec', $PostgresContainer, 'psql', '-v', 'ON_ERROR_STOP=1',
        '-U', $PostgresRole, '-d', 'postgres', '-c', "CREATE DATABASE $Name;"
    ) | Out-Null
    $script:createdDatabases += $Name
}

function Remove-CaseDatabase {
    param([Parameter(Mandatory)][string]$Name)
    & docker exec $PostgresContainer psql -v ON_ERROR_STOP=1 -U $PostgresRole -d postgres `
        -c "DROP DATABASE IF EXISTS $Name WITH (FORCE);" *> $null
    $script:createdDatabases = @($script:createdDatabases | Where-Object { $_ -ne $Name })
}

# `mc` ships inside the MinIO image, and running it there needs neither the
# compose network name nor an `mc` on the developer's PATH. loreserver HEADs its
# bucket at boot and never creates one, so this step is a hard prerequisite, not
# a convenience.
function Invoke-Mc {
    param([Parameter(Mandatory)][string[]]$McArgs)
    Invoke-Checked docker (@('exec', $MinioContainer, 'mc') + $McArgs)
}

function New-CaseBucket {
    param([Parameter(Mandatory)][string]$Name)
    Invoke-Mc @('mb', '--ignore-existing', "local/$Name") | Out-Null
    $script:createdBuckets += $Name
}

function Remove-CaseBucket {
    param([Parameter(Mandatory)][string]$Name)
    & docker exec $MinioContainer mc rb --force "local/$Name" *> $null
    $script:createdBuckets = @($script:createdBuckets | Where-Object { $_ -ne $Name })
}

try {
    # -- preflight ---------------------------------------------------------
    Write-Host '== preflight =='
    Assert-ContainerRunning -Name $PostgresContainer
    Assert-ContainerRunning -Name $MinioContainer
    Assert-Listening -Label 'MinIO' -Port 9000
    Assert-Listening -Label 'NATS (compose profile "notifications")' -Port 4222
    foreach ($required in @('jwks.json', 'jwt-private-key.pem')) {
        $path = Join-Path $fixtures $required
        if (-not (Test-Path $path)) { throw "missing TEST key material: $path" }
    }
    foreach ($tool in @('docker', 'cargo', 'bun', 'git')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is not on PATH" }
    }
    $bash = Resolve-GitBash
    New-Item -ItemType Directory -Force $runRoot | Out-Null

    # `mc` needs the alias before any bucket call, and setting it is idempotent.
    Invoke-Mc @('alias', 'set', 'local', 'http://127.0.0.1:9000', 'minioadmin', 'minioadmin') | Out-Null

    # -- build -------------------------------------------------------------
    Write-Host '== building loreserver (release) =='
    # Release, not debug: the AWS-SDK S3 path overflows the Windows main-thread
    # stack in a debug binary and the process panics before serving anything.
    # `--features failure_generator` is LOAD-BEARING, not a debug convenience.
    # The `outbox.*` anchors cases D and E kill on are `#[cfg(feature =
    # "failure_generator")]`, so a binary built without it reads no
    # `LORE_FRAGMENT_FAILPOINTS` at all: the process never aborts, and both
    # cases fail on a timeout that looks like a slow relay rather than a
    # missing feature. The feature is forwarded `lore-server` ->
    # `lore-postgres` deliberately so there is one chain to keep
    # (`lore-server/Cargo.toml:131`).
    Push-Location $loreRoot
    try {
        Invoke-Checked cargo @(
            'build', '-p', 'lore-server', '--release', '--bin', 'loreserver',
            '--features', 'failure_generator'
        ) | Out-Null
    }
    finally { Pop-Location }
    $serverBin = Join-Path $loreRoot 'target/release/loreserver.exe'
    if (-not (Test-Path $serverBin)) { $serverBin = Join-Path $loreRoot 'target/release/loreserver' }
    if (-not (Test-Path $serverBin)) { throw 'the release loreserver binary was not produced' }

    # -- gateway trust material and streams --------------------------------
    Write-Host '== provisioning the private gateway =='
    # The generator hardcodes cell `sfo3-cell-a` in the relay leaf's SPIFFE SAN,
    # and the gateway takes the cell from the CERTIFICATE, never from the
    # envelope. A different -CellId therefore needs its own leaf.
    $certScript = (Join-Path $gatewayRoot 'scripts/dev-certs.sh') -replace '\\', '/'
    $certDirPosix = $certDir -replace '\\', '/'
    Invoke-Checked $bash @($certScript, $certDirPosix) | Out-Null
    if ($CellId -ne 'sfo3-cell-a') {
        throw "dev-certs.sh mints its relay leaf for cell 'sfo3-cell-a'; -CellId '$CellId' has no " +
        'matching client certificate and the gateway would refuse it as SCOPE_MISMATCH.'
    }

    # Invoked directly rather than through `bun run --filter`, which does not
    # forward trailing arguments to the package script: the cell would silently
    # default and the streams this run publishes to would never be created.
    Push-Location $gatewayRoot
    try {
        $provisionOutput = Invoke-Checked bun @('scripts/provision-streams.ts', '--cell', $CellId, '--url', $NatsUrl)
    }
    finally { Pop-Location }

    # The cell's authoritative DURABLE stream, and its epoch.
    #
    # The gateway derives a stream's epoch from the JetStream stream's CREATION
    # TIMESTAMP in whole UNIX seconds (`broker/jetstream.ts`'s
    # `streamEpochFromCreated`) and refuses any Consume whose epoch disagrees
    # with what the broker reports. So the epoch is a discovered value, not a
    # chosen one: the harness stamps it into the cell's membership state, and a
    # constant anywhere in this stack would be wrong on every machine and
    # silently so, leaving every receiver looping on RECEIVER_EPOCH_MISMATCH_V1
    # with no boot failure to point at.
    #
    # `ensureCellStreams` UPDATES an existing stream rather than recreating it,
    # and this runner deliberately leaves the cell's streams behind, so the
    # value is stable across runs on one machine.
    $streamIdentity = "DURABLE-$CellId"
    $createdMatch = [regex]::Match(
        $provisionOutput,
        ('(?m)^\s*' + [regex]::Escape($streamIdentity) + '\s.*\bcreated=(?<created>\S+)\s*$')
    )
    if (-not $createdMatch.Success) {
        throw "could not read $streamIdentity's creation timestamp from the provisioner output; " +
        "the durable receiver's stream epoch cannot be derived.`n$provisionOutput"
    }
    # The fraction is dropped before parsing rather than after: NATS reports
    # nanosecond precision and .NET parses at most seven fractional digits.
    # Flooring to whole seconds is the derivation itself, so nothing is lost.
    $createdText = [regex]::Replace($createdMatch.Groups['created'].Value, '\.\d+', '')
    $streamEpoch = [DateTimeOffset]::Parse(
        $createdText,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    ).ToUnixTimeSeconds()
    if ($streamEpoch -le 0) {
        throw "derived a non-positive stream epoch ($streamEpoch) from '$createdText'"
    }
    Write-Host "   $streamIdentity epoch $streamEpoch (created $createdText)"

    $gatewayPrivatePort = $PortBase - 20
    $gatewayAdminPort = $PortBase - 19
    # `-AsArray` is load-bearing: `ConvertTo-Json` collapses a one-element array
    # to a bare object, and the gateway refuses a placement that is not a JSON
    # array with "must be a JSON array of placement records".
    # The revision the gateway serves. A receiver asserting any other value is
    # refused as RECEIVER_PLACEMENT_MISMATCH_V1, so the same variable reaches
    # the cases and is stamped into the cell's membership state.
    $placementRevision = 1
    $placement = @{
        region_id          = 'sfo3'
        cell_id            = $CellId
        shard_id           = 'shard-local'
        placement_epoch    = 12
        placement_revision = $placementRevision
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

    # -- cases -------------------------------------------------------------
    $ordinal = 0
    foreach ($result in $results) {
        $ordinal += 1
        $database = "wp109_aa2p_$($result.Case)_$runId"
        $bucket = "wp109-aa2p-$($result.Case)-$runId"
        $casePortBase = $PortBase + ($ordinal * 10)
        $caseWork = Join-Path $runRoot "case-$($result.Case)"

        Write-Host ""
        Write-Host "== case $($result.Case): $($result.Test) =="
        New-CaseDatabase -Name $database
        New-CaseBucket -Name $bucket
        New-Item -ItemType Directory -Force $caseWork | Out-Null

        $caseEnv = @{
            LORE_TEST_PG_URL             = "postgresql://$PostgresRole`:$PostgresRole@127.0.0.1:$PostgresHostPort/$database"
            LORE_AA2P_SERVER_BIN         = $serverBin
            LORE_AA2P_S3_BUCKET          = $bucket
            LORE_AA2P_S3_ENDPOINT        = $MinioEndpoint
            LORE_AA2P_S3_REGION          = 'us-east-1'
            LORE_AA2P_S3_ACCESS_KEY      = 'minioadmin'
            LORE_AA2P_S3_SECRET_KEY      = 'minioadmin'
            LORE_AA2P_JWKS_JSON          = (Join-Path $fixtures 'jwks.json')
            LORE_AA2P_JWT_PRIVATE_KEY    = (Join-Path $fixtures 'jwt-private-key.pem')
            LORE_AA2P_JWT_KID            = 'lorehub-test-key-1'
            LORE_AA2P_JWT_ISSUER         = 'https://id.commit0.localhost'
            LORE_AA2P_JWT_AUDIENCE       = 'lore-storage'
            LORE_AA2P_GATEWAY_URI        = "https://localhost:$gatewayPrivatePort"
            LORE_AA2P_CELL_ID            = $CellId
            LORE_AA2P_PLACEMENT_EPOCH    = '12'
            LORE_AA2P_STREAM_IDENTITY    = $streamIdentity
            LORE_AA2P_STREAM_EPOCH       = "$streamEpoch"
            LORE_AA2P_PLACEMENT_REVISION = "$placementRevision"
            LORE_AA2P_CLIENT_CERT        = (Join-Path $certDir 'relay.crt')
            LORE_AA2P_CLIENT_KEY         = (Join-Path $certDir 'relay.key')
            # The receiver's own least-privilege leaf. `Consume` and `Ack`
            # require the `receiver` role, and the relay leaf above
            # authenticates and is then UNAUTHORIZED_RECEIVER_ROLE_V1.
            LORE_AA2P_RECEIVER_CERT      = (Join-Path $certDir 'receiver.crt')
            LORE_AA2P_RECEIVER_KEY       = (Join-Path $certDir 'receiver.key')
            LORE_AA2P_TRUST_ROOTS        = (Join-Path $certDir 'ca.crt')
            # Namespaces every receiver's membership identity to THIS run. The
            # broker's streams and durable consumers outlive a run while the
            # case database does not, and a receiver that reuses a previous
            # run's identity at generation 1 attaches to that run's consumer
            # and inherits a permanent frontier gap. See `cell.rs`.
            LORE_AA2P_RUN_ID             = $runId
            LORE_AA2P_WORK_DIR           = $caseWork
            LORE_AA2P_PORT_BASE          = "$casePortBase"
            # The TEST process opens its own immutable store against the same
            # bucket to write revision content, and the AWS SDK reads these from
            # the environment. Without them the harness's own store fails to
            # authenticate while both server processes succeed, which reads as a
            # MinIO fault rather than a missing variable.
            AWS_ACCESS_KEY_ID            = 'minioadmin'
            AWS_SECRET_ACCESS_KEY        = 'minioadmin'
            AWS_REGION                   = 'us-east-1'
            AWS_DEFAULT_REGION           = 'us-east-1'
        }
        foreach ($pair in $caseEnv.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process')
        }

        Push-Location $loreRoot
        try {
            $cargoArgs = @(
                'test', '-p', 'lore-integration-tests', '--features', 'integration_tests',
                '--test', 'integration', '--', '--ignored', '--exact', $result.Test, '--test-threads=1', '--nocapture'
            )
            $commandLog.Add("cargo $($cargoArgs -join ' ')   # db=$database bucket=$bucket ports=$casePortBase")
            $output = & cargo @cargoArgs 2>&1 | Out-String
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
            foreach ($key in $caseEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
        }

        $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
        $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
        if ($runningMatch.Success) { $result.Ran = [int]$runningMatch.Groups[1].Value }
        if ($resultMatch.Success) {
            $result.Passed = [int]$resultMatch.Groups[1].Value
            $result.Failed = [int]$resultMatch.Groups[2].Value
        }

        if ($result.Ran -eq 1 -and $result.Passed -eq 1 -and $result.Failed -eq 0 -and $exitCode -eq 0) {
            $result.Status = 'PASS'
            Write-Host '   PASS'
        }
        elseif ($result.Ran -eq 1) {
            $result.Status = 'FAIL'
            $result.Note = 'see output above'
            Write-Warning "   FAIL`n$output"
        }
        else {
            # Zero executed tests is NOT RUN, never a pass. A filter that
            # matched nothing, a compile failure, and missing setup all land
            # here, and all three are the absence of evidence.
            $result.Status = 'NOT RUN'
            $result.Note = 'no test executed'
            Write-Warning "   NOT RUN`n$output"
        }

        $keep = $KeepOnFailure -and $result.Status -ne 'PASS'
        if ($keep) {
            Write-Warning "   keeping database $database, bucket $bucket, and $caseWork for debugging"
        }
        else {
            Remove-CaseDatabase -Name $database
            Remove-CaseBucket -Name $bucket
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
    if (-not $KeepOnFailure) {
        foreach ($database in @($createdDatabases)) { Remove-CaseDatabase -Name $database }
        foreach ($bucket in @($createdBuckets)) { Remove-CaseBucket -Name $bucket }
        if (Test-Path $runRoot) { Remove-Item -Recurse -Force $runRoot -ErrorAction SilentlyContinue }
    }
    else {
        Write-Warning "run artefacts kept under $runRoot"
    }
}

Write-Host ""
Write-Host '== commands =='
foreach ($line in $commandLog) { Write-Host "   $line" }

Write-Host ""
$results | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($results | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($results.Count)"
Write-Host ''
Write-Host 'NOW COVERED, and how (the cross-process governed mutation this runner used to be blind to):'
Write-Host '  Both loreservers point [environment.endpoint] auth_url at a rebac/auth-grpc stand-in'
Write-Host '  this harness serves in-process on the case band port +5'
Write-Host '  (tests/active_active_two_process_support/rebac_stub/). That one key builds the'
Write-Host '  repository-operation verifier a real loreserver otherwise has none of'
Write-Host '  (lore-server/src/domain.rs configure_domain_context), mounts the private'
Write-Host '  lore.domain.v1.DomainOperationService, and switches the repository-query authorizer'
Write-Host '  onto CheckUserPermission. The stub answers all three.'
Write-Host '  - case h: a fenced lock acquired through one process and released through the other'
Write-Host '    ONLY with its ownership token, each server reaching the coordinator through its own'
Write-Host '    DomainContext but the same database row. Both mutations go through the direct rail,'
Write-Host '    asserted against the stub''s own issue count.'
Write-Host '  - case i: a released client with NO carriage pushes through A (loreserver mints the'
Write-Host '    operation identity and asks the authorizer), the branch.pushed outbox row appears,'
Write-Host '    and the attempt receipt reads back COMMITTED/APPLIED through B by the lore-attempt-id'
Write-Host '    the client minted, while a different subject reads NOT_FOUND.'
Write-Host ''
Write-Host 'PIN: the stub is a TEST DOUBLE. The platform authorizer is the authority'
Write-Host '  (lorehub packages/control-plane/src/mutation-authorization.ts and'
Write-Host '  apps/auth-grpc/src/service-human-authorization.ts) together with its own tests. The'
Write-Host '  double mirrors the ten families, their role floors, the scope-family tripwire, the'
Write-Host '  issuer/subject echo checks and the bound-fields digest; the digest is pinned against'
Write-Host '  two vectors generated by running the platform implementation itself'
Write-Host '  (tests/rebac_stub_policy_test.rs, 15 pure cases, run with the ordinary cargo test'
Write-Host '  filter rebac_stub_policy, no live services).'
Write-Host ''
Write-Host 'BLOCKED, not covered by any case above:'
Write-Host '  - receiver resume from a captured position. A receiver that captured and then failed'
Write-Host '    allocates a NEW generation instead of resuming, because DurableStreamSource has no'
Write-Host '    resume-at-position operation that also restores the persisted frontier.'
Write-Host '    Missing artefact: ReceiverStore::read_checkpoint plus the TODO(WP-111) in'
Write-Host '    lore-server/src/plugins/remote_notification/receiver.rs.'
Write-Host '  - cross-process fenced ADMIN lock mutation (AdminLock/ForceUnlock over real gRPC).'
Write-Host '    The stub serves the two families (lock.force_release and lock.admin_acquire, both'
Write-Host '    owner-floored), so this is now only a missing case rather than a structural gap.'
Write-Host '  - the DENIAL half of the direct rail. Every case here grants the role its mutation'
Write-Host '    needs, so no case proves that an under-privileged principal is refused ACROSS TWO'
Write-Host '    PROCESSES. The stub''s policy is pinned by the pure suite, and the platform owns the'
Write-Host '    real decision, but neither is a live cross-process refusal.'
Write-Host '  - read-path authorization. Setting auth_url routes RepositoryGet and the metadata'
Write-Host '    RPCs through CheckUserPermission, and the stub answers that PERMISSIVELY on purpose:'
Write-Host '    it authenticates the bearer and then allows any urc-* resource. The read cases here'
Write-Host '    are about cross-process state, not access control, and none of them may be read as'
Write-Host '    evidence about it.'
Write-Host '  - a governed cross-process repository.create or repository.delete. Create is refused'
Write-Host '    on the direct rail by design on BOTH sides and stays on the mediated claim rail;'
Write-Host '    delete has no case written.'
Write-Host '  - governed CREATE CLAIM ACKNOWLEDGEMENT. Setting auth_url routes every repository'
Write-Host '    create through RebacApi.CreateResource, and loreserver requires an exact echo of the'
Write-Host '    attached claim before it opens the mutation transaction. The real platform answers'
Write-Host '    that from its own committed claim row; the stub ECHOES what it was sent, which is'
Write-Host '    exactly what a real verifier must never do. Nothing here is evidence about that'
Write-Host '    acknowledgement, and nothing was before either: this path called no authorizer at all'
Write-Host '    until auth_url was wired.'
Write-Host '  - a platform-side mirror of the digest vectors. The known-answer vectors in'
Write-Host '    tests/rebac_stub_policy_test.rs were generated by running the platform implementation'
Write-Host '    and hand-carried here, so they fail on a change to the Rust double and stay green on'
Write-Host '    a change to the platform preimage. The owed half is a matching vector in the'
Write-Host '    platform''s own suite.'
Write-Host '  - authorization expiry and the durable authorization row. The stub keeps minted'
Write-Host '    witnesses in memory for the life of a case, with no TTL and no retention sweep, so'
Write-Host '    nothing here exercises the platform''s five-minute window or its audit record.'

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
    exit 1
}
if ($failCount -ne 0 -or $notRunCount -ne 0) { exit 1 }
exit 0
