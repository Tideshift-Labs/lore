# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions a disposable PostgreSQL 16 (with a real BLAKE3 provider) and runs CR-038's forward
schema-upgrade live tier by exact name, reporting PASS / FAIL / NOT RUN as three distinct states.

.DESCRIPTION
CR-038 adds a forward step (migration 0028: the spool metadata true-up) and an `upgrade` verb
that moves an attested R27 cell to the current state offline, under a session advisory lock.
`cell_schema_forward_upgrade_live.rs` is the executable proof; this runner is its own container,
distinct from `run-cell-schema-install-live.ps1`'s, because two of its tests need a genuine BLAKE3
provider at `public.blake3(bytea)` (the flagship wedge/upgrade test and the true-up/underflow
test, both of which drive `drain_cleanup_release_v1`, which calls `local_blake3_v1`). The image is
built once and reused, the same `Dockerfile.postgres-blake3` shape
`lore-postgres/tests/run-write-behind-linux.ps1` uses on Linux, built here for the Windows Docker
Desktop Linux-container backend.

Steps:

  1. Cross-checks its own test name/target map against
     `cargo test -p lore-object-dispatch -- --ignored --list` before touching Docker.
  2. Refuses to continue if any container already carries this runner's ownership label.
  3. Builds (or reuses) the postgres-blake3 image, then starts one labelled, disposable container.
  4. Creates the four `object_dispatch_retention_*` roles ONCE, cluster-wide: owner NOLOGIN, the
     other three LOGIN, the migrator a non-inheriting member of owner (WITH INHERIT FALSE, SET
     TRUE) -- the same load-bearing shape `run-cell-schema-install-live.ps1` uses.
  5. Creates one database per test, handed to the test as the `postgres` superuser URL; the test
     itself derives the migrator/runtime/maintenance URLs by swapping the user.
  6. Runs each test by exact name, serially (`--test-threads=1`): several tests share one
     container-wide advisory lock key and role set, and must not interleave.
  7. Parses `running N tests` and `test result: ... P passed; F failed`. A filter that matched
     zero tests is NOT RUN, never a pass.
  8. Removes only its own labelled container.

.PARAMETER KeepOnFailure
Keeps the container for debugging when the run did not fully pass.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "wp-cr038-forward-upgrade-live-$runId"
$ownershipLabel = "com.tideshift.lore.cell-schema-forward-upgrade-live=$runId"
$containerStarted = $false
$runPassed = $false

$target = 'cell_schema_forward_upgrade_live'
$imageTag = 'lore-cell-schema-forward-upgrade:postgres16-blake3-v1'

$tests = @(
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_WEDGE_PG_URL'; Name = 'live_upgraded_cell_survives_the_load_that_wedges_an_unupgraded_cell'; Database = 'wedge' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_D5_PG_URL'; Name = 'live_write_behind_refuses_an_unupgraded_cell_and_accepts_an_upgraded_one'; Database = 'd5' },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_UPGRADE_REFUSALS_PG_URL'
        Name     = 'live_upgrade_refuses_unknown_states_future_markers_and_active_replicas'
        Database = 'refusals'
        # The test opens a SECOND database of its own inside this same case, to prove the
        # replica-active refusal without the drift/future-marker probes on the first database
        # also holding a session open.
        ExtraEnv = @{ 'LORE_TEST_CELL_SCHEMA_UPGRADE_REFUSALS_REPLICA_PG_URL' = 'refusals_replica' }
    },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_LOCK_PG_URL'; Name = 'live_two_concurrent_upgrades_exactly_one_proceeds'; Database = 'lock' },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_UPGRADE_PARITY_FRESH_PG_URL'
        Name     = 'live_fresh_install_and_upgraded_cell_attest_identical_manifests'
        Database = 'parity_fresh'
        ExtraEnv = @{ 'LORE_TEST_CELL_SCHEMA_UPGRADE_PARITY_UPGRADED_PG_URL' = 'parity_upgraded' }
    },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_LOST_COMMIT_PG_URL'; Name = 'live_upgrade_recovers_from_a_lost_commit_reply'; Database = 'lost_commit' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_KILL_MID_ATTEST_PG_URL'; Name = 'live_upgrade_recovers_from_a_kill_mid_attest'; Database = 'kill_mid_attest' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_KILL_BEFORE_COMMIT_PG_URL'; Name = 'live_upgrade_recovers_from_a_kill_before_commit'; Database = 'kill_before_commit' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_BACKFILL_STATES_PG_URL'; Name = 'live_backfill_leaves_other_states_untouched_and_the_guard_prevents_a_double_give_back'; Database = 'backfill_states' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_REAL_CAP_PG_URL'; Name = 'live_upgraded_cell_at_real_dev_cap_stays_writable'; Database = 'real_cap' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_TRUE_UP_PG_URL'; Name = 'live_release_true_up_matches_actual_size_and_underflow_raises'; Database = 'true_up' },
    # CR-038 addendum (2026-09-23): R25/R26 join the closed attested list.
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_CHAIN_PG_URL'; Name = 'live_install_at_r25_upgrades_to_current_and_drain_client_writes'; Database = 'r25_chain' },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_SPOOL_REFUSAL_PG_URL'
        Name     = 'live_r25_upgrade_refuses_a_spool_object_or_charged_quota_and_leaves_the_cell_at_r25'
        Database = 'r25_spool_refusal'
        ExtraEnv = @{ 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_QUOTA_REFUSAL_PG_URL' = 'r25_quota_refusal' }
    },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_DRIFT_PG_URL'; Name = 'live_r25_upgrade_refuses_a_state_outside_the_known_list'; Database = 'r25_drift' },
    @{ EnvVar = 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_LOST_COMMIT_PG_URL'; Name = 'live_upgrade_recovers_from_a_lost_commit_after_the_r25_to_r26_step'; Database = 'r25_lost_commit' },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FRESH_PG_URL'
        Name     = 'live_fresh_r25_upgrade_and_r26_resume_attest_identical_manifests'
        Database = 'r25_parity_fresh'
        ExtraEnv = @{
            'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FROM_R25_PG_URL' = 'r25_parity_from_r25'
            'LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FROM_R26_PG_URL' = 'r25_parity_from_r26'
        }
    }
)

$environmentNames = @($tests | ForEach-Object { $_.EnvVar })
foreach ($t in $tests) {
    if ($t.ContainsKey('ExtraEnv')) {
        $environmentNames += @($t.ExtraEnv.Keys)
    }
}
$priorEnvironment = @{}
foreach ($name in $environmentNames) {
    $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-IgnoredTestCatalog {
    Push-Location $loreRoot
    try {
        $output = & cargo test -p lore-object-dispatch -- --ignored --list 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "cargo test -p lore-object-dispatch -- --ignored --list failed:`n$output"
    }
    $catalog = @()
    $currentTarget = $null
    foreach ($line in ($output -split "`r?`n")) {
        $headerMatch = [regex]::Match($line, '^\s*Running tests\\(?<target>[^\\]+)\.rs\b')
        if ($headerMatch.Success) {
            $currentTarget = $headerMatch.Groups['target'].Value
            continue
        }
        if ($line -match '^\s*Running (?:unittests|benches)\b' -or $line -match '^\s*Doc-tests\b') {
            $currentTarget = $null
            continue
        }
        $nameMatch = [regex]::Match($line, '^(?<name>[A-Za-z0-9_]+): test$')
        if ($nameMatch.Success) {
            $catalog += [pscustomobject]@{ Target = $currentTarget; Name = $nameMatch.Groups['name'].Value }
        }
    }
    return $catalog
}

function Assert-CatalogMatchesKnownTests {
    Write-Host 'Cross-checking the ignored-test catalog against this harness''s known live tests...'
    $catalog = Get-IgnoredTestCatalog
    foreach ($t in $tests) {
        $found = @($catalog | Where-Object { $_.Target -eq $target -and $_.Name -eq $t.Name })
        if ($found.Count -ne 1) {
            throw "known live test $($t.Name) ($target) was not found (or was found more than once); it may have been renamed or moved"
        }
    }
    $ownCatalog = @($catalog | Where-Object { $_.Target -eq $target })
    $unknown = @($ownCatalog | Where-Object {
            $candidate = $_
            -not @($tests | Where-Object { $_.Name -eq $candidate.Name })
        })
    if ($unknown.Count -gt 0) {
        $descriptions = ($unknown | ForEach-Object { $_.Name }) -join '; '
        throw "found $target ignored test(s) unknown to this harness: $descriptions -- add them to the test map before trusting a green run"
    }
    Write-Host "Ignored-test catalog: $($ownCatalog.Count) test(s) in $target, all known."
}

function Assert-NoCollidingContainer {
    $labelFormat = '{{.Names}}|||{{.Status}}|||{{.Label "com.tideshift.lore.cell-schema-forward-upgrade-live.pid"}}' +
    '|||{{.Label "com.tideshift.lore.cell-schema-forward-upgrade-live.started"}}'
    $existingRaw = & docker ps -a --filter 'label=com.tideshift.lore.cell-schema-forward-upgrade-live' --format $labelFormat
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to check for a colliding cell-schema-forward-upgrade-live container'
    }
    $existing = @($existingRaw | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($existing.Count -eq 0) {
        return
    }
    $rows = $existing | ForEach-Object {
        $fields = $_ -split '\|\|\|'
        "  - $($fields[0]) [$($fields[1])] pid=$($fields[2]) started=$($fields[3])"
    }
    throw "found $($existing.Count) colliding container(s):`n$($rows -join "`n")`nCheck the pid label before treating one as an orphan."
}

function Build-PostgresBlake3Image {
    $existing = (& docker image inspect $imageTag 2>$null | Out-String).Trim()
    if ($existing -and $LASTEXITCODE -eq 0) {
        return
    }
    $context = [IO.Path]::GetFullPath((Join-Path $loreRoot '../lorehub/docker/dev-cell'))
    $dockerfile = Join-Path $context 'Dockerfile.postgres-blake3'
    if (-not (Test-Path -LiteralPath $dockerfile)) {
        throw "postgres-blake3 Dockerfile missing: $dockerfile"
    }
    Write-Host "Building $imageTag (plpython3u + blake3, one-time)..."
    Invoke-Checked docker @('build', '--file', $dockerfile, '--tag', $imageTag, $context)
}

try {
    Assert-CatalogMatchesKnownTests
    Assert-NoCollidingContainer
    Build-PostgresBlake3Image

    $containerStarted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.cell-schema-forward-upgrade-live.pid=$PID",
        '--label', "com.tideshift.lore.cell-schema-forward-upgrade-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        $imageTag
    )

    $portOutputRaw = & docker port $containerName '5432/tcp'
    $portExitCode = $LASTEXITCODE
    $portOutput = if ($null -ne $portOutputRaw) { ($portOutputRaw | Out-String).Trim() } else { '' }
    if ($portExitCode -ne 0 -or $portOutput -notmatch ':(?<port>[0-9]+)$') {
        throw 'failed to resolve the disposable PostgreSQL host port'
    }
    $port = $Matches.port

    $ready = $false
    foreach ($attempt in 1..120) {
        $logOutput = (& docker logs $containerName 2>&1) -join "`n"
        $readyEvents = [regex]::Matches($logOutput, 'database system is ready to accept connections').Count
        if ($readyEvents -ge 2) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        & docker logs $containerName
        throw 'disposable PostgreSQL did not become ready within 60 seconds'
    }

    $roleSql = @'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN
    CREATE ROLE object_dispatch_retention_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN
    CREATE ROLE object_dispatch_retention_runtime LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN
    CREATE ROLE object_dispatch_retention_maintenance LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN
    CREATE ROLE object_dispatch_retention_migrator LOGIN;
  END IF;
END
$$;
GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator
  WITH INHERIT FALSE, SET TRUE;
'@
    Invoke-Checked docker @(
        'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
        '-c', $roleSql
    )

    foreach ($t in $tests) {
        $databases = @($t.Database)
        if ($t.ContainsKey('ExtraEnv')) {
            $databases += @($t.ExtraEnv.Values)
        }
        foreach ($database in $databases) {
            Invoke-Checked docker @(
                'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
                '-c', "CREATE DATABASE $database;"
            )
            Invoke-Checked docker @(
                'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
                '-c', "GRANT CREATE ON DATABASE $database TO object_dispatch_retention_owner;"
            )
        }
        [Environment]::SetEnvironmentVariable($t.EnvVar, "postgresql://postgres@localhost:$port/$($t.Database)", 'Process')
        if ($t.ContainsKey('ExtraEnv')) {
            foreach ($extra in $t.ExtraEnv.GetEnumerator()) {
                [Environment]::SetEnvironmentVariable($extra.Key, "postgresql://postgres@localhost:$port/$($extra.Value)", 'Process')
            }
        }
    }

    $results = @()
    Push-Location $loreRoot
    try {
        foreach ($t in $tests) {
            Write-Host "Running $($t.Name) ($target)..."
            $cargoArgs = @(
                'test', '-p', 'lore-object-dispatch', '--test', $target, '--',
                '--ignored', '--exact', $t.Name, '--test-threads=1', '--nocapture'
            )
            $output = & cargo @cargoArgs 2>&1 | Out-String
            $exitCode = $LASTEXITCODE

            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
            if (-not $runningMatch.Success -or -not $resultMatch.Success) {
                Write-Warning $output
                throw "could not parse cargo test output for $($t.Name)"
            }
            $ran = [int]$runningMatch.Groups[1].Value
            $passed = [int]$resultMatch.Groups[1].Value
            $failed = [int]$resultMatch.Groups[2].Value
            $status = if ($ran -ne 1) { 'NOT RUN' } elseif ($passed -eq 1 -and $failed -eq 0 -and $exitCode -eq 0) { 'PASS' } else { 'FAIL' }
            $results += [pscustomobject]@{ Test = $t.Name; Status = $status; Passed = $passed; Failed = $failed; Ran = $ran }
            if ($status -eq 'PASS') { Write-Host '  PASS' } else { Write-Warning "  $status`n$output" }
        }
    }
    finally {
        Pop-Location
    }

    $results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $expected = $tests.Count
    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failures = @($results | Where-Object { $_.Status -ne 'PASS' })
    if ($passCount -ne $expected) {
        Write-Warning "$passCount of $expected forward-upgrade live tests passed; $($failures.Count) did not:"
        foreach ($failure in $failures) { Write-Warning "  $($failure.Test): $($failure.Status)" }
    }
    else {
        $runPassed = $true
        Write-Host "All $expected forward-upgrade live tests passed."
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], 'Process')
    }
    if ($containerStarted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"com.tideshift.lore.cell-schema-forward-upgrade-live`" }}" $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq $runId) {
            & docker rm --force --volumes $containerName *> $null
        }
        else {
            Write-Warning "refusing to remove unowned container $containerName"
        }
    }
    elseif ($containerStarted) {
        Write-Warning "keeping container $containerName for debugging (-KeepOnFailure)"
    }
}

if (-not $runPassed) {
    exit 1
}
