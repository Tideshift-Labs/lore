# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 18 (or 16, with -PostgresImage) instance and runs CR-039's
fragment schema forward upgrade inventory.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name, one at a
time, and reports PASS, FAIL, and NOT RUN separately. It verifies the compiled catalog before
Docker starts. A renamed, removed, added, or filtered-to-zero case is a setup failure.

The inventory spans two compiled targets: `lore-postgres`'s `domain_fragment_schema_upgrade`
(the coordinator's own real-Postgres proof) and `lore-server`'s `fragment_schema_upgrade_operator`
(one end-to-end run of the real `loreserver domain upgrade-fragments` binary). Neither needs
MinIO/S3: CR-039's upgrade is offline and database-only. Each case gets a fresh database in one
owned disposable container. Cleanup checks both the random run label and the owning PowerShell
process before removing the container and anonymous volume.

.PARAMETER PostgresImage
The PostgreSQL image to run. Default `postgres:18`. Its major must be 16 or 18, and the server's
`server_version_num` must match that major, or the run stops before any test.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [string[]]$OnlyCase = @(),
    [string]$PostgresImage = 'postgres:18'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The image tag names the major; the live server must then report that major.
$expectedMajor = if ($PostgresImage -match ':(?:pg|postgres)?(?<major>16|18)(?:[.-]|$)') { [int]$Matches.major } else {
    throw "PostgresImage $PostgresImage does not name a supported major (16 or 18) in its tag"
}

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "cr039-fragment-schema-upgrade-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.fragment-schema-upgrade-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Each entry is one compiled target plus the exact cases this runner owns.
# `Exact` means the target may hold no other ignored case, so a case added
# without updating this list is a setup failure rather than a silent skip.
$inventory = @(
    [pscustomobject]@{
        Package = 'lore-postgres'
        Kind    = 'test'
        Target  = 'domain_fragment_schema_upgrade'
        Exact   = $true
        Cases   = @(
            'revision_4_seam_fixture_matches_a_real_pre_stage_clean_cell',
            'happy_path_upgrades_a_seeded_clean_cell_then_runs_a_real_stage_drain_and_promotion',
            'rerun_after_success_reports_already_current_and_writes_nothing_further',
            'an_aborted_upgrade_transaction_leaves_the_cell_at_exact_revision_4_and_a_rerun_upgrades',
            'a_schema_state_column_mutated_during_the_step_rolls_back_the_whole_upgrade',
            'a_revision_5_catalog_is_refused_as_an_unknown_state',
            'a_partial_stage_table_is_refused_as_an_unknown_state',
            'a_staged_lifecycle_head_is_refused_by_name',
            'a_preparingstage_lifecycle_head_is_refused_by_name',
            'a_non_terminal_staged_reader_lease_is_refused_by_name',
            'a_disabled_fence_is_refused_by_name',
            'a_non_clean_cell_is_refused_by_name',
            'a_database_identity_mismatch_is_refused_by_name',
            'a_live_lock_holder_refuses_while_another_session_is_connected',
            'bootstrap_on_a_revision_4_clean_cell_returns_the_remedy_and_writes_nothing',
            'a_fresh_cell_and_an_upgraded_cell_have_an_identical_fragment_catalog',
            'an_idle_connected_session_refuses_the_upgrade_and_leaves_the_cell_at_revision_4',
            'a_v4_catalog_missing_two_known_indexes_is_refused_naming_both',
            'a_mid_ddl_failure_after_the_trigger_disable_rolls_back_and_reports_sqlstate',
            'a_realistic_row_exclusive_writer_refuses_while_another_session_is_connected',
            'bootstrap_on_a_clean_v5_cell_names_restore_or_escalate'
        )
    }
    [pscustomobject]@{
        Package = 'lore-server'
        Kind    = 'test'
        Target  = 'fragment_schema_upgrade_operator'
        Exact   = $true
        Cases   = @(
            'real_loreserver_binary_upgrades_a_revision_4_clean_cell_and_emits_parseable_json'
        )
    }
    # WP-115 ledger row 62: the NOWAIT backstop needs a pause between the backend count and the
    # table locks, so it compiles only with `failure_generator`. That build also lists the 21
    # cases above, hence not `Exact`: this entry checks only that its own case exists.
    [pscustomobject]@{
        Package  = 'lore-postgres'
        Kind     = 'test'
        Target   = 'domain_fragment_schema_upgrade'
        Exact    = $false
        Features = @('failure_generator')
        Failpoints = 'schema_upgrade.drain.before_update=pause'
        Cases    = @(
            'the_nowait_backstop_refuses_a_lock_holder_that_races_the_backend_count'
        )
    }
)

function Invoke-Checked([string]$Program, [string[]]$ArgumentList) {
    & $Program @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "$Program exited $LASTEXITCODE" }
}

function Invoke-CargoCaptured([string[]]$ArgumentList) {
    $output = (& cargo @ArgumentList 2>&1 | Out-String)
    $status = $LASTEXITCODE
    if ($status -ne 0) { throw "cargo exited ${status}:`n$output" }
    return $output
}

$results = [Collections.Generic.List[object]]::new()
$savedEnv = @{}
foreach ($key in @('LORE_TEST_PG_URL', 'LORE_FRAGMENT_FAILPOINTS', 'LORE_FRAGMENT_FAILPOINT_DIR')) {
    $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}

Push-Location $loreRoot
try {
    foreach ($target in $inventory) {
        $featureArgs = if ($target.PSObject.Properties['Features']) { @('--features', ($target.Features -join ',')) } else { @() }
        $failpoints = if ($target.PSObject.Properties['Failpoints']) { $target.Failpoints } else { $null }
        $arguments = @('test', '-j', '4', '-p', $target.Package, '--test', $target.Target) + $featureArgs + @('--', '--ignored', '--list')
        $catalog = Invoke-CargoCaptured $arguments
        $names = @([regex]::Matches($catalog, '(?m)^([A-Za-z0-9_:]+): test\r?$') | ForEach-Object { $_.Groups[1].Value })
        if ($target.Exact) {
            $diff = Compare-Object $names $target.Cases
            if ($names.Count -eq 0 -or @($diff).Count -ne 0) {
                throw "ignored catalog mismatch for $($target.Target): compiled [$($names -join ', ')] expected [$($target.Cases -join ', ')]"
            }
        }
        else {
            $missing = @($target.Cases | Where-Object { $names -notcontains $_ })
            if ($missing.Count -ne 0) {
                throw "ignored catalog for $($target.Target) $($featureArgs -join ' ') is missing [$($missing -join ', ')]"
            }
        }
        foreach ($case in $target.Cases) {
            $status = if ($OnlyCase.Count -gt 0 -and $OnlyCase -notcontains $case) { 'NOT RUN' } else { 'PENDING' }
            $results.Add([pscustomobject]@{ Package = $target.Package; Target = $target.Target; Test = $case; Status = $status; FeatureArgs = $featureArgs; Failpoints = $failpoints })
        }
    }

    $containerCreationAttempted = $true
    Invoke-Checked docker @(
        'run', '-d', '--name', $containerName,
        '--label', $ownershipLabel, '--label', "$ownershipLabelName.pid=$PID",
        '-p', '127.0.0.1::5432', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', $PostgresImage
    )
    $pgPort = ((& docker port $containerName '5432/tcp') -split ':')[-1].Trim()
    # The official image restarts internally after its first init pass, so
    # `pg_isready` can observe the transient first instance and race the
    # restart. Wait for BOTH "ready to accept connections" log lines, the
    # same signal the sibling fragment-lifecycle runner uses.
    $ready = $false
    $priorErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        foreach ($attempt in 1..120) {
            $logOutput = (& docker logs $containerName 2>&1) -join "`n"
            if ([regex]::Matches($logOutput, 'database system is ready to accept connections').Count -ge 2) {
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
    if (-not $ready) { throw 'PostgreSQL readiness timed out' }
    $serverVersionRaw = & docker exec $containerName psql -U postgres -d postgres -tAc 'SHOW server_version_num'
    if ($LASTEXITCODE -ne 0) { throw 'failed to query the disposable PostgreSQL server version' }
    $serverVersion = [int](($serverVersionRaw | Out-String).Trim())
    if ($serverVersion -lt ($expectedMajor * 10000) -or $serverVersion -ge (($expectedMajor + 1) * 10000)) {
        throw "expected PostgreSQL $expectedMajor, found server_version_num=$serverVersion"
    }
    Write-Host "PostgreSQL server_version_num=$serverVersion ($PostgresImage)"

    $index = 0
    foreach ($result in $results) {
        if ($result.Status -ne 'PENDING') { continue }
        $database = "cr039_schema_upgrade_$index"
        $index++
        Invoke-Checked docker @('exec', $containerName, 'createdb', '-U', 'postgres', $database)
        $env:LORE_TEST_PG_URL = "postgresql://postgres@127.0.0.1:$pgPort/$database`?sslmode=disable"
        # Failpoints are armed for their own case only, with a fresh rendezvous directory.
        $rendezvous = $null
        if ($result.Failpoints) {
            $rendezvous = Join-Path ([IO.Path]::GetTempPath()) "cr039-failpoints-$runId-$index"
            New-Item -ItemType Directory -Path $rendezvous | Out-Null
            $env:LORE_FRAGMENT_FAILPOINTS = $result.Failpoints
            $env:LORE_FRAGMENT_FAILPOINT_DIR = $rendezvous
        }
        else {
            Remove-Item Env:\LORE_FRAGMENT_FAILPOINTS, Env:\LORE_FRAGMENT_FAILPOINT_DIR -ErrorAction SilentlyContinue
        }
        try {
            $arguments = @('test', '-j', '4', '-p', $result.Package, '--test', $result.Target) + $result.FeatureArgs + @('--', '--ignored', '--exact', $result.Test, '--nocapture')
            $output = Invoke-CargoCaptured $arguments
            Write-Host $output
            if ($output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { throw 'expected exactly one executed test' }
            $result.Status = 'PASS'
        }
        catch {
            $result.Status = 'FAIL'
            Write-Warning $_
        }
        finally {
            if ($rendezvous) { Remove-Item -Recurse -Force -LiteralPath $rendezvous -ErrorAction SilentlyContinue }
        }
    }
    $runPassed = @($results | Where-Object Status -eq 'FAIL').Count -eq 0
    if (-not $runPassed) { throw 'fragment schema upgrade live tests failed' }
}
catch {
    $setupError = $_
    throw
}
finally {
    foreach ($key in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process')
    }
    $results | Format-Table Package, Target, Test, Status -AutoSize | Out-String -Width 240 | Write-Host
    if ($containerCreationAttempted) {
        if ($KeepOnFailure -and -not $runPassed) {
            Write-Host "Preserved owned container $containerName"
        }
        else {
            $inspection = & docker inspect $containerName 2>$null
            if ($LASTEXITCODE -eq 0) {
                $container = @($inspection | ConvertFrom-Json)[0]
                if ($container.Config.Labels.$ownershipLabelName -ne $runId -or $container.Config.Labels."$ownershipLabelName.pid" -ne "$PID") {
                    throw "refusing cleanup: ownership changed for $containerName"
                }
                Invoke-Checked docker @('rm', '--force', '--volumes', $containerName)
            }
        }
    }
    Pop-Location
    if ($setupError) { Write-Warning $setupError }
}
