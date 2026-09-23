# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 16 instance and runs CR-039's fragment schema forward upgrade
inventory.

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
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [string[]]$OnlyCase = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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
            'a_revision_5_catalog_is_refused_as_an_unknown_state',
            'a_partial_stage_table_is_refused_as_an_unknown_state',
            'a_staged_lifecycle_head_is_refused_by_name',
            'a_preparingstage_lifecycle_head_is_refused_by_name',
            'a_non_terminal_staged_reader_lease_is_refused_by_name',
            'a_disabled_fence_is_refused_by_name',
            'a_non_clean_cell_is_refused_by_name',
            'a_database_identity_mismatch_is_refused_by_name',
            'a_live_lock_holder_refuses_with_contention_not_a_wait',
            'bootstrap_on_a_revision_4_clean_cell_returns_the_remedy_and_writes_nothing',
            'a_fresh_cell_and_an_upgraded_cell_have_an_identical_fragment_catalog'
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

Push-Location $loreRoot
try {
    foreach ($target in $inventory) {
        $arguments = @('test', '-j', '4', '-p', $target.Package, '--test', $target.Target, '--', '--ignored', '--list')
        $catalog = Invoke-CargoCaptured $arguments
        $names = @([regex]::Matches($catalog, '(?m)^([A-Za-z0-9_:]+): test\r?$') | ForEach-Object { $_.Groups[1].Value })
        if ($target.Exact) {
            $diff = Compare-Object $names $target.Cases
            if ($names.Count -eq 0 -or @($diff).Count -ne 0) {
                throw "ignored catalog mismatch for $($target.Target): compiled [$($names -join ', ')] expected [$($target.Cases -join ', ')]"
            }
        }
        foreach ($case in $target.Cases) {
            if ($OnlyCase.Count -gt 0 -and $OnlyCase -notcontains $case) {
                $results.Add([pscustomobject]@{ Package = $target.Package; Target = $target.Target; Test = $case; Status = 'NOT RUN' })
                continue
            }
            $results.Add([pscustomobject]@{ Package = $target.Package; Target = $target.Target; Test = $case; Status = 'PENDING' })
        }
    }

    $containerCreationAttempted = $true
    Invoke-Checked docker @(
        'run', '-d', '--name', $containerName,
        '--label', $ownershipLabel, '--label', "$ownershipLabelName.pid=$PID",
        '-p', '127.0.0.1::5432', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16'
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

    $savedUrl = [Environment]::GetEnvironmentVariable('LORE_TEST_PG_URL', 'Process')
    $index = 0
    foreach ($result in $results) {
        if ($result.Status -ne 'PENDING') { continue }
        $database = "cr039_schema_upgrade_$index"
        $index++
        Invoke-Checked docker @('exec', $containerName, 'createdb', '-U', 'postgres', $database)
        $env:LORE_TEST_PG_URL = "postgresql://postgres@127.0.0.1:$pgPort/$database`?sslmode=disable"
        try {
            $arguments = @('test', '-j', '4', '-p', $result.Package, '--test', $result.Target, '--', '--ignored', '--exact', $result.Test, '--nocapture')
            $output = Invoke-CargoCaptured $arguments
            Write-Host $output
            if ($output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { throw 'expected exactly one executed test' }
            $result.Status = 'PASS'
        }
        catch {
            $result.Status = 'FAIL'
            Write-Warning $_
        }
    }
    if ($null -ne $savedUrl) { $env:LORE_TEST_PG_URL = $savedUrl } else { Remove-Item Env:\LORE_TEST_PG_URL -ErrorAction SilentlyContinue }

    $runPassed = @($results | Where-Object Status -eq 'FAIL').Count -eq 0
    if (-not $runPassed) { throw 'fragment schema upgrade live tests failed' }
}
catch {
    $setupError = $_
    throw
}
finally {
    $results | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
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
