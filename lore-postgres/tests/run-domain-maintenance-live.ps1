# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned disposable PostgreSQL 16 instance and runs CR-029's fixed maintenance inventory.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name, one at a time,
and reports PASS, FAIL, and NOT RUN separately. Before Docker starts, it checks the compiled
catalogs against the fixed cross-target inventory. A renamed, removed, or added case is a hard
setup failure, not a silent zero-test success.

The container is labelled with a random run id and the owning PowerShell process. Each exact case
gets a distinct database inside that container, which is dropped after the case. Teardown ownership
is registered before `docker run` is attempted. Cleanup inspects the exact run-id label and removes
only this runner's container and anonymous volume.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [ValidateRange(1, 86400)][int]$CommandTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
. (Join-Path $PSScriptRoot 'common/foreground_process.ps1')
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "wp116-domain-maintenance-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.domain-maintenance-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

$expectedCases = @(
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'stale_finalize_database_clock_equality_then_one_millisecond_commits_exactly_once' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_recovery_response_digest_tracks_merged_interval_while_marker_replay_is_stable' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_retention_persists_each_later_of_arm_and_refuses_early_prune' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_recovery_rejects_range_protocol_revision_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_recovery_rejects_range_quota_revision_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_recovery_rejects_range_digest_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_prune_bridge_merge_preserves_distant_successor_and_counters' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_prune_reverse_merge_preserves_distant_successor_and_counters' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'materialization_replay_from_retired_epoch_cannot_resurrect_or_charge_new_epoch' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_prune_rejects_neighbor_protocol_revision_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_prune_rejects_neighbor_quota_revision_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'completion_prune_rejects_neighbor_digest_without_mutation' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'namespace_state_absent_and_binding_mismatch_never_mutate' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'namespace_state_quiescent_and_outstanding_vectors_are_read_only' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'namespace_state_missing_coverage_is_nonquiescent_and_never_repaired' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'namespace_state_reads_one_snapshot_across_concurrent_retirement' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'stale_finalize_commits_once_replays_exactly_and_isolates_binding' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'stale_finalize_lost_commit_ack_is_unknown_then_authoritative_replay_adopts_commit' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase1_replays_then_atomically_exchanges_receipt_fence_for_tombstone' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase1_mismatch_leaves_the_dispatch_fence_untouched' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase2_completion_head_of_line_blocks_and_mutates_nothing' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase2_completion_unblocks_after_predecessor_retaining_assignment' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase2_completion_far_future_sequence_is_not_ready_not_mismatch' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_phase2_completion_lower_sequence_and_replay_pin_current_behaviour' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_attach_accepts_wire_applied_against_stored_applied_receipt' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_attach_accepts_wire_not_applied_against_stored_not_applied_receipt' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_attach_refuses_a_storage_encoded_terminal_outcome' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'terminal_attach_refuses_a_wire_outcome_disagreeing_with_the_stored_receipt' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'materialize_replay_preserves_receipt_and_changed_claim_mismatches' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'materialize_replay_with_a_null_receipt_is_mismatch_not_a_panic' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'materialize_capacity_revision_mismatch_writes_no_namespace' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'fresh_cell_seeds_global_counter_and_first_materialize_provisions_org_counter' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'materialize_changed_org_replay_mismatches_without_provisioning_wrong_org' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'fresh_org_stale_capacity_revision_blocks_without_provisioning_org_counter' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'retire_with_missing_org_counter_returns_mismatch_not_internal' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'retire_with_missing_global_counter_returns_mismatch_not_internal' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'retire_is_atomic_replays_absence_and_rejects_expired_permit' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'retire_requires_exact_fence_generation_and_final_range_digest' },
    [pscustomobject]@{ Target = 'domain_maintenance'; Test = 'retire_rejects_nonquiescent_namespace_and_changed_epoch_claim_without_mutation' },
    [pscustomobject]@{ Target = 'domain_coordinator_regressions'; Test = 'prepare_creates_the_dispatch_fence_with_the_exact_verified_binding' },
    [pscustomobject]@{ Target = 'domain_coordinator_regressions'; Test = 'repository_create_exact_replay_returns_the_committed_outcome' },
    [pscustomobject]@{ Target = 'domain_coordinator_regressions'; Test = 'expired_prepare_terminalization_survives_the_coordinator_return' },
    [pscustomobject]@{ Target = 'domain_coordinator_regressions'; Test = 'concurrent_repository_create_name_conflict_is_decisive_name_taken' },
    [pscustomobject]@{ Target = 'domain_claim_identity_digest'; Test = 'every_one_field_digest_mutation_is_refused_against_the_prepared_fence' }
)

$results = @(
    foreach ($case in $expectedCases) {
        [pscustomobject]@{
            Target = $case.Target
            Test   = $case.Test
            Status = 'NOT RUN'
            Passed = 0
            Failed = 0
            Ran    = 0
        }
    }
)

$priorPgUrl = [Environment]::GetEnvironmentVariable('LORE_TEST_PG_URL', 'Process')

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    $result = Invoke-ForegroundProcess -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $loreRoot -TimeoutSeconds $CommandTimeoutSeconds
    if ($result.ExitCode -ne 0) {
        throw "$FilePath exited with code $($result.ExitCode): $($result.Output)"
    }
}

function Get-MaintenanceTestCatalog {
    param(
        [Parameter(Mandatory)]
        [string]$Target
    )
    Push-Location $loreRoot
    try {
        $listArgs = @(
            'test', '-p', 'lore-postgres', '-j', '4', '--test', $Target, '--',
            '--ignored', '--list'
        )
        $result = Invoke-ForegroundProcess -FilePath cargo -ArgumentList $listArgs -WorkingDirectory $loreRoot -TimeoutSeconds $CommandTimeoutSeconds
        $output = $result.Output
        $exitCode = $result.ExitCode
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "maintenance test catalog failed:`n$output"
    }

    return @(
        foreach ($line in ($output -split "`r?`n")) {
            $match = [regex]::Match($line, '^(?<name>[A-Za-z0-9_]+): test$')
            if ($match.Success) {
                $match.Groups['name'].Value
            }
        }
    )
}

function Assert-ExpectedCatalog {
    foreach ($target in @($expectedCases.Target | Sort-Object -Unique)) {
        $expected = @($expectedCases | Where-Object { $_.Target -eq $target } | ForEach-Object { $_.Test })
        $catalog = @(Get-MaintenanceTestCatalog -Target $target)
        $missing = @($expected | Where-Object { $_ -notin $catalog })
        $unexpected = @($catalog | Where-Object { $_ -notin $expected })
        if ($catalog.Count -ne $expected.Count -or $missing.Count -ne 0 -or $unexpected.Count -ne 0) {
            $message = "expected exactly $($expected.Count) tests in $target; catalog has $($catalog.Count). " +
                "Missing=[$($missing -join ', ')]; unexpected=[$($unexpected -join ', ')]"
            throw $message
        }
    }
}

function Assert-NoCollidingContainer {
    $inspection = Invoke-ForegroundProcess -FilePath docker -ArgumentList @('ps', '--all', '--filter', "label=$ownershipLabelName", '--format', '{{.Names}}|{{.Status}}|{{.Label "com.tideshift.lore.domain-maintenance-live.pid"}}') -WorkingDirectory $loreRoot -TimeoutSeconds $CommandTimeoutSeconds
    $raw = $inspection.Output -split "`r?`n"
    if ($inspection.ExitCode -ne 0) {
        throw 'failed to inspect existing domain-maintenance live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another domain-maintenance live container exists; refusing to overlap:`n" +
            ($collisions -join "`n")
        throw $message
    }
}

try {
    Assert-ExpectedCatalog
    Assert-NoCollidingContainer

    # Register teardown ownership before creation. If docker creates the object and then returns an
    # error, the finally block still inspects and removes only the exact run-id-labelled resource.
    $containerCreationAttempted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.domain-maintenance-live.pid=$PID",
        '--label', "com.tideshift.lore.domain-maintenance-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        'postgres:16'
    )

    $portResult = Invoke-ForegroundProcess docker @('port', $containerName, '5432/tcp') $loreRoot $CommandTimeoutSeconds
    $portOutputRaw = $portResult.Output
    $portExitCode = $portResult.ExitCode
    $portOutput = if ($null -ne $portOutputRaw) { ($portOutputRaw | Out-String).Trim() } else { '' }
    if ($portExitCode -ne 0 -or $portOutput -notmatch ':(?<port>[0-9]+)$') {
        throw 'failed to resolve the disposable PostgreSQL host port'
    }
    $port = $Matches.port

    $ready = $false
    foreach ($attempt in 1..120) {
        $logResult = Invoke-ForegroundProcess docker @('logs', $containerName) $loreRoot $CommandTimeoutSeconds
        if ($logResult.ExitCode -ne 0) { throw "failed to read owned container logs: $($logResult.Output)" }
        $logOutput = $logResult.Output
        $readyEvents = [regex]::Matches(
            $logOutput,
            'database system is ready to accept connections'
        ).Count
        if ($readyEvents -ge 2) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        Write-Host $logOutput
        throw 'disposable PostgreSQL did not become ready within 60 seconds'
    }

    $versionResult = Invoke-ForegroundProcess docker @('exec', $containerName, 'psql', '-tA', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', '-c', 'SHOW server_version_num;') $loreRoot $CommandTimeoutSeconds
    $serverVersionRaw = $versionResult.Output
    if ($versionResult.ExitCode -ne 0) {
        throw 'failed to query the disposable PostgreSQL server version'
    }
    $serverVersion = [int](($serverVersionRaw | Out-String).Trim())
    if ($serverVersion -lt 160000 -or $serverVersion -ge 170000) {
        throw "expected PostgreSQL 16, found server_version_num=$serverVersion"
    }

    Push-Location $loreRoot
    try {
        $testOrdinal = 0
        foreach ($result in $results) {
            $testOrdinal += 1
            $databaseName = "wp116_maintenance_$($testOrdinal)_$($runId.Substring(0, 12))"
            Invoke-Checked docker @(
                'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1',
                '-U', 'postgres', '-d', 'postgres',
                '-c', "CREATE DATABASE $databaseName;"
            )
            [Environment]::SetEnvironmentVariable(
                'LORE_TEST_PG_URL',
                "postgresql://postgres@127.0.0.1:$port/$databaseName",
                'Process'
            )
            Write-Host "Running $($result.Test)..."
            try {
                $cargoArgs = @(
                    'test', '-p', 'lore-postgres', '-j', '4', '--test', $result.Target, '--',
                    '--ignored', '--exact', $result.Test, '--test-threads=1'
                )
                $processResult = Invoke-ForegroundProcess -FilePath cargo -ArgumentList $cargoArgs -WorkingDirectory $loreRoot -TimeoutSeconds $CommandTimeoutSeconds
                $output = $processResult.Output
                $exitCode = $processResult.ExitCode
            }
            finally {
                [Environment]::SetEnvironmentVariable(
                    'LORE_TEST_PG_URL',
                    $null,
                    'Process'
                )
                Invoke-Checked docker @(
                    'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1',
                    '-U', 'postgres', '-d', 'postgres',
                    '-c', "DROP DATABASE $databaseName WITH (FORCE);"
                )
            }
            # Preserve the actual Rust summary once for machine-readable evidence.
            Write-Host $output
            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match(
                $output,
                'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;'
            )

            if ($runningMatch.Success) {
                $result.Ran = [int]$runningMatch.Groups[1].Value
            }
            if ($resultMatch.Success) {
                $result.Passed = [int]$resultMatch.Groups[1].Value
                $result.Failed = [int]$resultMatch.Groups[2].Value
            }

            if ($result.Ran -eq 1 -and $result.Passed -eq 1 -and
                $result.Failed -eq 0 -and $exitCode -eq 0) {
                $result.Status = 'PASS'
                Write-Host '  PASS'
            }
            elseif ($result.Ran -eq 1) {
                $result.Status = 'FAIL'
                Write-Warning '  FAIL'
            }
            else {
                $result.Status = 'NOT RUN'
                Write-Warning '  NOT RUN'
            }
        }
    }
    finally {
        Pop-Location
    }

    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    if ($passCount -eq $expectedCases.Count) {
        $runPassed = $true
    }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $priorPgUrl, 'Process')

    if ($containerCreationAttempted -and ($runPassed -or -not $KeepOnFailure)) {
        $inspection = Invoke-ForegroundProcess docker @('inspect', '--format', "{{ index .Config.Labels `"$ownershipLabelName`" }}|{{ index .Config.Labels `"com.tideshift.lore.domain-maintenance-live.pid`" }}", $containerName) $loreRoot $CommandTimeoutSeconds
        $actualLabelRaw = $inspection.Output
        $inspectExitCode = $inspection.ExitCode
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq "$runId|$PID") {
            $removal = Invoke-ForegroundProcess docker @('rm', '--force', '--volumes', $containerName) $loreRoot $CommandTimeoutSeconds
            if ($removal.ExitCode -ne 0) { Write-Warning "failed to remove owned container: $($removal.Output)"; $runPassed = $false }
        }
        elseif ($inspectExitCode -eq 0) {
            Write-Warning "refusing to remove unowned container $containerName"
        }
    }
    elseif ($containerCreationAttempted) {
        Write-Warning "keeping container $containerName for debugging (-KeepOnFailure)"
    }
}

$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($results | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($expectedCases.Count)"

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
