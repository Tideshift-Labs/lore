# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 16 instance and runs WP-118's fixed fragment-lifecycle inventory.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name, one at a
time, and reports PASS, FAIL, and NOT RUN separately. It verifies the compiled catalog before
Docker starts. A renamed, removed, added, or filtered-to-zero case is a setup failure.

The inventory spans two compiled `lore-postgres` targets: `domain_fragment_lifecycle` (the
coordinator's own real-Postgres proof) and `domain_migration_parity` (the shared migration/
runtime catalog parity gate, which now also covers SCHEMA-118's fragment relations). A case
that is not in this inventory is NOT RUN, however green a plain `cargo test` looks.

Each case gets a fresh database in one owned disposable container. Cleanup checks both the
random run label and the owning PowerShell process before removing the container and
anonymous volume.

No `lore-server` target is in this inventory. Server activation/configuration has its own
non-live suites; this runner owns only coordinator and migration behavior requiring a real
PostgreSQL clock, transaction locks, or catalog inspection.
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
$containerName = "wp118-fragment-lifecycle-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.fragment-lifecycle-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Each entry is one compiled target plus the exact cases this runner owns.
# `Exact` means the target may hold no other ignored case, so a case added
# without updating this list is a setup failure rather than a silent skip.
$inventory = @(
    [pscustomobject]@{
        Package       = 'lore-postgres'
        Target        = 'domain_fragment_lifecycle'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @(
            'normal_direct_write_uses_legacy_key_and_missing_reoffer_uses_repair_epoch_key',
            'payload_free_coordinated_preflight_distinguishes_exact_readable_from_new_publication',
            'durable_write_claims_bind_replay_authorize_settle_and_expiry_to_database_state',
            'write_capability_cutover_is_exact_idempotent_and_database_attested',
            'claim_inventory_and_prune_preserve_cleanup_targets_and_bound_terminal_deletion',
            'prune_normalizes_expired_prepared_to_targetless_no_send_and_honors_batch_limit',
            'write_claim_head_lock_precedes_claim_insert_and_moved_lineage_refuses_send',
            'write_claim_acl_denies_public_and_retains_owner_access',
            'resolver_returns_the_identical_verdict_whether_asked_singly_or_batched',
            'stale_association_rejection_comes_from_repository_tombstone_not_generation_drift',
            'a_positive_read_requires_both_a_live_association_and_a_readable_current_epoch',
            'a_blocked_io_phase_does_not_hold_the_one_connection_pool',
            'two_independently_constructed_coordinators_race_one_fresh_head_and_exactly_one_wins',
            'a_replayed_direct_write_reuses_exact_claim_and_terminal_attempt_cannot_publish_twice',
            'a_stale_witness_from_a_competing_obliterate_fences_a_late_commit_with_zero_mutation',
            'a_prepared_repair_blocks_a_competitor_and_no_send_attempt_cannot_publish_late',
            'a_readable_to_unreadable_transition_bumps_every_live_associated_repository_atomically',
            'two_concurrent_transitions_over_an_overlapping_fanout_do_not_deadlock',
            'an_absent_fragment_schema_routes_legacy_but_a_partial_one_is_refused',
            'a_repair_on_a_missing_fragment_with_a_live_association_bumps_its_repository_fanout',
            'an_obliterate_on_a_readable_fragment_with_a_live_association_bumps_its_repository_fanout',
            'readiness_reports_zero_unresolved_rows_for_a_preparing_head_and_a_missing_head',
            'a_promotion_round_trip_allocates_a_new_epoch_and_publishes_under_remote_authority',
            # INV-EF P1-2/P1-3: the six previously-untested public entry points.
            'revalidate_push_witness_reports_unchanged_when_neither_scalar_moved',
            'revalidate_push_witness_is_satisfied_by_the_fallback_when_the_lifecycle_scalar_moved_and_required_fragments_are_still_readable',
            'revalidate_push_witness_aborts_when_a_required_fragment_is_no_longer_readable',
            'revalidate_push_witness_aborts_when_a_required_fragments_epoch_advanced',
            'revalidate_push_witness_refuses_over_the_revalidation_limit_before_locking_any_fragment_row',
            # CR-031:266 (INV-EF P2-2): the semantically-equivalent-epoch push fallback allowance.
            'revalidate_push_witness_accepts_a_required_fragment_promoted_to_a_semantically_equivalent_epoch',
            'revalidate_push_witness_aborts_when_the_new_epoch_describes_different_content',
            # Pre-Phase-5 hardening review: equivalent_epochs' all-or-nothing rule over a real
            # two-fragment batch, plus a required fragment whose captured epoch was never published.
            'revalidate_push_witness_all_or_nothing_over_a_mixed_divergent_batch',
            'revalidate_push_witness_aborts_when_the_captured_epoch_was_never_published',
            # WP-118 fix-round hardening review: the association-precedence case, the only case
            # in the file that moves BOTH push-witness scalars for the same required fragment.
            'revalidate_push_witness_aborts_when_the_association_set_moved_even_though_a_required_fragment_is_equivalent',
            'acquire_staged_leases_and_release_round_trip_a_batch_with_a_monotonic_reader_fence',
            # INV-EF P2-5/P2-6: acquire_staged_leases's three new refusals plus duplicate-lease_id replay.
            'acquire_staged_leases_refuses_a_lease_id_that_is_not_the_schema_length',
            'acquire_staged_leases_refuses_a_member_that_is_not_a_staged_epoch',
            'a_duplicate_staged_lease_id_replays_the_existing_lease_and_refuses_a_different_batch',
            # Pre-Phase-5 hardening review: the DISPOSITION_PURGED clause (both directions) and
            # validate_lease_members' duplicate-hash/empty-batch refusals.
            'acquire_staged_leases_refuses_a_purged_staged_member',
            'acquire_staged_leases_admits_a_quarantined_staged_member',
            # WP-118 fix-round hardening review: lock_lease_member_heads's Tombstoned/deleting head
            # check (one epoch deeper than the disposition guard alone) and its FOR SHARE
            # serialisation against a concurrent commit_obliterate.
            'acquire_staged_leases_refuses_a_member_whose_fragment_was_obliterated_after_promotion',
            'acquire_staged_leases_refuses_a_member_whose_head_is_mid_deletion',
            'acquire_staged_leases_waits_for_a_concurrently_locked_head',
            'acquire_staged_leases_refuses_a_duplicate_hash_batch_and_an_empty_batch',
            'commit_obliterate_purges_the_epoch_disposition_deletes_metering_and_tombstones_the_head',
            'commit_obliterate_fences_a_stale_intent_and_mutates_nothing',
            'enable_lifecycle_refuses_on_a_not_ready_cell_and_succeeds_once_ready',
            'enable_lifecycle_refuses_with_the_roll_forward_diagnostic_when_schema_version_exceeds_the_binary',
            'abandon_promotion_leaves_the_head_staged_and_readable_and_moves_no_repository_lifecycle_generation',
            'a_successful_repair_quarantines_the_predecessor_epoch_and_marks_the_successor_current_eligible',
            'query_matches_distinguish_exact_context_partition_and_unreadable_rows_in_one_batch',
            'guarded_association_requires_the_exact_readable_witness',
            'guarded_association_cannot_race_mark_missing_into_a_successful_residue',
            # INV-EF P1-1: the begin_obliterate fanout race (fixed at 76033cb).
            'a_concurrent_create_association_landing_between_the_plan_and_the_head_lock_is_refused_with_zero_mutation',
            'begin_obliterate_on_a_non_readable_head_moves_the_association_scalar_for_every_live_associated_repository'
        )
    },
    [pscustomobject]@{
        Package       = 'lore-postgres'
        Target        = 'domain_migration_parity'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @('migration_file_and_boot_time_ensure_schema_produce_identical_domain_catalogs')
    }
)

$results = @(
    foreach ($target in $inventory) {
        foreach ($testName in $target.Cases) {
            [pscustomobject]@{
                Package = $target.Package
                Target  = $target.Target
                Test    = $testName
                Status  = 'NOT RUN'
                Passed  = 0
                Failed  = 0
                Ran     = 0
            }
        }
    }
)

$unknownCases = @($OnlyCase | Where-Object { $_ -notin $results.Test })
if ($unknownCases.Count -ne 0) {
    throw "unknown -OnlyCase value(s): [$($unknownCases -join ', ')]"
}
$selectedResults = if ($OnlyCase.Count -eq 0) {
    @($results)
}
else {
    @($results | Where-Object { $_.Test -in $OnlyCase })
}

$priorPgUrl = [Environment]::GetEnvironmentVariable('LORE_TEST_PG_URL', 'Process')

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-TestCatalog {
    param(
        [Parameter(Mandatory)]
        [string]$Package,
        [Parameter(Mandatory)]
        [string]$Target
    )

    Push-Location $loreRoot
    $priorErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects. Cargo build
        # warnings are evidence output, not runner setup failures; the native exit code remains the
        # authority for success.
        $ErrorActionPreference = 'Continue'
        $listArgs = @('test', '-p', $Package, '--test', $Target, '--', '--ignored', '--list')
        $output = & cargo @listArgs 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "$Package/$Target test catalog failed:`n$output"
    }

    return @(
        foreach ($line in ($output -split "`r?`n")) {
            $match = [regex]::Match($line, '^(?<name>[A-Za-z0-9_:]+): test$')
            if ($match.Success) {
                $match.Groups['name'].Value
            }
        }
    )
}

function Assert-ExpectedCatalog {
    foreach ($target in $inventory) {
        $catalog = @(Get-TestCatalog -Package $target.Package -Target $target.Target)
        $label = "$($target.Package)/$($target.Target)"
        $missing = @($target.Cases | Where-Object { $_ -notin $catalog })
        if ($missing.Count -ne 0) {
            throw "$label is missing pinned cases: [$($missing -join ', ')]"
        }
        foreach ($case in $target.Cases) {
            if (@($catalog | Where-Object { $_ -eq $case }).Count -ne 1) {
                throw "$label must contain the pinned case '$case' exactly once"
            }
        }
        if ($target.Exact) {
            $unexpected = @($catalog | Where-Object { $_ -notin $target.Cases })
            if ($catalog.Count -ne $target.Cases.Count -or $unexpected.Count -ne 0) {
                throw ("$label must hold exactly $($target.Cases.Count) ignored cases; catalog has " +
                    "$($catalog.Count). Unexpected=[$($unexpected -join ', ')]")
            }
        }
        else {
            if ($target.ExactPrefixes.Count -eq 0) {
                throw "$label is neither Exact nor scoped by an ExactPrefix, so new cases beside its inventory would be silently NOT RUN"
            }
            foreach ($prefix in $target.ExactPrefixes) {
                $scoped = @($catalog | Where-Object { $_.StartsWith($prefix) })
                $unexpected = @($scoped | Where-Object { $_ -notin $target.Cases })
                if ($unexpected.Count -ne 0) {
                    throw ("$label has ignored cases under '$prefix' that this runner does not " +
                        "execute, so they are NOT RUN: [$($unexpected -join ', ')]")
                }
            }
        }
    }
}

function Assert-NoCollidingContainer {
    $raw = & docker ps --all --filter "label=$ownershipLabelName" --format '{{.Names}}|{{.Status}}'
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to inspect existing fragment-lifecycle live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another fragment-lifecycle live container exists; refusing to overlap:`n" +
            ($collisions -join "`n")
        throw $message
    }
}

try {
    Assert-ExpectedCatalog
    Assert-NoCollidingContainer

    $containerCreationAttempted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.fragment-lifecycle-live.pid=$PID",
        '--label', "com.tideshift.lore.fragment-lifecycle-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        'postgres:16'
    )

    $portOutputRaw = & docker port $containerName '5432/tcp'
    $portExitCode = $LASTEXITCODE
    $portOutput = if ($null -ne $portOutputRaw) { ($portOutputRaw | Out-String).Trim() } else { '' }
    if ($portExitCode -ne 0 -or $portOutput -notmatch ':(?<port>[0-9]+)$') {
        throw 'failed to resolve the disposable PostgreSQL host port'
    }
    $port = $Matches.port

    $ready = $false
    $priorErrorAction = $ErrorActionPreference
    try {
        # The postgres image writes its normal startup log to stderr.
        $ErrorActionPreference = 'Continue'
        foreach ($attempt in 1..120) {
            $logOutput = (& docker logs $containerName 2>&1) -join "`n"
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
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
    if (-not $ready) {
        & docker logs $containerName
        throw 'disposable PostgreSQL did not become ready within 60 seconds'
    }

    $serverVersionRaw = & docker exec $containerName psql -tA -v ON_ERROR_STOP=1 -U postgres -d postgres -c 'SHOW server_version_num;'
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to query the disposable PostgreSQL server version'
    }
    $serverVersion = [int](($serverVersionRaw | Out-String).Trim())
    if ($serverVersion -lt 160000 -or $serverVersion -ge 170000) {
        throw "expected PostgreSQL 16, found server_version_num=$serverVersion"
    }

    Push-Location $loreRoot
    try {
        $testOrdinal = 0
        foreach ($result in $selectedResults) {
            $testOrdinal += 1
            $databaseName = "wp118_fragment_$($testOrdinal)_$($runId.Substring(0, 12))"
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
            $priorErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $cargoArgs = @(
                    'test', '-p', $result.Package, '--test', $result.Target,
                    '--', '--ignored', '--exact', $result.Test, '--test-threads=1'
                )
                $output = & cargo @cargoArgs 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $priorErrorAction
                [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $null, 'Process')
                Invoke-Checked docker @(
                    'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1',
                    '-U', 'postgres', '-d', 'postgres',
                    '-c', "DROP DATABASE $databaseName WITH (FORCE);"
                )
            }

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
                Write-Warning "  FAIL`n$output"
            }
            else {
                $result.Status = 'NOT RUN'
                Write-Warning "  NOT RUN`n$output"
            }
        }
    }
    finally {
        Pop-Location
    }

    $passCount = @($selectedResults | Where-Object { $_.Status -eq 'PASS' }).Count
    if ($passCount -eq $selectedResults.Count) {
        $runPassed = $true
    }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $priorPgUrl, 'Process')

    if ($containerCreationAttempted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format '{{json .Config.Labels}}' $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $labels = if ($inspectExitCode -eq 0 -and $null -ne $actualLabelRaw) {
            ($actualLabelRaw | Out-String).Trim() | ConvertFrom-Json
        }
        else {
            $null
        }
        $actualRunId = if ($null -ne $labels) {
            $labels.PSObject.Properties[$ownershipLabelName].Value
        }
        $actualPid = if ($null -ne $labels) {
            $labels.PSObject.Properties['com.tideshift.lore.fragment-lifecycle-live.pid'].Value
        }
        if ($inspectExitCode -eq 0 -and $actualRunId -eq $runId -and $actualPid -eq "$PID") {
            & docker rm --force --volumes $containerName *> $null
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
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($results.Count)"

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
