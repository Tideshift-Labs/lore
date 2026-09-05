# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 16 instance and runs WP-117's fixed lock-fencing inventory.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name, one at a time,
and reports PASS, FAIL, and NOT RUN separately. It verifies the compiled catalog before Docker
starts. A renamed, removed, added, or filtered-to-zero case is a setup failure.

The inventory spans four compiled targets: the fenced-lock coordinator suite, migration/runtime
parity, the obliterate-fence regression (which needs SCHEMA-117 for its push case), and the
`lore-server` library's live boot, witness-bypass, and fenced-push cases. A case that is not in
this inventory is NOT RUN, however green a plain `cargo test` looks.

Each case gets a fresh database in one owned disposable container. Cleanup checks both the random
run label and the owning PowerShell process before removing the container and anonymous volume.
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
$containerName = "wp117-lock-fencing-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.lock-fencing-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Each entry is one compiled target plus the exact cases this runner owns.
# `Exact` means the target may hold no other ignored case, so a case added
# without updating this list is a setup failure rather than a silent skip.
#
# The `lore-server` library also holds ignored cases owned by other packages, so
# it cannot be exact wholesale. `ExactPrefixes` narrows the same guarantee to the
# modules this runner OWNS: a live case added under one of them without joining
# this inventory is a setup failure, not a silent NOT RUN. A pinned case can
# still sit outside every prefix when its module is shared with other packages
# (`grpc::handlers::branch_push::tests::` holds WP-116's cases too), in which
# case only that exact case is policed.
$inventory = @(
    [pscustomobject]@{
        Package       = 'lore-postgres'
        Target        = 'domain_lock_fencing'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @(
            'two_coordinators_racing_one_resource_choose_exactly_one_owner_pair',
            'racing_batches_are_all_or_nothing',
            'same_subject_under_different_issuers_is_foreign_for_every_owner_operation',
            'acquire_result_boundary_is_rejected_before_lock_mutation',
            'stale_release_renew_force_and_cleanup_cannot_touch_a_successor',
            'obsolete_repository_and_branch_generations_make_rows_logically_absent',
            'lease_clock_is_captured_after_the_namespace_lock_wait',
            'lock_operations_reuse_cr029_receipt_bands_markers_and_quota',
            'lock_mutations_take_the_receipt_before_domain_and_namespace_rows',
            'missing_and_repeated_release_are_not_found_and_empty_list_is_ok',
            'batched_status_orders_by_stored_key_and_repeats_a_duplicate_request',
            'an_absent_schema_routes_legacy_but_a_partial_one_is_refused',
            'arming_succeeds_once_the_public_mutation_contract_exists',
            'readiness_rejects_each_missing_fenced_precondition',
            'same_database_identity_accepts_only_the_domain_authority_database',
            'lock_backfill_is_restartable_and_quarantines_ambiguous_legacy_owners',
            'backfill_proves_fence_sequence_headroom_before_cutover',
            'push_witness_capture_and_transaction_local_revalidation_detect_change',
            'a_fresh_acquire_commits_exactly_one_lock_acquired_row_with_the_fence_and_owner_token',
            'a_same_owner_renewal_commits_exactly_one_lock_renewed_row_with_the_new_fence_and_token',
            'an_expiry_takeover_by_a_different_owner_commits_exactly_one_lock_taken_over_row_with_the_successors_fence',
            'owner_release_and_admin_force_release_each_commit_their_pinned_kind',
            'cleanup_and_lease_bootstrap_paths_never_append_an_outbox_row',
            'every_lock_rejection_kind_leaves_the_outbox_empty',
            'a_replayed_receipt_appends_no_second_row',
            'an_empty_resource_release_appends_no_row',
            'a_mixed_batch_of_the_callers_own_current_and_stale_generation_rows_is_a_renewal',
            'a_stale_generation_row_held_by_a_different_owner_is_a_takeover'
        )
    },
    [pscustomobject]@{
        Package       = 'lore-postgres'
        Target        = 'domain_migration_parity'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @('migration_file_and_boot_time_ensure_schema_produce_identical_domain_catalogs')
    },
    [pscustomobject]@{
        Package       = 'lore-postgres'
        Target        = 'domain_obliterate_fence'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @(
            'begin_obliterate_advances_live_generation_and_refuses_a_tombstoned_repository',
            'begin_obliterate_and_branch_push_commit_agree_on_the_repository_generation'
        )
    },
    [pscustomobject]@{
        Package       = 'lore-server'
        Target        = 'lib'
        Exact         = $false
        # The prefix narrowed twice, both times for the same reason: a claim
        # asserts this runner owns EVERY live case beneath it, so a case another
        # package adds there makes the claim false and the guard refuses to start
        # rather than under-run. Narrowing is the fix; dropping the claim is not,
        # because a target with no prefix at all polices nothing.
        #
        # `domain::tests::` went first, when WP-116 added
        # `a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation`
        # there, which `run-domain-enforcement-live.ps1` owns and runs as its seventh
        # case.
        #
        # `grpc::handlers::branch_push::governed_tests::` followed, when the
        # notification-hint work added
        # `committed_governed_push_fires_exactly_one_lorehub_notify_hook_post_and_a_repeat_no_op_fires_none`
        # and `hint_sender_queue_exhaustion_does_not_change_a_committed_governed_pushs_result`.
        # Those two are about the hook and hint rails, not lock fencing, so running
        # them here would claim coverage this tier does not own. The claim narrowed
        # to `::enforce_fenced_locks_`, which this runner does own whole, and the
        # one fenced-lock case outside it stays policed by exact name in `Cases` --
        # the same shared-module treatment `grpc::handlers::branch_push::tests::`
        # already gets.
        ExactPrefixes = @(
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_'
        )
        Cases         = @(
            'domain::tests::a_never_migrated_postgres_cell_boots_on_the_legacy_lock_route',
            'grpc::handlers::branch_push::tests::real_witness_capture_precedes_both_cr019_bypass_conditions',
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_blocks_a_push_from_a_foreign_owner_pair',
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_does_not_block_the_lock_holders_own_push',
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_treats_same_subject_under_a_different_issuer_as_foreign',
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_blocks_a_push_touching_the_locked_old_path_of_a_rename',
            'grpc::handlers::branch_push::governed_tests::enforce_fenced_locks_does_not_block_a_foreign_lock_on_an_untouched_path',
            'grpc::handlers::branch_push::governed_tests::missing_lock_namespace_row_leaves_the_branch_permanently_unpushable'
        )
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
        $listArgs = @('test', '-p', $Package)
        if ($Target -eq 'lib') {
            $listArgs += '--lib'
        }
        else {
            $listArgs += @('--test', $Target)
        }
        $listArgs += @('--', '--ignored', '--list')
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
            # A non-exact target with no prefixes polices nothing: every pinned
            # case would still be checked, but a sibling added beside them would
            # be silently NOT RUN, which is the failure this whole file exists
            # to prevent.
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
        throw 'failed to inspect existing lock-fencing live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another lock-fencing live container exists; refusing to overlap:`n" +
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
        '--label', "com.tideshift.lore.lock-fencing-live.pid=$PID",
        '--label', "com.tideshift.lore.lock-fencing-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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
        foreach ($result in $results) {
            $testOrdinal += 1
            $databaseName = "wp117_lock_$($testOrdinal)_$($runId.Substring(0, 12))"
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
                $cargoArgs = @('test', '-p', $result.Package)
                if ($result.Target -eq 'lib') {
                    $cargoArgs += '--lib'
                }
                else {
                    $cargoArgs += @('--test', $result.Target)
                }
                $cargoArgs += @('--', '--ignored', '--exact', $result.Test, '--test-threads=1')
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

    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    if ($passCount -eq $results.Count) {
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
            $labels.PSObject.Properties['com.tideshift.lore.lock-fencing-live.pid'].Value
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
