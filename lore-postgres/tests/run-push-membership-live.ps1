# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Run FINAL-PUSH-118 handler and counter cases on an owned PostgreSQL instance.
.DESCRIPTION
Each ignored case gets a fresh database. Catalog and executed test counts are checked.
The shared lifecycle runner owns its wider regression inventory.
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
$containerName = "wp118-push-membership-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.push-membership-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Each entry is one compiled target plus the exact cases this runner owns.
# `Exact` means the target may hold no other ignored case, so a case added
# without updating this list is a setup failure rather than a silent skip.
$inventory = @(
    [pscustomobject]@{ Package='lore-server'; Kind='lib'; Target='lore_server'; Exact=$false; ExactPrefixes=@('grpc::handlers::branch_push::governed_tests::membership_tests::'); Cases=@(
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_fresh_addition_after_preflight_publishes_on_first_attempt',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_fresh_addition_after_preflight_publishes_on_first_attempt',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_required_retirement_after_preflight_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_unrelated_retirement_after_preflight_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_required_rebind_after_preflight_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_unrelated_rebind_after_preflight_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_tombstone_recreate_after_preflight_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_lifecycle_move_without_complete_proof_refuses',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_more_than_4096_real_dependencies_allow_fresh_addition',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_publication_blocks_required_retirement_until_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_publication_blocks_unrelated_rebind_until_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_publication_blocks_unrelated_retirement_until_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_publication_blocks_required_rebind_until_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v1_publication_blocks_required_recreation_until_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_publication_allows_fresh_addition_after_commit',
            'grpc::handlers::branch_push::governed_tests::membership_tests::same_repo_bulk_upload_does_not_starve_real_branch_push',
            'grpc::handlers::branch_push::governed_tests::membership_tests::cross_repo_bulk_upload_does_not_abort_real_branch_push',
            'grpc::handlers::branch_push::governed_tests::membership_tests::v0_more_than_4096_real_dependencies_publish_before_fresh_addition',
            'grpc::handlers::branch_push::governed_tests::membership_tests::unchanged_fast_path_publishes_while_fragment_and_association_tables_are_locked',
            'grpc::handlers::branch_push::governed_tests::membership_tests::revision_number_rewrite_keeps_the_witness_from_before_preflight',
            'grpc::handlers::branch_push::governed_tests::membership_tests::server_merge_keeps_the_witness_from_before_preflight',
            'grpc::handlers::branch_push::governed_tests::membership_tests::admission_tests::active_membership_startup_rejects_non_postgres_immutable_authority',
            'grpc::handlers::branch_push::governed_tests::membership_tests::admission_tests::active_membership_startup_attaches_colocated_postgres_authority',
            'grpc::handlers::branch_push::governed_tests::membership_tests::admission_tests::dark_membership_startup_preserves_mixed_store_configuration',
            'grpc::handlers::branch_push::governed_tests::membership_tests::admission_tests::v0_activated_membership_rejects_missing_carriage_without_publication',
            'grpc::handlers::branch_push::governed_tests::membership_tests::admission_tests::v1_activated_membership_rejects_missing_carriage_without_publication',
            'grpc::handlers::branch_push::governed_tests::committed_governed_push_fires_exactly_one_lorehub_notify_hook_post_and_a_repeat_no_op_fires_none',
            'grpc::handlers::branch_push::governed_tests::hint_sender_queue_exhaustion_does_not_change_a_committed_governed_pushs_result'
    ) }
    [pscustomobject]@{ Package='lore-postgres'; Kind='test'; Target='domain_fragment_lifecycle'; Exact=$false; ExactPrefixes=@('domain_fragment_membership::'); Cases=@(
            'domain_fragment_membership::fresh_exact_keys_preserve_invalidation_but_rebind_and_recreate_advance_it',
            'domain_fragment_membership::guarded_binding_classifies_absence_and_replacement_and_fenced_calls_change_nothing',
            'domain_fragment_membership::both_obliterate_retirement_paths_advance_invalidation_with_retained_payload_control',
            'domain_fragment_membership::invalidation_overflow_rolls_back_rebind_and_retirement_without_wrapping'
    ) }
    [pscustomobject]@{ Package='lore-postgres'; Kind='test'; Target='domain_membership_cutover'; Exact=$true; ExactPrefixes=@(); Cases=@(
            'activation_drains_an_old_writer_before_committing_the_protocol',
            'old_snapshots_and_cached_statements_cannot_write_after_activation',
            'unmarked_legacy_association_and_publication_writes_are_denied',
            'upgraded_associations_advance_counters_and_transaction_markers_do_not_leak',
            'rollback_cannot_remove_the_protocol_and_damaged_fences_refuse_readiness',
            'installed_fences_with_missing_protocol_evidence_fail_closed',
            'activation_requires_all_readiness_prerequisites',
            'final_push_requires_a_witness_and_validated_publication_still_commits',
            'real_repeatable_read_push_started_before_activation_cannot_publish_without_a_witness'
    ) }
)
$printOutputCases = @($inventory[0].Cases | Where-Object { $_ -match "4096|bulk_upload" })

$results = @(
    foreach ($target in $inventory) {
        foreach ($testName in $target.Cases) {
            [pscustomobject]@{
                Package = $target.Package
                Kind    = $target.Kind
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
        [string]$Target,
        [Parameter(Mandatory)]
        [ValidateSet('test', 'lib')]
        [string]$Kind
    )

    Push-Location $loreRoot
    $priorErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects. Cargo build
        # warnings are evidence output, not runner setup failures; the native exit code remains the
        # authority for success.
        $ErrorActionPreference = 'Continue'
        $targetArgs = if ($Kind -eq 'lib') { @('--lib') } else { @('--test', $Target) }
        $listArgs = @('test', '-j', '4', '-p', $Package) + $targetArgs + @('--', '--ignored', '--list')
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
        $catalog = @(Get-TestCatalog -Package $target.Package -Target $target.Target -Kind $target.Kind)
        $label = "$($target.Package)/$($target.Kind):$($target.Target)"
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
        '--label', "com.tideshift.lore.push-membership-live.pid=$PID",
        '--label', "com.tideshift.lore.push-membership-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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
                $targetArgs = if ($result.Kind -eq 'lib') {
                    @('--lib')
                }
                else {
                    @('--test', $result.Target)
                }
                $cargoArgs = @('test', '-j', '4', '-p', $result.Package) + $targetArgs + @(
                    '--', '--ignored', '--exact', $result.Test, '--test-threads=1', '--nocapture'
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
                if ($result.Test -in $printOutputCases) {
                    Write-Host "  --- captured output for $($result.Test) ---"
                    Write-Host $output
                }
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
            $labels.PSObject.Properties['com.tideshift.lore.push-membership-live.pid'].Value
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

$results | Format-Table -AutoSize | Out-String -Width 320 | Write-Host
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
