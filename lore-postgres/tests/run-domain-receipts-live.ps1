# Copyright 2026 Tideshift Labs
# Copyright 2026 Khurram Virani
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs the exact domain receipt lifecycle catalog against owned PostgreSQL 16.
.DESCRIPTION
Every ignored case receives a fresh database. The compiled inventory and exact one-test result
are checked before success is reported. Cleanup requires the random run label and owning PID.
The deterministic cases attest database interleavings and disconnection boundaries, not process
crashes or gRPC response loss. No ambient database is used.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [string]$PostgresImage = 'postgres:18'
)

$ErrorActionPreference = 'Stop'

# The image tag names the PostgreSQL major this run expects; the live server must report it.
$expectedPgMajor = if ($PostgresImage -match ':(?:pg|postgres)?(?<major>16|18)(?:[.-]|$)') { [int]$Matches.major } else {
    throw "PostgresImage $PostgresImage does not name PostgreSQL 16 or 18 in its tag"
}
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "wp115-receipt-deterministic-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.receipt-deterministic-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Every ignored test in this target must appear exactly once in this inventory.
$inventory = @(
    [pscustomobject]@{
        Package = 'lore-postgres'
        Target = 'domain_receipts_lifecycle'
        Exact = $true
        ExactPrefixes = @()
        Cases = @(
            'receipt_retention_persists_both_later_of_arms_without_shortening_policy',
            'future_marker_retention_persists_uuid_arrival_plus_full_safety_horizon',
            'deterministic_same_attempt_admission_waits_for_the_original_token',
            'deterministic_changed_intent_admission_cannot_obtain_the_original_token',
            'deterministic_serializable_admission_loser_returns_contention_without_token',
            'deterministic_precommit_disconnect_keeps_prepared_and_no_event',
            'deterministic_postcommit_disconnect_reads_original_receipt_and_event_without_replay',
            'coordinator_clock_get_samples_the_database_clock',
            'coordinator_prepare_commit_is_visible_and_receipt_get_replays_it',
            'attempt_receipt_get_finds_a_persisted_client_attempt_id_only_under_its_own_subject',
            'prepare_stale_is_expired_or_unknown_and_writes_nothing',
            'prepare_admissible_persists_a_prepared_row',
            'prepare_receipt_bearing_future_commits_a_real_not_applied_receipt',
            'prepare_beyond_horizon_creates_a_compact_marker_and_no_ordinary_receipt',
            'prepare_exact_retry_returns_the_same_token',
            'prepare_retry_with_a_changed_binding_field_returns_mismatch_and_mutates_nothing',
            'consume_is_single_use_once_the_receipt_is_terminal',
            'consume_rejects_a_token_presented_for_the_wrong_key_or_binding',
            'consume_and_receipt_get_reject_changed_canonical_intent',
            'prepare_expires_a_past_ttl_prepared_row',
            'consume_expires_a_past_ttl_prepared_row',
            'receipt_get_of_a_past_ttl_prepared_row',
            'commit_terminal_against_an_already_committed_row_errors',
            'receipt_get_of_a_prepared_row_carries_no_token',
            'prepare_of_a_future_marker_under_a_different_binding_must_return_mismatch',
            'receipt_get_of_a_future_marker_under_a_different_binding_must_return_mismatch',
            'beyond_horizon_prepare_at_retained_quota_limit_is_capacity_exhausted',
            'beyond_horizon_prepare_at_hourly_quota_limit_is_capacity_exhausted',
            'prepare_accepts_an_authorization_witness',
            'concurrent_duplicate_future_marker_prepares_do_not_double_count_the_quota',
            # The bounded online-bootstrap DDL cases. They live in this target
            # because they exercise the schema install that the receipt store
            # boots on, against a real database and a real concurrent writer.
            'online_bootstrap_completes_while_receipt_writer_keeps_its_transaction_open',
            'online_bootstrap_releases_previous_ddl_before_a_blocked_statement',
            'online_bootstrap_skips_existing_index_during_an_open_write',
            'online_bootstrap_rejects_a_failed_concurrent_index',
            'online_bootstrap_refuses_missing_index_on_populated_table',
            'online_bootstrap_preserves_quoted_semicolons_and_dollar_quoted_blocks',
            'online_bootstrap_seed_replay_preserves_advanced_counters',
            'online_bootstrap_rejects_mixed_alter_but_preserves_nested_and_quoted_commas',
            'online_bootstrap_missing_index_refuses_an_uncommitted_writer_without_waiting'
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
        $listArgs = @('test', '-p', $Package, '-j', '4')
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
        throw 'failed to inspect existing domain-receipt live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another domain-receipt live container exists; refusing to overlap:`n" +
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
        '--label', "com.tideshift.lore.receipt-deterministic-live.pid=$PID",
        '--label', "com.tideshift.lore.receipt-deterministic-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        $PostgresImage
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
    if ($serverVersion -lt ($expectedPgMajor * 10000) -or $serverVersion -ge (($expectedPgMajor + 1) * 10000)) {
        throw "expected PostgreSQL $expectedPgMajor, found server_version_num=$serverVersion"
    }

    Push-Location $loreRoot
    try {
        $testOrdinal = 0
        foreach ($result in $results) {
            $testOrdinal += 1
            $databaseName = "wp115_receipt_$($testOrdinal)_$($runId.Substring(0, 12))"
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
                $cargoArgs = @('test', '-p', $result.Package, '-j', '4')
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
            $labels.PSObject.Properties['com.tideshift.lore.receipt-deterministic-live.pid'].Value
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
