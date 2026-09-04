# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 16 instance and runs WP-116's outbox-producer inventory
(`lore-postgres/tests/domain_outbox_producers.rs`), one fresh database per case.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name and reports
PASS, FAIL, and NOT RUN separately against an EXPECTED count, on the pattern of
`run-lock-fencing-live.ps1`. It verifies the compiled catalog before Docker starts: a renamed,
removed, added, or filtered-to-zero case is a setup failure, not a silent short count.

Each case gets its own fresh database in one owned disposable container -- running this crate's
whole ignored tier against ONE shared database is invalid: cross-test interference between this
file's cases and other `#[ignore]`d suites (fragment-lifecycle, lock-fencing) that mutate shared
domain rows produces failures that are pure noise and pass again in isolation. This runner exists
so "PASS=N against EXPECTED=N" is citable evidence rather than an ambiguous exit code.

`domain_outbox_producers.rs`'s own `store()` helper installs SCHEMA-117 via
`PostgresLockCoordinator::bootstrap()` before any domain row, so this runner does not need a
separate bootstrap step per case -- each case's own connection does it.
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
$containerName = "wp116-outbox-producers-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.outbox-producers-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

$package = 'lore-postgres'
$target = 'domain_outbox_producers'

# Exact: this target must hold no ignored case beyond this list, so a case added
# without updating this runner is a setup failure rather than a silent NOT RUN.
$cases = @(
    'admission_rejection_leaves_no_row',
    'begin_obliterate_commits_exactly_one_repository_obliterated_row',
    'begin_obliterate_on_a_tombstoned_repository_leaves_no_row',
    'branch_delete_admission_rejection_leaves_no_row',
    'branch_delete_commits_exactly_one_branch_deleted_row_at_the_committed_generation',
    'branch_delete_generation_mismatch_leaves_no_row',
    'branch_delete_missing_branch_leaves_no_row',
    'branch_delete_missing_repository_leaves_no_row',
    'branch_delete_of_the_default_branch_leaves_no_row',
    'branch_delete_projection_removes_only_its_own_row',
    'branch_delete_releases_only_its_own_name_row_leaving_a_sibling_intact',
    'branch_delete_retry_on_an_already_tombstoned_branch_leaves_no_second_row',
    'branch_delete_under_a_tombstoned_repository_leaves_no_row',
    'branch_metadata_cas_mismatch_reports_the_branch_metadata_hash_as_observed_pointer',
    'branch_push_cas_mismatch_leaves_no_row',
    'branch_push_current_head_noop_leaves_no_row_even_with_event_supplied',
    'branch_push_tip_advance_commits_exactly_one_row_with_branch_generation_and_revision_identity',
    'committed_row_idempotency_key_matches_the_pin_1_preimage',
    'metadata_cas_mismatch_leaves_no_row',
    'metadata_cas_success_commits_exactly_one_row_with_the_new_generation',
    'repository_create_exact_fingerprint_retry_leaves_no_second_row',
    'repository_create_name_taken_rejection_leaves_no_row_even_with_event_supplied',
    'repository_create_over_cap_events_is_rejected_at_validation_with_zero_rows',
    'repository_create_wired_event_commits_exactly_one_row_with_pinned_fields',
    'repository_create_wired_two_events_commits_both_rows_with_pinned_fields_in_order',
    'repository_delete_commits_exactly_one_row_at_the_tombstone_generation',
    'repository_delete_not_found_rejection_leaves_no_row',
    'repository_delete_retry_on_an_already_tombstoned_repository_leaves_no_second_row',
    'repository_delete_with_three_extra_live_branches_still_commits_exactly_one_row'
)

$results = @(
    foreach ($testName in $cases) {
        [pscustomobject]@{
            Test   = $testName
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

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-TestCatalog {
    Push-Location $loreRoot
    $priorErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects. Cargo build
        # warnings are evidence output, not runner setup failures; the native exit code remains the
        # authority for success.
        $ErrorActionPreference = 'Continue'
        $listArgs = @('test', '-p', $package, '--test', $target, '--', '--ignored', '--list')
        $output = & cargo @listArgs 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "$package/$target test catalog failed:`n$output"
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
    $catalog = @(Get-TestCatalog)
    $label = "$package/$target"
    $missing = @($cases | Where-Object { $_ -notin $catalog })
    if ($missing.Count -ne 0) {
        throw "$label is missing pinned cases: [$($missing -join ', ')]"
    }
    foreach ($case in $cases) {
        if (@($catalog | Where-Object { $_ -eq $case }).Count -ne 1) {
            throw "$label must contain the pinned case '$case' exactly once"
        }
    }
    $unexpected = @($catalog | Where-Object { $_ -notin $cases })
    if ($catalog.Count -ne $cases.Count -or $unexpected.Count -ne 0) {
        throw ("$label must hold exactly $($cases.Count) ignored cases; catalog has " +
            "$($catalog.Count). Unexpected=[$($unexpected -join ', ')]")
    }
}

function Assert-NoCollidingContainer {
    $raw = & docker ps --all --filter "label=$ownershipLabelName" --format '{{.Names}}|{{.Status}}'
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to inspect existing outbox-producers live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another outbox-producers live container exists; refusing to overlap:`n" +
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
        '--label', "com.tideshift.lore.outbox-producers-live.pid=$PID",
        '--label', "com.tideshift.lore.outbox-producers-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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
            $databaseName = "wp116_outbox_$($testOrdinal)_$($runId.Substring(0, 12))"
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
                    'test', '-p', $package, '--test', $target,
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
            $labels.PSObject.Properties['com.tideshift.lore.outbox-producers-live.pid'].Value
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
