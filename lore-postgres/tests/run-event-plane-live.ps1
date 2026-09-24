# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL 18 (or 16, with -PostgresImage) instance and runs contract
amendment A-32's live event-plane inventory
(`lore-postgres/tests/domain_outbox_event_plane.rs`), one fresh database per case.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name and reports
PASS, FAIL, and NOT RUN separately against an EXPECTED count, on the pattern of
`run-outbox-producers-live.ps1`. It verifies the compiled catalog before Docker starts: a renamed,
removed, added, or filtered-to-zero case is a setup failure, not a silent short count.

Each case gets its own fresh database in one owned disposable container -- running this crate's
whole ignored tier against ONE shared database is invalid (see the `lore-outbox-relay` skill's
"Never run this crate's `--ignored` tier against one shared database").

Scope: `set_event_plane`'s offline switch mechanics (pending-row refusal, verbatim move of
`broker_accepted`/`consumer_safe` rows to `lore_outbox_retired_events` with audit, the
`AlreadyCurrent` rerun, the durable-with-rows refusal, the numbackends and ACCESS EXCLUSIVE NOWAIT
contention gates) and `read_boot_facts`. The pure resolution matrix
(`[notification] event_plane` parsing, `outbox_production_enabled`, `check_marker`) is proven by
unit tests in `lore-server/src/event_relay/plane.rs` and
`lore-postgres/src/domain/outbox/event_plane.rs` and is not re-run here. This runner does not cover
a live, end-to-end proof that every CR-032 producer site appends zero rows under `live_only` through
the real `DomainContext`/`Governed*` wrapper types -- see the test file's own module docs for what
stands in for that (a static call-site sweep plus the `outbox_cell_id()` unit predicate) and the
follow-up this leaves open.

.PARAMETER PostgresImage
The PostgreSQL image to run. Default `postgres:18`. Its major must be 16 or 18, and the server's
`server_version_num` must match that major, or the run stops before any test.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [string]$PostgresImage = 'postgres:18'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "a32-event-plane-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.event-plane-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

$package = 'lore-postgres'
$target = 'domain_outbox_event_plane'

# The image tag names the major the pins are for; the live server must then report that major.
$expectedMajor = if ($PostgresImage -match ':(?:pg|postgres)?(?<major>16|18)(?:[.-]|$)') { [int]$Matches.major } else {
    throw "PostgresImage $PostgresImage does not name a supported major (16 or 18) in its tag"
}

# Exact: this target must hold no ignored case beyond this list, so a case added
# without updating this runner is a setup failure rather than a silent NOT RUN.
$cases = @(
    'a_held_table_lock_refuses_the_switch_even_when_backend_count_passes',
    'a_second_connected_backend_refuses_the_switch_until_it_disconnects',
    'read_boot_facts_reports_the_marker_and_whether_the_cell_holds_any_outbox_row',
    'rerunning_an_applied_switch_reports_already_current',
    'switching_back_to_durable_carries_a_stray_pending_row_and_restarts_its_age',
    'switching_to_live_only_moves_broker_accepted_and_consumer_safe_rows_verbatim_with_audit',
    'switching_to_live_only_refuses_while_a_pending_row_exists',
    'switching_to_live_only_refuses_while_a_parked_dead_letter_exists',
    'requeue_and_replay_refuse_on_a_live_only_cell',
    'durable_re_entry_retires_every_live_receiver_generation_with_audit',
    'durable_re_entry_refuses_while_a_reset_fence_is_in_progress'
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
        throw 'failed to inspect existing event-plane live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another event-plane live container exists; refusing to overlap:`n" +
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
        '--label', "com.tideshift.lore.event-plane-live.pid=$PID",
        '--label', "com.tideshift.lore.event-plane-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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
    if ($serverVersion -lt ($expectedMajor * 10000) -or $serverVersion -ge (($expectedMajor + 1) * 10000)) {
        throw "expected PostgreSQL $expectedMajor, found server_version_num=$serverVersion"
    }
    Write-Host "PostgreSQL server_version_num=$serverVersion ($PostgresImage)"

    Push-Location $loreRoot
    try {
        $testOrdinal = 0
        foreach ($result in $results) {
            $testOrdinal += 1
            $databaseName = "a32_event_plane_$($testOrdinal)_$($runId.Substring(0, 12))"
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
            $labels.PSObject.Properties['com.tideshift.lore.event-plane-live.pid'].Value
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
