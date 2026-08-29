# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned disposable PostgreSQL 16 instance and runs CR-029's eight maintenance tests.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner opts in to each case by exact name, one at a time,
and reports PASS, FAIL, and NOT RUN separately. Before Docker starts, it checks the compiled
`domain_maintenance` catalog against the fixed eight-case inventory. A renamed, removed, or added
case is a hard setup failure, not a silent zero-test success.

The container is labelled with a random run id and the owning PowerShell process. Each exact case
gets a distinct database inside that container, which is dropped after the case. Teardown ownership
is registered before `docker run` is attempted. Cleanup inspects the exact run-id label and removes
only this runner's container and anonymous volume.
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
$containerName = "wp116-domain-maintenance-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.domain-maintenance-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

$expectedTests = @(
    'stale_finalize_commits_once_replays_exactly_and_isolates_binding',
    'stale_finalize_lost_commit_ack_is_unknown_then_authoritative_replay_adopts_commit',
    'terminal_phase1_replays_then_atomically_exchanges_receipt_fence_for_tombstone',
    'materialize_replay_preserves_receipt_and_changed_claim_mismatches',
    'materialize_capacity_revision_mismatch_writes_no_namespace',
    'retire_is_atomic_replays_absence_and_rejects_expired_permit',
    'retire_requires_exact_fence_generation_and_final_range_digest',
    'retire_rejects_nonquiescent_namespace_and_changed_epoch_claim_without_mutation'
)

$results = @(
    foreach ($name in $expectedTests) {
        [pscustomobject]@{
            Test   = $name
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

function Get-MaintenanceTestCatalog {
    Push-Location $loreRoot
    try {
        $listArgs = @(
            'test', '-p', 'lore-postgres', '--test', 'domain_maintenance', '--',
            '--ignored', '--list'
        )
        $output = & cargo @listArgs 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
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
    $catalog = @(Get-MaintenanceTestCatalog)
    $missing = @($expectedTests | Where-Object { $_ -notin $catalog })
    $unexpected = @($catalog | Where-Object { $_ -notin $expectedTests })
    if ($catalog.Count -ne 8 -or $missing.Count -ne 0 -or $unexpected.Count -ne 0) {
        $message = "expected exactly 8 domain-maintenance tests; catalog has $($catalog.Count). " +
            "Missing=[$($missing -join ', ')]; unexpected=[$($unexpected -join ', ')]"
        throw $message
    }
}

function Assert-NoCollidingContainer {
    $raw = & docker ps --all --filter "label=$ownershipLabelName" --format '{{.Names}}|{{.Status}}|{{.Label "com.tideshift.lore.domain-maintenance-live.pid"}}'
    if ($LASTEXITCODE -ne 0) {
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
                    'test', '-p', 'lore-postgres', '--test', 'domain_maintenance', '--',
                    '--ignored', '--exact', $result.Test, '--test-threads=1'
                )
                $output = & cargo @cargoArgs 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
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
    if ($passCount -eq 8) {
        $runPassed = $true
    }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $priorPgUrl, 'Process')

    if ($containerCreationAttempted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"$ownershipLabelName`" }}|{{ index .Config.Labels `"com.tideshift.lore.domain-maintenance-live.pid`" }}" $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq "$runId|$PID") {
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
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=8"

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
