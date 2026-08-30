# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs the seven WP-116 real-construction enforcement regressions on disposable PostgreSQL 16 databases.

.DESCRIPTION
The Rust cases remain `#[ignore]`. This runner verifies the fixed fully-qualified inventory, runs
each exact case in its own fresh database, and reports PASS, FAIL, and NOT RUN distinctly. The
container and anonymous volume are removed only after their exact random ownership label is checked.
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
$containerName = "wp116-domain-enforcement-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.domain-enforcement-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

$expectedTests = @(
    'plugins::postgres::tests::configured_domain_enforcement_reaches_the_published_postgres_mutable_store',
    'grpc::handlers::branch_push::tests::enforcing_cell_rejects_before_legacy_branch_push_body',
    'grpc::revision::v1::branch_push::test::enforcing_cell_rejects_before_v1_branch_push_body',
    'grpc::handlers::branch_metadata_set::test::enforcing_cell_rejects_before_legacy_metadata_cas_body',
    'grpc::revision::v1::branch_metadata_set::test::enforcing_cell_rejects_before_v1_metadata_cas_body',
    'grpc::handlers::obliterate::tests::enforcing_cell_rejects_before_obliterate_body',
    'domain::tests::a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation'
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

function Get-EnforcementTestCatalog {
    Push-Location $loreRoot
    try {
        $output = & cargo test -p lore-server --lib -- --ignored --list 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "enforcement test catalog failed:`n$output"
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
    $catalog = @(Get-EnforcementTestCatalog)
    $missing = @($expectedTests | Where-Object { $_ -notin $catalog })
    if ($expectedTests.Count -ne 7 -or $missing.Count -ne 0) {
        throw "expected seven WP-116 enforcement tests; missing=[$($missing -join ', ')]"
    }
}

function Assert-NoCollidingContainer {
    $raw = & docker ps --all --filter "label=$ownershipLabelName" --format '{{.Names}}|{{.Status}}'
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to inspect existing domain-enforcement live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        throw "another domain-enforcement live container exists; refusing to overlap:`n$($collisions -join "`n")"
    }
}

try {
    Assert-ExpectedCatalog
    Assert-NoCollidingContainer

    $containerCreationAttempted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.domain-enforcement-live.pid=$PID",
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
        $logs = (& docker logs $containerName 2>&1) -join "`n"
        if ([regex]::Matches($logs, 'database system is ready to accept connections').Count -ge 2) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw 'disposable PostgreSQL did not become ready within 60 seconds'
    }

    $serverVersionRaw = & docker exec $containerName psql -tA -v ON_ERROR_STOP=1 -U postgres -d postgres -c 'SHOW server_version_num;'
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to query disposable PostgreSQL version'
    }
    $serverVersion = [int](($serverVersionRaw | Out-String).Trim())
    if ($serverVersion -lt 160000 -or $serverVersion -ge 170000) {
        throw "expected PostgreSQL 16, found server_version_num=$serverVersion"
    }

    Push-Location $loreRoot
    try {
        $ordinal = 0
        foreach ($result in $results) {
            $ordinal += 1
            $databaseName = "wp116_enforcement_$($ordinal)_$($runId.Substring(0, 12))"
            Invoke-Checked docker @(
                'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1',
                '-U', 'postgres', '-d', 'postgres', '-c', "CREATE DATABASE $databaseName;"
            )
            [Environment]::SetEnvironmentVariable(
                'LORE_TEST_PG_URL',
                "postgresql://postgres@127.0.0.1:$port/$databaseName",
                'Process'
            )
            Write-Host "Running $($result.Test)..."
            try {
                $output = & cargo test -p lore-server --lib -- --ignored --exact $result.Test --test-threads=1 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
            }
            finally {
                [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $null, 'Process')
                Invoke-Checked docker @(
                    'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1',
                    '-U', 'postgres', '-d', 'postgres', '-c', "DROP DATABASE $databaseName WITH (FORCE);"
                )
            }

            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
            if ($runningMatch.Success) {
                $result.Ran = [int]$runningMatch.Groups[1].Value
            }
            if ($resultMatch.Success) {
                $result.Passed = [int]$resultMatch.Groups[1].Value
                $result.Failed = [int]$resultMatch.Groups[2].Value
            }
            if ($result.Ran -eq 1 -and $result.Passed -eq 1 -and $result.Failed -eq 0 -and $exitCode -eq 0) {
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
    if ($passCount -eq $expectedTests.Count) {
        $runPassed = $true
    }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $priorPgUrl, 'Process')
    if ($containerCreationAttempted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"$ownershipLabelName`" }}|{{ index .Config.Labels `"com.tideshift.lore.domain-enforcement-live.pid`" }}" $containerName 2>$null
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

$results | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($results | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($expectedTests.Count)"
if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
