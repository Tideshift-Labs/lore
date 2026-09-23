# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions a disposable PostgreSQL 16 and runs CR-038 D5's `drain_handles` schema-gate live tier
by exact name, reporting PASS / FAIL / NOT RUN as three distinct states.

.DESCRIPTION
`FragmentProviderEntry::drain_handles` (`src/drain.rs`) refuses before any spool work when a cell
predates the spool metadata true-up (`DrainError::SchemaUpgradeRequired`) or reports a schema
revision this build does not know (`DrainError::SchemaUnknown`). Both live tests exercise
`drain_handles` itself -- not `DrainClient::verify_schema_revision` called directly, which is what
`run-cell-schema-forward-upgrade-live.ps1`'s D5 case proves -- so deleting the
`verify_schema_revision()` call inside `drain_handles` is caught only here.

Neither test needs a real BLAKE3 provider: `cell_schema_install`'s forward steps and
`install_cell_schema` do not call `local_blake3_v1`, only real drain reservation traffic does (see
`run-cell-schema-forward-upgrade-live.ps1`'s own note), and both tests here refuse before reaching
reservation traffic. A plain `postgres:16` image is enough.

Steps:

  1. Cross-checks its own test name map against `cargo test -p lore-fragment-provider --lib --
     --ignored --list` before touching Docker.
  2. Refuses to continue if any container already carries this runner's ownership label.
  3. Starts one labelled, disposable `postgres:16` container.
  4. Creates the four `object_dispatch_retention_*` roles ONCE, cluster-wide (the same load-bearing
     shape `run-cell-schema-forward-upgrade-live.ps1` uses).
  5. Creates one database per test, handed to the test as the `postgres` superuser URL.
  6. Runs each test by exact name, serially (`--test-threads=1`).
  7. Parses `running N tests` and `test result: ... P passed; F failed`. A filter that matched zero
     tests is NOT RUN, never a pass.
  8. Removes only its own labelled container.

.PARAMETER KeepOnFailure
Keeps the container for debugging when the run did not fully pass.
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
$containerName = "wp-cr038-drain-handles-schema-gate-live-$runId"
$ownershipLabel = "com.tideshift.lore.drain-handles-schema-gate-live=$runId"
$containerStarted = $false
$runPassed = $false

$imageTag = 'postgres:16'

$tests = @(
    @{ EnvVar = 'LORE_TEST_DRAIN_HANDLES_SCHEMA_GATE_UPGRADE_REQUIRED_PG_URL'; Name = 'drain_handles_refuses_a_cell_that_predates_the_spool_metadata_true_up'; Database = 'upgrade_required' },
    @{ EnvVar = 'LORE_TEST_DRAIN_HANDLES_SCHEMA_GATE_UNKNOWN_PG_URL'; Name = 'drain_handles_refuses_a_cell_schema_revision_this_build_does_not_know'; Database = 'schema_unknown' }
)

$environmentNames = @($tests | ForEach-Object { $_.EnvVar })
$priorEnvironment = @{}
foreach ($name in $environmentNames) {
    $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

function Get-IgnoredTestCatalog {
    Push-Location $loreRoot
    try {
        $output = & cargo test -p lore-fragment-provider --lib -- --ignored --list 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "cargo test -p lore-fragment-provider --lib -- --ignored --list failed:`n$output"
    }
    $catalog = @()
    foreach ($line in ($output -split "`r?`n")) {
        $nameMatch = [regex]::Match($line, '^(?<name>tests::[A-Za-z0-9_]+): test$')
        if ($nameMatch.Success) {
            $catalog += $nameMatch.Groups['name'].Value -replace '^tests::', ''
        }
    }
    return $catalog
}

function Assert-CatalogMatchesKnownTests {
    Write-Host 'Cross-checking the ignored-test catalog against this harness''s known live tests...'
    $catalog = Get-IgnoredTestCatalog
    foreach ($t in $tests) {
        $found = @($catalog | Where-Object { $_ -eq $t.Name })
        if ($found.Count -ne 1) {
            throw "known live test $($t.Name) was not found (or was found more than once); it may have been renamed or moved"
        }
    }
    $unknown = @($catalog | Where-Object {
            $candidate = $_
            -not @($tests | Where-Object { $_.Name -eq $candidate })
        })
    if ($unknown.Count -gt 0) {
        $descriptions = $unknown -join '; '
        throw "found lore-fragment-provider ignored test(s) unknown to this harness: $descriptions -- add them to the test map before trusting a green run"
    }
    Write-Host "Ignored-test catalog: $($catalog.Count) test(s), all known."
}

function Assert-NoCollidingContainer {
    $labelFormat = '{{.Names}}|||{{.Status}}|||{{.Label "com.tideshift.lore.drain-handles-schema-gate-live.pid"}}' +
    '|||{{.Label "com.tideshift.lore.drain-handles-schema-gate-live.started"}}'
    $existingRaw = & docker ps -a --filter 'label=com.tideshift.lore.drain-handles-schema-gate-live' --format $labelFormat
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to check for a colliding drain-handles-schema-gate-live container'
    }
    $existing = @($existingRaw | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($existing.Count -eq 0) {
        return
    }
    $rows = $existing | ForEach-Object {
        $fields = $_ -split '\|\|\|'
        "  - $($fields[0]) [$($fields[1])] pid=$($fields[2]) started=$($fields[3])"
    }
    throw "found $($existing.Count) colliding container(s):`n$($rows -join "`n")`nCheck the pid label before treating one as an orphan."
}

try {
    Assert-CatalogMatchesKnownTests
    Assert-NoCollidingContainer

    $containerStarted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.drain-handles-schema-gate-live.pid=$PID",
        '--label', "com.tideshift.lore.drain-handles-schema-gate-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
        $imageTag
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
        $readyEvents = [regex]::Matches($logOutput, 'database system is ready to accept connections').Count
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

    $roleSql = @'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN
    CREATE ROLE object_dispatch_retention_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN
    CREATE ROLE object_dispatch_retention_runtime LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN
    CREATE ROLE object_dispatch_retention_maintenance LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN
    CREATE ROLE object_dispatch_retention_migrator LOGIN;
  END IF;
END
$$;
GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator
  WITH INHERIT FALSE, SET TRUE;
'@
    Invoke-Checked docker @(
        'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
        '-c', $roleSql
    )

    foreach ($t in $tests) {
        Invoke-Checked docker @(
            'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
            '-c', "CREATE DATABASE $($t.Database);"
        )
        Invoke-Checked docker @(
            'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
            '-c', "GRANT CREATE ON DATABASE $($t.Database) TO object_dispatch_retention_owner;"
        )
        [Environment]::SetEnvironmentVariable($t.EnvVar, "postgresql://postgres@localhost:$port/$($t.Database)", 'Process')
    }

    $results = @()
    Push-Location $loreRoot
    try {
        foreach ($t in $tests) {
            Write-Host "Running $($t.Name)..."
            $cargoArgs = @(
                'test', '-p', 'lore-fragment-provider', '--lib', '--',
                '--ignored', '--exact', "tests::$($t.Name)", '--test-threads=1', '--nocapture'
            )
            $output = & cargo @cargoArgs 2>&1 | Out-String
            $exitCode = $LASTEXITCODE

            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
            if (-not $runningMatch.Success -or -not $resultMatch.Success) {
                Write-Warning $output
                throw "could not parse cargo test output for $($t.Name)"
            }
            $ran = [int]$runningMatch.Groups[1].Value
            $passed = [int]$resultMatch.Groups[1].Value
            $failed = [int]$resultMatch.Groups[2].Value
            $status = if ($ran -ne 1) { 'NOT RUN' } elseif ($passed -eq 1 -and $failed -eq 0 -and $exitCode -eq 0) { 'PASS' } else { 'FAIL' }
            $results += [pscustomobject]@{ Test = $t.Name; Status = $status; Passed = $passed; Failed = $failed; Ran = $ran }
            if ($status -eq 'PASS') { Write-Host '  PASS' } else { Write-Warning "  $status`n$output" }
        }
    }
    finally {
        Pop-Location
    }

    $results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $expected = $tests.Count
    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failures = @($results | Where-Object { $_.Status -ne 'PASS' })
    if ($passCount -ne $expected) {
        Write-Warning "$passCount of $expected drain-handles schema-gate live tests passed; $($failures.Count) did not:"
        foreach ($failure in $failures) { Write-Warning "  $($failure.Test): $($failure.Status)" }
    }
    else {
        $runPassed = $true
        Write-Host "All $expected drain-handles schema-gate live tests passed."
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], 'Process')
    }
    if ($containerStarted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"com.tideshift.lore.drain-handles-schema-gate-live`" }}" $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq $runId) {
            & docker rm --force --volumes $containerName *> $null
        }
        else {
            Write-Warning "refusing to remove unowned container $containerName"
        }
    }
    elseif ($containerStarted) {
        Write-Warning "keeping container $containerName for debugging (-KeepOnFailure)"
    }
}

if (-not $runPassed) {
    exit 1
}
