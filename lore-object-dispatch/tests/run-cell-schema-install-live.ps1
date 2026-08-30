# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions a disposable PostgreSQL 16 and runs the WP-114 CD-1 cell-schema installer/attester live
tier by exact name, reporting PASS / FAIL / NOT RUN as three distinct states.

.DESCRIPTION
WP-114 CD-1 requires the cell authority schema to be installed out of band under the migrator role
and attested against the live PostgreSQL catalog. `src/cell_schema_install.rs` is that installer;
this runner is its executable proof.

It differs from `run-local-authority-live.ps1` (CD-2) in one way that matters: the tests here
connect **as** `object_dispatch_retention_migrator`, a real LOGIN role, rather than as a superuser
using `SET SESSION AUTHORIZATION`. The installer's first precondition is
`session_user = 'object_dispatch_retention_migrator'`, so exercising the production path requires a
real login. Nothing else in the crate needs that, which is why this runner owns its own container
rather than sharing CD-2's.

Steps:

  1. Cross-checks its own test name/target map against
     `cargo test -p lore-object-dispatch -- --ignored --list` before touching Docker, so a renamed
     or newly added live test fails fast instead of silently going NOT RUN.
  2. Refuses to continue if any container already carries this runner's ownership label, printing
     each one's name, status, owning pid and start time. A label proves self-consistency, never
     ownership: check whether that pid is still alive before treating a labelled container as an
     orphan. Do not remove one on a hunch.
  3. Starts one labelled, disposable PostgreSQL 16 (no TLS -- the cell authority is the cell's own
     database, reached inside the cell).
  4. Creates the four `object_dispatch_retention_*` roles, with the migrator as a LOGIN role and a
     member of the owner role, and one database per test with CREATE granted to the owner. Every
     database is handed over EMPTY: installing the chain is the thing under test.
  5. Runs each test by exact name, serially.
  6. Parses `running N tests` and `test result: ... P passed; F failed`. A filter that matched zero
     tests is NOT RUN, never a pass.
  7. Removes only its own labelled container.

.PARAMETER Measure
Runs only the measurement helper, which installs a fresh chain and prints the live catalog manifest
digests. Use it to (re)measure the pinned constants in `cell_schema_install.rs` after a frozen
migration or the manifest query changes. It is not a gate and reports no PASS.

.PARAMETER KeepOnFailure
Keeps the container for debugging when the run did not fully pass.
#>

[CmdletBinding()]
param(
    [switch]$Measure,
    [switch]$KeepOnFailure
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "wp114-cell-schema-install-live-$runId"
$ownershipLabel = "com.tideshift.lore.cell-schema-install-live=$runId"
$containerStarted = $false
$runPassed = $false

$target = 'cell_schema_install_live'

$gateTests = @(
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_CLEAN_PG_URL'
        Name     = 'live_postgres_cell_schema_installs_clean_and_attests'
        Database = 'cell_schema_clean'
        # A second URL onto the SAME database, authenticated as a non-migrator, so the test can
        # prove every entry point refuses one. `postgres` is deliberate: a superuser can read every
        # digest, so refusing it proves a real boundary rather than an incidental privilege gap.
        ExtraEnv = @{ 'LORE_TEST_CELL_SCHEMA_CLEAN_OUTSIDER_PG_URL' = 'postgres' }
    },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_IDEMPOTENT_PG_URL'
        Name     = 'live_postgres_cell_schema_install_is_idempotent'
        Database = 'cell_schema_idempotent'
    },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_PARTIAL_PG_URL'
        Name     = 'live_postgres_cell_schema_refuses_a_partial_install'
        Database = 'cell_schema_partial'
    },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_DRIFT_PG_URL'
        Name     = 'live_postgres_cell_schema_refuses_a_drifted_catalog'
        Database = 'cell_schema_drift'
    },
    @{
        EnvVar   = 'LORE_TEST_CELL_SCHEMA_REVOKE_PG_URL'
        Name     = 'live_postgres_cell_schema_revokes_service_privileges_after_replacement'
        Database = 'cell_schema_revoke'
    }
)

$measureTest = @{
    EnvVar   = 'LORE_TEST_CELL_SCHEMA_MEASURE_PG_URL'
    Name     = 'live_postgres_cell_schema_measure_catalog_manifest'
    Database = 'cell_schema_measure'
}

# Assign inside the branches, not from the `if` expression: a one-element result coming out of an
# `if` expression unwraps to the hashtable itself, and `$tests.Count` then reports its key count.
$tests = @()
if ($Measure) {
    $tests = @($measureTest)
}
else {
    $tests = @($gateTests)
}
$knownTests = @($gateTests) + @($measureTest)

$environmentNames = @($knownTests | ForEach-Object { $_.EnvVar })
foreach ($known in $knownTests) {
    if ($known.ContainsKey('ExtraEnv')) {
        $environmentNames += @($known.ExtraEnv.Keys)
    }
}
$priorEnvironment = @{}
foreach ($name in $environmentNames) {
    $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

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

function Get-IgnoredTestCatalog {
    Push-Location $loreRoot
    try {
        $listArgs = @('test', '-p', 'lore-object-dispatch', '--', '--ignored', '--list')
        $output = & cargo @listArgs 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "cargo test -p lore-object-dispatch -- --ignored --list failed:`n$output"
    }

    $catalog = @()
    $currentTarget = $null
    foreach ($line in ($output -split "`r?`n")) {
        $headerMatch = [regex]::Match($line, '^\s*Running tests\\(?<target>[^\\]+)\.rs\b')
        if ($headerMatch.Success) {
            $currentTarget = $headerMatch.Groups['target'].Value
            continue
        }
        if ($line -match '^\s*Running (?:unittests|benches)\b' -or $line -match '^\s*Doc-tests\b') {
            $currentTarget = $null
            continue
        }
        $nameMatch = [regex]::Match($line, '^(?<name>[A-Za-z0-9_]+): test$')
        if ($nameMatch.Success) {
            $catalog += [pscustomobject]@{ Target = $currentTarget; Name = $nameMatch.Groups['name'].Value }
        }
    }
    return $catalog
}

function Assert-CatalogMatchesKnownTests {
    Write-Host 'Cross-checking the ignored-test catalog against this harness''s known live tests...'
    $catalog = Get-IgnoredTestCatalog

    foreach ($t in $knownTests) {
        $found = @($catalog | Where-Object { $_.Target -eq $target -and $_.Name -eq $t.Name })
        if ($found.Count -ne 1) {
            throw "known live test $($t.Name) ($target) was not found (or was found more than once) in the ignored-test catalog; it may have been renamed or moved"
        }
    }

    $ownCatalog = @($catalog | Where-Object { $_.Target -eq $target })
    $unknown = @($ownCatalog | Where-Object {
            $candidate = $_
            -not @($knownTests | Where-Object { $_.Name -eq $candidate.Name })
        })
    if ($unknown.Count -gt 0) {
        $descriptions = ($unknown | ForEach-Object { $_.Name }) -join '; '
        throw "found $target ignored test(s) unknown to this harness: $descriptions -- add them to the test map (and provision a database) before trusting a green run"
    }
    Write-Host "Ignored-test catalog: $($ownCatalog.Count) test(s) in $target, all known."
}

function Assert-NoCollidingContainer {
    # A container's ownership label is only ever the run-id suffix of its own name, so it proves
    # self-consistency and never ownership. The `.pid` and `.started` labels below are what let a
    # later observer decide whether a labelled container is genuinely an orphan: check that the pid
    # is no longer running first. Removing one on a hunch has already destroyed an in-progress run
    # once on this rig (2026-08-28, the local-authority tier).
    $labelFormat = '{{.Names}}|||{{.Status}}|||{{.Label "com.tideshift.lore.cell-schema-install-live.pid"}}' +
    '|||{{.Label "com.tideshift.lore.cell-schema-install-live.started"}}'
    $existingRaw = & docker ps -a --filter 'label=com.tideshift.lore.cell-schema-install-live' --format $labelFormat
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to check for a colliding cell-schema-install-live container'
    }
    $existing = @($existingRaw | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($existing.Count -eq 0) {
        return
    }

    $rows = $existing | ForEach-Object {
        $fields = $_ -split '\|\|\|'
        $name = $fields[0]
        $status = if ($fields.Count -gt 1) { $fields[1] } else { '(unknown status)' }
        $ownerPid = if ($fields.Count -gt 2 -and $fields[2]) { $fields[2] } else { '(no pid label)' }
        $started = if ($fields.Count -gt 3 -and $fields[3]) { $fields[3] } else { '(no started label)' }
        "  - $name [$status] pid=$ownerPid started=$started"
    }
    throw "found $($existing.Count) container(s) already carrying the com.tideshift.lore.cell-schema-install-live label:`n$($rows -join "`n")`nAnother run may be in progress. Check ``Get-Process -Id <pid>`` for the pid label above and only treat a container as an orphan if that pid is gone."
}

try {
    Assert-CatalogMatchesKnownTests
    Assert-NoCollidingContainer

    # Set before the call: `docker run --detach` can create the container and still exit non-zero,
    # and the teardown path must own it from the moment creation is attempted.
    $containerStarted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.cell-schema-install-live.pid=$PID",
        '--label', "com.tideshift.lore.cell-schema-install-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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

    # The migrator is a LOGIN role and a NON-INHERITING member of the owner role. All three parts
    # are load-bearing. The installer requires session_user = migrator; every frozen migration opens
    # with `SET LOCAL ROLE object_dispatch_retention_owner`, which needs membership; and the
    # membership must not inherit, because 0008's and 0011's catalog asserts reject any service role
    # holding a table privilege on an authority table and `has_table_privilege` counts privileges
    # reached through an inheriting membership. A plain GRANT here makes the very first install call
    # fail with DISPATCH_AUTHORITY_CATALOG_MISMATCH, with nothing actually drifted -- observed on
    # this rig, 2026-08-30, before the grant was corrected.
    $roleSql = @'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN
    CREATE ROLE object_dispatch_retention_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN
    CREATE ROLE object_dispatch_retention_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN
    CREATE ROLE object_dispatch_retention_maintenance NOLOGIN;
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
        [Environment]::SetEnvironmentVariable(
            $t.EnvVar,
            "postgresql://object_dispatch_retention_migrator@localhost:$port/$($t.Database)",
            'Process'
        )
        if ($t.ContainsKey('ExtraEnv')) {
            foreach ($extra in $t.ExtraEnv.GetEnumerator()) {
                [Environment]::SetEnvironmentVariable(
                    $extra.Key,
                    "postgresql://$($extra.Value)@localhost:$port/$($t.Database)",
                    'Process'
                )
            }
        }
    }

    $results = @()
    Push-Location $loreRoot
    try {
        foreach ($t in $tests) {
            Write-Host "Running $($t.Name) ($target)..."
            $cargoArgs = @(
                'test', '-p', 'lore-object-dispatch', '--test', $target, '--',
                '--ignored', '--exact', $t.Name, '--test-threads=1', '--nocapture'
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

            $status = if ($ran -ne 1) {
                'NOT RUN'
            }
            elseif ($passed -eq 1 -and $failed -eq 0 -and $exitCode -eq 0) {
                'PASS'
            }
            else {
                'FAIL'
            }

            $results += [pscustomobject]@{
                Test   = $t.Name
                Status = $status
                Passed = $passed
                Failed = $failed
                Ran    = $ran
            }

            foreach ($line in ($output -split "`r?`n")) {
                # Not anchored: cargo's own harness output can share a line with the first println.
                if ($line -match 'MEASURED ') {
                    Write-Host $line
                }
            }

            if ($status -eq 'PASS') {
                Write-Host '  PASS'
            }
            else {
                Write-Warning "  $status`n$output"
            }
        }
    }
    finally {
        Pop-Location
    }

    $results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    # Assert what this run is meant to prove: that every test actually reported PASS. `$ran -ne 1`
    # above is what proves each one executed rather than matching nothing under `--exact`.
    $expected = $tests.Count
    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failures = @($results | Where-Object { $_.Status -ne 'PASS' })
    if ($passCount -ne $expected) {
        Write-Warning "$passCount of $expected cell-schema-install live tests passed; $($failures.Count) did not:"
        foreach ($failure in $failures) {
            Write-Warning "  $($failure.Test): $($failure.Status)"
        }
    }
    else {
        $runPassed = $true
        if ($Measure) {
            Write-Host 'Measurement run complete. Copy the MEASURED digests into cell_schema_install.rs.'
        }
        else {
            Write-Host "All $expected cell-schema-install live tests passed."
        }
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], 'Process')
    }

    if ($containerStarted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"com.tideshift.lore.cell-schema-install-live`" }}" $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq $runId) {
            # --volumes: postgres:16 declares VOLUME /var/lib/postgresql/data, so a plain
            # `docker rm --force` leaves an anonymous, unreferenced volume behind every run.
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
