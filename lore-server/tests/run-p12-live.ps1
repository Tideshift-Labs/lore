# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs `lore-server/tests/p12_live.rs`'s four real-construction cases on the shared test PostgreSQL,
one fresh database each.

.DESCRIPTION
The Rust cases stay `#[ignore]`. This runner verifies the fixed three-case inventory against
`cargo test ... -- --ignored --list` (a renamed, removed, or newly-added case is a setup failure,
never a silent short count), runs each in its own fresh database, and reports PASS, FAIL, and
NOT RUN distinctly. Uses the workspace's existing test PostgreSQL container rather than
provisioning a disposable one, on the pattern of `lore-postgres/tests/run-active-active-shared-backend-live.ps1`
and `lore-postgres/tests/run-fragment-lifecycle-live.ps1` — other agent lanes run in this checkout
concurrently and a `postgres:16` container of its own is contention this proof does not need.

Exit code is 1 unless every case is PASS. Cite PASS against EXPECTED, never the exit code alone.
#>

[CmdletBinding()]
param(
    [string[]]$OnlyCase,
    [switch]$KeepOnFailure,
    [string]$PgContainer = 'lorehub-dataplane-test-postgres-1',
    [string]$PgHost = '127.0.0.1',
    [int]$PgPort = 11832,
    [string]$PgUser = 'lorehub',
    [string]$PgPassword = 'lorehub',
    [string]$ComposeFile = 'D:\github\lorehub-all\lorehub\docker\compose.yaml'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$package = 'lore-server'
$target = 'p12_live'
$setupError = $null
$runPassed = $false

$expectedTests = @(
    'branch_delete_governed_and_real_legacy_delete_agree_on_the_lore_mutable_end_state',
    'exact_mediated_obliterate_consumes_while_tuple_tamper_preserves_prepared',
    'governed_create_projection_rows_match_the_legacy_writers_exactly',
    'released_client_push_with_no_carriage_commits_one_branch_pushed_row_via_internal_prepare'
)

if ($OnlyCase) {
    $unknown = @($OnlyCase | Where-Object { $_ -notin $expectedTests })
    if ($unknown.Count -ne 0) {
        throw "unknown -OnlyCase value(s): [$($unknown -join ', ')]"
    }
}

$results = @(
    foreach ($name in $expectedTests) {
        [pscustomobject]@{
            Test   = $name
            Status = 'NOT RUN'
            Ran    = 0
            Passed = 0
            Failed = 0
        }
    }
)

$priorPgUrl = [Environment]::GetEnvironmentVariable('LORE_TEST_PG_URL', 'Process')

function Invoke-Psql {
    param([Parameter(Mandatory)][string]$Sql)
    $output = & docker exec --env "PGPASSWORD=$PgPassword" $PgContainer `
        psql -v ON_ERROR_STOP=1 -U $PgUser -d postgres -c $Sql 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "psql failed for [$Sql]:`n$output"
    }
    return $output
}

function Get-TestCatalog {
    Push-Location $loreRoot
    $priorErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects. Cargo build
        # warnings are evidence output, not runner setup failures; the native exit code remains
        # the authority for success.
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
        throw "$package/$target catalog failed:`n$output"
    }
    return @(
        foreach ($line in ($output -split "`r?`n")) {
            $match = [regex]::Match($line, '^(?<name>[A-Za-z0-9_:]+): test$')
            if ($match.Success) { $match.Groups['name'].Value }
        }
    )
}

function Assert-ExpectedCatalog {
    $catalog = @(Get-TestCatalog)
    $missing = @($expectedTests | Where-Object { $_ -notin $catalog })
    if ($missing.Count -ne 0) {
        throw "$package/$target is missing pinned cases: [$($missing -join ', ')]"
    }
    $unexpected = @($catalog | Where-Object { $_ -notin $expectedTests })
    if ($unexpected.Count -ne 0 -or $catalog.Count -ne $expectedTests.Count) {
        throw ("$package/$target must hold exactly $($expectedTests.Count) ignored cases; " +
            "catalog has $($catalog.Count). Unexpected=[$($unexpected -join ', ')]")
    }
}

function Assert-Postgres {
    $state = & docker inspect --format '{{.State.Running}}' $PgContainer 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $state.Trim() -ne 'true') {
        throw ("the shared test PostgreSQL container '$PgContainer' is not running. Start the " +
            "data plane first: docker compose -f $ComposeFile up -d test-postgres")
    }
    $versionRaw = & docker exec --env "PGPASSWORD=$PgPassword" $PgContainer `
        psql -tA -v ON_ERROR_STOP=1 -U $PgUser -d postgres -c 'SHOW server_version_num;' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "failed to query the test PostgreSQL server version:`n$($versionRaw | Out-String)"
    }
    $version = [int](($versionRaw | Out-String).Trim())
    if ($version -lt 160000 -or $version -ge 170000) {
        throw "expected PostgreSQL 16, found server_version_num=$version"
    }
}

try {
    Assert-ExpectedCatalog
    Assert-Postgres

    Push-Location $loreRoot
    try {
        $ordinal = 0
        foreach ($result in $results) {
            $ordinal += 1
            if ($OnlyCase -and $result.Test -notin $OnlyCase) { continue }

            # Lowercase: an unquoted identifier folds and a mixed-case name would then not match
            # the DROP below.
            $databaseName = "wp119_p12_$($ordinal)_$($runId.Substring(0, 12))"
            Invoke-Psql "CREATE DATABASE $databaseName;" | Out-Null
            [Environment]::SetEnvironmentVariable(
                'LORE_TEST_PG_URL',
                "postgresql://$($PgUser):$($PgPassword)@$($PgHost):$($PgPort)/$databaseName",
                'Process'
            )

            Write-Host "Running $($result.Test)..."
            $exitCode = 1
            $output = ''
            $priorErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $cargoArgs = @(
                    'test', '-p', $package, '--test', $target, '--',
                    '--ignored', '--exact', $result.Test, '--test-threads=1'
                )
                $output = & cargo @cargoArgs 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $priorErrorAction
                [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $null, 'Process')
                if (-not ($KeepOnFailure -and $exitCode -ne 0)) {
                    Invoke-Psql "DROP DATABASE $databaseName WITH (FORCE);" | Out-Null
                }
                else {
                    Write-Warning "keeping database $databaseName for debugging (-KeepOnFailure)"
                }
            }

            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
            if ($runningMatch.Success) { $result.Ran = [int]$runningMatch.Groups[1].Value }
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

    $selected = if ($OnlyCase) { @($results | Where-Object { $_.Test -in $OnlyCase }) } else { $results }
    $passCount = @($selected | Where-Object { $_.Status -eq 'PASS' }).Count
    if ($passCount -eq $selected.Count -and $selected.Count -gt 0) { $runPassed = $true }
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL', $priorPgUrl, 'Process')
}

$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$selected = if ($OnlyCase) { @($results | Where-Object { $_.Test -in $OnlyCase }) } else { $results }
$passCount = @($selected | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($selected | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($selected | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($selected.Count)"
if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
