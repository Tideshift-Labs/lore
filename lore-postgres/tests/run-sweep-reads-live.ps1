# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions an owned PostgreSQL instance and runs WP-120's refresh-read inventory (the Gate 0 receipt).

.DESCRIPTION
Proves, through the real `RepositoryGet` / `BranchGet` handlers and the real fenced
`LoreLockService::query`, that the authoritative generations the contract adds are
present and move with the domain rows:

- `repository_generation` equals `lore_domain_repositories.generation` and rises after a
  metadata CAS; a deleted repository is NotFound;
- `branch_generation` equals `lore_domain_branches.generation`, rises after a head-changing
  push and after protect and unprotect, and is unchanged by a same-head push;
- `namespace_generation` equals the `lore_domain_lock_namespaces` row, its fence rises after
  an acquire and after a release, and it is absent for an all-branch query, an unknown branch
  and the legacy lock route, and lock activity on one branch leaves a sibling branch's
  namespace untouched.

The Rust cases stay `#[ignore]`. This runner opts in to each case by exact name, one at a time,
and reports PASS, FAIL, and NOT RUN separately. It verifies the compiled catalog before Docker
starts. A renamed, removed, added, or filtered-to-zero case is a setup failure. A disposable
container is always created: the shared `lorehub` development database and the slot-0 data plane
containers are never touched. Each case gets a fresh database in that container; cleanup checks
both the random run label and the owning PowerShell process before removing the container and
anonymous volume.

The handler-level cases without Postgres (field absent without a domain context, present and
passed through, forwarded variants) are plain unit tests:
`cargo test -p lore-server --test unit -- refresh_generation`.
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
$containerName = "wp120-sweep-reads-live-$runId"
$ownershipLabelName = 'com.tideshift.lore.sweep-reads-live'
$ownershipLabel = "$ownershipLabelName=$runId"
$containerCreationAttempted = $false
$runPassed = $false
$setupError = $null

# Each entry is one compiled target plus the exact cases this runner owns.
# `Exact` means the target may hold no other ignored case, so a case added
# without updating this list is a setup failure rather than a silent skip.
#
# The `lore-server` `unit` test binary also holds ignored cases owned by other packages, so
# it cannot be exact wholesale. `ExactPrefixes` narrows the same guarantee to the
# modules this runner OWNS: a live case added under one of them without joining
# this inventory is a setup failure, not a silent NOT RUN. A pinned case can
# still sit outside every prefix when its module is shared with other packages
# (`grpc::handlers::branch_push::` holds WP-116's cases too), in which
# case only that exact case is policed.
$inventory = @(
    [pscustomobject]@{
        Package       = 'lore-server'
        Target        = 'sweep_reads_live'
        Exact         = $true
        ExactPrefixes = @()
        Cases         = @(
            'wp120_repository_generation_is_read_and_increases_after_a_metadata_cas',
            'wp120_branch_generation_increases_on_head_change_and_protection_only',
            'wp120_a_deleted_repository_is_not_found'
        )
    },
    [pscustomobject]@{
        Package       = 'lore-server'
        Target        = 'p12_lock_service_fenced_routing'
        # The target also holds other packages' ignored cases, so it cannot be exact
        # wholesale. The `wp120_` prefix is this runner's: a live case added under it
        # without joining this list is a setup failure, not a silent NOT RUN.
        Exact         = $false
        ExactPrefixes = @('wp120_')
        Cases         = @(
            'wp120_single_branch_query_namespace_fence_advances_on_acquire_and_release',
            'wp120_query_without_a_branch_carries_no_namespace_generation',
            'wp120_query_of_an_unknown_branch_carries_no_namespace_generation',
            'wp120_legacy_route_query_carries_no_namespace_generation',
            'wp120_lock_activity_on_one_branch_does_not_move_a_sibling_branch_namespace'
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
        throw 'failed to inspect existing sweep-reads live containers'
    }
    $collisions = @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        $message = "another sweep-reads live container exists; refusing to overlap:`n" +
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
        '--label', "com.tideshift.lore.sweep-reads-live.pid=$PID",
        '--label', "com.tideshift.lore.sweep-reads-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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
            $databaseName = "wp120_sweep_$($testOrdinal)_$($runId.Substring(0, 12))"
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
                # Echo cargo's output verbatim on every branch so `test result:` lines reach stdout
                # (the Gate 0 receipt producers parse them).
                Write-Host $output
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
            $labels.PSObject.Properties['com.tideshift.lore.sweep-reads-live.pid'].Value
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
