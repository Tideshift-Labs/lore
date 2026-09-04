# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs WP-109 Phase 2's shared-backend proof (`lore-postgres/tests/active_active_shared_backend.rs`)
against one real PostgreSQL instance and one real MinIO endpoint, a fresh database per case.

.DESCRIPTION
The Rust cases stay `#[ignore]`. This runner opts in to each case by exact name and reports PASS,
FAIL, and NOT RUN separately against an EXPECTED count, on the pattern of
`run-outbox-producers-live.ps1` and `run-fragment-lifecycle-live.ps1`.

Three things it does that the sibling runners do not, each for a reason:

1. **It uses the workspace's existing test PostgreSQL container instead of provisioning its own.**
   Three other agent lanes run in this checkout concurrently and a fourth disposable
   `postgres:16` is contention this proof does not need. Each case still gets a fresh database,
   which is the isolation arm that matters; the harness adds a `CaseNamespace` schema on top.
2. **It owns the failpoint configuration.** `domain/fragments/failpoints.rs` reads
   `LORE_FRAGMENT_FAILPOINTS` once per process through a `LazyLock`, so a case cannot arm its own
   anchors. The two failpoint cases are therefore launched with the exact spec they need and with
   `--features failure_generator`; `env::failpoints` in the harness refuses to run under any other
   spec, so a mis-driven case is NOT RUN rather than a silent pass with no barrier.
3. **It distinguishes "the environment was absent" from "the race failed".** The harness panics
   with the `WP109-NOT-RUN:` marker when a required variable is unset, and this runner maps that
   marker to NOT RUN. A live case that returned early would be counted `passed` by Rust's harness,
   which is exactly the failure WP-109 forbids.

Exit code is 1 unless every case is PASS. Do not cite the exit code alone: cite PASS against
EXPECTED, with NOT RUN at zero.

.PARAMETER OnlyCase
Restrict the run to these exact case names. Under `pwsh -File` a comma list arrives as ONE string,
so invoke through `-Command` when passing more than one:

    pwsh -Command "& '<abs path>/run-active-active-shared-backend-live.ps1' -OnlyCase a1_x,b1_y"

.PARAMETER Seed
Identity seed handed to every case. Omit for a fresh random seed per case; pass the seed a failing
case printed to replay its identities. It does not replay the interleaving.
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
    [string]$S3Endpoint = 'http://127.0.0.1:9000',
    [string]$S3Region = 'us-east-1',
    [string]$S3AccessKey = 'minioadmin',
    [string]$S3SecretKey = 'minioadmin',
    [string]$ComposeFile = 'D:\github\lorehub-all\lorehub\docker\compose.yaml',
    [string]$Seed
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$package = 'lore-postgres'
$target = 'active_active_shared_backend'
$setupError = $null
$runPassed = $false

# The whole inventory, in the order the work package lists the races. `Failpoint` is the exact
# LORE_FRAGMENT_FAILPOINTS spec the case requires; a case with one is built and run with
# --features failure_generator, and the harness refuses to proceed under any other spec.
$cases = @(
    [pscustomobject]@{ Test = 'a1_two_sets_racing_one_repository_name_leave_exactly_one_live_owner'; Failpoint = $null },
    [pscustomobject]@{ Test = 'a2_a_name_released_by_one_set_is_reusable_by_the_other_but_the_identity_is_not'; Failpoint = $null },
    [pscustomobject]@{ Test = 'b1_two_sets_pushing_one_head_advance_it_exactly_once'; Failpoint = $null },
    [pscustomobject]@{ Test = 'b2_a_push_racing_a_repository_delete_never_advances_a_tombstoned_branch'; Failpoint = $null },
    [pscustomobject]@{ Test = 'b3_a_push_racing_begin_obliterate_is_fenced_by_the_repository_generation'; Failpoint = $null },
    [pscustomobject]@{ Test = 'c1_two_sets_racing_one_lock_resource_choose_exactly_one_owner'; Failpoint = $null },
    [pscustomobject]@{ Test = 'c2_an_expired_lease_takeover_by_one_set_fences_the_other_sets_renew_and_release'; Failpoint = $null },
    [pscustomobject]@{ Test = 'c3_a_release_racing_a_force_release_removes_the_row_exactly_once'; Failpoint = $null },
    [pscustomobject]@{ Test = 'c4_a_lock_from_one_set_invalidates_the_other_sets_captured_push_witness'; Failpoint = $null },
    [pscustomobject]@{ Test = 'd1_two_sets_putting_one_hash_converge_on_one_object_and_keep_both_associations'; Failpoint = $null },
    [pscustomobject]@{ Test = 'd2_a_read_during_a_concurrent_put_never_advertises_bytes_it_cannot_serve'; Failpoint = $null },
    [pscustomobject]@{ Test = 'd3_a_copy_racing_the_last_association_obliterate_never_dangles_across_two_sets'; Failpoint = $null },
    [pscustomobject]@{ Test = 'e1_a_committed_mutation_leaves_its_classified_rows_and_a_rejected_one_leaves_none'; Failpoint = $null },
    [pscustomobject]@{ Test = 'e2_two_relay_claimers_over_one_backlog_never_claim_the_same_row'; Failpoint = $null },
    [pscustomobject]@{ Test = 'e3_broker_acceptance_from_one_set_fences_a_stale_claim_from_the_other'; Failpoint = $null },
    [pscustomobject]@{ Test = 'e4_a_broker_epoch_reset_requeues_accepted_rows_with_their_original_keys'; Failpoint = $null },
    [pscustomobject]@{ Test = 'e5_consumer_safe_advances_only_under_the_required_checkpoint_vector'; Failpoint = $null },
    [pscustomobject]@{ Test = 'f1_a_lost_publication_commit_acknowledgement_is_reconciled_by_a_restarted_set'; Failpoint = 'publication.commit.settled=unknown' },
    [pscustomobject]@{ Test = 'f2_a_claim_held_inside_its_transaction_does_not_block_the_other_sets_claim'; Failpoint = 'outbox.claim.after_select=pause' }
)

if ($OnlyCase) {
    $unknown = @($OnlyCase | Where-Object { $_ -notin $cases.Test })
    if ($unknown.Count -ne 0) {
        throw "unknown -OnlyCase value(s): [$($unknown -join ', ')]"
    }
}

$results = @(
    foreach ($case in $cases) {
        [pscustomobject]@{
            Test      = $case.Test
            Failpoint = if ($null -eq $case.Failpoint) { '-' } else { $case.Failpoint }
            Status    = 'NOT RUN'
            Seed      = ''
            Ran       = 0
            Passed    = 0
            Failed    = 0
        }
    }
)

$priorEnv = @{}
foreach ($name in @(
        'LORE_TEST_PG_URL', 'LORE_TEST_S3_ENDPOINT', 'LORE_TEST_S3_REGION',
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'AWS_DEFAULT_REGION',
        'LORE_FRAGMENT_FAILPOINTS', 'LORE_FRAGMENT_FAILPOINT_DIR', 'LORE_TEST_SEED')) {
    $priorEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Set-ProcessEnv {
    param([string]$Name, $Value)
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

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
    param([switch]$WithFailureGenerator)
    Push-Location $loreRoot
    $priorErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord objects. Cargo build
        # warnings are evidence output, not runner setup failures; the native exit code remains
        # the authority for success.
        $ErrorActionPreference = 'Continue'
        $listArgs = @('test', '-p', $package)
        if ($WithFailureGenerator) { $listArgs += @('--features', 'failure_generator') }
        $listArgs += @('--test', $target, '--', '--ignored', '--list')
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

# A renamed, removed, added, or filtered-to-zero case must be a setup failure, not a silent short
# count. Both tiers are checked, because the failpoint cases exist only in one of them and a case
# that fell out of the feature-gated tier would otherwise vanish without a word.
function Assert-ExpectedCatalogs {
    $defaultExpected = @($cases | Where-Object { $null -eq $_.Failpoint } | ForEach-Object { $_.Test })
    $allExpected = @($cases | ForEach-Object { $_.Test })

    $defaultCatalog = @(Get-TestCatalog)
    $missing = @($defaultExpected | Where-Object { $_ -notin $defaultCatalog })
    if ($missing.Count -ne 0) {
        throw "$package/$target (default features) is missing pinned cases: [$($missing -join ', ')]"
    }
    $unexpected = @($defaultCatalog | Where-Object { $_ -notin $defaultExpected })
    if ($unexpected.Count -ne 0 -or $defaultCatalog.Count -ne $defaultExpected.Count) {
        throw ("$package/$target (default features) must hold exactly $($defaultExpected.Count) " +
            "ignored cases; catalog has $($defaultCatalog.Count). Unexpected=[$($unexpected -join ', ')]")
    }

    $fullCatalog = @(Get-TestCatalog -WithFailureGenerator)
    $missing = @($allExpected | Where-Object { $_ -notin $fullCatalog })
    if ($missing.Count -ne 0) {
        throw "$package/$target (failure_generator) is missing pinned cases: [$($missing -join ', ')]"
    }
    $unexpected = @($fullCatalog | Where-Object { $_ -notin $allExpected })
    if ($unexpected.Count -ne 0 -or $fullCatalog.Count -ne $allExpected.Count) {
        throw ("$package/$target (failure_generator) must hold exactly $($allExpected.Count) " +
            "ignored cases; catalog has $($fullCatalog.Count). Unexpected=[$($unexpected -join ', ')]")
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

function Assert-MinIO {
    $probe = "$($S3Endpoint.TrimEnd('/'))/minio/health/live"
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $probe -Method Get -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -eq 200) { return }
        }
        catch {
            if ($attempt -eq 1) {
                Write-Host "MinIO is not answering at $probe; starting it from $ComposeFile..."
                & docker compose -f $ComposeFile up -d minio minio-init *> $null
                Start-Sleep -Seconds 3
                continue
            }
        }
    }
    throw ("MinIO is not reachable at $probe. Start it with: " +
        "docker compose -f $ComposeFile up -d minio minio-init")
}

try {
    Assert-ExpectedCatalogs
    Assert-Postgres
    Assert-MinIO

    $failpointDir = Join-Path ([System.IO.Path]::GetTempPath()) "wp109-failpoints-$runId"
    New-Item -ItemType Directory -Force -Path $failpointDir | Out-Null

    Set-ProcessEnv 'LORE_TEST_S3_ENDPOINT' $S3Endpoint
    Set-ProcessEnv 'LORE_TEST_S3_REGION' $S3Region
    Set-ProcessEnv 'AWS_ACCESS_KEY_ID' $S3AccessKey
    Set-ProcessEnv 'AWS_SECRET_ACCESS_KEY' $S3SecretKey
    Set-ProcessEnv 'AWS_REGION' $S3Region
    Set-ProcessEnv 'AWS_DEFAULT_REGION' $S3Region
    Set-ProcessEnv 'LORE_FRAGMENT_FAILPOINT_DIR' $failpointDir

    Push-Location $loreRoot
    try {
        $ordinal = 0
        foreach ($result in $results) {
            $ordinal += 1
            if ($OnlyCase -and $result.Test -notin $OnlyCase) { continue }
            $case = $cases | Where-Object { $_.Test -eq $result.Test }

            # Lowercase, because an unquoted identifier folds and a mixed-case name would then
            # not match the DROP below.
            $databaseName = "wp109_$($ordinal)_$($runId.Substring(0, 12))"
            Invoke-Psql "CREATE DATABASE $databaseName;" | Out-Null
            Set-ProcessEnv 'LORE_TEST_PG_URL' `
                "postgresql://$($PgUser):$($PgPassword)@$($PgHost):$($PgPort)/$databaseName"
            if ($Seed) { Set-ProcessEnv 'LORE_TEST_SEED' $Seed } else { Set-ProcessEnv 'LORE_TEST_SEED' $null }
            Set-ProcessEnv 'LORE_FRAGMENT_FAILPOINTS' $case.Failpoint

            Write-Host "Running $($result.Test)..."
            # Reset before the try, not inside it: if `cargo` itself throws, the
            # `finally` below still reads `$exitCode`, and without this it would
            # read the PREVIOUS case's value and decide the database drop from
            # an unrelated result.
            $exitCode = 1
            $output = ''
            $priorErrorAction = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $cargoArgs = @('test', '-p', $package)
                if ($null -ne $case.Failpoint) { $cargoArgs += @('--features', 'failure_generator') }
                $cargoArgs += @(
                    '--test', $target, '--',
                    '--ignored', '--exact', $result.Test, '--test-threads=1', '--nocapture'
                )
                $output = & cargo @cargoArgs 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $priorErrorAction
                Set-ProcessEnv 'LORE_TEST_PG_URL' $null
                Set-ProcessEnv 'LORE_FRAGMENT_FAILPOINTS' $null
                if (-not ($KeepOnFailure -and $exitCode -ne 0)) {
                    Invoke-Psql "DROP DATABASE $databaseName WITH (FORCE);" | Out-Null
                }
                else {
                    Write-Warning "keeping database $databaseName for debugging (-KeepOnFailure)"
                }
            }

            $runningMatch = [regex]::Match($output, 'running (\d+) tests?')
            $resultMatch = [regex]::Match($output, 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed;')
            $seedMatch = [regex]::Match($output, 'case identity seed: (\d+)')
            if ($runningMatch.Success) { $result.Ran = [int]$runningMatch.Groups[1].Value }
            if ($resultMatch.Success) {
                $result.Passed = [int]$resultMatch.Groups[1].Value
                $result.Failed = [int]$resultMatch.Groups[2].Value
            }
            if ($seedMatch.Success) { $result.Seed = $seedMatch.Groups[1].Value }

            if ($output -match 'WP109-NOT-RUN:') {
                # The harness refused to run: a required variable, credential, or failpoint spec
                # was absent. Never a pass, and not a failed race either.
                $result.Status = 'NOT RUN'
                Write-Warning "  NOT RUN (environment)`n$output"
            }
            elseif ($result.Ran -eq 1 -and $result.Passed -eq 1 -and $result.Failed -eq 0 -and $exitCode -eq 0) {
                $result.Status = 'PASS'
                # The evidence lines the work package asks for: seed, namespace creation and
                # release, barrier attestations, and outcome tallies.
                foreach ($line in ($output -split "`r?`n")) {
                    if ($line -match '^(case identity seed|case namespace|case object namespace|barrier attested|table gate|advisory gate|failpoint|race tally)') {
                        Write-Host "    $line"
                    }
                }
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
    foreach ($name in $priorEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $priorEnv[$name], 'Process')
    }
}

$results | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
$selected = if ($OnlyCase) { @($results | Where-Object { $_.Test -in $OnlyCase }) } else { $results }
$passCount = @($selected | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($selected | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($selected | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount EXPECTED=$($selected.Count)"
Write-Host ("A case that panicked may have retained its schema or bucket for debug; the lines above " +
    "name them. Retained MinIO buckets are prefixed wp109-.")

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) {
    exit 1
}
