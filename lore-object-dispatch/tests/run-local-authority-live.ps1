# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Provisions a disposable PostgreSQL 16 and runs the eleven `local_authority_*` cell-authority live
tests in lore-object-dispatch by exact name, reporting pass/fail/NOT RUN distinctly.

.DESCRIPTION
WP-114 CD-2: the local-authority live tests are `#[ignore]` fixtures gated on per-test
`LORE_TEST_LOCAL_*_PG_URL` environment variables with no provisioning script before this file
existed. WP-114 CD-3 added the two `local_authority_dispatcher_identity_*` tests (schema and
provisioning) for the per-participant dispatcher-identity edge (0018-0020; CR-033 D8), bringing
the total from nine to eleven. This runner:

  1. Cross-checks its own eleven-entry name/target/env-var map against
     `cargo test -p lore-object-dispatch -- --ignored --list` (ground truth, not the README)
     before touching Docker. A known test missing from the catalog, or an unknown
     `local_authority_*` ignored test appearing in it, is a hard failure -- this is what keeps a
     renamed or newly added live test from silently going NOT RUN or silently unexercised.
  2. Checks for a colliding container: any container already carrying the
     `com.tideshift.lore.local-authority-live` label is a hard failure, printed with its name,
     status, and (if present) owning pid/start-time labels, before any container work happens.
     Added after an incident where a container carrying this label was manually removed based on
     a *self-consistency* check (its label equals its own name's run-id) that was mistaken for an
     *ownership* check -- it destroyed a different, still-in-progress run. See
     `Assert-NoCollidingContainer`'s comment for the full account.
  3. Starts one labelled, disposable PostgreSQL 16 container (no TLS -- these tests call
     `tokio_postgres::connect` with `NoTls`, unlike the retention-client live tier), additionally
     labelled with the owning PowerShell process id and an ISO 8601 UTC start time so an outside
     observer can check whether the owning process is actually still alive before ever treating a
     labelled container as safe to remove.
  4. Creates the four cluster-wide `object_dispatch_retention_*` roles once, idempotently, and
     shares that one container/cluster across all eleven tests plus the install-chain-proof
     database (twelve databases total). This is safe specifically because a role census across
     all eleven test bodies (`grep`-verified) found zero `ALTER ROLE`, `DROP ROLE`, cross-role
     `GRANT ... TO`, `CREATEDB`, `SUPERUSER`, or `BYPASSRLS` -- the one `ALTER ROLE` hit in the
     crate is a string literal inside `local_authority_schema.rs`'s forbidden-keyword assertion
     list, not an execution, and that file has no live test. Every `REVOKE`/`GRANT EXECUTE` is
     object-scoped and schema-qualified (`ON ALL TABLES IN SCHEMA object_store_retention`, `ON
     FUNCTION`, `ON TYPE`, ...), and `SET SESSION AUTHORIZATION` is session-local. The only
     cluster-level effect any test has is the identical idempotent `CREATE ROLE ... NOLOGIN`
     guard, which is convergent and is state every test wants anyway. One container per test was
     not needed.
  5. Creates twelve databases: one per live test, plus `local_install_chain_proof`.
  6. Installs the CD-1 cell install set (0002, 0003, then 0007 through 0022, in that exact
     order, resolved by numeric prefix) into `local_install_chain_proof` and asserts the CD-1
     "expected inert state": four of the five tables 0002 creates -- the ones inert while
     0004-0006 are uninstalled; the fifth, `object_dispatch_retention_schema_state`, is written by
     0003's install procedure and is not part of this check -- exist, and none of the 0004-0006
     mutation/readback procedures they would need are installed. This is the first
     executed proof that the post-deletion install chain installs cleanly together, and today
     the only place that assertion runs at all -- no `local_authority_*` test makes it. Live
     catalog *attestation* (not just clean DDL) of the 0007-0011 layers is a distinct, narrower
     claim covered by one specific test, not by this step: see
     `live_postgres_chain_install_replay_read_and_drift_fail_closed`
     (`local_authority_put_reservation_provisioning`), the only test that calls all three install
     procedures (`object_store_retention_install_v1`,
     `object_store_dispatch_authority_install_v1`,
     `object_store_dispatch_put_reservation_install_v1`) and both catalog readbacks
     (`object_store_dispatch_authority_read_state_v1` for the 0007/0008 layer,
     `object_store_dispatch_put_reservation_read_state_v1` for the 0010/0011 layer), and proves
     drift fails closed on both. Two things that layer does *not* cover, recorded here because
     nothing else covers them either: 0003's retention-layer readback
     (`object_store_retention_read_state_v1`) has no live caller among the eleven (grep-verified,
     zero hits), and migrations 0012-0017 have no dedicated `read_state` procedure at all --
     they are codecs and mutations, attested behaviorally by their own live tests instead.
     WP-114 CD-3's 0019 adds the chain's one growth-tolerant readback
     (`object_store_dispatch_dispatcher_identity_read_state_v1`), which does have a live caller
     (`local_authority_dispatcher_identity_provisioning`'s own live test, which self-installs the
     required 0002, 0003, 0007-0020 prefix plus all four then-current layer installs into its own
     dedicated database). Migration 0020 narrows that readback to the runtime authority and adds
     maintenance-only participant pre-enrollment plus runtime registration, canonical-record
     projection, concurrent-generation races, and exact foreign-key drift to the same live case.
     Separately (also grep-verified): `local_authority_put_spool_ready_mutation.rs` self-installs
     0002, 0003 and 0007 through 0017 -- the chain its own subject needs, which since CD-3 is a
     proper prefix of the install set rather than the whole of it, and
     `local_authority_dispatcher_identity_schema`'s own live test self-installs only 0002, 0007,
     and 0018 -- the minimal chain needed to exercise D8's per-participant ACTIVE-uniqueness index
     and the retained attempts foreign key without the 0019 readback. Only this step's
     (`local_install_chain_proof`) database receives 0018-0022 and the inert-state assertion.
  7. Pre-installs migrations 0002 and 0009 (only) into the `local_codec` database, matching
     `local_authority_canonical_codec.rs`'s own stated requirement -- it is the one live test
     that does not self-provision its schema. The other ten tests self-provision their roles
     (idempotently) and self-install their own required migration subset from their own
     `include_str!`'d copies, so their databases are handed over empty.
  8. Runs the eleven tests by exact name, serially, via
     `cargo test -p lore-object-dispatch --test <target> -- --ignored --exact <name>`.
  9. Parses each invocation's `running N tests` and `test result: ... P passed; F failed`
     lines. A test whose filter matched zero tests is reported NOT RUN, never as a pass.
  10. Tears down its own labelled container unless `-KeepOnFailure` is passed and a failure
      occurred.

Model: `run-retention-client-live.ps1`. That script's certificate/pg_hba plumbing does not
apply here (no TLS, no external-endpoint client-cert contract) and is intentionally not
reused; the run-id-labelled container, `Invoke-Checked`, the readiness loop waiting for two
"database system is ready to accept connections" log lines, and the label-guarded removal are.

Out of scope: `spool_verifier.rs`'s `linux_observation_is_descriptor_bound_exact_and_fail_closed`
is `#[cfg(target_os = "linux")]`-gated, so it does not compile into a Windows test binary at
all -- it is unenumerable here, not merely ignored, and `cargo test -- --ignored --list` on this
rig never lists it. This runner cannot detect it and does not attempt it; it is reported NOT RUN
from static knowledge of the source, not from anything this harness observed. The
retention-client live tier keeps its own runner unmodified.
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
$containerName = "wp114-local-authority-live-$runId"
$ownershipLabel = "com.tideshift.lore.local-authority-live=$runId"
$containerStarted = $false
$runPassed = $false

$tests = @(
    @{
        EnvVar   = 'LORE_TEST_LOCAL_CODEC_PG_URL'
        Target   = 'local_authority_canonical_codec'
        Name     = 'live_postgres_reserved_and_spool_ready_bytes_match_independent_rust_vectors'
        Database = 'local_codec'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_RESERVATION_SCHEMA_PG_URL'
        Target   = 'local_authority_put_reservation_schema'
        Name     = 'live_postgres_enforces_put_result_shape_time_ack_and_service_acl'
        Database = 'local_put_reservation_schema'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_RESERVATION_PROVISIONING_PG_URL'
        Target   = 'local_authority_put_reservation_provisioning'
        Name     = 'live_postgres_chain_install_replay_read_and_drift_fail_closed'
        Database = 'local_put_reservation_provisioning'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_RESERVATION_RECORD_CODEC_PG_URL'
        Target   = 'local_authority_put_reservation_record_codec'
        Name     = 'live_postgres_row_bytes_match_independent_vector_and_invalid_inputs_fail'
        Database = 'local_put_reservation_record_codec'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_RESERVE_PUT_MUTATION_PG_URL'
        Target   = 'local_authority_reserve_put_mutation'
        Name     = 'live_postgres_reserve_put_is_atomic_exact_and_replay_safe'
        Database = 'local_reserve_put_mutation'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_CODEC_PG_URL'
        Target   = 'local_authority_put_upload_progress_codec'
        Name     = 'live_postgres_progress_codec_is_exact_and_replay_safe'
        Database = 'local_put_upload_progress_codec'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_MUTATION_PG_URL'
        Target   = 'local_authority_put_upload_progress_mutation'
        Name     = 'live_postgres_progress_mutation_is_atomic_and_replay_safe'
        Database = 'local_put_upload_progress_mutation'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_SPOOL_READY_CODEC_PG_URL'
        Target   = 'local_authority_put_spool_ready_codec'
        Name     = 'live_postgres_ready_codec_is_exact_fail_closed_and_replay_safe'
        Database = 'local_put_spool_ready_codec'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_PUT_SPOOL_READY_MUTATION_PG_URL'
        Target   = 'local_authority_put_spool_ready_mutation'
        Name     = 'live_postgres_spool_ready_is_atomic_replay_safe_and_source_dark'
        Database = 'local_put_spool_ready_mutation'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_DISPATCHER_IDENTITY_SCHEMA_PG_URL'
        Target   = 'local_authority_dispatcher_identity_schema'
        Name     = 'live_postgres_dispatcher_identity_admits_concurrent_participants_and_retains_the_attempts_foreign_key'
        Database = 'local_dispatcher_identity_schema'
    },
    @{
        EnvVar   = 'LORE_TEST_LOCAL_DISPATCHER_IDENTITY_PROVISIONING_PG_URL'
        Target   = 'local_authority_dispatcher_identity_provisioning'
        Name     = 'live_postgres_dispatcher_identity_readback_authorizes_by_role_and_fails_closed_on_catalog_drift'
        Database = 'local_dispatcher_identity_provisioning'
    }
)

$installChainProofDatabase = 'local_install_chain_proof'
$databaseNames = @($tests | ForEach-Object { $_.Database }) + @($installChainProofDatabase)

# CR-033 D5's cell install set, shared with the classification check below so the two cannot
# drift apart.
$cd1InstallSetNumbers = @(2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)
$cd1KnownDeferredNumbers = @(4, 5, 6)

$environmentNames = @($tests | ForEach-Object { $_.EnvVar })
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

function Resolve-MigrationPath {
    param(
        [Parameter(Mandatory)]
        [int]$Number
    )

    $prefix = '{0:D4}_' -f $Number
    $paths = @(
        Get-ChildItem -LiteralPath (Join-Path $crateRoot 'migrations') -File |
            Where-Object { $_.Name.StartsWith($prefix, [StringComparison]::Ordinal) }
    )
    if ($paths.Count -ne 1) {
        throw "expected exactly one migration file for slot $prefix, found $($paths.Count)"
    }
    return $paths[0].FullName
}

function Install-MigrationToDatabase {
    param(
        [Parameter(Mandatory)]
        [string]$DatabaseName,
        [Parameter(Mandatory)]
        [string]$Path
    )

    Get-Content -Raw -LiteralPath $Path |
        & docker exec -i $containerName psql -v ON_ERROR_STOP=1 -U postgres -d $DatabaseName
    if ($LASTEXITCODE -ne 0) {
        throw "failed to install migration $Path into $DatabaseName"
    }
}

function Get-PgScalar {
    param(
        [Parameter(Mandatory)]
        [string]$DatabaseName,
        [Parameter(Mandatory)]
        [string]$Sql
    )

    $rawOutput = & docker exec $containerName psql -tA -v ON_ERROR_STOP=1 -U postgres -d $DatabaseName -c $Sql
    if ($LASTEXITCODE -ne 0) {
        throw "query against $DatabaseName failed: $Sql"
    }
    if ($null -eq $rawOutput) {
        return ''
    }
    return ($rawOutput | Out-String).Trim()
}

function Get-IgnoredTestCatalog {
    # Ground truth for what is actually ignored in this crate right now, not the README and not
    # this script's own hardcoded map. No infrastructure is needed for `--list`; run it before
    # touching Docker so a renamed/added/removed live test fails fast and cheaply.
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

function Assert-IgnoredTestCatalogMatchesKnownTests {
    param(
        [Parameter(Mandatory)]
        [array]$Tests
    )

    # The retention-client and cell-schema-install live tiers are the crate's other ignored tiers,
    # each with its own runner. Named here so a brand-new ignored test outside every known family is
    # caught, not silently accepted.
    $knownOtherIgnoredTests = @(
        # retention-client live tier -- run-retention-client-live.ps1
        'exact_maintenance_mtls_read_is_bounded_and_reconnects_after_response_stall',
        'transfer_retries_one_serialization_abort_then_applies_once',
        'transfer_retries_one_deadlock_abort_then_applies_once',
        'prune_lost_commit_response_adopts_exact_immutable_receipt_without_duplicate_mutation',
        # WP-114 CD-1 cell-schema installer/attester -- run-cell-schema-install-live.ps1
        'live_postgres_cell_schema_installs_clean_and_attests',
        'live_postgres_cell_schema_install_is_idempotent',
        'live_postgres_cell_schema_refuses_a_partial_install',
        'live_postgres_cell_schema_refuses_a_drifted_catalog',
        'live_postgres_cell_schema_revokes_service_privileges_after_replacement',
        'live_postgres_cell_schema_measure_catalog_manifest',
        # WP-114 CD-4 provider charge tier -- run-provider-charge-live.ps1
        'live_postgres_last_unit_charges_are_atomic_and_fail_closed',
        'live_postgres_frozen_revision_grammar_and_idempotent_publication_replay',
        'live_postgres_charge_refuses_a_non_serializable_caller',
        'live_postgres_successor_fence_and_stage3_publication_matrix',
        'live_postgres_expired_exact_publication_replays_but_charge_fails_closed',
        'live_postgres_missing_malformed_and_stage3_inconsistent_configs_fail_closed',
        'live_postgres_cd5_charge_before_send_conformance_and_authority_unavailable'
    )

    Write-Host 'Cross-checking the ignored-test catalog against this harness''s known live tests...'
    $catalog = Get-IgnoredTestCatalog

    foreach ($t in $Tests) {
        $found = @($catalog | Where-Object { $_.Target -eq $t.Target -and $_.Name -eq $t.Name })
        if ($found.Count -ne 1) {
            $message = "known live test $($t.Name) ($($t.Target)) was not found (or was found more than once) " +
            "in 'cargo test -p lore-object-dispatch -- --ignored --list'; it may have been renamed or moved"
            throw $message
        }
    }

    $localAuthorityCatalog = @($catalog | Where-Object { $_.Target -like 'local_authority_*' })
    $unknownLocalAuthority = @($localAuthorityCatalog | Where-Object {
            $candidate = $_
            -not @($Tests | Where-Object { $_.Target -eq $candidate.Target -and $_.Name -eq $candidate.Name })
        })
    if ($unknownLocalAuthority.Count -gt 0) {
        $descriptions = ($unknownLocalAuthority | ForEach-Object { "$($_.Name) ($($_.Target))" }) -join '; '
        $message = "found local_authority_* ignored test(s) unknown to this harness: $descriptions -- " +
        'update the harness''s test map (and provision its database) before trusting a green run'
        throw $message
    }

    $otherCatalog = @($catalog | Where-Object { $_.Target -notlike 'local_authority_*' })
    $unexpectedOther = @($otherCatalog | Where-Object { $knownOtherIgnoredTests -notcontains $_.Name })
    if ($unexpectedOther.Count -gt 0) {
        $descriptions = ($unexpectedOther | ForEach-Object { "$($_.Name) ($($_.Target))" }) -join '; '
        $message = "found unexpected ignored test(s) outside the local_authority_* family and the known " +
        "retention-client and cell-schema-install live tiers: $descriptions"
        throw $message
    }
    if ($otherCatalog.Count -ne $knownOtherIgnoredTests.Count) {
        $missing = @($knownOtherIgnoredTests | Where-Object { $name = $_; -not @($otherCatalog | Where-Object { $_.Name -eq $name }) })
        Write-Warning "the other live tiers' ignored-test count changed: expected $($knownOtherIgnoredTests.Count), found $($otherCatalog.Count) (missing: $($missing -join ', '))"
    }

    $catalogMessage = "Ignored-test catalog: $($catalog.Count) total ($($localAuthorityCatalog.Count) local_authority_* known, $($otherCatalog.Count) in the other known live tiers). " +
    "spool_verifier's Linux-only live test is #[cfg(target_os = 'linux')]-gated and does not compile " +
    'into this Windows binary at all, so it cannot appear in this catalog; it is NOT RUN by static ' +
    'knowledge of the source, not because this harness observed and skipped it.'
    Write-Host $catalogMessage
}

function Assert-NoCollidingContainer {
    # A container's `com.tideshift.lore.local-authority-live` label is only ever the run-id
    # suffix of its own name (see $ownershipLabel below), so it can prove self-consistency, never
    # ownership -- an outside observer cannot tell "mine" from "someone else's still-running
    # instance" from that label alone. Incident, 2026-08-28: a concurrent verification run and a
    # SIGPIPE-truncated invocation produced exactly one container carrying this label; it was
    # manually removed by exact name after only a self-consistency check, destroying an in-progress
    # run (four tests reported ConnectionRefused). This preflight turns that collision into one
    # legible error before any test runs, and the `.pid`/`.started` labels on the container this
    # run creates (below) give a later observer a real ownership test: check whether that pid is
    # still alive before ever assuming a labelled container is an orphan.
    $labelFormat = '{{.Names}}|||{{.Status}}|||{{.Label "com.tideshift.lore.local-authority-live.pid"}}' +
    '|||{{.Label "com.tideshift.lore.local-authority-live.started"}}'
    $existingRaw = & docker ps -a --filter 'label=com.tideshift.lore.local-authority-live' --format $labelFormat
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to check for a colliding local-authority-live container'
    }
    $existing = @($existingRaw | Where-Object { $_ -and $_.Trim().Length -gt 0 })
    if ($existing.Count -eq 0) {
        return
    }

    $rows = $existing | ForEach-Object {
        $fields = $_ -split '\|\|\|'
        $name = $fields[0]
        $status = if ($fields.Count -gt 1) { $fields[1] } else { '(unknown status)' }
        $ownerPid = if ($fields.Count -gt 2 -and $fields[2]) { $fields[2] } else { '(no pid label -- predates this guard)' }
        $started = if ($fields.Count -gt 3 -and $fields[3]) { $fields[3] } else { '(no started label -- predates this guard)' }
        "  - $name [$status] pid=$ownerPid started=$started"
    }
    $message = "found $($existing.Count) container(s) already carrying the " +
    "com.tideshift.lore.local-authority-live label:`n$($rows -join "`n")`n" +
    'Another run may be in progress, or these are orphans left by a killed/crashed run. Do not ' +
    'remove one on a hunch: on Windows, check `Get-Process -Id <pid>` (or `tasklist /FI "PID eq ' +
    '<pid>"`) for the pid label above -- only treat a container as an orphan if that pid is no ' +
    'longer running. A label alone (including this script''s own $ownershipLabel) only proves a ' +
    "container is self-consistent, never that it is yours or that its owner is dead."
    throw $message
}

function Assert-MigrationSetIsFullyClassified {
    param(
        [Parameter(Mandatory)]
        [int[]]$InstallSet,
        [Parameter(Mandatory)]
        [int[]]$KnownDeferred
    )

    # Resolve-MigrationPath already prevents a silent skip or duplicate within the install set
    # itself, and 0004-0006 cannot enter it since they are never in $InstallSet. What neither of
    # those catches is a brand-new migration file (e.g. a future 0018_*.sql) that is simply absent
    # from both lists -- it would be silently excluded from the install-chain proof rather than
    # flagged for classification. Every file on disk must be accounted for one way or the other.
    $classified = @($InstallSet) + @($KnownDeferred)
    $files = Get-ChildItem -LiteralPath (Join-Path $crateRoot 'migrations') -File
    $unclassified = @($files | Where-Object {
            $numberMatch = [regex]::Match($_.Name, '^(?<number>[0-9]{4})_')
            if (-not $numberMatch.Success) {
                return $true
            }
            $number = [int]$numberMatch.Groups['number'].Value
            $classified -notcontains $number
        })
    if ($unclassified.Count -gt 0) {
        $names = ($unclassified | ForEach-Object { $_.Name }) -join ', '
        $message = "found migration file(s) not classified as installed or known-deferred: $names -- " +
        "add the new migration's number to the install set (and this harness's test map, if it has " +
        'a live test) or to the known-deferred set before trusting this harness'
        throw $message
    }
}

try {
    Assert-IgnoredTestCatalogMatchesKnownTests -Tests $tests
    Assert-MigrationSetIsFullyClassified -InstallSet $cd1InstallSetNumbers -KnownDeferred $cd1KnownDeferredNumbers
    Assert-NoCollidingContainer

    # Set before the call, not after: `docker run --detach` can create the container and still
    # exit non-zero (port-bind failure, network programming error), in which case `Invoke-Checked`
    # throws. If $containerStarted were only set on a successful return, that throw would skip
    # teardown, and the labelled container it left behind would then hard-fail every subsequent
    # run's Assert-NoCollidingContainer preflight until someone cleaned it up by hand -- exactly
    # the kind of manual cleanup that caused the incident this preflight exists to prevent. Setting
    # it here means the teardown path owns the container from the moment creation is attempted,
    # even if the container object was never actually created (the `finally` block's own
    # `docker inspect` check then just reports nothing to remove).
    $containerStarted = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--label', "com.tideshift.lore.local-authority-live.pid=$PID",
        '--label', "com.tideshift.lore.local-authority-live.started=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))",
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

    # Cluster-wide roles, created once, idempotently. Every self-provisioning live test also
    # creates these itself with the same IF-NOT-EXISTS guard, so this is redundant for those
    # eight; it is a hard prerequisite for `local_codec`, which does not self-provision, and for
    # `local_install_chain_proof`'s migration install below (0004-0006's REVOKE statements name
    # these roles and would fail against a not-yet-existing role even though they are not
    # installed themselves).
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
    CREATE ROLE object_dispatch_retention_migrator NOLOGIN;
  END IF;
END
$$;
'@
    Invoke-Checked docker @(
        'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
        '-c', $roleSql
    )

    foreach ($databaseName in $databaseNames) {
        Invoke-Checked docker @(
            'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
            '-c', "CREATE DATABASE $databaseName;"
        )
        # Every migration begins with `SET LOCAL ROLE object_dispatch_retention_owner;`, which
        # drops the acting role's superuser bypass for the rest of that transaction, so the
        # owner role needs its own CREATE privilege on the database to run `CREATE SCHEMA ...
        # AUTHORIZATION object_dispatch_retention_owner`. The self-provisioning tests grant this
        # to themselves too; granting it here is redundant for those and required for the two
        # harness-installed databases below.
        Invoke-Checked docker @(
            'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres',
            '-c', "GRANT CREATE ON DATABASE $databaseName TO object_dispatch_retention_owner;"
        )
    }

    Write-Host "Installing the CD-1 cell install set (0002, 0003, 0007-0022) into $installChainProofDatabase..."
    foreach ($number in $cd1InstallSetNumbers) {
        Install-MigrationToDatabase -DatabaseName $installChainProofDatabase -Path (Resolve-MigrationPath -Number $number)
    }

    $retainedTableCount = Get-PgScalar -DatabaseName $installChainProofDatabase -Sql @'
SELECT count(*) FROM information_schema.tables
WHERE table_schema = 'object_store_retention'
  AND table_name IN (
    'object_dispatch_full_record_ownership',
    'object_dispatch_record_storage_counters',
    'object_dispatch_compact_receipts',
    'object_dispatch_compact_prune_watermark'
  );
'@
    if ($retainedTableCount -ne '4') {
        throw "expected 4 of the 5 tables 0002 creates to be present-but-inert, found $retainedTableCount"
    }

    $deferredProcedureCount = Get-PgScalar -DatabaseName $installChainProofDatabase -Sql @'
SELECT count(*) FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'object_store_retention'
  AND p.proname IN (
    'object_store_retention_read_transfer_v1',
    'object_store_retention_read_prune_v1',
    'object_store_retention_apply_transfer_v1',
    'object_store_retention_apply_prune_v1',
    'object_store_retention_read_prune_v2',
    'object_store_retention_apply_prune_v2'
  );
'@
    if ($deferredProcedureCount -ne '0') {
        throw "expected zero installed 0004-0006 procedures, found $deferredProcedureCount"
    }
    Write-Host "Install-chain proof: 0002, 0003, 0007-0022 installed cleanly; 4 of the 5 tables" `
        "0002 creates are present-but-inert; 0 deferred 0004-0006 procedures are installed."

    Write-Host "Pre-installing 0002 and 0009 into $($tests[0].Database) for the canonical-codec live test..."
    foreach ($number in @(2, 9)) {
        Install-MigrationToDatabase -DatabaseName $tests[0].Database -Path (Resolve-MigrationPath -Number $number)
    }

    foreach ($t in $tests) {
        [Environment]::SetEnvironmentVariable(
            $t.EnvVar,
            "postgresql://postgres@localhost:$port/$($t.Database)",
            'Process'
        )
    }

    $results = @()
    Push-Location $loreRoot
    try {
        foreach ($t in $tests) {
            Write-Host "Running $($t.Name) ($($t.Target))..."
            $cargoArgs = @(
                'test', '-p', 'lore-object-dispatch', '--test', $t.Target, '--',
                '--ignored', '--exact', $t.Name, '--test-threads=1'
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
                Target = $t.Target
                Status = $status
                Passed = $passed
                Failed = $failed
                Ran    = $ran
            }

            if ($status -eq 'PASS') {
                Write-Host "  PASS"
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

    # Assert what this is meant to prove: that all eleven actually reported PASS, not merely that
    # the (fixed-size) $tests map produced eleven result rows -- a count check against $results
    # would only ever catch $tests itself being resized, which is not an execution guarantee.
    # $ran -ne 1 above is what actually proves each test executed for real rather than matching
    # nothing under --exact.
    $passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failures = @($results | Where-Object { $_.Status -ne 'PASS' })
    if ($passCount -ne 11) {
        Write-Warning "$passCount of 11 local-authority live tests passed; $($failures.Count) did not:"
        foreach ($failure in $failures) {
            Write-Warning "  $($failure.Test): $($failure.Status)"
        }
    }
    else {
        $runPassed = $true
        Write-Host "All 11 local-authority live tests passed."
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], 'Process')
    }

    if ($containerStarted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabelRaw = & docker inspect --format "{{ index .Config.Labels `"com.tideshift.lore.local-authority-live`" }}" $containerName 2>$null
        $inspectExitCode = $LASTEXITCODE
        $actualLabel = if ($null -ne $actualLabelRaw) { ($actualLabelRaw | Out-String).Trim() } else { '' }
        if ($inspectExitCode -eq 0 -and $actualLabel -eq $runId) {
            # --volumes: postgres:16 declares VOLUME /var/lib/postgresql/data, so a plain
            # `docker rm --force` leaves an anonymous, now-unreferenced volume behind every run.
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
