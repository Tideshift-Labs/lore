# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs the Unix-gated write-behind tiers of `lore-postgres` inside a disposable Linux container.

.DESCRIPTION
`lore-postgres/src/store/write_behind` is Unix-only by owner ruling (2026-09-16):
`WriteBehindStage::open` returns `WriteBehindError::UnsupportedPlatform` off Unix. Three test
surfaces are therefore `#![cfg(unix)]`/`#[cfg(all(test, unix))]` and are SILENTLY ABSENT on the
Windows dev rig -- a `cfg` gate absents a test rather than failing it, so a Windows run reports
zero tests, not a failure:

  * `tests/write_behind_stage.rs`          -- 10 offline cases, whole file `#![cfg(unix)]`.
  * `tests/write_behind_staging_lifecycle.rs` -- 4 `#[ignore]` live-Postgres cases, whole file
    `#![cfg(unix)]`. `run-fragment-lifecycle-live.ps1` only adds this target to its inventory
    when the HOST is Unix, so on Windows that runner is green with the target never enumerated.
  * The `lore-postgres` LIB target's 5 Unix-only cases -- `write_behind::root::durability_tests`
    (4, offline) plus `store::immutable_store::tests::first_put_staged_call_returns_exact_readable_witness_without_retry`
    (1, `#[ignore]`, live).

  * The `lore-server` LIB target's Unix-only write-behind case --
    `plugins::postgres::tests::the_same_write_behind_block_is_accepted_on_unix`, paired with a
    differently-named `cfg(not(unix))` twin. This runner was scoped `-p lore-postgres` until
    2026-09-19, so that arm sat outside it and had never been compiled on this rig. NOTE the
    count differential CANNOT detect this one: the `lore-server` lib catalog is IDENTICAL on both
    platforms, because each platform drops one case and gains the other. The discriminating
    evidence is name presence, which is what this runner now pins.

This runner executes all of them on Linux and reports ENUMERATED COUNTS, not just exit codes.

.NOTES
Isolation, and why each piece is the way it is:

  * The working tree is ROBOCOPIED to a scratch directory and the copy is bind-mounted, never
    the live checkout. `lore-proto`'s build script writes generated output back into its own
    SOURCE directory, so a read-only mount fails the build outright and a read-write mount would
    put a container process inside a checkout sibling lanes are mid-edit on.
  * `CARGO_TARGET_DIR` and `CARGO_HOME` point at NAMED DOCKER VOLUMES, never the bind mount, so
    a Linux build can never write into (or share) the Windows `target/`. The volumes persist
    between runs, which is what makes a second run incremental.
  * One long-lived container (`sleep infinity`) driven by `docker exec`, so enumeration, the
    offline targets and the live cases share one warm build without re-entering `docker run`.
  * The live cases get their own `postgres:16` container on a per-run bridge network, with one
    throwaway database per case -- the same shape `run-fragment-lifecycle-live.ps1` uses.

Exit code: 0 when every pinned case passed, 1 otherwise (including setup failure). Never 2 --
the aggregate runner classifies 2 as `fail` for a required tier anyway, and this tier is
required: a box that cannot reach a Linux Docker engine has not run these tests.

Cleanup checks the run label AND the owning PowerShell process id before removing anything.

`-IncludeCompileFail` -- WHAT THESE TARGETS ACTUALLY ARE, and the one command they need.

`lore-fragment-provider`'s `direct_put_compile_fail` and `drain_capability_compile_fail` are NOT
trybuild targets. There is no trybuild dependency and no trybuild scratch directory anywhere in
this workspace. Each is a plain `#[test]` that SHELLS OUT to

  cargo check --offline --quiet --manifest-path
      lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml --bin <name>

and asserts on the resulting rustc diagnostic. That fixture is a SEPARATE CRATE with its OWN
CHECKED-IN `Cargo.lock`, outside the workspace and resolved independently of it.

That is the whole mechanism, and it is why three earlier attempts concluded this was unfixable:
they warmed the WORKSPACE registry (a cold-vs-warm `$cargoVolume` question) and read the
resulting "attempting to make an HTTP request, but --offline was specified" as a cache-warmth
problem. Warming the workspace registry can NEVER satisfy a lockfile naming versions the
workspace never resolves -- `aho-corasick v1.1.5` and `anyhow` were symptoms of a DIFFERENT
dependency graph, not of a cold cache. No amount of workspace building fixes it.

The fix is one network-enabled, FIXTURE-SCOPED prefetch before the targets run:

  cargo fetch --manifest-path
      lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml

`cargo fetch` honours that manifest's own `Cargo.lock`, so it populates `$CARGO_HOME` with
exactly the versions the nested `--offline` check will ask for. The block below runs it. With it,
both targets pass in this container; measured 2026-09-18 in `rust:slim-trixie` against a clean
`git archive` of `d34386e0` -- `direct_put_compile_fail` 1 passed / 0 failed / 0 ignored and
`drain_capability_compile_fail` 1 passed / 0 failed / 0 ignored, exit 0.

They remain opt-in and NON-GATING: they belong to a different crate, neither touches the
Unix-gated staging code this runner exists for, and the prefetch needs network, which this
runner does not otherwise require.
#>

[CmdletBinding()]
param(
    [switch]$KeepOnFailure,
    [switch]$SkipLive,
    [switch]$IncludeCompileFail,
    [switch]$Clippy
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$shortId = $runId.Substring(0, 12)
$labelName = 'com.tideshift.lore.write-behind-linux'
$buildContainer = "wb-linux-build-$shortId"
$pgContainer = "wb-linux-pg-$shortId"
$networkName = "wb-linux-net-$shortId"
$targetVolume = 'lore-write-behind-linux-target'
$cargoVolume = 'lore-write-behind-linux-cargo'
$scratchRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lore-write-behind-linux-$shortId"
$sourceCopy = Join-Path $scratchRoot 'lore'
$imageContext = Join-Path $scratchRoot 'image'

$createdContainers = [System.Collections.Generic.List[string]]::new()
$createdNetwork = $false
$setupError = $null
$runPassed = $false

# Reported beside the Linux number so a reader sees the DELTA the platform gate causes, not just
# a green count. Measured on this rig 2026-09-18 with `cargo test -p lore-postgres --lib -- --list`
# against the SAME working tree the Linux run copied: Windows 190, Linux 195 -- exactly the five
# Unix-only cases pinned below. This constant is a REPORTING aid and deliberately gates nothing:
# it goes stale the moment a lib case is added on either platform, whereas the per-name pins in
# $libUnixOnlyOffline/$libUnixOnlyLive stay true. (The 187/192 pair in WP-115's worklog is the
# same delta measured before a sibling lane added three more lib cases.)
$windowsLibEnumerated = 190

# Offline (non-`#[ignore]`) Unix-only targets. These are NOT pinned case-by-case, and that is a
# deliberate difference from `run-fragment-lifecycle-live.ps1`: there, every case is `#[ignore]`,
# so a case absent from the inventory is silently NOT RUN and an exact name list is the only
# defence. Here `cargo test --test <target>` runs everything the target enumerates, so no case
# can hide -- the only failure mode is the whole target vanishing behind its `cfg` gate. So the
# pin is a FLOOR on the enumerated count plus "every enumerated case ran, and none was ignored",
# which survives a sibling lane renaming or adding a case without going stale the same day.
$offlineInventory = @(
    [pscustomobject]@{
        Kind         = 'test'
        Target       = 'write_behind_stage'
        # 10 cases at the time this runner was written (2026-09-18); a sibling lane was adding an
        # 11th in the working tree. A drop BELOW this floor means the platform gate, a deleted
        # case, or a filtered-to-zero run -- all of which must fail loudly.
        MinimumCases = 10
    }
)

# Unix-only LIB cases. Pinned by SUFFIX so a module-path move does not silently drop the pin,
# and asserted present-exactly-once in the Linux catalog: this is the direct evidence that the
# Linux run contained what the Windows run cannot contain.
$libUnixOnlyOffline = @(
    'durability_tests::open_syncs_root_after_provisioning_both_top_level_directories',
    'durability_tests::root_fsync_failure_refuses_open',
    'durability_tests::each_writer_syncs_both_ancestors_even_when_creator_has_not_synced_them',
    'durability_tests::existing_fanout_parent_fsync_failure_refuses_the_second_writer'
)
$libUnixOnlyLive = @(
    'store::immutable_store::tests::first_put_staged_call_returns_exact_readable_witness_without_retry'
)

# `#[ignore]` + Unix + live Postgres. Nothing has ever executed this target, on any platform.
$liveInventory = @(
    [pscustomobject]@{
        Kind   = 'test'
        Target = 'write_behind_staging_lifecycle'
        Exact  = $true
        Cases  = @(
            'staged_commit_then_witness_capture_through_the_put_staged_sequence',
            'crash_between_finalize_and_commit_staged_orphans_the_file_and_retry_gets_a_fresh_epoch',
            'crash_between_commit_staged_and_association_recovers_with_exactly_one_file',
            'first_attempt_captures_staged_authority_and_binds_the_association'
        )
    }
)

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Case,
        [Parameter(Mandatory)][string]$Status,
        # ENUMERATED and PASSED are separate columns on purpose. Two lanes reported this same
        # tree accurately on 2026-09-18 and appeared to disagree (192 vs 188) purely because one
        # counted the catalog and the other counted passes. A harness that prints one number
        # invites exactly that, and here the catalog size is the load-bearing figure: it is what
        # a `cfg` gate silently takes away.
        [int]$Enumerated = 0,
        [int]$Ran = 0,
        [int]$Passed = 0,
        [int]$Failed = 0,
        [string]$Note = '',
        # A row that is REPORTED but does not decide the exit code. Used for the opt-in
        # best-effort rows, and for anything `-SkipLive` deliberately did not run, so the
        # gating set is a property of the row rather than a string match on its note.
        [switch]$NonGating
    )
    $results.Add([pscustomobject]@{
            Target     = $Target
            Case       = $Case
            Status     = $Status
            Enumerated = $Enumerated
            Ran        = $Ran
            Passed     = $Passed
            Failed     = $Failed
            Gating     = -not $NonGating
            Note       = $Note
        })
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($ArgumentList -join ' ') exited with code $LASTEXITCODE"
    }
}

# Native tools write progress to stderr; PowerShell promotes redirected stderr to ErrorRecords.
# The native exit code stays the authority.
function Invoke-Captured {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    $priorErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @ArgumentList 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorAction
    }
    return [pscustomobject]@{ Output = $output; ExitCode = $exitCode }
}

function Invoke-InContainer {
    param(
        [Parameter(Mandatory)][string[]]$Command,
        [string[]]$EnvironmentPairs = @()
    )
    $arguments = @('exec', '--workdir', '/src')
    foreach ($pair in $EnvironmentPairs) { $arguments += @('--env', $pair) }
    $arguments += @($buildContainer) + $Command
    return Invoke-Captured docker $arguments
}

function Get-Catalog {
    param(
        [Parameter(Mandatory)][ValidateSet('lib', 'test')][string]$Kind,
        [string]$Target,
        [string]$Package = 'lore-postgres',
        [switch]$IgnoredOnly
    )
    $targetArgs = if ($Kind -eq 'lib') { @('--lib') } else { @('--test', $Target) }
    $command = @('cargo', 'test', '-p', $Package) + $targetArgs + @('--')
    if ($IgnoredOnly) { $command += '--ignored' }
    $command += '--list'
    $run = Invoke-InContainer -Command $command
    if ($run.ExitCode -ne 0) {
        throw "catalog for $Package/$Kind`:$Target failed:`n$($run.Output)"
    }
    return @(
        foreach ($line in ($run.Output -split "`r?`n")) {
            $match = [regex]::Match($line, '^(?<name>[A-Za-z0-9_:]+): test$')
            if ($match.Success) { $match.Groups['name'].Value }
        }
    )
}

function Read-TestCounts {
    param([Parameter(Mandatory)][string]$Output)
    $ran = 0; $passed = 0; $failed = 0; $ignored = 0
    $runningMatch = [regex]::Match($Output, 'running (\d+) tests?')
    if ($runningMatch.Success) { $ran = [int]$runningMatch.Groups[1].Value }
    $resultMatch = [regex]::Match(
        $Output,
        'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored'
    )
    if ($resultMatch.Success) {
        $passed = [int]$resultMatch.Groups[1].Value
        $failed = [int]$resultMatch.Groups[2].Value
        $ignored = [int]$resultMatch.Groups[3].Value
    }
    return [pscustomobject]@{ Ran = $ran; Passed = $passed; Failed = $failed; Ignored = $ignored }
}

try {
    # ---- preconditions -------------------------------------------------------------------
    $osType = (& docker info --format '{{.OSType}}' 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $osType -ne 'linux') {
        throw "a Linux Docker engine is required; 'docker info' reported OSType='$osType'"
    }

    $collisionsRaw = & docker ps --all --filter "label=$labelName" --format '{{.Names}}|{{.Status}}'
    if ($LASTEXITCODE -ne 0) { throw 'failed to inspect existing write-behind Linux containers' }
    $collisions = @($collisionsRaw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($collisions.Count -ne 0) {
        throw "another write-behind Linux container exists; refusing to overlap:`n$($collisions -join "`n")"
    }

    # The copy carries UNCOMMITTED files (that is the point during a multi-lane run), so the
    # HEAD alone does not identify what ran. Print both, and say plainly when the tree was dirty:
    # a reader comparing these counts against another lane's needs to know whether the two ran
    # the same bytes.
    $headSha = (& git -C $loreRoot rev-parse HEAD 2>$null | Out-String).Trim()
    $dirtyCount = @(& git -C $loreRoot status --porcelain 2>$null | Where-Object { $_ }).Count
    $treeLabel = if ($dirtyCount -eq 0) { "$headSha (clean tree)" } else { "$headSha + $dirtyCount uncommitted path(s)" }
    Write-Host "Tree under test: $treeLabel"
    $global:LASTEXITCODE = 0

    # ---- isolated source copy ------------------------------------------------------------
    New-Item -ItemType Directory -Path $sourceCopy -Force | Out-Null
    New-Item -ItemType Directory -Path $imageContext -Force | Out-Null
    # /E all subdirectories, /XD the disk-hungry target/ and .git/. The copy still carries every
    # UNCOMMITTED file, which is the interesting state during a multi-lane run.
    # /XJ excludes junctions and symlinks. There are none under `lore` today, and because robocopy
    # materialises a junction's CONTENTS rather than a link, the scratch copy could not have let
    # cleanup escape into another tree either -- so this is a COST guard, not a safety one: without
    # it a junction appearing later (a `node_modules` link, a worktree) would be copied wholesale.
    & robocopy $loreRoot $sourceCopy /E /XJ /XD target .git /NFL /NDL /NJH /NJS /NP /R:1 /W:1 | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy of the working tree failed with code $LASTEXITCODE" }
    $global:LASTEXITCODE = 0

    # ---- toolchain image -----------------------------------------------------------------
    # Same base as lore-server/Dockerfile. protobuf-compiler is required: lore-proto's
    # prost/tonic build script shells out to protoc. `libprotobuf-dev` is required TOO and is
    # NOT implied by it on Debian trixie: the well-known types (google/protobuf/timestamp.proto,
    # imported by lock.proto) ship in that package's /usr/include, and without it the build fails
    # at `protoc failed: google/protobuf/timestamp.proto: File not found` (measured 2026-09-18).
    $dockerfile = @(
        'FROM rust:slim-trixie',
        'RUN apt-get update && apt-get install -y --no-install-recommends build-essential protobuf-compiler libprotobuf-dev pkg-config && rm -rf /var/lib/apt/lists/*',
        # `rust:slim-*` ships no clippy component, so `-Clippy` fails with "'cargo-clippy' is not
        # installed for the toolchain" unless it is added here (measured 2026-09-18).
        'RUN rustup component add clippy'
    ) -join "`n"
    Set-Content -Path (Join-Path $imageContext 'Dockerfile') -Value $dockerfile -NoNewline
    $imageTag = 'lore-write-behind-linux:3'
    & docker image inspect $imageTag *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Building $imageTag ..."
        Invoke-Checked docker @('build', '--tag', $imageTag, $imageContext)
    }
    $global:LASTEXITCODE = 0

    Invoke-Checked docker @('volume', 'create', $targetVolume)
    Invoke-Checked docker @('volume', 'create', $cargoVolume)

    Invoke-Checked docker @('network', 'create', $networkName)
    $createdNetwork = $true

    # ---- build container -----------------------------------------------------------------
    Invoke-Checked docker @(
        'run', '--detach', '--name', $buildContainer,
        '--label', "$labelName=$runId",
        '--label', "$labelName.pid=$PID",
        '--network', $networkName,
        '--volume', "$($sourceCopy):/src",
        '--volume', "$($targetVolume):/cargo-target",
        '--volume', "$($cargoVolume):/cargo-home",
        '--env', 'CARGO_TARGET_DIR=/cargo-target',
        '--env', 'CARGO_HOME=/cargo-home',
        '--workdir', '/src',
        $imageTag, 'sleep', 'infinity'
    )
    $createdContainers.Add($buildContainer)

    # ---- enumeration ---------------------------------------------------------------------
    Write-Host 'Enumerating catalogs (cold build; this compiles the dependency graph) ...'
    $libCatalog = @(Get-Catalog -Kind 'lib')
    $libIgnored = @(Get-Catalog -Kind 'lib' -IgnoredOnly)
    Write-Host "lore-postgres lib: Linux enumerates $($libCatalog.Count) (Windows baseline $windowsLibEnumerated), of which $($libIgnored.Count) are #[ignore]."

    foreach ($suffix in ($libUnixOnlyOffline + $libUnixOnlyLive)) {
        $matched = @($libCatalog | Where-Object { $_ -eq $suffix -or $_.EndsWith(":$suffix") })
        if ($matched.Count -ne 1) {
            throw "lib catalog must contain the Unix-only case '$suffix' exactly once; found $($matched.Count)"
        }
    }

    foreach ($target in $offlineInventory) {
        $catalog = @(Get-Catalog -Kind $target.Kind -Target $target.Target)
        if ($catalog.Count -lt $target.MinimumCases) {
            throw ("$($target.Target) enumerated $($catalog.Count) cases, below its floor of " +
                "$($target.MinimumCases). On a non-Unix host this target enumerates ZERO.")
        }
        $ignoredCatalog = @(Get-Catalog -Kind $target.Kind -Target $target.Target -IgnoredOnly)
        if ($ignoredCatalog.Count -ne 0) {
            throw ("$($target.Target) gained #[ignore] cases this runner does not opt into, so " +
                "they would be silently NOT RUN: [$($ignoredCatalog -join ', ')]")
        }
        $target | Add-Member -NotePropertyName Enumerated -NotePropertyValue $catalog.Count -Force
        Write-Host "$($target.Target): enumerates $($catalog.Count) cases (floor $($target.MinimumCases))."
    }

    foreach ($target in $liveInventory) {
        $catalog = @(Get-Catalog -Kind $target.Kind -Target $target.Target)
        $missing = @($target.Cases | Where-Object { $_ -notin $catalog })
        if ($missing.Count -ne 0) {
            throw "$($target.Target) is missing pinned cases: [$($missing -join ', ')]"
        }
        if ($target.Exact) {
            $unexpected = @($catalog | Where-Object { $_ -notin $target.Cases })
            if ($catalog.Count -ne $target.Cases.Count -or $unexpected.Count -ne 0) {
                throw ("$($target.Target) must hold exactly $($target.Cases.Count) cases; catalog " +
                    "has $($catalog.Count). Unexpected=[$($unexpected -join ', ')]")
            }
        }
    }

    # ---- offline targets -----------------------------------------------------------------
    foreach ($target in $offlineInventory) {
        Write-Host "Running lore-postgres --test $($target.Target) ..."
        $run = Invoke-InContainer -Command @(
            'cargo', 'test', '-p', 'lore-postgres', '--test', $target.Target,
            '--', '--test-threads=1'
        )
        $counts = Read-TestCounts -Output $run.Output
        $status = if ($run.ExitCode -eq 0 -and $counts.Ran -eq $target.Enumerated -and
            $counts.Passed -eq $target.Enumerated -and $counts.Failed -eq 0) { 'PASS' } else { 'FAIL' }
        Add-Result -Target $target.Target -Case '(whole target)' -Status $status `
            -Enumerated $target.Enumerated -Ran $counts.Ran -Passed $counts.Passed -Failed $counts.Failed `
            -Note "floor $($target.MinimumCases)"
        if ($status -ne 'PASS') { Write-Warning "  FAIL`n$($run.Output)" } else { Write-Host "  PASS ($($counts.Passed)/$($target.Enumerated))" }
    }

    # The lib target's non-ignored cases, which is where durability_tests lives.
    Write-Host 'Running lore-postgres --lib ...'
    $libRun = Invoke-InContainer -Command @('cargo', 'test', '-p', 'lore-postgres', '--lib')
    $libCounts = Read-TestCounts -Output $libRun.Output
    # The enumerated count is GATING here, not decoration. Without the `Ran -eq $libCatalog.Count`
    # term a single passing case satisfied `Passed -gt 0` and the row still PRINTED
    # `Enumerated=195` beside it -- the exact shape of green-for-work-not-run this runner exists
    # to stop. RAN is the honest partner for ENUMERATED, not PASSED: `--list` enumerates the
    # `#[ignore]` cases too and libtest counts them in `running N tests`, so with 3 ignored cases
    # `Passed -eq $libCatalog.Count` would be red on a perfectly good run, while
    # `Ran -eq $libCatalog.Count` says exactly what is wanted -- every enumerated case was
    # accounted for (passed, failed or ignored), nothing was filtered away.
    $libStatus = if ($libRun.ExitCode -eq 0 -and $libCounts.Failed -eq 0 -and $libCounts.Passed -gt 0 -and
        $libCounts.Ran -eq $libCatalog.Count) { 'PASS' } else { 'FAIL' }
    Add-Result -Target 'lib' -Case '(non-ignored)' -Status $libStatus `
        -Enumerated $libCatalog.Count -Ran $libCounts.Ran -Passed $libCounts.Passed -Failed $libCounts.Failed `
        -Note "Windows enumerates $windowsLibEnumerated for the same tree; $($libCounts.Ignored) ignored"
    if ($libStatus -ne 'PASS') { Write-Warning "  FAIL`n$($libRun.Output)" } else { Write-Host "  PASS ($($libCounts.Passed) passed, $($libCounts.Ignored) ignored)" }

    # ---- lore-server's Unix arm ------------------------------------------------------------
    # This runner was scoped `-p lore-postgres`, so `lore-server`'s own Unix-gated case sat
    # outside it and `the_same_write_behind_block_is_accepted_on_unix` had never been compiled on
    # this rig until it was run by hand on 2026-09-19. The gap is invisible to a count
    # differential -- the catalog was 1,842 on BOTH platforms, measured 2026-09-19 -- because the two
    # arms are a `cfg(unix)`/`cfg(not(unix))` PAIR with DIFFERENT NAMES: each platform drops one
    # case and gains the other, so the total never moves. The only evidence that discriminates is
    # "was this exact name in the catalog", which is what the pin below asserts.
    Write-Host 'Enumerating lore-server lib ...'
    $serverCatalog = @(Get-Catalog -Kind 'lib' -Package 'lore-server')
    $serverUnixOnly = 'plugins::postgres::tests::the_same_write_behind_block_is_accepted_on_unix'
    $serverNonUnixOnly = 'plugins::postgres::tests::an_otherwise_valid_write_behind_block_is_refused_at_boot_off_unix'
    foreach ($suffix in @($serverUnixOnly)) {
        $matched = @($serverCatalog | Where-Object { $_ -eq $suffix -or $_.EndsWith(":$suffix") })
        if ($matched.Count -ne 1) {
            throw "lore-server lib catalog must contain the Unix-only case '$suffix' exactly once; found $($matched.Count)"
        }
    }
    # The negative half, and it is not decoration: it is what proves the positive pin above
    # measured the PLATFORM rather than a case that happens to exist everywhere. If the
    # `cfg(not(unix))` twin were also present here, the pair would not be a pair.
    $nonUnixPresent = @($serverCatalog | Where-Object { $_ -eq $serverNonUnixOnly -or $_.EndsWith(":$serverNonUnixOnly") })
    if ($nonUnixPresent.Count -ne 0) {
        throw "the cfg(not(unix)) twin '$serverNonUnixOnly' must be ABSENT from a Linux catalog; found $($nonUnixPresent.Count)"
    }
    Write-Host "lore-server lib: Linux enumerates $($serverCatalog.Count); the Unix-only case is present and its non-Unix twin is absent."

    Write-Host 'Running lore-server --lib ...'
    $serverRun = Invoke-InContainer -Command @('cargo', 'test', '-p', 'lore-server', '--lib')
    $serverCounts = Read-TestCounts -Output $serverRun.Output
    # `Ran -eq $serverCatalog.Count` for the same reason the `lore-postgres` lib row uses it: it
    # accounts for every enumerated case (passed, failed or ignored) and so catches a
    # filtered-to-zero run that an exit code alone would call green.
    $serverStatus = if ($serverRun.ExitCode -eq 0 -and $serverCounts.Failed -eq 0 -and
        $serverCounts.Passed -gt 0 -and $serverCounts.Ran -eq $serverCatalog.Count) { 'PASS' } else { 'FAIL' }
    Add-Result -Target 'lore-server lib' -Case '(non-ignored)' -Status $serverStatus `
        -Enumerated $serverCatalog.Count -Ran $serverCounts.Ran -Passed $serverCounts.Passed `
        -Failed $serverCounts.Failed `
        -Note "carries the cfg(unix) write-behind arm; $($serverCounts.Ignored) ignored"
    if ($serverStatus -ne 'PASS') { Write-Warning "  FAIL`n$($serverRun.Output)" } else { Write-Host "  PASS ($($serverCounts.Passed) passed, $($serverCounts.Ignored) ignored)" }

    if ($IncludeCompileFail) {
        # Best-effort, and in a DIFFERENT crate: both compile-fail targets belong to
        # `lore-fragment-provider`, not `lore-postgres`.
        #
        # Neither is a trybuild target (see the header). Each shells out to
        # `cargo check --offline --manifest-path <fixture>/Cargo.toml`, and that fixture crate
        # carries its OWN `Cargo.lock` resolved independently of this workspace. So the deps that
        # nested check needs are ones NO workspace build ever downloads, warm volume or not. The
        # only thing that puts them in `$CARGO_HOME` is a fetch scoped to that manifest, which is
        # what this does. It needs NETWORK; nothing else in this runner does.
        $fixtureManifest = 'lore-object-dispatch/tests/compile_fail/get_only_rejects_metered/Cargo.toml'
        Write-Host "Prefetching the compile-fail fixture crate's own lockfile ($fixtureManifest) ..."
        $fetchRun = Invoke-InContainer -Command @('cargo', 'fetch', '--manifest-path', $fixtureManifest)
        if ($fetchRun.ExitCode -ne 0) {
            # Reported, not fatal: this whole block is non-gating, and a failed prefetch turns
            # into two honest FAIL rows below rather than aborting the Unix-gated tiers that are
            # the point of the runner.
            Write-Warning "fixture prefetch failed (exit $($fetchRun.ExitCode)); the compile-fail rows below will fail offline:`n$($fetchRun.Output)"
        }
        foreach ($target in @('direct_put_compile_fail', 'drain_capability_compile_fail')) {
            Write-Host "Running lore-fragment-provider --test $target (best effort) ..."
            $run = Invoke-InContainer -Command @('cargo', 'test', '-p', 'lore-fragment-provider', '--test', $target)
            $counts = Read-TestCounts -Output $run.Output
            # Each target holds exactly one `#[test]`. Exit code alone would call a
            # filtered-to-zero run green, so require the case to have actually run and passed.
            $status = if ($run.ExitCode -eq 0 -and $counts.Ran -eq 1 -and $counts.Passed -eq 1 -and
                $counts.Failed -eq 0) { 'PASS' } elseif ($counts.Ran -eq 1) { 'FAIL' } else { 'NOT RUN' }
            Add-Result -Target $target -Case '(whole target)' -Status $status `
                -Enumerated 1 -Ran $counts.Ran -Passed $counts.Passed -Failed $counts.Failed `
                -Note 'opt-in, needs network for the fixture prefetch; reported, does not gate' -NonGating
            if ($status -eq 'PASS') { Write-Host "  PASS (1/1)" } else { Write-Warning "  $status`n$($run.Output)" }
        }
    }

    if ($Clippy) {
        # The `cfg(unix)` blind spot is a LINT gap as well as a test gap: `cargo clippy` on the
        # Windows rig never lints `write_behind/root.rs`'s Unix arm at all, so findings there are
        # invisible until someone runs clippy on Linux. This step closes that.
        #
        # REPORTED, NOT GATING, and off by default -- deliberately. As of 22361e11 the Unix arm
        # carries pre-existing findings that belong to the write-behind lane, not to this runner,
        # and this runner changes no Rust source. Making it gate today would turn a REGISTERED
        # required tier red for someone else's backlog; leaving it silent would repeat the exact
        # mistake this runner exists to fix. Flip `-NonGating` off once the Unix arm is clean.
        # Measured again 2026-09-18 at b86d3083: the Unix arm now reports ZERO span lines, so the
        # backlog this deferral was written for looks cleared -- confirm on the write-behind lane's
        # own tree before flipping, since this runner changes no Rust source and cannot keep it so.
        # Read the per-FILE breakdown, not the total. Measured 2026-09-18 at 0188a6bb: a blanket
        # `-D warnings` over this crate in the container reports 129 findings, and the large
        # majority are in files the Windows rig lints perfectly well (coordinator.rs, 33;
        # maintenance.rs, 23) -- i.e. they are a container-vs-rig TOOLCHAIN VERSION difference,
        # not a platform blind spot. The signal is the handful in the Unix-gated module, which
        # no Windows clippy run can ever emit. Report both, and never let the total gate.
        Write-Host 'Running cargo clippy -p lore-postgres --all-targets (Linux, reported only) ...'
        $rustcVersion = (Invoke-InContainer -Command @('rustc', '--version')).Output.Trim()
        $clippyRun = Invoke-InContainer -Command @(
            'cargo', 'clippy', '-p', 'lore-postgres', '--all-targets', '--no-deps', '-j4', '--', '-D', 'warnings'
        )
        # These are `-->` SPAN LINES, not findings: one finding with a primary span plus a
        # `note:`/`help:` span contributes several. Counting distinct findings from the human
        # renderer is not reliably possible (`--message-format=json` would be, at the cost of a
        # second parse this non-gating step does not earn), so the column is NAMED for what it
        # actually counts. Zero span lines in a file still means zero findings in it, which is all
        # the Unix-gated check below asserts.
        $spanLines = @(
            foreach ($line in ($clippyRun.Output -split "`r?`n")) {
                $match = [regex]::Match($line, '^\s*-->\s*(?<file>[^:]+):')
                if ($match.Success) { $match.Groups['file'].Value }
            }
        )
        $unixGated = @($spanLines | Where-Object { $_ -like '*store/write_behind/*' })
        Write-Host "  toolchain in container: $rustcVersion"
        Write-Host "  span lines by file (upper bound on findings, not a finding count):"
        $spanLines | Group-Object | Sort-Object Count -Descending |
            ForEach-Object { Write-Host "    $($_.Count)`t$($_.Name)" }
        Add-Result -Target 'clippy' -Case 'store/write_behind (Unix-gated)' `
            -Status $(if ($unixGated.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
            -Note "$($unixGated.Count) span line(s) the Windows rig can never emit; $($spanLines.Count) span lines crate-wide, mostly toolchain-version noise. Span lines over-count findings. Reported, does not gate." `
            -NonGating
    }

    # ---- live cases ----------------------------------------------------------------------
    if ($SkipLive) {
        foreach ($target in $liveInventory) {
            foreach ($case in $target.Cases) {
                Add-Result -Target $target.Target -Case $case -Status 'NOT RUN' -Note '-SkipLive' -NonGating
            }
        }
        foreach ($case in $libUnixOnlyLive) {
            Add-Result -Target 'lib' -Case $case -Status 'NOT RUN' -Note '-SkipLive' -NonGating
        }
    }
    else {
        Invoke-Checked docker @(
            'run', '--detach', '--name', $pgContainer,
            '--label', "$labelName=$runId",
            '--label', "$labelName.pid=$PID",
            '--network', $networkName,
            '--network-alias', 'wb-postgres',
            '--env', 'POSTGRES_HOST_AUTH_METHOD=trust',
            'postgres:16'
        )
        $createdContainers.Add($pgContainer)

        $ready = $false
        foreach ($attempt in 1..120) {
            $logs = (Invoke-Captured docker @('logs', $pgContainer)).Output
            if ([regex]::Matches($logs, 'database system is ready to accept connections').Count -ge 2) {
                $ready = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) {
            & docker logs $pgContainer
            throw 'disposable PostgreSQL did not become ready within 60 seconds'
        }

        $versionRun = Invoke-Captured docker @('exec', $pgContainer, 'psql', '-tA', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', '-c', 'SHOW server_version_num;')
        if ($versionRun.ExitCode -ne 0) { throw 'failed to query the disposable PostgreSQL server version' }
        # The capture carries stderr as well as stdout, so it is not guaranteed to be a clean
        # integer. A bare [int] cast on a psql notice would throw a PowerShell conversion error
        # that says nothing about what happened; match first and report the capture instead.
        $versionText = $versionRun.Output.Trim()
        if ($versionText -notmatch '^\d+$') {
            throw "expected server_version_num to be a bare integer; psql returned:`n$versionText"
        }
        $serverVersion = [int]$versionText
        if ($serverVersion -lt 160000 -or $serverVersion -ge 170000) {
            throw "expected PostgreSQL 16, found server_version_num=$serverVersion"
        }

        $liveCases = @(
            foreach ($target in $liveInventory) {
                foreach ($case in $target.Cases) {
                    [pscustomobject]@{ Kind = $target.Kind; Target = $target.Target; Case = $case }
                }
            }
            foreach ($case in $libUnixOnlyLive) {
                [pscustomobject]@{ Kind = 'lib'; Target = 'lib'; Case = $case }
            }
        )

        $ordinal = 0
        foreach ($entry in $liveCases) {
            $ordinal += 1
            $databaseName = "wb_linux_$($ordinal)_$shortId"
            Invoke-Checked docker @(
                'exec', $pgContainer, 'psql', '-v', 'ON_ERROR_STOP=1',
                '-U', 'postgres', '-d', 'postgres', '-c', "CREATE DATABASE $databaseName;"
            )
            Write-Host "Running $($entry.Target)::$($entry.Case) ..."
            try {
                $targetArgs = if ($entry.Kind -eq 'lib') { @('--lib') } else { @('--test', $entry.Target) }
                $command = @('cargo', 'test', '-p', 'lore-postgres') + $targetArgs + @(
                    '--', '--ignored', '--exact', $entry.Case, '--test-threads=1', '--nocapture'
                )
                $run = Invoke-InContainer -Command $command -EnvironmentPairs @(
                    "LORE_TEST_PG_URL=postgresql://postgres@wb-postgres:5432/$databaseName"
                )
            }
            finally {
                # Deliberately NOT Invoke-Checked. A throw from a `finally` replaces whatever
                # exception was already in flight, so a failed cleanup drop would erase the real
                # failure that caused it. Report it and let the original error stand; the whole
                # PostgreSQL container is removed at teardown anyway, so a leaked throwaway
                # database costs nothing.
                $dropRun = Invoke-Captured docker @(
                    'exec', $pgContainer, 'psql', '-v', 'ON_ERROR_STOP=1',
                    '-U', 'postgres', '-d', 'postgres', '-c', "DROP DATABASE $databaseName WITH (FORCE);"
                )
                if ($dropRun.ExitCode -ne 0) {
                    Write-Warning "failed to drop throwaway database $databaseName (exit $($dropRun.ExitCode)):`n$($dropRun.Output)"
                }
            }
            $counts = Read-TestCounts -Output $run.Output
            $status = if ($counts.Ran -eq 1 -and $counts.Passed -eq 1 -and $counts.Failed -eq 0 -and $run.ExitCode -eq 0) {
                'PASS'
            }
            elseif ($counts.Ran -eq 1) { 'FAIL' } else { 'NOT RUN' }
            Add-Result -Target $entry.Target -Case $entry.Case -Status $status `
                -Enumerated 1 -Ran $counts.Ran -Passed $counts.Passed -Failed $counts.Failed
            if ($status -eq 'PASS') { Write-Host '  PASS' } else { Write-Warning "  $status`n$($run.Output)" }
        }
    }

    $failures = @($results | Where-Object { $_.Gating -and $_.Status -ne 'PASS' })
    $runPassed = $failures.Count -eq 0
}
catch {
    $setupError = $_.Exception.Message
}
finally {
    $keep = $KeepOnFailure -and -not $runPassed
    if ($keep) {
        Write-Warning "keeping containers [$($createdContainers -join ', ')], network $networkName and $sourceCopy for debugging (-KeepOnFailure)"
    }
    else {
        foreach ($container in $createdContainers) {
            # A label restating only the container's own name proves self-consistency, not
            # ownership. Confirm the run id AND the owning process id before removing anything.
            $labelRaw = & docker inspect --format '{{json .Config.Labels}}' $container 2>$null
            $inspectExit = $LASTEXITCODE
            if ($inspectExit -ne 0) { continue }
            $labels = ($labelRaw | Out-String).Trim() | ConvertFrom-Json
            $actualRunId = $labels.PSObject.Properties[$labelName].Value
            $actualPid = $labels.PSObject.Properties["$labelName.pid"].Value
            if ($actualRunId -eq $runId -and $actualPid -eq "$PID") {
                & docker rm --force --volumes $container *> $null
            }
            else {
                Write-Warning "refusing to remove unowned container $container"
            }
        }
        if ($createdNetwork) { & docker network rm $networkName *> $null }
        if (Test-Path $scratchRoot) { Remove-Item -Recurse -Force $scratchRoot -ErrorAction SilentlyContinue }
    }
    $global:LASTEXITCODE = 0
}

$results | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$notRunCount = @($results | Where-Object { $_.Status -eq 'NOT RUN' }).Count
Write-Host "Summary: PASS=$passCount FAIL=$failCount NOT RUN=$notRunCount"
if ($treeLabel) { Write-Host "Tree under test: $treeLabel" }

if ($null -ne $setupError) {
    Write-Warning "Setup failed: $setupError"
}
if (-not $runPassed) { exit 1 }
