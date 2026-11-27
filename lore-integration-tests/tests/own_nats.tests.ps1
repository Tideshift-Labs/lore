# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
# Daemon-free tests for own_nats.ps1: every docker call goes through a fake
# -Docker script block that records its argument list.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'own_nats.ps1')

$script:cases = 0
function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
}
# A strict assertion that the implementation currently fails: recorded, the
# run continues, and the file exits non-zero at the end. Not weakened.
$script:defects = [Collections.Generic.List[string]]::new()
function Assert-Defect($Condition, [string]$Message) {
    if (-not $Condition) { $script:defects.Add($Message); Write-Host "DEFECT: $Message" }
}
function Assert-Equal($Actual, $Expected, [string]$Message) {
    $a = @($Actual) -join '|'
    $e = @($Expected) -join '|'
    if ($a -ne $e) { throw "FAIL: $Message`n  expected: $e`n  actual:   $a" }
}
function Assert-Throws([scriptblock]$Block, [string]$Pattern, [string]$Message) {
    $threw = $null
    try { $null = & $Block } catch { $threw = $_.Exception.Message }
    if ($null -eq $threw) { throw "FAIL: $Message (nothing thrown)" }
    if ($threw -notmatch $Pattern) { throw "FAIL: $Message (thrown '$threw', wanted /$Pattern/)" }
}

# A fake docker: a hashtable state of what exists, a call log, and optional
# per-command failure. `Containers`, `Volumes`, `Networks` are the project's
# labelled resources; `Mounts` maps container -> volume names it mounts;
# `ExtraVolumes` are unlabelled (anonymous) volumes that exist by name only.
function New-FakeDocker {
    param(
        [string[]]$Containers = @(),
        [string[]]$Volumes = @(),
        [string[]]$Networks = @(),
        [hashtable]$Mounts = @{},
        [string[]]$ExtraVolumes = @(),
        [string[]]$FailOn = @(),
        [string[]]$ThrowOn = @(),
        [int]$UpExit = 0,
        [scriptblock]$OnUp = $null
    )
    $state = [pscustomobject]@{
        Calls        = [Collections.Generic.List[string]]::new()
        Containers   = [Collections.Generic.List[string]]::new($Containers)
        Volumes      = [Collections.Generic.List[string]]::new($Volumes)
        Networks     = [Collections.Generic.List[string]]::new($Networks)
        ExtraVolumes = [Collections.Generic.List[string]]::new($ExtraVolumes)
        Mounts       = $Mounts
        FailOn       = $FailOn
        ThrowOn      = $ThrowOn
        UpExit       = $UpExit
        OnUp         = $OnUp
    }
    $block = {
        param([string[]]$DockerArgs)
        $line = $DockerArgs -join ' '
        $state.Calls.Add($line)
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = $o } }
        foreach ($f in $state.ThrowOn) { if ($line -like $f) { throw "fake docker threw: $line" } }
        foreach ($f in $state.FailOn) {
            if ($line -like $f) { return [pscustomobject]@{ ExitCode = 1; Output = "boom: $line" } }
        }
        switch -Wildcard ($line) {
            'compose *' {
                if ($state.OnUp) { & $state.OnUp }
                return [pscustomobject]@{ ExitCode = $state.UpExit; Output = 'up output' }
            }
            'ps -a *' { return (& $ok (($state.Containers -join "`n"))) }
            'volume ls *' { return (& $ok (($state.Volumes -join "`n"))) }
            'network ls *' { return (& $ok (($state.Networks -join "`n"))) }
            'inspect *' {
                $name = $DockerArgs[-1]
                $m = if ($state.Mounts.ContainsKey($name)) { $state.Mounts[$name] } else { @() }
                return (& $ok ((@($m) -join "`n")))
            }
            'rm -f *' { [void]$state.Containers.Remove($DockerArgs[-1]); return (& $ok '') }
            'volume rm *' {
                [void]$state.Volumes.Remove($DockerArgs[-1]); [void]$state.ExtraVolumes.Remove($DockerArgs[-1])
                return (& $ok '')
            }
            'network rm *' { [void]$state.Networks.Remove($DockerArgs[-1]); return (& $ok '') }
            'volume inspect *' {
                $name = $DockerArgs[-1]
                $exists = $state.Volumes.Contains($name) -or $state.ExtraVolumes.Contains($name)
                return [pscustomobject]@{ ExitCode = $(if ($exists) { 0 } else { 1 }); Output = '' }
            }
            default { return [pscustomobject]@{ ExitCode = 1; Output = "unexpected docker call: $line" } }
        }
    }.GetNewClosure()
    [pscustomobject]@{ Block = $block; State = $state }
}

$compose = 'C:\fake\lorehub\docker\compose.yaml'

# --- plan ---------------------------------------------------------------
$plan = New-OwnNatsPlan -RunId 'abc123def' -PortBase 41400 -ComposeFile $compose
Assert-Equal $plan.Project 'lore-aa2p-abc123def' 'plan project'
Assert-Equal $plan.Port 41382 'plan client port'
Assert-Equal $plan.MonitorPort 41383 'plan monitor port'
Assert-Equal $plan.Url 'nats://127.0.0.1:41382' 'plan url'
Assert-Equal $plan.UpArgs @('compose', '-f', $compose, '-p', 'lore-aa2p-abc123def', '--profile', 'notifications', 'up', '-d', '--wait', 'nats') 'plan UpArgs'
Assert-Equal $plan.Environment['COMPOSE_PROJECT_NAME'] 'lore-aa2p-abc123def' 'env project'
Assert-Equal $plan.Environment['LH_NATS_PORT'] '41382' 'env nats port'
Assert-Equal $plan.Environment['LH_NATS_MONITOR_PORT'] '41383' 'env monitor port'
Assert-True ($plan.Environment.Contains('LH_PG_VOLUME_SUFFIX') -and $null -eq $plan.Environment['LH_PG_VOLUME_SUFFIX']) 'env unsets LH_PG_VOLUME_SUFFIX'
$script:cases++

# --- plan refusals ------------------------------------------------------
Assert-Throws { New-OwnNatsPlan -RunId 'abc123def' -PortBase 4240 -ComposeFile $compose } '4222' 'port 4222 refused'
Assert-Throws { New-OwnNatsPlan -RunId 'abc123def' -PortBase 8240 -ComposeFile $compose } '8223' 'port 8223 refused'
Assert-Throws { New-OwnNatsPlan -RunId 'abc123def' -PortBase 500 -ComposeFile $compose } 'outside 1024' 'low port refused'
Assert-Throws { New-OwnNatsPlan -RunId 'abc123def' -PortBase 65560 -ComposeFile $compose } 'outside 1024' 'high port refused'
$upperRefused = $false
try { $null = New-OwnNatsPlan -RunId 'ABC123DEF' -PortBase 41400 -ComposeFile $compose } catch { $upperRefused = $true }
Assert-True $upperRefused 'uppercase run id refused (case-sensitive match)'
foreach ($bad in @('abc12', 'abc_123def', 'abc 123def', ('a' * 33), 'abc123;rm')) {
    Assert-Throws { New-OwnNatsPlan -RunId $bad -PortBase 41400 -ComposeFile $compose } 'run id' "bad run id '$bad' refused"
}
$script:cases++

# --- Start-OwnNats ------------------------------------------------------
$env:LH_NATS_PORT = 'sentinel-port'
$env:COMPOSE_PROJECT_NAME = 'sentinel-project'
$env:LH_PG_VOLUME_SUFFIX = 'sentinel-suffix'
Remove-Item Env:LH_NATS_MONITOR_PORT -ErrorAction SilentlyContinue
$seen = @{}
$fake = New-FakeDocker -Containers @('lore-aa2p-abc123def-nats-1') -Volumes @('lore-aa2p-abc123def_nats') -Networks @('lore-aa2p-abc123def_default') -Mounts @{ 'lore-aa2p-abc123def-nats-1' = @('lore-aa2p-abc123def_nats', 'anon0123') } -OnUp {
    $seen['port'] = $env:LH_NATS_PORT
    $seen['mon'] = $env:LH_NATS_MONITOR_PORT
    $seen['proj'] = $env:COMPOSE_PROJECT_NAME
    $seen['suffix'] = $env:LH_PG_VOLUME_SUFFIX
}
$res = Start-OwnNats -Plan $plan -Docker $fake.Block
Assert-Equal $seen['port'] '41382' 'LH_NATS_PORT set during up'
Assert-Equal $seen['mon'] '41383' 'LH_NATS_MONITOR_PORT set during up'
Assert-Equal $seen['proj'] 'lore-aa2p-abc123def' 'COMPOSE_PROJECT_NAME set during up'
Assert-True ([string]::IsNullOrEmpty($seen['suffix'])) 'LH_PG_VOLUME_SUFFIX unset during up'
Assert-Equal $env:LH_NATS_PORT 'sentinel-port' 'LH_NATS_PORT restored'
Assert-Equal $env:COMPOSE_PROJECT_NAME 'sentinel-project' 'COMPOSE_PROJECT_NAME restored'
Assert-Equal $env:LH_PG_VOLUME_SUFFIX 'sentinel-suffix' 'LH_PG_VOLUME_SUFFIX restored'
Assert-True ($null -eq [Environment]::GetEnvironmentVariable('LH_NATS_MONITOR_PORT', 'Process')) 'previously-unset var is truly unset again, not an empty string'
Assert-Equal $fake.State.Calls[0] ($plan.UpArgs -join ' ') 'up call args'
Assert-Equal $res.Containers @('lore-aa2p-abc123def-nats-1') 'start returns container'
Assert-Equal $res.AnonymousVolumes @('anon0123') 'start reports anonymous volume'
Assert-Equal $res.Volumes @('lore-aa2p-abc123def_nats', 'anon0123') 'start volumes include anonymous'
$script:cases++

# up failure throws and still restores env
$failFake = New-FakeDocker -UpExit 3
Assert-Throws { Start-OwnNats -Plan $plan -Docker $failFake.Block } 'exited 3' 'up failure throws'
Assert-Equal $env:LH_NATS_PORT 'sentinel-port' 'env restored after failed up'
# wrong container count throws
$twoFake = New-FakeDocker -Containers @('a', 'b')
Assert-Throws { Start-OwnNats -Plan $plan -Docker $twoFake.Block } 'exactly one container' 'two containers refused'
$zeroFake = New-FakeDocker
Assert-Throws { Start-OwnNats -Plan $plan -Docker $zeroFake.Block } 'exactly one container' 'zero containers refused'
Remove-Item Env:LH_NATS_PORT, Env:COMPOSE_PROJECT_NAME, Env:LH_PG_VOLUME_SUFFIX -ErrorAction SilentlyContinue
$script:cases++

# --- Remove-OwnNats -----------------------------------------------------
$fake = New-FakeDocker -Containers @('lore-aa2p-abc123def-nats-1') -Volumes @('lore-aa2p-abc123def_nats') -Networks @('lore-aa2p-abc123def_default') -Mounts @{ 'lore-aa2p-abc123def-nats-1' = @('lore-aa2p-abc123def_nats', 'anon0123') } -ExtraVolumes @('anon0123')
$r = Remove-OwnNats -Plan $plan -Docker $fake.Block
$mutations = @($fake.State.Calls | Where-Object { $_ -match '^(rm|volume rm|network rm|compose|system|.*prune)' })
Assert-Equal $mutations @('rm -f lore-aa2p-abc123def-nats-1', 'volume rm lore-aa2p-abc123def_nats', 'volume rm anon0123', 'network rm lore-aa2p-abc123def_default') 'only exact-name removals issued'
Assert-True ($r.Clean) 'clean after successful removal'
Assert-Equal $r.ContainersLeft 0 'containers left'
Assert-Equal $r.VolumesLeft 0 'volumes left'
Assert-Equal $r.NetworksLeft 0 'networks left'
Assert-Equal $r.Errors @() 'no errors'
$script:cases++

# nothing to remove: no mutating calls, clean
$empty = New-FakeDocker
$r = Remove-OwnNats -Plan $plan -Docker $empty.Block
Assert-True ($r.Clean) 'empty project is clean'
Assert-Equal @($empty.State.Calls | Where-Object { $_ -match '^(rm|volume rm|network rm)' }).Count 0 'no removals when nothing found'
$script:cases++

# failed removal: no throw, Clean false, Errors set
$stuck = New-FakeDocker -Containers @('lore-aa2p-abc123def-nats-1') -Volumes @('lore-aa2p-abc123def_nats') -Networks @('lore-aa2p-abc123def_default') -FailOn @('rm -f *')
$r = Remove-OwnNats -Plan $plan -Docker $stuck.Block
Assert-True (-not $r.Clean) 'failed removal is not clean'
Assert-True ($r.Errors.Count -ge 1 -and ($r.Errors -join ' ') -match 'docker rm -f lore-aa2p-abc123def-nats-1') 'removal error recorded'
Assert-Equal $r.ContainersLeft 1 'container still counted as left'
$script:cases++

# an anonymous volume that survives is counted even though it has no label
$anon = New-FakeDocker -Containers @('c1') -Mounts @{ 'c1' = @('anon9') } -ExtraVolumes @('anon9') -FailOn @('volume rm anon9')
$r = Remove-OwnNats -Plan $plan -Docker $anon.Block
Assert-True (-not $r.Clean) 'surviving anonymous volume is not clean'
Assert-Equal $r.VolumesLeft 1 'surviving anonymous volume counted'
$script:cases++

# a throwing volume inspect: no throw, volume counted as left, error recorded
$thrower = New-FakeDocker -Containers @('c1') -Mounts @{ 'c1' = @('anon7') } -ExtraVolumes @('anon7') -ThrowOn @('volume inspect *')
$r = Remove-OwnNats -Plan $plan -Docker $thrower.Block
Assert-True (-not $r.Clean) 'throwing inspect is not clean'
Assert-Equal $r.VolumesLeft 1 'throwing inspect counts the volume as left'
Assert-True ($r.Errors.Count -ge 1) 'throwing inspect adds an Error'
$script:cases++

# discovery failure: no throw, not clean
$noDocker = { param([string[]]$DockerArgs) [pscustomobject]@{ ExitCode = 1; Output = 'daemon down' } }
$r = Remove-OwnNats -Plan $plan -Docker $noDocker
Assert-True (-not $r.Clean) 'discovery failure is not clean'
Assert-True ($r.Errors.Count -ge 1) 'discovery failure recorded'
Assert-Equal $r.ContainersLeft -1 'unknown left is -1'
$script:cases++

# --- Get-CaseReceiverIdentities -----------------------------------------
Assert-Equal (Get-CaseReceiverIdentities -CasePortBase 41400 -RunId 'abc123def') @('wp109-recv-a-41401-abc123def', 'wp109-recv-b-41403-abc123def') 'receiver identities'
Assert-Equal (Get-CaseReceiverIdentities -CasePortBase 41410 -RunId 'zzz999') @('wp109-recv-a-41411-zzz999', 'wp109-recv-b-41413-zzz999') 'receiver identities, next case'
# cross-check the source of truth so a drift in cell.rs / mod.rs fails here
$support = Join-Path $PSScriptRoot 'active_active_two_process_support'
$cellRs = Get-Content -Raw (Join-Path $support 'cell.rs')
$modRs = Get-Content -Raw (Join-Path $support 'mod.rs')
Assert-True ($cellRs.Contains('wp109-recv-{name}-{grpc_port}-{}')) 'cell.rs identity format unchanged'
Assert-True ($modRs -match 'a_ports[\s\S]*?\(self\.port_base \+ 1, self\.port_base \+ 2\)') 'mod.rs a_ports is +1'
Assert-True ($modRs -match 'b_ports[\s\S]*?\(self\.port_base \+ 3, self\.port_base \+ 4\)') 'mod.rs b_ports is +3'
$script:cases++

# --- Get-PruneConsumersArgs ---------------------------------------------
$ids = @('wp109-recv-a-41401-r', 'wp109-recv-b-41403-r')
Assert-Equal (Get-PruneConsumersArgs -NatsUrl 'nats://127.0.0.1:41382' -CellId 'cell-1' -RunId 'r' -Identities $ids) @('scripts/prune-run-consumers.ts', '--url', 'nats://127.0.0.1:41382', '--cell', 'cell-1', '--run-id', 'r', '--max-generation', '64', '--identity', $ids[0], '--identity', $ids[1]) 'prune args without RequireEmpty'
$withEmpty = Get-PruneConsumersArgs -NatsUrl 'nats://127.0.0.1:41382' -CellId 'cell-1' -RunId 'r' -Identities $ids -MaxGeneration 8 -RequireEmpty
Assert-Equal $withEmpty[-1] '--require-empty' 'RequireEmpty appended last'
Assert-Equal $withEmpty[8] '8' 'MaxGeneration honored'
Assert-Equal (@(Get-PruneConsumersArgs -NatsUrl 'u' -CellId 'c' -RunId 'r' -Identities $ids) -contains '--require-empty') $false 'no --require-empty by default'
Assert-Equal $withEmpty[3..6] @('--cell', 'cell-1', '--run-id', 'r') '--run-id follows --cell'
Assert-Throws { Get-PruneConsumersArgs -NatsUrl 'u' -CellId 'c' -Identities $ids } 'RunId' 'RunId is mandatory'
$script:cases++

# --- static: runner has no default broker URL ---------------------------
$runner = Get-Content -Raw (Join-Path $PSScriptRoot 'run-active-active-two-process-live.ps1')
Assert-True ($runner -notmatch '\$NatsUrl\s*=\s*[''"]') 'NatsUrl has no literal default'
Assert-True ($runner -notmatch '\[string\]\$NatsUrl\s*=') 'NatsUrl param has no default value'
Assert-True ($runner -notmatch 'nats://[^\s''"]*:4222') 'runner names no nats://...:4222 URL'
Assert-True ($runner -notmatch '(?m)^\s*\$NatsUrl\s*=\s*.*4222') 'runner never assigns NatsUrl from 4222'
Assert-True ($runner -match "own_nats\.ps1") 'runner dot-sources own_nats.ps1'
$script:cases++

if ($script:defects.Count -gt 0) {
    throw "own_nats: $($script:cases) groups ran; $($script:defects.Count) implementation defect(s): $($script:defects -join ' || ')"
}
Write-Host "PASS: own_nats ($($script:cases) groups)"
