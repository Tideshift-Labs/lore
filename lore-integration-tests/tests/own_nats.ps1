# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

# A run-owned NATS JetStream broker for the live runners, brought up from the
# lorehub compose `nats` service so image, version and JetStream config are the
# dev data plane's own, never a hand copy. Dot-source this file.
#
# Ownership is by name. The compose project is `lore-aa2p-<run id>`, so every
# container, volume and network compose creates carries a name and a
# `com.docker.compose.project` label no other run or slot can have. Teardown
# removes exactly those names, one by one, and then proves each is gone. It
# never runs `compose down` over a project it did not just name, and never a
# prune.
#
# Every docker call goes through `-Docker`, a script block taking the argument
# list and returning `[pscustomobject]@{ ExitCode; Output }`, so the tests can
# drive the whole lifecycle without a daemon.

$script:OwnNatsDefaultDocker = {
    param([string[]]$DockerArgs)
    $output = & docker @DockerArgs 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

# Slot 0's broker ports (lorehub docker/compose.yaml defaults). A run-owned
# broker must never take them.
$script:OwnNatsSlot0Ports = @(4222, 8223)

function New-OwnNatsPlan {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][int]$PortBase,
        [Parameter(Mandatory)][string]$ComposeFile
    )
    if ($RunId -cnotmatch '^[a-z0-9]{6,32}$') {
        throw "run id '$RunId' must be 6..32 lowercase letters or digits (it names a compose project)"
    }
    $project = "lore-aa2p-$RunId"
    # The runner's band below the first case: the gateway takes PortBase-20 and
    # -19, so the broker takes -18 (client) and -17 (monitoring).
    $port = $PortBase - 18
    $monitorPort = $PortBase - 17
    foreach ($candidate in @($port, $monitorPort)) {
        if ($candidate -in $script:OwnNatsSlot0Ports) {
            throw "own NATS port $candidate is slot 0's broker port; choose another -PortBase"
        }
        if ($candidate -lt 1024 -or $candidate -gt 65535) {
            throw "own NATS port $candidate is outside 1024..65535; choose another -PortBase"
        }
    }
    [pscustomobject]@{
        Project     = $project
        Port        = $port
        MonitorPort = $monitorPort
        Url         = "nats://127.0.0.1:$port"
        ComposeFile = $ComposeFile
        UpArgs      = @('compose', '-f', $ComposeFile, '-p', $project, '--profile', 'notifications', 'up', '-d', '--wait', 'nats')
        Environment = [ordered]@{
            COMPOSE_PROJECT_NAME = $project
            LH_NATS_PORT         = "$port"
            LH_NATS_MONITOR_PORT = "$monitorPort"
            # Unset, so the volume takes compose's default `-pg18` suffix and the
            # launching shell's value for another stack never reaches this
            # project. Teardown finds the volume by label either way.
            LH_PG_VOLUME_SUFFIX  = $null
        }
    }
}

function Get-OwnNatsLines {
    param([string]$Text)
    @(($Text -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Everything docker holds for the plan's project: containers, volumes and
# networks by the compose project label, plus every volume a container mounts
# (an anonymous one has no project label). Read-only.
function Get-OwnNatsResources {
    param(
        [Parameter(Mandatory)]$Plan,
        [scriptblock]$Docker = $script:OwnNatsDefaultDocker
    )
    $label = "label=com.docker.compose.project=$($Plan.Project)"
    $containers = & $Docker @('ps', '-a', '--filter', $label, '--format', '{{.Names}}')
    if ($containers.ExitCode -ne 0) { throw "docker ps failed: $($containers.Output)" }
    $volumes = & $Docker @('volume', 'ls', '--filter', $label, '--format', '{{.Name}}')
    if ($volumes.ExitCode -ne 0) { throw "docker volume ls failed: $($volumes.Output)" }
    $networks = & $Docker @('network', 'ls', '--filter', $label, '--format', '{{.Name}}')
    if ($networks.ExitCode -ne 0) { throw "docker network ls failed: $($networks.Output)" }
    $containerNames = Get-OwnNatsLines $containers.Output
    $volumeNames = [Collections.Generic.List[string]]::new()
    foreach ($name in (Get-OwnNatsLines $volumes.Output)) { $volumeNames.Add($name) }
    $anonymous = [Collections.Generic.List[string]]::new()
    foreach ($container in $containerNames) {
        $mounts = & $Docker @('inspect', '--format', '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}', $container)
        if ($mounts.ExitCode -ne 0) { throw "docker inspect $container failed: $($mounts.Output)" }
        foreach ($name in (Get-OwnNatsLines $mounts.Output)) {
            if (-not $volumeNames.Contains($name)) { $volumeNames.Add($name); $anonymous.Add($name) }
        }
    }
    [pscustomobject]@{
        Containers       = @($containerNames)
        Volumes          = @($volumeNames)
        AnonymousVolumes = @($anonymous)
        Networks         = @(Get-OwnNatsLines $networks.Output)
    }
}

# Set or, for $null, truly unset one process variable. A $null handed to a .NET
# [string] parameter from PowerShell arrives as '', which leaves the variable
# set to empty rather than absent.
function Set-OwnNatsEnv {
    param([Parameter(Mandatory)][string]$Name, [AllowNull()]$Value)
    if ($null -eq $Value) { Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue }
    else { Set-Item -Path "Env:$Name" -Value $Value }
}

function Start-OwnNats {
    param(
        [Parameter(Mandatory)]$Plan,
        [scriptblock]$Docker = $script:OwnNatsDefaultDocker
    )
    $saved = @{}
    foreach ($key in $Plan.Environment.Keys) {
        $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        Set-OwnNatsEnv -Name $key -Value $Plan.Environment[$key]
    }
    try {
        $up = & $Docker $Plan.UpArgs
    }
    finally {
        foreach ($key in $saved.Keys) { Set-OwnNatsEnv -Name $key -Value $saved[$key] }
    }
    if ($up.ExitCode -ne 0) {
        throw "docker compose up of the run-owned NATS ($($Plan.Project)) exited $($up.ExitCode)`n$($up.Output)"
    }
    $resources = Get-OwnNatsResources -Plan $Plan -Docker $Docker
    if ($resources.Containers.Count -ne 1) {
        throw "expected exactly one container in project $($Plan.Project), found $($resources.Containers.Count): $($resources.Containers -join ', ')"
    }
    $resources
}

# Remove every resource of the plan's project by exact name, then prove none is
# left. Resources are re-discovered here rather than taken from Start-OwnNats,
# so a broker whose `up` failed halfway is still cleaned. Returns the counts
# left and the names removed; never throws for a failed removal, so a teardown
# in a `finally` reports rather than masks the run's own result.
function Remove-OwnNats {
    param(
        [Parameter(Mandatory)]$Plan,
        [scriptblock]$Docker = $script:OwnNatsDefaultDocker
    )
    $errors = [Collections.Generic.List[string]]::new()
    $found = $null
    try { $found = Get-OwnNatsResources -Plan $Plan -Docker $Docker }
    catch { $errors.Add($_.Exception.Message) }
    if ($null -ne $found) {
        # Containers first (they hold the volumes and the network), then the rest.
        # Each removal is contained: one failure must not stop the others.
        $removals = @(
            foreach ($name in $found.Containers) { , @('rm', '-f', $name) }
            foreach ($name in $found.Volumes) { , @('volume', 'rm', $name) }
            foreach ($name in $found.Networks) { , @('network', 'rm', $name) }
        )
        foreach ($removal in $removals) {
            try {
                $r = & $Docker $removal
                if ($r.ExitCode -ne 0) { $errors.Add("docker $($removal -join ' ') exited $($r.ExitCode): $($r.Output.Trim())") }
            }
            catch { $errors.Add("docker $($removal -join ' ') failed: $($_.Exception.Message)") }
        }
    }
    $left = $null
    try { $left = Get-OwnNatsResources -Plan $Plan -Docker $Docker }
    catch { $errors.Add($_.Exception.Message) }
    # An anonymous volume carries no project label, so re-check the recorded
    # names directly.
    $anonymousLeft = @()
    if ($null -ne $found) {
        $anonymousLeft = @(foreach ($name in $found.AnonymousVolumes) {
                # A failed check counts as left: absence must be shown, not assumed.
                try { if ((& $Docker @('volume', 'inspect', $name)).ExitCode -eq 0) { $name } }
                catch { $errors.Add("docker volume inspect $name failed: $($_.Exception.Message)"); $name }
            })
    }
    [pscustomobject]@{
        Removed        = $found
        ContainersLeft = if ($null -ne $left) { $left.Containers.Count } else { -1 }
        VolumesLeft    = if ($null -ne $left) { $left.Volumes.Count + $anonymousLeft.Count } else { -1 }
        NetworksLeft   = if ($null -ne $left) { $left.Networks.Count } else { -1 }
        Errors         = @($errors)
        Clean          = ($null -ne $left -and $errors.Count -eq 0 -and $left.Containers.Count -eq 0 -and
            ($left.Volumes.Count + $anonymousLeft.Count) -eq 0 -and $left.Networks.Count -eq 0)
    }
}

# The receiver identities one case's two processes use. Mirrors
# `active_active_two_process_support/cell.rs` (RECEIVER_IDENTITY) and `mod.rs`
# (a_ports/b_ports): process A's gRPC port is the case band +1, B's is +3.
function Get-CaseReceiverIdentities {
    param([Parameter(Mandatory)][int]$CasePortBase, [Parameter(Mandatory)][string]$RunId)
    @("wp109-recv-a-$($CasePortBase + 1)-$RunId", "wp109-recv-b-$($CasePortBase + 3)-$RunId")
}

# argv for the gateway's consumer prune (lorehub apps/notification-gateway/
# scripts/prune-run-consumers.ts). `-RequireEmpty` only on a run-owned broker.
function Get-PruneConsumersArgs {
    param(
        [Parameter(Mandatory)][string]$NatsUrl,
        [Parameter(Mandatory)][string]$CellId,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string[]]$Identities,
        [int]$MaxGeneration = 64,
        [switch]$RequireEmpty
    )
    # `--run-id` makes the script refuse any identity not ending in it.
    $argv = @('scripts/prune-run-consumers.ts', '--url', $NatsUrl, '--cell', $CellId, '--run-id', $RunId, '--max-generation', "$MaxGeneration")
    foreach ($identity in $Identities) { $argv += @('--identity', $identity) }
    if ($RequireEmpty) { $argv += '--require-empty' }
    $argv
}
