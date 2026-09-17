# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

<#
.SYNOPSIS
Runs CR-034's ignored budget-pin-refresh tests against disposable PostgreSQL 16.
#>

[CmdletBinding()]
param([switch]$KeepOnFailure)

$ErrorActionPreference = 'Stop'
$runId = [Guid]::NewGuid().ToString('N')
$container = "cr034-budget-pin-refresh-live-$runId"
$label = "com.tideshift.lore.budget-pin-refresh-live=$runId"
$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$passed = $false
$started = $false
$envName = 'LORE_TEST_BUDGET_PIN_REFRESH_PG_URL'
$priorEnv = [Environment]::GetEnvironmentVariable($envName, 'Process')
$tests = @(
    'live_postgres_head_read_function_is_the_only_door_and_is_least_privilege',
    'live_postgres_pinned_writer_renews_across_a_publish_and_debits_only_the_new_fence',
    'live_postgres_two_generations_of_drift_refuses_the_attempt_and_debits_nothing',
    'live_postgres_expiry_refuses_typed_and_never_enters_the_refresh_branch'
)

function Invoke-Checked {
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE"
    }
}

try {
    $existing = @(& docker ps -a --filter 'label=com.tideshift.lore.budget-pin-refresh-live' --format '{{.Names}}')
    if ($LASTEXITCODE -ne 0) { throw 'failed to inspect Docker containers' }
    if (@($existing | Where-Object { $_ }).Count -ne 0) {
        throw "another budget-pin-refresh live container exists: $($existing -join ', ')"
    }

    $catalog = & cargo test -p lore-object-dispatch --test budget_pin_refresh_live -- --ignored --list 2>&1 | Out-String
    $missing = @($tests | Where-Object { $catalog -notmatch "(?m)^$([regex]::Escape($_)): test\r?$" })
    $listed = @([regex]::Matches($catalog, '(?m)^(live_postgres_[^:]+): test\r?$') | ForEach-Object { $_.Groups[1].Value })
    if ($LASTEXITCODE -ne 0 -or $missing.Count -ne 0 -or $listed.Count -ne $tests.Count) {
        throw "the exact ignored test is absent from the compiled catalog`n$catalog"
    }

    $started = $true
    Invoke-Checked docker @(
        'run', '--detach', '--name', $container, '--label', $label,
        '--label', "com.tideshift.lore.budget-pin-refresh-live.pid=$PID",
        '--publish', '127.0.0.1::5432', '--env', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16'
    )
    $portRaw = & docker port $container '5432/tcp'
    if ($LASTEXITCODE -ne 0 -or ($portRaw | Out-String) -notmatch ':(?<port>\d+)') {
        throw 'failed to resolve PostgreSQL port'
    }
    $port = $Matches.port
    $ready = $false
    foreach ($attempt in 1..120) {
        $logs = (& docker logs $container 2>&1) -join "`n"
        if ([regex]::Matches($logs, 'database system is ready to accept connections').Count -ge 2) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'PostgreSQL did not become ready' }

    $roleSql = @'
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN
    CREATE ROLE object_dispatch_retention_owner NOLOGIN;
  END IF;
END $$;
'@
    Invoke-Checked docker @(
        'exec', $container, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', '-c', $roleSql
    )
    $index = 0
    foreach ($test in $tests) {
        $index++
        $database = "budget_pin_refresh_$index"
        Invoke-Checked docker @('exec', $container, 'createdb', '-U', 'postgres', $database)
        $grantSql = "GRANT CREATE ON DATABASE $database TO object_dispatch_retention_owner;"
        Invoke-Checked docker @(
            'exec', $container, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', '-c', $grantSql
        )

        [Environment]::SetEnvironmentVariable(
            $envName,
            "postgresql://postgres@localhost:$port/$database",
            'Process'
        )
        Push-Location $loreRoot
        try {
            $args = @(
                'test', '-p', 'lore-object-dispatch', '--test', 'budget_pin_refresh_live', '--',
                '--ignored', '--exact', $test, '--test-threads=1', '--nocapture'
            )
            $output = & cargo @args 2>&1 | Out-String
            $exit = $LASTEXITCODE
            Write-Host $output
            if ($output -notmatch 'running 1 test' -or $output -notmatch '1 passed; 0 failed' -or $exit -ne 0) {
                throw "budget-pin-refresh live test $test did not pass exactly once"
            }
        }
        finally { Pop-Location }
    }
    $passed = $true
}
finally {
    [Environment]::SetEnvironmentVariable($envName, $priorEnv, 'Process')
    if ($started -and ($passed -or -not $KeepOnFailure)) {
        $actual = & docker inspect --format '{{ index .Config.Labels "com.tideshift.lore.budget-pin-refresh-live" }}' $container 2>$null
        if ($LASTEXITCODE -eq 0 -and ($actual | Out-String).Trim() -eq $runId) {
            & docker rm --force --volumes $container *> $null
        }
    }
}

if (-not $passed) { exit 1 }
