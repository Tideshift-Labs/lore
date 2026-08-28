# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
    [switch]$KeepOnFailure
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$crateRoot = Split-Path -Parent $PSScriptRoot
$loreRoot = Split-Path -Parent $crateRoot
$runId = [Guid]::NewGuid().ToString('N')
$containerName = "wp121-retention-client-live-$runId"
$ownershipLabel = "com.tideshift.lore.retention-client-live=$runId"
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) "lore-retention-client-live-$runId"
$fixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
$expectedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$containerStarted = $false
$runPassed = $false

$environmentNames = @(
    'LORE_TEST_RETENTION_PG_URL',
    'LORE_TEST_RETENTION_ADMIN_PG_URL',
    'LORE_TEST_RETENTION_ROOT_CA_PEM_PATH',
    'LORE_TEST_RETENTION_CLIENT_CERT_PEM_PATH',
    'LORE_TEST_RETENTION_CLIENT_KEY_PEM_PATH',
    'LORE_TEST_RETENTION_ADMIN_CLIENT_CERT_PEM_PATH',
    'LORE_TEST_RETENTION_ADMIN_CLIENT_KEY_PEM_PATH',
    'LORE_TEST_RETENTION_SERVER_CERT_PEM_PATH',
    'LORE_TEST_RETENTION_SERVER_KEY_PEM_PATH',
    'LORE_TEST_RETENTION_FIXTURE_RUN_ID'
)
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

function Install-Migration {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Get-Content -Raw -LiteralPath $Path |
        & docker exec -i $containerName psql -v ON_ERROR_STOP=1 -U postgres -d retention
    if ($LASTEXITCODE -ne 0) {
        throw "failed to install migration $Path"
    }
}

try {
    if (-not $fixtureRoot.StartsWith($expectedTempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "fixture directory escaped the operating-system temporary directory"
    }
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

    @'
local all all trust
hostssl all all 0.0.0.0/0 cert clientcert=verify-full
hostssl all all ::/0 cert clientcert=verify-full
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::/0 reject
'@ | Set-Content -LiteralPath (Join-Path $fixtureRoot 'pg_hba.conf') -Encoding ascii

    $certificateScript = @'
set -euo pipefail
cd /fixture
openssl genrsa -out ca.key 3072
openssl req -x509 -new -sha256 -key ca.key -days 2 -subj '/CN=WP121 Retention Live Test CA' -out ca.crt

openssl genrsa -out server.key 2048
openssl req -new -sha256 -key server.key -subj '/CN=localhost' -out server.csr
printf '%s\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > server.ext
openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.crt

openssl genrsa -out maintenance.key 2048
openssl req -new -sha256 -key maintenance.key -subj '/CN=object_dispatch_retention_maintenance' -out maintenance.csr
printf '%s\n' 'extendedKeyUsage=clientAuth' > maintenance.ext
openssl x509 -req -sha256 -in maintenance.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile maintenance.ext -out maintenance.crt

openssl genrsa -out admin.key 2048
openssl req -new -sha256 -key admin.key -subj '/CN=postgres' -out admin.csr
printf '%s\n' 'extendedKeyUsage=clientAuth' > admin.ext
openssl x509 -req -sha256 -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile admin.ext -out admin.crt
'@
    Invoke-Checked docker @(
        'run', '--rm',
        '--mount', "type=bind,source=$fixtureRoot,destination=/fixture",
        'postgres:16', 'bash', '-euc', $certificateScript
    )

    $postgresStartScript = @'
set -euo pipefail
mkdir -p /tmp/retention-tls
cp /fixture/ca.crt /fixture/server.crt /fixture/server.key /tmp/retention-tls/
chown -R postgres:postgres /tmp/retention-tls
chmod 0600 /tmp/retention-tls/server.key
exec docker-entrypoint.sh postgres \
  -c listen_addresses='*' \
  -c ssl=on \
  -c ssl_min_protocol_version='TLSv1.3' \
  -c ssl_ca_file='/tmp/retention-tls/ca.crt' \
  -c ssl_cert_file='/tmp/retention-tls/server.crt' \
  -c ssl_key_file='/tmp/retention-tls/server.key' \
  -c hba_file='/fixture/pg_hba.conf'
'@
    Invoke-Checked docker @(
        'run', '--detach', '--name', $containerName,
        '--label', $ownershipLabel,
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_DB=retention',
        '--env', 'POSTGRES_PASSWORD=fixture-only-unused',
        '--mount', "type=bind,source=$fixtureRoot,destination=/fixture,readonly",
        'postgres:16', 'bash', '-euc', $postgresStartScript
    )
    $containerStarted = $true

    $portOutput = (& docker port $containerName '5432/tcp').Trim()
    if ($LASTEXITCODE -ne 0 -or $portOutput -notmatch ':(?<port>[0-9]+)$') {
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

    $roleSql = @'
CREATE ROLE object_dispatch_retention_owner NOLOGIN;
CREATE ROLE object_dispatch_retention_runtime NOLOGIN;
CREATE ROLE object_dispatch_retention_maintenance LOGIN;
CREATE ROLE object_dispatch_retention_migrator LOGIN;
GRANT CREATE ON DATABASE retention TO object_dispatch_retention_owner;
'@
    Invoke-Checked docker @(
        'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'retention',
        '-c', $roleSql
    )

    foreach ($migration in 2..6) {
        $paths = @(
            Get-ChildItem -LiteralPath (Join-Path $crateRoot 'migrations') -File |
                Where-Object { $_.Name.StartsWith(('000{0}_' -f $migration), [StringComparison]::Ordinal) }
        )
        if ($paths.Count -ne 1) {
            throw "missing exactly one migration for slot 000$migration"
        }
        $path = $paths[0]
        Install-Migration $path.FullName
    }

    $installSql = @'
SET SESSION AUTHORIZATION object_dispatch_retention_migrator;
BEGIN ISOLATION LEVEL SERIALIZABLE;
SELECT (object_store_retention.object_store_retention_install_v1(
  'object-store-retention-provisioning-v1',
  'object-store-retention-authority-schema-v1',
  decode('f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd', 'hex'),
  1
)).result_code;
COMMIT;
'@
    Invoke-Checked docker @(
        'exec', $containerName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'retention',
        '-c', $installSql
    )

    $env:LORE_TEST_RETENTION_PG_URL = "postgresql://object_dispatch_retention_maintenance@localhost:$port/retention?sslmode=require"
    $env:LORE_TEST_RETENTION_ADMIN_PG_URL = "postgresql://postgres@localhost:$port/retention?sslmode=require"
    $env:LORE_TEST_RETENTION_ROOT_CA_PEM_PATH = Join-Path $fixtureRoot 'ca.crt'
    $env:LORE_TEST_RETENTION_CLIENT_CERT_PEM_PATH = Join-Path $fixtureRoot 'maintenance.crt'
    $env:LORE_TEST_RETENTION_CLIENT_KEY_PEM_PATH = Join-Path $fixtureRoot 'maintenance.key'
    $env:LORE_TEST_RETENTION_ADMIN_CLIENT_CERT_PEM_PATH = Join-Path $fixtureRoot 'admin.crt'
    $env:LORE_TEST_RETENTION_ADMIN_CLIENT_KEY_PEM_PATH = Join-Path $fixtureRoot 'admin.key'
    $env:LORE_TEST_RETENTION_SERVER_CERT_PEM_PATH = Join-Path $fixtureRoot 'server.crt'
    $env:LORE_TEST_RETENTION_SERVER_KEY_PEM_PATH = Join-Path $fixtureRoot 'server.key'
    $env:LORE_TEST_RETENTION_FIXTURE_RUN_ID = $runId

    Push-Location $loreRoot
    try {
        Invoke-Checked cargo @(
            'test', '-p', 'lore-object-dispatch', '--test', 'retention_client_live', '--',
            '--ignored', '--test-threads=1'
        )
    }
    finally {
        Pop-Location
    }
    $runPassed = $true
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $priorEnvironment[$name], 'Process')
    }

    if ($containerStarted -and ($runPassed -or -not $KeepOnFailure)) {
        $actualLabel = (& docker inspect --format "{{ index .Config.Labels `"com.tideshift.lore.retention-client-live`" }}" $containerName 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $actualLabel -eq $runId) {
            # --volumes: postgres:16 declares VOLUME /var/lib/postgresql/data, so a plain
            # `docker rm --force` leaves an anonymous, now-unreferenced volume behind every run.
            & docker rm --force --volumes $containerName *> $null
        }
        else {
            Write-Warning "refusing to remove unowned container $containerName"
        }
    }

    if (($runPassed -or -not $KeepOnFailure) -and (Test-Path -LiteralPath $fixtureRoot)) {
        $resolvedFixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
        if ($resolvedFixtureRoot.StartsWith($expectedTempRoot, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path -Leaf $resolvedFixtureRoot) -eq "lore-retention-client-live-$runId") {
            Remove-Item -LiteralPath $resolvedFixtureRoot -Recurse -Force
        }
        else {
            Write-Warning "refusing to remove unexpected fixture directory $resolvedFixtureRoot"
        }
    }
}
