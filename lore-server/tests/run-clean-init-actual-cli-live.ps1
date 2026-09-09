# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Run WP118 single-server actual CLI proof against owned PostgreSQL and MinIO.
.DESCRIPTION
Every ignored case receives an empty database. Operator cases create their own buckets.
The compiled catalog must agree with the test source. Zero-test runs fail.
#>
[CmdletBinding()]
param([switch]$KeepOnFailure, [switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$loreRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runId = [Guid]::NewGuid().ToString('N')
$label = 'com.tideshift.lore.actual-cli-tests'
$pgName = "lore-actual-cli-pg-$runId"
$s3Name = "lore-actual-cli-s3-$runId"
$tlsRoot = Join-Path ([IO.Path]::GetTempPath()) "lore-actual-cli-tls-$runId"
$owned = [Collections.Generic.List[string]]::new()
$passed = $false
$results = [Collections.Generic.List[object]]::new()
$targets = @(
    @{ Package = 'lore-server'; Target = 'clean_init_actual_cli'; Kind = 'test'; Prefix = ''; Source = 'lore-server/tests/clean_init_actual_cli.rs' }
)
$savedEnv = @{}
foreach ($key in @('LORE_TEST_ACTUAL_CLI', 'LORE_TEST_CLI_TLS_CERT', 'LORE_TEST_CLI_TLS_KEY', 'LORE_TEST_SINGLE_RPC_SERVER', 'LORE_TEST_SINGLE_RPC_LOG', 'LORE_TEST_PG_URL', 'LORE_TEST_S3_ENDPOINT', 'LORE_TEST_S3_REGION', 'LORE_TEST_CLEAN_INIT_CA_PATH', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_EC2_METADATA_DISABLED')) {
    $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}

function Invoke-Checked([string]$Program, [string[]]$ArgumentList) {
    & $Program @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "$Program exited $LASTEXITCODE" }
}

function Invoke-CargoCaptured([string[]]$ArgumentList) {
    $output = (& cargo @ArgumentList 2>&1 | Out-String)
    $status = $LASTEXITCODE
    if ($status -ne 0) { throw "cargo exited ${status}:`n$output" }
    return $output
}

Push-Location $loreRoot
try {
    if (-not $SkipBuild) {
        $null = Invoke-CargoCaptured @('build', '-p', 'lore-client', '--release', '--bin', 'lore', '-j', '4')
        $null = Invoke-CargoCaptured @('build', '-p', 'lore-server', '--release', '--bin', 'loreserver', '-j', '4')
    }
    # Ask Cargo rather than assuming its target directory; test:all uses a shared warm target.
    $metadataJson = (& cargo metadata --no-deps --format-version 1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata exited $LASTEXITCODE" }
    $targetDirectory = ($metadataJson | ConvertFrom-Json).target_directory
    if ([string]::IsNullOrWhiteSpace($targetDirectory) -or -not [IO.Path]::IsPathFullyQualified($targetDirectory)) { throw 'Cargo target directory must be absolute' }
    $env:LORE_TEST_ACTUAL_CLI = Join-Path $targetDirectory 'release/lore.exe'
    if (-not (Test-Path -LiteralPath $env:LORE_TEST_ACTUAL_CLI)) { throw 'actual release CLI missing' }
    Write-Host ('CLI release SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $env:LORE_TEST_ACTUAL_CLI).Hash)
    $env:LORE_TEST_SINGLE_RPC_SERVER = Join-Path $targetDirectory 'release/loreserver.exe'
    if (-not (Test-Path -LiteralPath $env:LORE_TEST_SINGLE_RPC_SERVER)) { throw 'release loreserver missing' }
    Write-Host ('Server release SHA256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $env:LORE_TEST_SINGLE_RPC_SERVER).Hash)
    $env:LORE_TEST_SINGLE_RPC_LOG = Join-Path (Split-Path -Parent $loreRoot) '.codex/tmp/actual-cli-server.log'
    foreach ($target in $targets) {
        $targetArgs = if ($target.Kind -eq 'lib') { @('--lib') } else { @('--test', $target.Target) }
        $arguments = @('test', '-j', '4', '-p', $target.Package) + $targetArgs + @('--', '--ignored', '--list')
        $catalog = Invoke-CargoCaptured $arguments
        $names = @([regex]::Matches($catalog, '(?m)^([A-Za-z0-9_:]+): test\r?$') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_.StartsWith($target.Prefix) })
        $source = Get-Content -Raw (Join-Path $loreRoot $target.Source)
        $expected = @([regex]::Matches($source, '#\[ignore[^\]]*\]\s*async fn ([a-z0-9_]+)') | ForEach-Object { $target.Prefix + $_.Groups[1].Value })
        if ($names.Count -eq 0 -or $expected.Count -eq 0 -or @(Compare-Object $names $expected).Count -ne 0) {
            throw "ignored catalog/source mismatch for $($target.Target): compiled [$($names -join ', ')] source [$($expected -join ', ')]"
        }
        foreach ($name in $names) {
            $results.Add([pscustomobject]@{ Package = $target.Package; Target = $target.Target; Kind = $target.Kind; Test = $name; Status = 'NOT RUN' })
        }
    }
    foreach ($spec in @(
        @{ Name = $pgName; Args = @('-p', '127.0.0.1::5432', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16-alpine') },
        @{ Name = $s3Name; Args = @('-p', '127.0.0.1::9000', '-e', 'MINIO_ROOT_USER=cleaninit', '-e', 'MINIO_ROOT_PASSWORD=cleaninit-local-tests', 'minio/minio:latest', 'server', '/data') }
    )) {
        $owned.Add($spec.Name)
        $arguments = @('run', '-d', '--name', $spec.Name, '--label', "$label=$runId", '--label', "$label.pid=$PID") + $spec.Args
        Invoke-Checked docker $arguments
    }
    $pgPort = ((& docker port $pgName '5432/tcp') -split ':')[-1].Trim()
    $s3Port = ((& docker port $s3Name '9000/tcp') -split ':')[-1].Trim()
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $logs = (& docker logs $pgName 2>&1) -join "`n"
        if ([regex]::Matches($logs, 'database system is ready to accept connections').Count -ge 2) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'PostgreSQL readiness timed out' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    # Only the dispatch pool requires pinned TLS. Domain/store fixture clients keep their
    # plaintext local setup path; the serving dispatch client verifies the fixture CA.
    New-Item -ItemType Directory -Path $tlsRoot | Out-Null
    $caKey = Join-Path $tlsRoot 'ca.key'
    $ca = Join-Path $tlsRoot 'ca.crt'
    $serverKey = Join-Path $tlsRoot 'server.key'
    $serverCsr = Join-Path $tlsRoot 'server.csr'
    $serverCert = Join-Path $tlsRoot 'server.crt'
    $serverExt = Join-Path $tlsRoot 'server.ext'
    Set-Content -LiteralPath $serverExt -Encoding ascii -Value "subjectAltName=DNS:localhost`nextendedKeyUsage=serverAuth"
    Invoke-Checked openssl @('genrsa', '-out', $caKey, '2048')
    Invoke-Checked openssl @('req', '-x509', '-new', '-sha256', '-key', $caKey, '-days', '2', '-subj', '/CN=Clean init disposable CA', '-out', $ca)
    Invoke-Checked openssl @('genrsa', '-out', $serverKey, '2048')
    Invoke-Checked openssl @('req', '-new', '-sha256', '-key', $serverKey, '-subj', '/CN=localhost', '-out', $serverCsr)
    Invoke-Checked openssl @('x509', '-req', '-sha256', '-in', $serverCsr, '-CA', $ca, '-CAkey', $caKey, '-CAcreateserial', '-days', '2', '-extfile', $serverExt, '-out', $serverCert)
    Invoke-Checked docker @('cp', $serverKey, "${pgName}:/tmp/clean-init-server.key")
    Invoke-Checked docker @('cp', $serverCert, "${pgName}:/tmp/clean-init-server.crt")
    Invoke-Checked docker @('exec', $pgName, 'chown', 'postgres:postgres', '/tmp/clean-init-server.key', '/tmp/clean-init-server.crt')
    Invoke-Checked docker @('exec', $pgName, 'chmod', '0600', '/tmp/clean-init-server.key')
    foreach ($sql in @("ALTER SYSTEM SET ssl='on'", "ALTER SYSTEM SET ssl_cert_file='/tmp/clean-init-server.crt'", "ALTER SYSTEM SET ssl_key_file='/tmp/clean-init-server.key'")) {
        Invoke-Checked docker @('exec', $pgName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-c', $sql)
    }
    Invoke-Checked docker @('restart', $pgName)
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        & docker exec $pgName pg_isready -U postgres *> $null
        if ($LASTEXITCODE -eq 0) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'PostgreSQL TLS restart timed out' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    # Docker may allocate a new random host port when the TLS restart recreates
    # its forwarding rule. Resolve and probe the current mapping before tests.
    $pgPort = ((& docker port $pgName '5432/tcp') -split ':')[-1].Trim()
    $probe = [Net.Sockets.TcpClient]::new()
    try { $probe.Connect('127.0.0.1', [int]$pgPort) }
    finally { $probe.Dispose() }
    Invoke-Checked docker @('exec', $pgName, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-c', 'CREATE ROLE object_dispatch_retention_owner NOLOGIN; CREATE ROLE object_dispatch_retention_runtime LOGIN; CREATE ROLE object_dispatch_retention_maintenance LOGIN; CREATE ROLE object_dispatch_retention_migrator LOGIN; GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator WITH INHERIT FALSE, SET TRUE;')
    $env:LORE_TEST_CLEAN_INIT_CA_PATH = $ca
    $env:LORE_TEST_CLI_TLS_CERT = $serverCert
    $env:LORE_TEST_CLI_TLS_KEY = $serverKey
    $env:LORE_TEST_S3_ENDPOINT = "http://127.0.0.1:$s3Port"
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        try {
            $null = Invoke-WebRequest "$env:LORE_TEST_S3_ENDPOINT/minio/health/ready" -TimeoutSec 2
            break
        }
        catch {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'MinIO readiness timed out' }
            Start-Sleep -Milliseconds 200
        }
    } while ($true)
    $env:LORE_TEST_S3_REGION = 'us-east-1'
    $env:AWS_ACCESS_KEY_ID = 'cleaninit'
    $env:AWS_SECRET_ACCESS_KEY = 'cleaninit-local-tests'
    $env:AWS_EC2_METADATA_DISABLED = 'true'
    $index = 0
    foreach ($result in $results) {
        $database = "clean_init_$index"
        $env:LORE_TEST_SINGLE_RPC_LOG = Join-Path (Split-Path -Parent $loreRoot) ".codex/tmp/actual-cli-server-$index.log"
        $index++
        Invoke-Checked docker @('exec', $pgName, 'createdb', '-U', 'postgres', $database)
        $env:LORE_TEST_PG_URL = "postgresql://postgres@127.0.0.1:$pgPort/$database`?sslmode=disable"
        try {
            $targetArgs = if ($result.Kind -eq 'lib') { @('--lib') } else { @('--test', $result.Target) }
            $arguments = @('test', '-j', '4', '-p', $result.Package) + $targetArgs + @('--', '--ignored', '--exact', $result.Test, '--nocapture')
            $output = Invoke-CargoCaptured $arguments
            Write-Host $output
            if ($output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { throw 'expected exactly one executed test' }
            $result.Status = 'PASS'
        }
        catch {
            $result.Status = 'FAIL'
            Write-Warning $_
        }
    }
    $passed = @($results | Where-Object Status -ne 'PASS').Count -eq 0
    if (-not $passed) { throw 'clean initialization live tests failed' }
}
finally {
    $results | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
    foreach ($key in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process') }
    foreach ($name in $owned) {
        if ($KeepOnFailure -and -not $passed) { Write-Host "Preserved owned container $name"; continue }
        $inspection = & docker inspect $name 2>$null
        if ($LASTEXITCODE -ne 0) { continue }
        $container = @($inspection | ConvertFrom-Json)[0]
        if ($container.Config.Labels.$label -ne $runId -or $container.Config.Labels."$label.pid" -ne "$PID") {
            throw "refusing cleanup: ownership changed for $name"
        }
        Invoke-Checked docker @('rm', '--force', '--volumes', $name)
    }
    if (($passed -or -not $KeepOnFailure) -and (Test-Path -LiteralPath $tlsRoot)) {
        $resolved = (Resolve-Path -LiteralPath $tlsRoot).Path
        $expected = [IO.Path]::GetFullPath($tlsRoot)
        $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
        if ($resolved -ne $expected -or (Split-Path -Parent $resolved) -ne $parent) { throw 'TLS fixture cleanup escaped owned temporary directory' }
        foreach ($file in @('ca.key','ca.crt','ca.srl','server.key','server.csr','server.crt','server.ext')) {
            $ownedFile = Join-Path $resolved $file
            if (Test-Path -LiteralPath $ownedFile -PathType Leaf) { Remove-Item -LiteralPath $ownedFile -Force }
        }
        Remove-Item -LiteralPath $resolved
    }
    Pop-Location
}
