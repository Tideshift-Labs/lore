# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
# Supported budget operator against an owned TLS PostgreSQL fixture.
[CmdletBinding()]
param([switch]$KeepOnFailure)
$ErrorActionPreference = 'Stop'
$runId = [Guid]::NewGuid().ToString('N')
$container = "wp115-budget-configure-live-$runId"
$labelKey = 'com.tideshift.lore.budget-configure-live'
$loreRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) $container))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
$started = $false
$passed = $false
$envNames = @('LORE_TEST_BUDGET_CONFIGURE_PG_URL', 'LORE_TEST_BUDGET_CONFIGURE_CA_PATH')
$prior = @{}
foreach ($name in $envNames) { $prior[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$tests = @(
 'live_budget_publish_verify_replay_preserves_depletion',
 'live_budget_exact_binding_drift_and_absence_refuse',
 'live_budget_wrong_role_tls_and_database_identity_refuse',
 'live_budget_renewal_carries_depletion_without_reset',
 'live_budget_legacy_replay_and_v2_successor_preserve_old_identity_and_depletion',
 'live_budget_expired_reconcile_is_read_only_and_allows_successor'
)
function Invoke-Checked {
 param([string]$Command, [string[]]$Arguments)
 & $Command @Arguments
 if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}
function Invoke-Sql {
 param([string]$Database, [string]$Sql)
 Invoke-Checked docker @('exec', $container, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', $Database, '-c', $Sql)
}
try {
 Push-Location $loreRoot
 try {
  $catalogArgs = @('test', '-p', 'lore-object-dispatch', '--test', 'budget_configure_live', '-j', '4', '--', '--ignored', '--list')
  $catalog = & cargo @catalogArgs 2>&1 | Out-String
  $exit = $LASTEXITCODE
 } finally { Pop-Location }
 $listed = @([regex]::Matches($catalog, '(?m)^([^\r\n:]+): test\r?$') | ForEach-Object { $_.Groups[1].Value })
 if ($exit -ne 0 -or $listed.Count -ne $tests.Count -or @(Compare-Object $tests $listed).Count -ne 0) {
  throw "compiled ignored inventory differs from runner; no fixture created`n$catalog"
 }
 if (-not $fixtureRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture path escaped temporary root' }
 New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
 $caKey = Join-Path $fixtureRoot 'ca.key'
 $ca = Join-Path $fixtureRoot 'ca.crt'
 $key = Join-Path $fixtureRoot 'server.key'
 $csr = Join-Path $fixtureRoot 'server.csr'
 $cert = Join-Path $fixtureRoot 'server.crt'
 $ext = Join-Path $fixtureRoot 'server.ext'
 Set-Content -LiteralPath $ext -Value "subjectAltName=DNS:localhost`nextendedKeyUsage=serverAuth" -Encoding ascii
 Invoke-Checked openssl @('genrsa', '-out', $caKey, '2048')
 Invoke-Checked openssl @('req', '-x509', '-new', '-sha256', '-key', $caKey, '-days', '2', '-subj', '/CN=CD8 disposable CA', '-out', $ca)
 Invoke-Checked openssl @('genrsa', '-out', $key, '2048')
 Invoke-Checked openssl @('req', '-new', '-sha256', '-key', $key, '-subj', '/CN=localhost', '-out', $csr)
 Invoke-Checked openssl @('x509', '-req', '-sha256', '-in', $csr, '-CA', $ca, '-CAkey', $caKey, '-CAcreateserial', '-days', '2', '-extfile', $ext, '-out', $cert)
 Invoke-Checked docker @('run', '--detach', '--name', $container, '--label', "$labelKey=$runId", '--label', "$labelKey.pid=$PID", '--publish', '127.0.0.1::5432', '--env', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:16')
 $started = $true
 $ready = $false
 foreach ($attempt in 1..120) {
  $logs = (& docker logs $container 2>&1) -join "`n"
  if ([regex]::Matches($logs, 'database system is ready to accept connections').Count -ge 2) { $ready = $true; break }
  Start-Sleep -Milliseconds 500
 }
 if (-not $ready) { throw 'PostgreSQL initialization timeout' }
 Invoke-Checked docker @('cp', $key, "${container}:/tmp/cd8-server.key")
 Invoke-Checked docker @('cp', $cert, "${container}:/tmp/cd8-server.crt")
 Invoke-Checked docker @('exec', $container, 'chown', 'postgres:postgres', '/tmp/cd8-server.key', '/tmp/cd8-server.crt')
 Invoke-Checked docker @('exec', $container, 'chmod', '0600', '/tmp/cd8-server.key')
 Invoke-Sql postgres "ALTER SYSTEM SET ssl = 'on'"
 Invoke-Sql postgres "ALTER SYSTEM SET ssl_cert_file = '/tmp/cd8-server.crt'"
 Invoke-Sql postgres "ALTER SYSTEM SET ssl_key_file = '/tmp/cd8-server.key'"
 $hba = Join-Path $fixtureRoot 'pg_hba.conf'
 Set-Content -LiteralPath $hba -Encoding ascii -Value "local all all trust`nhostssl all all 0.0.0.0/0 trust`nhostssl all all ::/0 trust`nhostnossl all all 0.0.0.0/0 reject`nhostnossl all all ::/0 reject"
 Invoke-Checked docker @('cp', $hba, "${container}:/tmp/cd8-pg_hba.conf")
 Invoke-Sql postgres "ALTER SYSTEM SET hba_file = '/tmp/cd8-pg_hba.conf'"
 Invoke-Checked docker @('restart', $container)
 $ready = $false
 foreach ($attempt in 1..120) {
  & docker exec $container pg_isready -U postgres *> $null
  if ($LASTEXITCODE -eq 0) { $ready = $true; break }
  Start-Sleep -Milliseconds 500
 }
 if (-not $ready) { throw 'PostgreSQL TLS restart timeout' }
 $portRaw = (& docker port $container '5432/tcp' | Out-String).Trim()
 if ($LASTEXITCODE -ne 0 -or $portRaw -notmatch ':(?<port>\d+)$') { throw 'failed to resolve owned port' }
 $port = $Matches.port
 Invoke-Sql postgres 'CREATE ROLE object_dispatch_retention_owner NOLOGIN; CREATE ROLE object_dispatch_retention_runtime LOGIN; CREATE ROLE object_dispatch_retention_maintenance LOGIN; CREATE ROLE object_dispatch_retention_migrator LOGIN; GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator WITH INHERIT FALSE, SET TRUE;'
 [Environment]::SetEnvironmentVariable($envNames[1], $ca, 'Process')
 $index = 0
 $failures = @()
 foreach ($test in $tests) {
  $index++
  $db = "budget_$index"
  Invoke-Checked docker @('exec', $container, 'createdb', '-U', 'postgres', $db)
  Invoke-Sql $db "GRANT CREATE ON DATABASE $db TO object_dispatch_retention_owner"
  [Environment]::SetEnvironmentVariable($envNames[0], "postgresql://postgres@localhost:$port/${db}?sslmode=require", 'Process')
  Push-Location $loreRoot
  try {
   $cargoArgs = @('test', '-p', 'lore-object-dispatch', '--test', 'budget_configure_live', '-j', '4', '--', '--ignored', '--exact', $test, '--test-threads=1', '--nocapture')
   $output = & cargo @cargoArgs 2>&1 | Out-String
   $exit = $LASTEXITCODE
  } finally { Pop-Location }
  Write-Host $output
  if ($exit -ne 0 -or $output -notmatch '(?m)^running 1 test\r?$' -or $output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { $failures += $test }
 }
 if ($failures.Count -ne 0) { throw "FAIL/NOT RUN: $($failures -join ', ')" }
 $passed = $true
 Write-Host "$($tests.Count) passed; 0 failed; 0 skipped. Budget publication and verification only."
} finally {
 foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $prior[$name], 'Process') }
 if ($started -and ($passed -or -not $KeepOnFailure)) {
  $actual = (& docker inspect --format "{{ index .Config.Labels `"$labelKey`" }}" $container 2>$null | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $actual -ne $runId) { throw 'owned container label did not match; cleanup refused' }
  Invoke-Checked docker @('rm', '--force', '--volumes', $container)
 }
 if (($passed -or -not $KeepOnFailure) -and (Test-Path -LiteralPath $fixtureRoot)) {
  $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $fixtureRoot).Path)
  if ($resolved -ne $fixtureRoot -or -not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture cleanup path escaped owned root' }
  # Remove only this runner's named outputs; an unexpected file keeps the directory for inspection.
  foreach ($file in @('ca.key','ca.crt','ca.srl','server.key','server.csr','server.crt','server.ext','pg_hba.conf')) {
   $ownedFile = Join-Path $resolved $file
   if (Test-Path -LiteralPath $ownedFile -PathType Leaf) { Remove-Item -LiteralPath $ownedFile -Force }
  }
  Remove-Item -LiteralPath $resolved
 }
}
