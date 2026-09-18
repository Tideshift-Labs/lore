# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
# CD-6 real SDK retry proof against an owned TLS PostgreSQL fixture.
[CmdletBinding()]
param([switch]$KeepOnFailure)
$ErrorActionPreference = 'Stop'
$runId = [Guid]::NewGuid().ToString('N')
$container = "wp115-fragment-retry-live-$runId"
$labelKey = 'com.tideshift.lore.fragment-retry-live'
$loreRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) $container))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
$started = $false
$passed = $false
$envNames = @('LORE_TEST_RETRY_PG_URL', 'LORE_TEST_RETRY_RUNTIME_URL', 'LORE_TEST_RETRY_CA_PATH', 'LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL', 'LORE_CELL_BUDGET_MAINTENANCE_URL', 'LORE_CELL_BUDGET_CA_PEM')
$prior = @{}
foreach ($name in $envNames) { $prior[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$testPrefix = 'store::fragment_transport::tests::'
$ordinaryTest = "${testPrefix}resolved_sdk_retries_are_rejected_before_any_http_request"
$liveTest = "${testPrefix}real_sdk_hidden_retry_is_counted_and_closes_the_governed_ledger"
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
  $catalog = & cargo test -p lore-postgres --lib -j 4 -- --list 2>&1 | Out-String
  $catalogExit = $LASTEXITCODE
  foreach ($test in @($ordinaryTest, $liveTest)) {
   if ($catalogExit -ne 0 -or $catalog -notmatch "(?m)^$([regex]::Escape($test)): test\r?$") { throw "required retry test absent; no fixture created`n$catalog" }
  }
  $listed = @([regex]::Matches($catalog, '(?m)^(store::fragment_transport::tests::[^\r\n]+): test\r?$') | ForEach-Object { $_.Groups[1].Value })
  if ($listed.Count -ne 2 -or @(Compare-Object @($ordinaryTest, $liveTest) $listed).Count -ne 0) { throw "retry test inventory differs from runner; no fixture created`n$catalog" }
  Invoke-Checked cargo @('build', '-p', 'lore-object-dispatch', '--bin', 'cell-schema-install', '--bin', 'cell-budget-configure', '-j', '4')
  $ordinary = & cargo test -p lore-postgres --lib -j 4 -- --exact $ordinaryTest --nocapture 2>&1 | Out-String
  $ordinaryExit = $LASTEXITCODE
  Write-Host $ordinary
  if ($ordinaryExit -ne 0 -or $ordinary -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { throw 'constructor test did not pass exactly once' }
 } finally { Pop-Location }
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
 Invoke-Checked openssl @('req', '-x509', '-new', '-sha256', '-key', $caKey, '-days', '2', '-subj', '/CN=CD6 disposable CA', '-out', $ca)
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
 Invoke-Checked docker @('cp', $key, "${container}:/tmp/cd6-server.key")
 Invoke-Checked docker @('cp', $cert, "${container}:/tmp/cd6-server.crt")
 Invoke-Checked docker @('exec', $container, 'chown', 'postgres:postgres', '/tmp/cd6-server.key', '/tmp/cd6-server.crt')
 Invoke-Checked docker @('exec', $container, 'chmod', '0600', '/tmp/cd6-server.key')
 Invoke-Sql postgres "ALTER SYSTEM SET ssl = 'on'"
 Invoke-Sql postgres "ALTER SYSTEM SET ssl_cert_file = '/tmp/cd6-server.crt'"
 Invoke-Sql postgres "ALTER SYSTEM SET ssl_key_file = '/tmp/cd6-server.key'"
 $hba = Join-Path $fixtureRoot 'pg_hba.conf'
 Set-Content -LiteralPath $hba -Encoding ascii -Value "local all all trust`nhostssl all all 0.0.0.0/0 trust`nhostssl all all ::/0 trust`nhostnossl all postgres,object_dispatch_retention_migrator 0.0.0.0/0 trust`nhostnossl all all 0.0.0.0/0 reject`nhostnossl all postgres,object_dispatch_retention_migrator ::/0 trust`nhostnossl all all ::/0 reject"
 Invoke-Checked docker @('cp', $hba, "${container}:/tmp/cd6-pg_hba.conf")
 Invoke-Sql postgres "ALTER SYSTEM SET hba_file = '/tmp/cd6-pg_hba.conf'"
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
 $db = 'retry_conformance'
 Invoke-Checked docker @('exec', $container, 'createdb', '-U', 'postgres', $db)
 Invoke-Sql $db "GRANT CREATE ON DATABASE $db TO object_dispatch_retention_owner"
 $identityRaw = & docker exec $container psql -v ON_ERROR_STOP=1 -U postgres -d $db -At -F '|' -c "SELECT system_identifier::text, (SELECT oid FROM pg_database WHERE datname=current_database()) FROM pg_control_system()"
 if ($LASTEXITCODE -ne 0 -or ($identityRaw | Out-String).Trim() -notmatch '^(?<system>\d+)\|(?<oid>\d+)$') { throw 'failed to read disposable database identity' }
 $systemIdentifier = $Matches.system
 $databaseOid = [uint32]$Matches.oid
 $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
 $budgetPath = Join-Path $fixtureRoot 'budget.json'
 @{
  schemaRevision = 'local-cell-budget-policy-v1'
  provenance = 'operator-selected-local-development-limit-v1'
  cellId = 'retry-conformance-cell'
  providerBoundaryId = 'retry-conformance-boundary'
  providerEndpoint = 'http://127.0.0.1'
  providerBucket = 'retry-conformance-fragments'
  evidenceReference = 'disposable-CD6-retry-conformance-fixture'
  systemIdentifier = $systemIdentifier
  databaseOid = $databaseOid
  allocationRevision = 'retry-conformance-r1'
  allocationFence = 1
  issuedAtUnixMs = $now
  hardExpiresAtUnixMs = $now + 600000
  sharedUnits = 100
  classUnits = 20
  listUnits = 5
  refillIntervalMs = 60000
  predecessor = $null
 } | ConvertTo-Json | Set-Content -LiteralPath $budgetPath -Encoding utf8NoBOM
 [Environment]::SetEnvironmentVariable('LORE_TEST_RETRY_PG_URL', "postgresql://postgres@localhost:$port/${db}?sslmode=disable", 'Process')
 [Environment]::SetEnvironmentVariable('LORE_TEST_RETRY_RUNTIME_URL', "postgresql://object_dispatch_retention_runtime@localhost:$port/${db}?sslmode=require", 'Process')
 [Environment]::SetEnvironmentVariable('LORE_TEST_RETRY_CA_PATH', $ca, 'Process')
 [Environment]::SetEnvironmentVariable('LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL', "postgresql://object_dispatch_retention_migrator@localhost:$port/${db}?sslmode=disable", 'Process')
 [Environment]::SetEnvironmentVariable('LORE_CELL_BUDGET_MAINTENANCE_URL', "postgresql://object_dispatch_retention_maintenance@localhost:$port/${db}?sslmode=require", 'Process')
 [Environment]::SetEnvironmentVariable('LORE_CELL_BUDGET_CA_PEM', (Get-Content -Raw -LiteralPath $ca), 'Process')
 Push-Location $loreRoot
 try {
  Invoke-Checked cargo @('run', '-p', 'lore-object-dispatch', '--bin', 'cell-schema-install', '--', 'install')
  Invoke-Checked cargo @('run', '-p', 'lore-object-dispatch', '--bin', 'cell-budget-configure', '--', 'publish', $budgetPath)
  Invoke-Checked cargo @('run', '-p', 'lore-object-dispatch', '--bin', 'cell-budget-configure', '--', 'verify', $budgetPath)
  $output = & cargo test -p lore-postgres --lib -j 4 -- --ignored --exact $liveTest --test-threads=1 --nocapture 2>&1 | Out-String
  $testExit = $LASTEXITCODE
 } finally { Pop-Location }
 Write-Host $output
 if ($testExit -ne 0 -or $output -notmatch '(?m)^running 1 test\r?$' -or $output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') { throw 'live retry proof did not pass exactly once' }
 $passed = $true
 Write-Host '2 passed; 0 failed; 0 skipped. Constructor rejection and real hidden retry ledger closure.'
} finally {
 foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $prior[$name], 'Process') }
 if ($started -and ($passed -or -not $KeepOnFailure)) {
  $actual = (& docker inspect --format "{{ index .Config.Labels `"$labelKey`" }}" $container 2>$null | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $actual -ne $runId) { throw 'owned container label did not match; cleanup refused' }
  $actualPid = (& docker inspect --format "{{ index .Config.Labels `"$labelKey.pid`" }}" $container 2>$null | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $actualPid -ne "$PID") { throw 'owned container PID label did not match; cleanup refused' }
  Invoke-Checked docker @('rm', '--force', '--volumes', $container)
 }
 if (($passed -or -not $KeepOnFailure) -and (Test-Path -LiteralPath $fixtureRoot)) {
  $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $fixtureRoot).Path)
  if ($resolved -ne $fixtureRoot -or -not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture cleanup path escaped owned root' }
  # Remove only this runner's named outputs; an unexpected file keeps the directory for inspection.
  foreach ($file in @('ca.key','ca.crt','ca.srl','server.key','server.csr','server.crt','server.ext','pg_hba.conf','budget.json')) {
   $ownedFile = Join-Path $resolved $file
   if (Test-Path -LiteralPath $ownedFile -PathType Leaf) { Remove-Item -LiteralPath $ownedFile -Force }
  }
  try {
   [IO.Directory]::Delete($resolved, $false)
  } catch [IO.IOException] {
   if ([IO.Directory]::Exists($resolved) -and @([IO.Directory]::EnumerateFileSystemEntries($resolved)).Count -gt 0) {
    Write-Warning "Unexpected fixture files remain; retained for inspection: $resolved"
   } else {
    throw
   }
  }
 }
}
