# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
Run WP118 repository-create metadata transaction tests on owned PostgreSQL16.
.DESCRIPTION
Each ignored test receives a fresh database. Provider observations are fixture-only;
the separate single-server RPC tier proves actual provider uploads.
#>
[CmdletBinding()]
param([switch]$KeepOnFailure, [switch]$LegacyProjection)
$ErrorActionPreference='Stop'
$loreRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$runId=[Guid]::NewGuid().ToString('N')
$name="lore-create-metadata-$runId"
$label='com.tideshift.lore.create-metadata-tests'
$saved=[Environment]::GetEnvironmentVariable('LORE_TEST_PG_URL','Process')
$created=$false
$passed=$false
$results=[Collections.Generic.List[object]]::new()
function Checked([string]$program,[string[]]$arguments){ & $program @arguments; if($LASTEXITCODE -ne 0){throw "$program exited $LASTEXITCODE"} }
function Invoke-CargoCaptured([string[]]$arguments){$output=(& cargo @arguments 2>&1|Out-String);$code=$LASTEXITCODE;if($code -ne 0){throw "cargo exited ${code}:`n$output"};return $output}
Push-Location $loreRoot
try {
    $catalog=Invoke-CargoCaptured @('test','-p','lore-postgres','--test','domain_repository_create_metadata','-j4','--','--ignored','--list')
    $names=@([regex]::Matches($catalog,'(?m)^([a-z0-9_]+): test\r?$')|ForEach-Object{$_.Groups[1].Value})
    $source=Get-Content -Raw (Join-Path $PSScriptRoot 'domain_repository_create_metadata.rs')
    $expected=@([regex]::Matches($source,'#\[ignore[^\]]*\]\s*async fn ([a-z0-9_]+)')|ForEach-Object{$_.Groups[1].Value})
    if($names.Count -eq 0 -or $expected.Count -eq 0 -or @(Compare-Object $names $expected).Count -ne 0){throw 'compiled/source inventory mismatch'}
    foreach($test in $names){$results.Add([pscustomobject]@{Test=$test;Status='NOT RUN'})}
    $created=$true
    Checked docker @('run','-d','--name',$name,'--label',"$label=$runId",'--label',"$label.pid=$PID",'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine')
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    do{$logs=(& docker logs $name 2>&1)-join "`n";if([regex]::Matches($logs,'database system is ready to accept connections').Count -ge 2){break};if([DateTime]::UtcNow -ge $deadline){throw 'PostgreSQL readiness deadline'};Start-Sleep -Milliseconds 200}while($true)
    $port=((& docker port $name '5432/tcp')-split ':')[-1].Trim()
    $index=0
    foreach($result in $results){
        $database="metadata_$index";$index++
        Checked docker @('exec',$name,'createdb','-U','postgres',$database)
        $env:LORE_TEST_PG_URL="postgresql://postgres@127.0.0.1:$port/$database`?sslmode=disable"
        try{$output=Invoke-CargoCaptured @('test','-p','lore-postgres','--test','domain_repository_create_metadata','-j4','--','--ignored','--exact',$result.Test,'--nocapture');Write-Host $output;if($output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;'){throw 'expected exactly one test'};$result.Status='PASS'}catch{$result.Status='FAIL';Write-Warning $_}
    }
    $passed=@($results|Where-Object Status -ne 'PASS').Count -eq 0
    if(-not $passed){throw 'repository create metadata tests failed'}
    if($LegacyProjection){
        # Reuse the existing oracle on this runner's disposable backend, never its shared default.
        Checked pwsh @('-NoProfile','-File',(Join-Path $loreRoot 'lore-server/tests/run-p12-live.ps1'),'-OnlyCase','governed_create_projection_rows_match_the_legacy_writers_exactly','-PgContainer',$name,'-PgHost','127.0.0.1','-PgPort',$port,'-PgUser','postgres','-PgPassword','fixture')
    }
}finally{
    $results|Format-Table -AutoSize|Out-String -Width 200|Write-Host
    [Environment]::SetEnvironmentVariable('LORE_TEST_PG_URL',$saved,'Process')
    if($created){if($KeepOnFailure -and -not $passed){Write-Host "Retained owned container $name"}else{$inspect=& docker inspect $name 2>$null;if($LASTEXITCODE -eq 0){$container=@($inspect|ConvertFrom-Json)[0];if($container.Config.Labels.$label -ne $runId -or $container.Config.Labels."$label.pid" -ne "$PID"){throw 'container ownership changed'};Checked docker @('rm','--force','--volumes',$name)}}}
    Pop-Location
}
