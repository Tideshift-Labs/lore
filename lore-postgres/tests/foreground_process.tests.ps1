# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common/foreground_process.ps1')
$testRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ok = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', '[Console]::Out.Write("a" * 100000); [Console]::Error.Write("b" * 100000)') $testRoot 20
if ($ok.ExitCode -ne 0 -or $ok.TimedOut -or $ok.Output.Length -ne 200000) { throw 'Pipe-draining success case failed' }
$failed = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', 'exit 9') $testRoot 20
if ($failed.ExitCode -ne 9 -or $failed.TimedOut) { throw 'Nonzero exit was lost' }
$childScript = @'
$info = [Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.ArgumentList.Add('-NoProfile')
$info.ArgumentList.Add('-Command')
$info.ArgumentList.Add('Start-Sleep -Seconds 60')
$descendant = [Diagnostics.Process]::Start($info)
[Console]::Out.WriteLine("DESCENDANT=$($descendant.Id)")
Start-Sleep -Seconds 60
'@
$elapsed = [Diagnostics.Stopwatch]::StartNew()
# Allow the gated launcher and fixture's PowerShell startup before asserting cleanup.
$timeout = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $childScript) $testRoot 8
if ($elapsed.Elapsed.TotalSeconds -gt 14) { throw 'Parent-held timeout exceeded deadline plus bounded cleanup grace' }
if ($timeout.ExitCode -ne 124 -or -not $timeout.TimedOut) { throw 'Deadline did not fail distinctly' }
if (Get-Process -Id $timeout.ProcessId -ErrorAction SilentlyContinue) { throw 'Timed-out child survived' }
if ($timeout.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Fixture did not start its descendant' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Timed-out descendant survived' }
$parentExitsFirst = $childScript -replace 'Start-Sleep -Seconds 60\s*$', '[Console]::Out.WriteLine("PARENT_EXITING=$PID"); exit 0'
$elapsed.Restart()
$orphan = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $parentExitsFirst) $testRoot 8
if ($elapsed.Elapsed.TotalSeconds -gt 14) { throw 'Inherited pipe drain exceeded deadline plus bounded cleanup grace' }
if ($orphan.ExitCode -ne 124 -or -not $orphan.TimedOut) { throw 'Parent exit concealed a live descendant or inherited pipe' }
if ($orphan.Output -notmatch 'PARENT_EXITING=(\d+)') { throw 'Fixture parent did not reach its exit' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Exited fixture parent survived' }
if ($orphan.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Parent-exits-first fixture did not start a descendant' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Descendant outlived exited parent and job cleanup' }
if ($orphan.Output -notmatch 'owned job is empty and output pipes are closed') { throw 'Missing verified cleanup result' }
$detachedOutput = $parentExitsFirst -replace '\$info.CreateNoWindow = \$true', '$info.CreateNoWindow = $true; $info.UseShellExecute = $true; $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden'
$elapsed.Restart()
$completed = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $detachedOutput) $testRoot 20
if ($completed.ExitCode -ne 0 -or $completed.TimedOut) { throw 'Completed command was changed into a timeout by its detached helper' }
if ($elapsed.Elapsed.TotalSeconds -gt 14) { throw 'Completed command waited for detached helper instead of bounded cleanup' }
if ($completed.Output -notmatch 'PARENT_EXITING=(\d+)') { throw 'Normal-completion fixture did not reach parent exit' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Completed parent survived' }
if ($completed.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Normal-completion fixture did not start its detached helper' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Detached helper survived successful command cleanup' }
Write-Host 'PASS: output drain, exit code, parent-held timeout, inherited-pipe timeout, and normal completion with detached-helper cleanup (5 cases)'
