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
# Bound the time AFTER the deadline, not total wall: the helper's deadline clock starts before the
# child does, so launcher and fixture startup cost (which grows under load) is already inside the
# timeout. Past the deadline the helper may spend only its cleanup grace, plus scheduling slack.
$cleanupGraceSeconds = 5 # mirrors the cleanup grace in common/foreground_process.ps1
$schedulingSlackSeconds = 5
$postDeadlineLimit = $cleanupGraceSeconds + $schedulingSlackSeconds
# The deadline must cover launcher plus fixture pwsh startup under load, so the fixture can print
# DESCENDANT/PARENT_EXITING before it fires. The fixture's 60 s natural lifetime still puts a
# deadline-not-enforced regression ~40 s past the deadline, far over the limit above.
$timeoutCaseSeconds = 20
$elapsed = [Diagnostics.Stopwatch]::StartNew()
$timeout = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $childScript) $testRoot $timeoutCaseSeconds
$postDeadline = $elapsed.Elapsed.TotalSeconds - $timeoutCaseSeconds
if ($postDeadline -gt $postDeadlineLimit) { throw ('Parent-held timeout returned {0:N1}s after the deadline, over the {1}s cleanup grace plus slack' -f $postDeadline, $postDeadlineLimit) }
if ($timeout.ExitCode -ne 124 -or -not $timeout.TimedOut) { throw 'Deadline did not fail distinctly' }
if (Get-Process -Id $timeout.ProcessId -ErrorAction SilentlyContinue) { throw 'Timed-out child survived' }
if ($timeout.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Fixture did not start its descendant' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Timed-out descendant survived' }
$parentExitsFirst = $childScript -replace 'Start-Sleep -Seconds 60\s*$', '[Console]::Out.WriteLine("PARENT_EXITING=$PID"); [Console]::Out.WriteLine("PARENT_EXIT_TICKS=$([DateTime]::UtcNow.Ticks)"); exit 0'
$elapsed.Restart()
$orphan = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $parentExitsFirst) $testRoot $timeoutCaseSeconds
$postDeadline = $elapsed.Elapsed.TotalSeconds - $timeoutCaseSeconds
if ($postDeadline -gt $postDeadlineLimit) { throw ('Inherited pipe drain returned {0:N1}s after the deadline, over the {1}s cleanup grace plus slack' -f $postDeadline, $postDeadlineLimit) }
if ($orphan.ExitCode -ne 124 -or -not $orphan.TimedOut) { throw 'Parent exit concealed a live descendant or inherited pipe' }
if ($orphan.Output -notmatch 'PARENT_EXITING=(\d+)') { throw 'Fixture parent did not reach its exit' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Exited fixture parent survived' }
if ($orphan.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Parent-exits-first fixture did not start a descendant' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Descendant outlived exited parent and job cleanup' }
if ($orphan.Output -notmatch 'owned job is empty and output pipes are closed') { throw 'Missing verified cleanup result' }
$detachedOutput = $parentExitsFirst -replace '\$info.CreateNoWindow = \$true', '$info.CreateNoWindow = $true; $info.UseShellExecute = $true; $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden'
$completedCaseSeconds = 20
$completed = Invoke-ForegroundProcess pwsh @('-NoProfile', '-Command', $detachedOutput) $testRoot $completedCaseSeconds
$returnedTicks = [DateTime]::UtcNow.Ticks
if ($completed.ExitCode -ne 0 -or $completed.TimedOut) { throw 'Completed command was changed into a timeout by its detached helper, or slow fixture startup reached the deadline' }
# The fixture's own startup is load-sensitive, so measure from the parent's exit to the helper's
# return instead of total wall. A helper that waited for the detached process would add ~60s here.
if ($completed.Output -notmatch 'PARENT_EXIT_TICKS=(\d+)') { throw 'Normal-completion fixture did not report its parent exit time' }
$exitToReturn = ($returnedTicks - [int64]$Matches[1]) / [TimeSpan]::TicksPerSecond
if ($exitToReturn -lt 0) { throw ('Helper returned {0:N1}s before the fixture parent exited' -f $exitToReturn) }
if ($exitToReturn -gt $postDeadlineLimit) { throw ('Completed command returned {0:N1}s after parent exit, over the {1}s cleanup grace plus slack; it waited for the detached helper' -f $exitToReturn, $postDeadlineLimit) }
if ($completed.Output -notmatch 'PARENT_EXITING=(\d+)') { throw 'Normal-completion fixture did not reach parent exit' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Completed parent survived' }
if ($completed.Output -notmatch 'DESCENDANT=(\d+)') { throw 'Normal-completion fixture did not start its detached helper' }
if (Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue) { throw 'Detached helper survived successful command cleanup' }
Write-Host 'PASS: output drain, exit code, parent-held timeout, inherited-pipe timeout, and normal completion with detached-helper cleanup (5 cases)'
