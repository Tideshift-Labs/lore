# Copyright 2026 Tideshift Labs
# SPDX-License-Identifier: MIT

# Same x64 Job Object layout and gated-start pattern as the desktop e2e runner.
# Keep the binding local: the Lore test runner must not depend on a sibling checkout.
if (-not ('NamespaceForegroundJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class NamespaceForegroundJob : IDisposable {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes, IntPtr name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int kind, byte[] info, int length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int kind, byte[] info, int length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    IntPtr handle;
    public NamespaceForegroundJob() {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("This test runner requires 64-bit Windows");
        handle = CreateJobObjectW(IntPtr.Zero, IntPtr.Zero);
        if (handle == IntPtr.Zero) throw new Win32Exception();
        byte[] info = new byte[144];
        BitConverter.GetBytes(0x2000u).CopyTo(info, 16); // KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(handle, 9, info, info.Length)) {
            var error = new Win32Exception(); Dispose(); throw error;
        }
    }
    public void Assign(IntPtr process) {
        if (!AssignProcessToJobObject(handle, process)) throw new Win32Exception();
    }
    public void Terminate() {
        if (!TerminateJobObject(handle, 124)) throw new Win32Exception();
    }
    public uint ActiveProcesses {
        get {
            byte[] info = new byte[48]; // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
            if (!QueryInformationJobObject(handle, 1, info, info.Length, IntPtr.Zero)) throw new Win32Exception();
            return BitConverter.ToUInt32(info, 40);
        }
    }
    public void Dispose() {
        if (handle == IntPtr.Zero) return;
        var closing = handle; handle = IntPtr.Zero;
        if (!CloseHandle(closing)) throw new Win32Exception();
    }
}
'@
}

function Invoke-ForegroundProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 600
    )
    $targetPath = (Get-Command $FilePath -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    # The launcher cannot create the target until the parent assigns it to the job
    # and supplies the JSON command on stdin. Descendants inherit membership at birth.
    $launcher = @'
$ErrorActionPreference = 'Stop'
$command = [Console]::In.ReadLine() | ConvertFrom-Json
if ($null -eq $command) { exit 125 }
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $command.FileName
$info.WorkingDirectory = $command.WorkingDirectory
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
foreach ($argument in $command.Arguments) { $info.ArgumentList.Add($argument) }
$target = [Diagnostics.Process]::Start($info)
$stdoutCopy = $target.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
$stderrCopy = $target.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
$target.WaitForExit()
[Threading.Tasks.Task]::WaitAll(@($stdoutCopy, $stderrCopy))
exit $target.ExitCode
'@
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    foreach ($argument in @('-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($launcher)))) {
        $startInfo.ArgumentList.Add($argument)
    }
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $startInfo
    $started = $false
    $job = [NamespaceForegroundJob]::new()
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    try {
        $started = $child.Start()
        if (-not $started) { throw "Could not start $FilePath" }
        # Drain both pipes concurrently so either stream can exceed the OS pipe buffer.
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        $job.Assign($child.Handle)
        $command = @{ FileName = $targetPath; WorkingDirectory = $WorkingDirectory; Arguments = $ArgumentList } | ConvertTo-Json -Compress
        $child.StandardInput.WriteLine($command)
        $child.StandardInput.Close()
        $timedOut = $false
        while (-not ($child.HasExited -and $stdout.IsCompleted -and $stderr.IsCompleted)) {
            if ($deadline.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                $job.Terminate()
                break
            }
            Start-Sleep -Milliseconds 25
        }
        $exitCode = if ($timedOut) { 124 } else { $child.ExitCode }
        # Detached helpers such as MSVC telemetry are cleanup work once the command
        # and its pipes finish, not a reason to wait for the command deadline.
        if (-not $timedOut -and $job.ActiveProcesses -ne 0) { $job.Terminate() }
        # Cleanup has its own finite grace after command completion. Do not claim
        # termination until the job is empty and every inherited pipe has closed.
        $cleanup = [Diagnostics.Stopwatch]::StartNew()
        while (-not ($child.HasExited -and $stdout.IsCompleted -and $stderr.IsCompleted -and $job.ActiveProcesses -eq 0)) {
            if ($cleanup.Elapsed.TotalSeconds -ge 5) { throw 'Owned job or output pipes did not settle within cleanup grace' }
            Start-Sleep -Milliseconds 25
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($timedOut) { $output += "`nTimed out after $TimeoutSeconds seconds; owned job is empty and output pipes are closed." }
        [pscustomobject]@{
            Output = $output
            ExitCode = $exitCode
            TimedOut = $timedOut
            ProcessId = $child.Id
        }
    }
    finally {
        $job.Dispose()
        if ($started -and -not $child.HasExited) {
            # Assignment may have failed while the launcher was still gated.
            $child.Kill($true)
            if (-not $child.WaitForExit(5000)) { Write-Warning "Owned launcher $($child.Id) did not exit during cleanup" }
        }
        $child.Dispose()
    }
}
