# Define the list of processes to suspend
$processesToSuspend = @(
    "brave",    # Replace with the actual process names (without .exe)
    "chrome",
    "Spotify",
    "WhatsApp",
    #"GoogleDriveFS", # seems to crashe Explorer related stuff
    "notepad"   # for testing purposes, notepad is considered a process worth of suspension
)

# TODO: allow defining a whitelist of processes NOT to suspend and we do suspend everything else

# TODO: if user gives focus to any suspended process, resume it temporarily.

# Define the list of game process names to check
$gameProcessNames = @(
    "Overwatch",  # Replace with your game's process name (without .exe)
    "gw2-64",
    "Fortnite-Client-Win64-Shipping",  # runs as admin
    "FortniteLauncher",
    "CalculatorApp"  # for testing purposes, Calculator is considered a game
)


# Add necessary .NET assemblies for API calls
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ProcessManager
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const int THREAD_SUSPEND_RESUME = 0x0002;

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    public const int SW_MINIMIZE = 6;

    public static void SuspendProcess(int pid)
    {
        var process = System.Diagnostics.Process.GetProcessById(pid);

        foreach (System.Diagnostics.ProcessThread thread in process.Threads)
        {
            IntPtr pOpenThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);

            if (pOpenThread != IntPtr.Zero)
            {
                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }
    }

    public static void ResumeProcess(int pid)
    {
        var process = System.Diagnostics.Process.GetProcessById(pid);

        foreach (System.Diagnostics.ProcessThread thread in process.Threads)
        {
            IntPtr pOpenThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);

            if (pOpenThread != IntPtr.Zero)
            {
                ResumeThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }
    }

    public static bool MinimizeProcessWindow(int pid)
    {
        var process = System.Diagnostics.Process.GetProcessById(pid);

        if (IsWindowVisible(process.MainWindowHandle))
        {
            ShowWindow(process.MainWindowHandle, SW_MINIMIZE);
            return true;  // Window was minimized
        }

        return false;  // No window was minimized
    }
}
"@


# should we run once or constantly?
$checkOnce = $false
if ($args -contains "--check-once") {
    $checkOnce = $true
    Write-Host "Checking for game processes once"
} else {
    Write-Host "Listening for game processes..."
}

# Used to store info on suspended process for resumption later
$suspendedProcesses = @()

try {
    while ($true) {

        $runningGameProcesses = Get-Process | Where-Object { $gameProcessNames -contains $_.Name }

        if ($runningGameProcesses) {

            foreach ($runningGameProcess in $runningGameProcesses) {
                Write-Host "**** Game detected: $($runningGameProcess.Name) ($($runningGameProcess.Id))"
            }

            # Suspend processes from the blacklist
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name }) {
                try {

                    if ([ProcessManager]::MinimizeProcessWindow($proc.Id)) {
                        Write-Host "Minimized: $($proc.Name) (PID $($proc.Id))"
                    }

                    [ProcessManager]::SuspendProcess($proc.Id)
                    Write-Host "Suspended: $($proc.Name) ($($proc.Id))"

                    # Store suspended process details..
                    $suspendedProcesses += [PSCustomObject]@{ Name = $proc.Name; Id = $proc.Id }
                } catch {
                    Write-Host "!!!! Failed to minimise/suspend: $($proc.Name) ($($proc.Id)). Error: $_"
                }
            }

            # Wait for the game(s) to exit
            foreach ($runningGameProcess in $runningGameProcesses) {
                Write-Host -NoNewline "**** Waiting for game $($runningGameProcess.Name) ($($runningGameProcess.Id)) to exit... "
                $runningGameProcess.WaitForExit()
                Write-Host "[Exited]"
            }


            # Resume suspended processes
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name }) {
                try {
                    [ProcessManager]::ResumeProcess($proc.Id)
                    Write-Host "Resumed: $($proc.Name) ($($proc.Id))"
                    # TODO: we could remove from $suspendedProcessIds one by one as they are resumed
                } catch {
                    Write-Host "Failed to resume: $($proc.Name) ($($proc.Id)). Error: $_"
                }
            }
            $suspendedProcesses = @()  # Reset the array to an empty state
            # this is a bit hacky in case some didn't resume properly but if they didn't, what are we going to do about it anyway?

            if (!$checkOnce) {
                Write-Host "Listening for game processes..."
            }

        } else {
            if ($checkOnce) {
                Write-Host "No game process detected."
                break
            }
        }

        Start-Sleep -Seconds 2
    }
}
finally {

    Write-Host "Shutting down..."

    # Ensure suspended processes are resumed if the script is terminated (e.g. Ctrl-C)
    foreach ($suspendedProcess in $suspendedProcesses) {
        [ProcessManager]::ResumeProcess($suspendedProcess.Id)
        Write-Host "Resumed: $($suspendedProcess.Name) ($($suspendedProcess.Id))"
    }
}