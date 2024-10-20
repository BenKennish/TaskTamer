# Define the list of processes to suspend (without .exe)
$processesToSuspend = @(
    "brave",
    "chrome",
    "Spotify",
    "WhatsApp",
    "Signal",
    #"GoogleDriveFS", # seems to crash Explorer related stuff
    "notepad"   # for testing purposes, notepad is considered a process to suspend
)

# TODO: allow defining a whitelist of processes NOT to suspend and we suspend everything else
#       very likely to suspend things that will cause problems tho
# TODO: if user gives focus to any suspended process (before game has been closed), resume it temporarily.

# Define the list of game process names (without ".exe") to check
$gameProcessNames = @(
    "Overwatch",
    "Fortnite-Client-Win64-Shipping",  # doesn't seem to work, maybe as it runs as admin?
    "FortniteLauncher",
    "gw2-64",
    "CalculatorApp",  # for testing purposes, Calculator is considered a game
    "Time"  # for testing purposes, the Clock app ("Time.exe") is considered a game
)


# this will enable/disable the display of Write-Debug messages
#$DebugPreference = 'Continue'   #SilentlyContinue is the default

# Add necessary .NET assemblies for API calls
# using Add-Type cmdlet (C# code)
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
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    public const int SW_MINIMIZE = 6;


    public static void SuspendProcess(int pid)
    {
        var process = System.Diagnostics.Process.GetProcessById(pid);

        foreach (System.Diagnostics.ProcessThread thread in process.Threads)
        {
            IntPtr pOpenThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)thread.Id);

            if (pOpenThread != IntPtr.Zero)
            {
                if (SuspendThread(pOpenThread) == unchecked((uint)-1))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                CloseHandle(pOpenThread);
            }
            else
            {
                // If OpenThread failed, throw an exception
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
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
                if (ResumeThread(pOpenThread) == -1)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                CloseHandle(pOpenThread);
            }
            else
            {
                // If OpenThread failed, throw an exception
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }
    }

    public static int MinimizeProcessWindows(int pid)
    {
        var minimisedWindows = 0;

        // minimises the main window handle
        // possibly unnecessary as this window will be minimised below anyway
        var process = System.Diagnostics.Process.GetProcessById(pid);

        if (process.MainWindowHandle != IntPtr.Zero) // && !IsIconic(process.MainWindowHandle))
        {
            ShowWindow(process.MainWindowHandle, SW_MINIMIZE);
            minimisedWindows++;
        }

        // minimize other windows of the process
        // FIXME: doesn't seem to minimise all the windows
        foreach (var window in System.Diagnostics.Process.GetProcesses())
        {
            if (window.Id == pid
                && window.MainWindowHandle != IntPtr.Zero 
                //&& !IsIconic(window.MainWindowHandle)
                )
            {
                ShowWindow(window.MainWindowHandle, SW_MINIMIZE);
                minimisedWindows++;
            }
        }

        return minimisedWindows;
    }
}
"@



function Resume-Processes {

    foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name }) 
    {
        try 
        {
            [ProcessManager]::ResumeProcess($proc.Id)
            Write-Output "Resumed: $($proc.Name) ($($proc.Id))"
            # FIXME: processes suspended from a previous iteration of the script 
            # (e.g. interupted by Ctrl-C before the script does the resuming)
            # don't seem to resume ok and idk why.  maybe cos a different process suspended them?

        } 
        catch 
        {
            Write-Error "Failed to resume: $($proc.Name) ($($proc.Id)). Error: $_"
        }
    }
}


# change window appearance
$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host  # Clear the console to apply the new colors


Write-Output "/----------------\"
Write-Output "| Suspender v0.1 |"
Write-Output "\----------------/"
Write-Output ""


if ($args -contains "--resume-all")
{
    # Resume all processes first 
    # (used primarily for debugging when a previous script failed to resume processes)
    Resume-Processes
}


# should we run once or constantly?
$checkOnce = $false
if ($args -contains "--check-once") 
{
    $checkOnce = $true
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Checking for game processes once"
}
else
{
    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for game processes..."
}


# Used to store info on suspended process for resumption later
$suspendedProcesses = @()


try 
{
    while ($true)
    {
        $runningGameProcesses = Get-Process | Where-Object { $gameProcessNames -contains $_.Name }

        if ($runningGameProcesses)
        {

            foreach ($runningGameProcess in $runningGameProcesses) 
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Game detected: $($runningGameProcess.Name) ($($runningGameProcess.Id))"
            }

            # Minimise windows of all processes in the blacklist
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name }) 
            {
                try
                {
                    $minimisedWindows = [ProcessManager]::MinimizeProcessWindows($proc.Id);

                    if ($minimisedWindows)
                    {
                        Write-Host "Minimised: $($proc.Name) ($($proc.Id)) [$($minimisedWindows) windows]";
                    }
                }
                catch 
                {
                    Write-Host "!!!! Failed to minimise: $($proc.Name) ($($proc.Id)). Error: $_";
                }
            }

            # Optional: Wait a short time to ensure minimize commands are processed
            Start-Sleep -Milliseconds 2000

            # Suspend all processes in the blacklist
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name })
            {
                try
                {
                    [ProcessManager]::SuspendProcess($proc.Id)
                    Write-Output "Suspended: $($proc.Name) ($($proc.Id))"

                    # Store suspended process details..
                    $suspendedProcesses += [PSCustomObject]@{ Name = $proc.Name; Id = $proc.Id }
                }
                catch
                {
                    Write-Error "!!!! Failed to suspend: $($proc.Name) ($($proc.Id)). Error: $_"
                }
            }


            # Wait for the game(s) to exit
            foreach ($runningGameProcess in $runningGameProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for game $($runningGameProcess.Name) ($($runningGameProcess.Id)) to exit... "
                $runningGameProcess.WaitForExit()
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Exited"
            }

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so 
            # this isn't a priority to fix

            Resume-Processes

            $suspendedProcesses = @()  # Reset the array to an empty state
            # this is a bit hacky in case some didn't resume properly but if they didn't,
            # what are we going to do about it anyway?

            if (!$checkOnce)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for game processes after 2s..."
            }
            else
            {
                break
            }
        }
        else
        {
            if ($checkOnce)
            {
                Write-Output "No game process detected."
                break
            }
        }
        Start-Sleep -Seconds 2
    }
}
finally
{
    Write-Output "[$(Get-Date -Format 'HH:mm')] Shutting down..."

    # Ensure suspended processes are resumed if the script is terminated (e.g. Ctrl-C)
    foreach ($suspendedProcess in $suspendedProcesses)
    {
        [ProcessManager]::ResumeProcess($suspendedProcess.Id)
        Write-Output "Resumed: $($suspendedProcess.Name) ($($suspendedProcess.Id))"
    }
}