# List of names of processes (without ".exe") to suspend a.k.a. target processes
$processesToSuspend = @(
    "brave",
    "chrome",
    "Spotify",
    "WhatsApp",
    "Signal",
    #"GoogleDriveFS", # seems to crash Explorer related stuff
    "notepad"   # for testing purposes, notepad is considered a process to suspend
)

# TODO: show a pause icon in notification area when suspending and a play icon when resuming
# TODO: allow defining a whitelist of processes NOT to suspend and we suspend everything else
#       note: very likely to suspend things that will cause problems tho
# TODO: if user gives focus to any suspended process (before game has been closed), resume it temporarily.
#       this gets quite complicated to do in a way that doesn't potentially increase load on the system
#       as it can require repeatedly polling in a while() loop
#       OR perhaps just detect when a game loses focus and then unsuspend and resuspend when it gains focus again


# List of names of processes (without ".exe") to check, a.k.a. trigger processes (e.g. video games)
$gameProcessNames = @(
    "Overwatch",
    "FortniteLauncher",
    "RocketLeague",
    "gw2-64",
    "CalculatorApp",  # for testing purposes
    "Solitaire"  # for testing purposes
)


# TODO: run user configurable list of commands when detecting a game (unimplemented)
$cmdsToRunOnGameLaunch = @(
    "wsl --shutdown"
)

# this will enable/disable the display of Write-Debug messages
#$DebugPreference = 'Continue'   #SilentlyContinue is the default


# map process PIDs to RAM (bytes) usages
$pidRAMUsages = @{
    #e.g 6231 = 38125123
}


# Add necessary .NET assemblies for API calls
# using Add-Type cmdlet (C# code)
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

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
        var numWindowsMinimised = 0;

        // minimises the main window handle
        // possibly unnecessary as this window will be minimised below anyway
        var process = System.Diagnostics.Process.GetProcessById(pid);

        if (process.MainWindowHandle != IntPtr.Zero) // && !IsIconic(process.MainWindowHandle))
        {
            if (!ShowWindow(process.MainWindowHandle, SW_MINIMIZE))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                //int errorCode = Marshal.GetLastWin32Error();
                //Console.WriteLine("Failed to minimize window for process "+process.ProcessName+". Error code: "+errorCode);
            }
            else
            {
                numWindowsMinimised++;
            }
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
                if (!ShowWindow(window.MainWindowHandle, SW_MINIMIZE))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    //int errorCode = Marshal.GetLastWin32Error();
                    //Console.WriteLine("Failed to minimize window for process "+process.ProcessName+". Error code: "+errorCode);
                }
                numWindowsMinimised++;
            }
        }

        return numWindowsMinimised;
    }
}
"@


function Install-and-Import-Module
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue))
    {
        try
        {
            Install-Module -Name $Name -Scope CurrentUser -Force -ErrorAction Stop
            #Write-Output "Module $Name installed successfully."
        }
        catch
        {
            Write-Error "!!! Failed to install $Name module."
            exit 1
        }
    }

    Import-Module $Name

    if (-not (Get-Module -Name $Name))
    {
        Write-Error "!!! Failed to import $Name module."
        exit 1
    }
    else
    {
        #Write-Output "$Name module is installed and imported."
    }
}


function Bytes-HumanReadable
{
    param (
        [Parameter(Mandatory=$true)] [double]$Bytes,
        [int]$DecimalDigits = 1,
        [bool]$DisplayPlus = $false
    )

    $units = @("B", "KB", "MB", "GB", "TB", "PB")
    $unitIndex = 0

    if ($Bytes -eq 0)
    {
        return "0"
    }

    while ([Math]::Abs($Bytes) -ge 1024 -and $unitIndex -lt $units.Length - 1)
    {
        $Bytes /= 1024
        $unitIndex++
    }

    $formattedResult = "{0:N$($DecimalDigits)} {1}" -f $Bytes, $units[$unitIndex]

    if ($DisplayPlus -and $Bytes -gt 0)
    {
        # add a "+" at start if requested
        $formattedResult = "+$formattedResult"
    }

    return $formattedResult
}


function Resume-Processes
{
    # used to track how the RAM usage of all suspended processes changed
    $totalRAMDelta = 0

    foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name }) 
    {
        try 
        {
            if ($pidRAMUsages)
            {
                $prevRamUsage = $pidRAMUsages[$proc.Id]
                $currRamUsage = $proc.WorkingSet64
                # done before resuming process in case resuming causes immediate swapping from page file to RAM

                $delta = $currRamUsage - $prevRamUsage
                $totalRAMDelta += $delta

                $currRamUsageHR = Bytes-HumanReadable -Bytes $currRamUsage
                $deltaHR = Bytes-HumanReadable -Bytes $delta -DisplayPlus $true
            }

            [ProcessManager]::ResumeProcess($proc.Id)

            if ($pidRAMUsages)
            {
                Write-Output "Resumed: $($proc.Name) ($($proc.Id)) - $($currRamUsageHR) RAM [$($deltaHR)]"
            }
            else
            {
                Write-Output "Resumed: $($proc.Name) ($($proc.Id))"
            }

            # FIXME: processes suspended from a previous iteration of the script 
            # (e.g. interupted by Ctrl-C before the script does the resuming)
            # don't seem to resume ok and idk why.  maybe cos a different process suspended them?

        } 
        catch 
        {
            Write-Error "Failed to resume: $($proc.Name) ($($proc.Id)). Error: $_"
        }
    }

    $totalRAMDeltaHR = Bytes-HumanReadable -Bytes $totalRAMDelta -DisplayPlus $true
    Write-Output "Total RAM usage change during suspension: $($totalRAMDeltaHR)"
}


Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force  #prevents issues when this script runs as compiled exe
Install-and-Import-Module -Name "BurntToast"


# change window appearance
$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host  # Clear the console to apply the new colors

Write-Output "/--------------------\"
Write-Output "| AutoSuspender v0.5 |"
Write-Output "\--------------------/"
Write-Output ""

if ($args -contains "--resume-all")
{
    # Resume all processes first 
    # (used primarily for debugging when a previous script failed to resume processes)
    Resume-Processes
}


# should we run once or constantly?
# e.g. use this if the script will be run whenever a new process is ran on the system
$checkOnce = $false
if ($args -contains "--check-once") 
{
    $checkOnce = $true
}

# Used to store info on suspended process for resumption later
$suspendedProcesses = @()


# Define the full path to the icon files using 
# the path of the folder where the script is located
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$pauseIconPath = Join-Path -Path $scriptDirectory -ChildPath "/images/pause.ico"
$playIconPath = Join-Path -Path $scriptDirectory -ChildPath "/images/play.ico"

# did we sit idle last time around the while() loop?
$wasIdleLastLoop = $false

try 
{
    while ($true)
    {
        if (-not ($wasIdleLastLoop))
        {
            if ($checkOnce)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Checking for game processes..."
            }
            else
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for game processes..."
            }
        }

        $wasIdleLastLoop = $true
        $runningGameProcesses = Get-Process | Where-Object { $gameProcessNames -contains $_.Name }

        if ($runningGameProcesses)
        {
            $wasIdleLastLoop = $false

            foreach ($runningGameProcess in $runningGameProcesses) 
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningGameProcess.Name) ($($runningGameProcess.Id))"
                New-BurntToastNotification -Text "$($runningGameProcess.Name) is running", "AutoSuspender is minimising and suspending target processes to improve performance." -AppLogo $pauseIconPath
            }

            # Minimise windows of all target processes
            # FIXME: doesn't seem to work for certain apps (e.g. Microsoft Store apps)
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name })
            {
                try
                {
                    $numWindowsMinimised = [ProcessManager]::MinimizeProcessWindows($proc.Id);

                    if ($numWindowsMinimised)
                    {
                        Write-Output "Minimised: $($proc.Name) ($($proc.Id)) [$($numWindowsMinimised) windows]";
                    }
                }
                catch
                {
                    Write-Output "!!!! Failed to minimise: $($proc.Name) ($($proc.Id)). Error: $_";
                }
            }

            # Optional: Wait a short time to ensure minimize commands are processed
            Start-Sleep -Milliseconds 1500

            # Suspend all target processes
            foreach ($proc in Get-Process | Where-Object { $processesToSuspend -contains $_.Name })
            {
                try
                {
                    $ramUsage = $proc.WorkingSet64
                    $pidRAMUsages[$proc.Id] = $ramUsage
                    #HR = human readable
                    $ramUsageHR = Bytes-HumanReadable -Bytes $proc.WorkingSet64

                    [ProcessManager]::SuspendProcess($proc.Id)
                    Write-Output "Suspended: $($proc.Name) ($($proc.Id)) - $($ramUsageHR) RAM"

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
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningGameProcess.Name) ($($runningGameProcess.Id)) to exit..."
                $runningGameProcess.WaitForExit()
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Exited"
            }

            New-BurntToastNotification -Text "$($runningGameProcess.Name) exited", "AutoSuspender is resuming target processes." -AppLogo $playIconPath

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so 
            # this isn't a priority to fix

            Resume-Processes

            $suspendedProcesses = @()  # Reset the array to an empty state
            # this is a bit hacky in case some didn't resume properly but if they didn't,
            # what are we going to do about it anyway?

            if ($checkOnce)
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

        if (-not ($wasIdleLastLoop))
        {
            Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Sleeping for 2 seconds..."
            Start-Sleep -Seconds 2
        }

    }
}
catch 
{
    Write-Error "!!!! An error occurred: $_"
    Write-Output "Press Enter to exit."
    Read-Host
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

    # reset window appearance?
    #$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
    #$Host.UI.RawUI.ForegroundColor = 'White'
    #Clear-Host  # Clear the console to apply the new colors

}