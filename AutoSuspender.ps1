# AutoSuspender
#
# Automatically suspend chosen target processes (and minimise their windows) 
# whenever chosen trigger processes (e.g. video games) are running, and 
# automatically resume the target processes when the trigger process closes.


# TODO: allow defining a whitelist of processes NOT to suspend and we suspend everything else
#       note: very likely to suspend things that will cause problems tho
#
# TODO: if user gives focus to any suspended process (before game has been closed), resume it temporarily.
#       this gets quite complicated to do in a way that doesn't potentially increase load on the system
#       as it can require repeatedly polling in a while() loop
#       OR perhaps just detect when a game loses focus and then unsuspend everything and resuspend them when it gains focus again
#       OR they could just manually ctrl-C the script and then run it again before restoring the game app
#
# TODO: allow setting CPU priority to Low for certain processes (and restore current priority when trigger process closes)
#       rather than suspending them using $proc.PriorityClass property
#
# TODO: run user configurable list of commands when detecting a game?

# List of names of processes (without ".exe") to suspend: target processes
$targetProcessNames = @(
    "brave",
    "chrome",
    "Spotify",
    "WhatsApp",
    "Signal",
    "java", #for Minecraft - NOTE: will also trigger everything else Java!
    "Minecraft",
    #"GoogleDriveFS", # seems to crash Explorer related stuff, presumably when it accesses the virtual drive
    "notepad"   # for testing purposes, notepad is considered a process to suspend
)


# List of names of processes (without ".exe") to check: trigger processes (e.g. video games)
$triggerProcessNames = @(
    "Overwatch",
    "FortniteLauncher",
    "RocketLeague",
    "gw2-64",
    "CalculatorApp", # for testing purposes
    "Solitaire"      # for testing purposes
)
# TODO make this a hashmap like "gw2-64" => "Guild Wars 2"
# and use the value for display purposes

# this will enable/disable the display of Write-Debug messages
#$DebugPreference = 'Continue'   #SilentlyContinue is the default


# map process PIDs to RAM (bytes) usages
# this is a hash table, not an array
# used to remember the RAM usage of target processes 
# just prior to suspension
$pidRamUsages = @{}


# Process, PID, RAM, deltaRAM, Notes
$tableFormat = "{0,-11} {1,-6} {2,10} {3,11} {4,-10}"


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


# -----------------------------------------------------------------------------
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
}


# -----------------------------------------------------------------------------
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



# display a subtotal row for the previous processes if there was more than 1 with same name
function Process-Subtotal
{
    param (
        [int]$sameProcessCount,
        [int64]$sameProcessRamTotal,
        [int64]$sameProcessRamDeltaTotal,
        [string]$lastProcessName
    )

    if ($sameProcessCount -gt 1)
    {
        $sameProcessRamTotalHR = Bytes-HumanReadable -Bytes $sameProcessRamTotal    

        if ($sameProcessRamDeltaTotal -ne 0)
        {
            $sameProcessRamDeltaTotalHR = Bytes-HumanReadable -Bytes $sameProcessRamDeltaTotal -DisplayPlus $true
        }
        else
        {
            $sameProcessRamDeltaTotalHR = ""
        }
        Write-Host ($tableFormat -f "$lastProcessName +", "-----", $sameProcessRamTotalHR, $sameProcessRamDeltaTotalHR, $dryRunText) -ForegroundColor Yellow

    }
}



# functionised as used in multiple locations
# TODO: repurpose this as a function for both suspend and resume operations
# as lots of code duplication
# -----------------------------------------------------------------------------
function Resume-Processes
{

    $lastProcessName = ""
    $sameProcessCount = 0
    $sameProcessRamTotal = 0

    # used to track how the RAM usage of all suspended processes changed 
    # over the lifetime of the trigger process
    $totalRamDelta = 0
    $sameProcessRamDeltaTotal = 0

    # Write-Host used over Write-Output as this function can be called
    # once the script is terminating and it then has no access to Write-Output pipeline
    Write-Host "Resuming processes..."
    Write-Host ($tableFormat -f "Name", "PID", "RAM", "Change", "")


    # we don't look at suspendedProcesses array but just do another process scan
    # this might result in trying to resume new processes that weren't suspended (doesnt matter)
    foreach ($proc in Get-Process | Where-Object { $targetProcessNames -contains $_.Name })
    {
        # calculate RAM based calcs for current process
        $prevRamUsage = $pidRamUsages[$proc.Id]  # the RAM usage of this PID just before it was suspended
        $currRamUsage = $proc.WorkingSet64
        # stored before resuming the process in case resuming causes immediate swapping from page file to RAM

        $ramUsageDelta = $currRamUsage - $prevRamUsage
        $totalRamDelta += $ramUsageDelta

        $currRamUsageHR = Bytes-HumanReadable -Bytes $currRamUsage
        $ramUsageDeltaHR = Bytes-HumanReadable -Bytes $ramUsageDelta -DisplayPlus $true


        # display subtotal for a group of processes with the same name
        if ($proc.name -ne $lastProcessName)
        {
            Process-Subtotal -sameProcessCount $sameProcessCount -sameProcessRamTotal $sameProcessRamTotal -sameProcessRamDeltaTotal $sameProcessRamDeltaTotal -lastProcessName $lastProcessName

            $sameProcessName = $proc.Name
            $sameProcessCount = 1
            $sameProcessRamTotal = $proc.WorkingSet64
            $sameProcessRamDeltaTotal = $ramUsageDelta

        }
        else
        {
            # same process name as last time
            $sameProcessCount++
            $sameProcessRamTotal += $proc.WorkingSet64
            $sameProcessRamDeltaTotal += $ramUsageDelta
        }

        Write-Host ($tableFormat -f $proc.Name, $proc.Id, $currRamUsageHR, $ramUsageDeltaHR, $dryRunText)

        if (!$dryRun)
        {
            try
            {
                [ProcessManager]::ResumeProcess($proc.Id)
            }
            catch
            {
                # NB: Write-Error won't work in the script's finally block
                Write-Host "Failed to resume: $($proc.Name) ($($proc.Id)). Error: $_"
            }
        }

        $lastProcessName = $proc.name
    }

    Process-Subtotal -sameProcessCount $sameProcessCount -sameProcessRamTotal $sameProcessRamTotal -sameProcessRamDeltaTotal $sameProcessRamDeltaTotal -lastProcessName $lastProcessName

    Write-Host ""
    if ($pidRamUsages)
    {
        $totalRamDeltaHR = Bytes-HumanReadable -Bytes $totalRamDelta -DisplayPlus $true
        #Write-Host "Overall change in RAM usage of all these processes during suspension: $($totalRamDeltaHR)"
        Write-Host ($tableFormat -f "TOTAL", "ALL", "", $totalRamDeltaHR, $dryRunText)
    }
}



# -----------------------------------------------------------------------------
function Clean-Up
{
    # must use Write-Host here
    # Write-Output and Write-Error are not available when application is 
    # shutting down

    Write-Host "[$(Get-Date -Format 'HH:mm')] Shutting down..."

    if ($suspendedProcesses)
    {
        Resume-Processes
    }

    # reset window appearance?
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host  # Clear the console to apply the new colors

    Write-Host "Goodbye"
}



#prevent issues when this script runs as compiled .exe:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Install-and-Import-Module -Name "BurntToast"

# change window appearance
$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host  # Clear the console to apply the new colors

# when set to true, no minimise windows or suspend process operations will occur
$dryRun = $false

# text to indicate to user that script is in dry run mode
$dryRunText = ""

if ($args -contains "--dry-run")
{
    $dryRun = $true
    $dryRunText = " <dry run>"
}


# Define cleanup actions.  NB: does not work if terminal window is closed
$cleanupAction = {
    Write-Output "Cleaning up before exit..."
    Clean-Up
    # ensures the script does indeed stop
    # optional, but if we are cleaning up, we probably want to insist on closure
    Stop-Process -Id $PID
}

# Register the AppDomain's ProcessExit event for general script termination
[System.AppDomain]::CurrentDomain.add_ProcessExit({
    & $cleanupAction
})

# Register for Ctrl+C handling, see also 'ConsoleBreak'
$null = Register-EngineEvent -SourceIdentifier ConsoleCancelEventHandler -Action {
    Write-Host "Ctrl+C detected, initiating cleanup..."
    & $cleanupAction
}


Write-Output "/======================\"
Write-Output "| AutoSuspender v0.6.1 |$($dryRunText)"
Write-Output "\======================/"
Write-Output ""
# TODO get unicode box drawing chars working properly

if ($args -contains "--resume-all")
{
    # Resume all target processes first
    # (used primarily for debugging when a previous script failed to resume processes)

    Write-Output "Resuming all processes ('--resume-all')"
    Resume-Processes

    # FIXME: this is necessary because if the script terminates when a trigger process is running
    # for some reason, simply running the script again and then closing the trigger process
    # doesn't mean that they are resumed and idk why
}


# should we run once or constantly?
# e.g. use --check-once if the script will be run whenever a new process is ran on the system
# (probably run it invisibly so a terminal windows doesnt keep appearing)
$checkOnce = $false
if ($args -contains "--check-once")
{
    $checkOnce = $true
}

# Are there some processes that we suspended and have yet to resume?
$suspendedProcesses = $false


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
        $runningTriggerProcesses = Get-Process | Where-Object { $triggerProcessNames -contains $_.Name }

        if ($runningTriggerProcesses)
        {
            $wasIdleLastLoop = $false

            foreach ($runningTriggerProcess in $runningTriggerProcesses) 
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id))"
                New-BurntToastNotification -Text "$($runningTriggerProcess.Name) is running", "AutoSuspender is minimising and suspending target processes to improve performance." -AppLogo $pauseIconPath
            }

            # Minimise windows of all target processes
            # FIXME: doesn't seem to work for certain apps (e.g. Microsoft Store apps like WhatsAp;)
            foreach ($proc in Get-Process | Where-Object { $targetProcessNames -contains $_.Name })
            {
                try
                {
                    $numWindowsMinimised = 0;
                    if (!$dryRun)
                    {
                        $numWindowsMinimised = [ProcessManager]::MinimizeProcessWindows($proc.Id)
                    }

                    if ($numWindowsMinimised)
                    {
                        Write-Output "Minimised: $($proc.Name) ($($proc.Id)) [$($numWindowsMinimised) windows]$($dryRunText)"
                    }
                }
                catch
                {
                    Write-Error "!!!! Failed to minimise: $($proc.Name) ($($proc.Id)). Error: $_";
                }
            }

            # Wait a short time to ensure minimize commands are processed
            Start-Sleep -Milliseconds 250

            # variables used for keeping track when there are more than one target processes with a specific name
            $lastProcessName = ""
            $sameProcessCount = 0
            $sameProcessRamTotal = 0

            Write-Output "Suspending processes..."
            Write-Host ($tableFormat -f "Name", "PID", "RAM", "", "") -ForegroundColor Yellow

            # Suspend all target processes
            foreach ($proc in Get-Process | Where-Object { $targetProcessNames -contains $_.Name })
            {

                # display subtotal for a group of processes
                if ($proc.name -ne $lastProcessName)
                {
                    #if ($sameProcessCount -gt 1)
                    #{
                    #   $sameProcessRamTotalHR = Bytes-HumanReadable -Bytes $sameProcessRamTotal
                    #   # display a subtotal row for the previous processes if there was more than 1
                    #   Write-Host ($tableFormat -f "$lastProcessName++", "---", $sameProcessRamTotalHR, "", $dryRunText) -ForegroundColor Yellow
                    #}
                    Process-Subtotal -sameProcessCount $sameProcessCount -sameProcessRamTotal $sameProcessRamTotal -lastProcessName $lastProcessName

                    $sameProcessName = $proc.Name
                    $sameProcessCount = 1
                    $sameProcessRamTotal = $proc.WorkingSet64
                }
                else
                {
                    # same process name as last time
                    $sameProcessCount++
                    $sameProcessRamTotal += $proc.WorkingSet64
                }

                #TODO: maybe investigate $proc.PagedMemorySize64
                #                        $proc.PriorityBoostEnabled
                #                        $proc.MainWindowTitle
                #                        $proc.MainWindowHandle

                $pidRamUsages[$proc.Id] = $proc.WorkingSet64
                # "HR" - human readable
                $ramUsageHR = Bytes-HumanReadable -Bytes $proc.WorkingSet64

                Write-Output ($tableFormat -f $proc.Name, $proc.Id, $ramUsageHR, "", $dryRunText)

                # suspend the process
                try
                {
                    if (!$dryRun)
                    {
                        [ProcessManager]::SuspendProcess($proc.Id)
                    }

                    $suspendedProcesses = $true
                    #$suspendedProcesses += [PSCustomObject]@{ Name = $proc.Name; Id = $proc.Id }
                }
                catch
                {
                    Write-Error "!!!! Failed to suspend: $($proc.Name) ($($proc.Id)). Error: $_"
                }

                $lastProcessName = $proc.name

            }

            #we might need to display another subtotal row if sameProcessCount > 1
            Process-Subtotal -sameProcessCount $sameProcessCount -sameProcessRamTotal $sameProcessRamTotal -lastProcessName $lastProcessName

            # Wait for the trigger process(es) to exit
            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) to exit..."

                # here's how we might run some code async
                #$job = Start-ThreadJob -ScriptBlock {
                #        $killer = New-Object -TypeName 'Assassin'
                #        Start-Sleep 5
                #        Write-Host 'raise'
                #        $killer.Raise(0)
                #}

                $runningTriggerProcess.WaitForExit()
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) Exited"
            }

            New-BurntToastNotification -Text "$($runningTriggerProcess.Name) exited", "AutoSuspender is resuming target processes." -AppLogo $playIconPath

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so 
            # this isn't a priority to fix

            Resume-Processes
            $suspendedProcesses = $false

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
            Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Sleeping for 3 seconds..."
        }

        Start-Sleep -Seconds 3

    }
}
catch 
{
    Write-Error "!!!! An error occurred: $_"
    Write-Host "Press Enter to exit."
    Read-Host
}
finally
{
    Clean-Up
    Unregister-Event -SourceIdentifier ConsoleCancelEventHandler
}