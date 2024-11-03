# AutoSuspender
#   by Ben Kennish (ben@kennish.net)

# Automatically suspend chosen target processes (and minimise their windows)
# whenever chosen trigger processes (e.g. video games) are running, and
# automatically resume the target processes when the trigger process closes.

# ----------- TODO list --------------
# TODO: allow defining a whitelist of processes NOT to suspend and we suspend everything else
#       note: very likely to suspend things that will cause problems tho
#
# TODO: if user gives focus to any suspended process (before game has been closed), resume it temporarily.
#       this gets quite complicated to do in a way that doesn't potentially increase load on the system
#       as it can require repeatedly polling in a while() loop
#       OR perhaps just detect when a game loses focus and then unsuspend everything and resuspend them when it gains focus again
#       OR they could just manually ctrl-C the script and then run it again before restoring the game app
#
# TODO: allow setting CPU priority to Low for certain processes using $proc.PriorityClass property
#       (and restore previous priority when the trigger process closes) rather than suspending them
#
# TODO: other ways to improve performance
# - run user configurable list of commands when detecting a game  e.g. wsl --shutdown
# - adjust windows visual settings
#       Set registry key for best performance in visual effects
#       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 2
# -Set Power Plan to High Performance
#    powercfg /setactive SCHEME_MIN
# - Example for setting affinity
#    $process = Get-Process -Name 'SomeProcess'
#    $process.ProcessorAffinity = 0x0000000F # Adjust based on available cores
# - Close down unneeded game launchers (not used to launch any current games?)
#
# TODO: print other global memory usage stats (e.g. total VM, disk cache, etc)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$DebugPreference = 'Continue'   # this will enable/disable the display of Write-Debug messages, "SilentlyContinue" is the default
#Set-PSDebug -Trace 2


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


# install and import a module
# -----------------------------------------------------------------------------
function Enable-Module
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
            throw "Failed to install $Name module"
        }
    }

    Import-Module $Name

    if (-not (Get-Module -Name $Name))
    {
        throw "Failed to import $Name module"
    }
}


# convert a number of bytes into a more human readable string format
# -----------------------------------------------------------------------------
function ConvertTo-HumanReadable
{
    param (
        [Parameter(Mandatory=$true)] [double]$Bytes,
        [int]$DecimalDigits = 1,
        [switch]$DisplayPlus
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
        $formattedResult = "+$formattedResult"
    }

    return $formattedResult
}



# display a subtotal row for the previous processes if there was more than 1 with same name
# -----------------------------------------------------------------------------
function Write-Subtotal
{
    param (
        [Parameter(Mandatory = $true)] [int]$sameProcessCount,
        [Parameter(Mandatory = $true)] [string]$lastProcessName,
        [Parameter(Mandatory = $true)] [int64]$sameProcessRamTotal,
        [int64]$sameProcessRamDeltaTotal
    )

    if ($sameProcessCount -gt 1)
    {
        # only show subtotal when there is 2+ processes
        if ($sameProcessRamDeltaTotal -ne $null)
        {
            Write-Host ($tableFormat -f "$lastProcessName",
                                    "+++++",
                                    (ConvertTo-HumanReadable -Bytes $sameProcessRamTotal),
                                    (ConvertTo-HumanReadable -Bytes $sameProcessRamDeltaTotal),
                                    "") -ForegroundColor Yellow
        }
        else
        {
            Write-Host ($tableFormat -f "$lastProcessName",
                        "+++++",
                        (ConvertTo-HumanReadable -Bytes $sameProcessRamTotal),
                        "",
                        "") -ForegroundColor Yellow
        }
    }
}


# Suspend / resume target processes
# -----------------------------------------------------------------------------
function Set-TargetProcessesState
{
    [CmdletBinding(DefaultParameterSetName = 'Suspend')]
    param (
        [Parameter(ParameterSetName = 'Suspend', Mandatory=$true)]
        [switch]$Suspend,

        [Parameter(ParameterSetName = 'Resume', Mandatory=$true)]
        [switch]$Resume,
        [Parameter(ParameterSetName = 'Resume')]
        [switch]$NoDeltas
    )

    $lastProcessName = ""
    $sameProcessCount = 0
    $sameProcessRamTotal = 0
    $totalRamUsage = 0

    # used to track how the RAM usage of target processes changed during their suspension
    if ($Resume -and -not $NoDeltas)
    {
        $totalRamDelta = 0
        $sameProcessRamDeltaTotal = 0
    }
    else 
    {
        $sameProcessRamDeltaTotal = $null
    }

    # using Write-Host not Write-Output as this function can be called while
    # the script is terminating and then has no access to Write-Output pipeline

    if ($Suspend)
    {
        # create a lock file to indicate a script terminated before it could resume processes
        $PID | Out-File -FilePath $lockFilePath -Force
    }

    if ($Suspend -or $NoDeltas)
    {
        Write-Host ($tableFormat -f "NAME", "PID", "RAM", "", "") -ForegroundColor Yellow
    }
    else
    {
        Write-Host ($tableFormat -f "NAME", "PID", "RAM", "CHANGE", "") -ForegroundColor Yellow
    }


    # NB: for a -Resume, we don't look at suspendedProcesses array but just do another process scan
    # this might result in trying to resume new processes that weren't suspended (by us)
    # (probably doesn't matter but it's not very elegant)
    foreach ($proc in Get-Process | Where-Object { $targetProcessNames -contains $_.Name })
    {
        #TODO: these might be useful properties:
        #        $proc.PagedMemorySize64
        #        $proc.PriorityBoostEnabled
        #        $proc.MainWindowTitle
        #        $proc.MainWindowHandle
        # see also: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-8.0

        $proc.Refresh()  # refresh the memory stats for the process

        $totalRamUsage += $proc.WorkingSet64

        if ($Suspend)
        {
            $pidRamUsages[$proc.Id] = $proc.WorkingSet64  # store current RAM usage before we suspend
        }
        elseif (-not $NoDeltas)
        {
            # if we are doing a -Resume and calculating deltas
            $ramUsageDelta = $proc.WorkingSet64 - $pidRamUsages[$proc.Id]
            $totalRamDelta += $ramUsageDelta
        }


        if ($proc.Name -ne $lastProcessName)
        {
            # if this process has a different name to the last one

            # display subtotal for the previous group of processes with the same name
            if ($lastProcessName -ne "")
            {
                Write-Subtotal `
                    -sameProcessCount $sameProcessCount `
                    -lastProcessName $lastProcessName `
                    -sameProcessRamTotal $sameProcessRamTotal `
                    -sameProcessRamDeltaTotal $sameProcessRamDeltaTotal  # this will be null if untracked
            }

            $lastProcessName = $proc.Name
            $sameProcessCount = 1
            $sameProcessRamTotal = $proc.WorkingSet64

            if ($Resume -and -not $NoDeltas)
            {
                $sameProcessRamDeltaTotal = $ramUsageDelta
            }
        }
        else
        {
            # this process has same name as last one. continuing adding the subtotals
            $sameProcessCount++
            $sameProcessRamTotal += $proc.WorkingSet64

            if ($Resume -and -not $NoDeltas)
            {
                $sameProcessRamDeltaTotal += $ramUsageDelta
            }
        }


        if ($Resume -and -not $NoDeltas)
        {
            Write-Host ($tableFormat -f
                            $proc.Name,
                            $proc.Id,
                            (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64),
                            (ConvertTo-HumanReadable -Bytes $ramUsageDelta -DisplayPlus),
                            "[$($proc.MainWindowTitle)]"
                        )
        }
        else
        {
            Write-Host ($tableFormat -f
                            $proc.Name,
                            $proc.Id,
                            (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64),
                            "",
                            "[$($proc.MainWindowTitle)]"
                        )
        }

        if (!$dryRun)
        {
            try
            {
                if ($Suspend)
                {
                    [ProcessManager]::SuspendProcess($proc.Id)
                }
                elseif ($Resume)
                {
                    [ProcessManager]::ResumeProcess($proc.Id)
                }
            }
            catch
            {
                $verb = "suspend"
                if ($Resume)
                {
                    $verb = "resume"
                }

                # NB: Write-Error won't work in the script's finally block
                Write-Host "ERROR: Failed to $($verb) $($proc.Name) ($($proc.Id)):"
                Write-Host "$_"
            }
        }

        $lastProcessName = $proc.name
    }

    Write-Subtotal `
        -sameProcessCount $sameProcessCount `
        -lastProcessName $lastProcessName `
        -sameProcessRamTotal $sameProcessRamTotal `
        -sameProcessRamDeltaTotal $sameProcessRamDeltaTotal  # this will be null if untracked

    if ($Resume -and -not $NoDeltas)
    {
        Write-Host ($tableFormat -f
                    "<TOTAL>",
                    "+++++",
                    (ConvertTo-HumanReadable -Bytes $totalRamUsage),
                    (ConvertTo-HumanReadable -Bytes $totalRamDelta -DisplayPlus),
                    "") -ForegroundColor Yellow
    }
    else
    {
        Write-Host ($tableFormat -f
            "<TOTAL>",
            "+++++",
            (ConvertTo-HumanReadable -Bytes $totalRamUsage),
            "-",
            "") -ForegroundColor Yellow
    }

}


# clean up function
# -----------------------------------------------------------------------------
function Reset-Environment
{
    # must use Write-Host here
    # Write-Output and Write-Error are not available when application is
    # shutting down

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Shutting down..."

    if ($suspendedProcesses)
    {
        Set-TargetProcessesState -Resume
    }

    if (Test-Path -Path $lockFilePath)
    {
        try
        {
            Remove-Item -Path $lockFilePath -Force -ErrorAction Stop
        }
        catch
        {
            # cannot use Write-Error here
            Write-Host "Error deleting ${lockFilePath}: $_"
        }
    }

    # reset window appearance
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host  # Clear the console to apply the new colors

    Write-Host "[Goodbye] o/"
}



# =============================================================================
# =============================================================================


# this prevents issues with external PS code when this script is compiled to a .exe:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force


# a hash table used to map process PIDs to RAM (bytes) usages
# used to save RAM usage of target processes just before they are suspended
$pidRamUsages = @{}

# Process, PID, RAM, deltaRAM, Notes
$tableFormat = "{0,-11} {1,-6} {2,10} {3,11} {4,-10}"


# Define cleanup actions.  NB: does not work if terminal window is closed
$cleanupAction = {
    Write-Output "Cleaning up before exit..."
    Reset-Environment
    # ensures the script does indeed stop
    # optional, but if we are cleaning up, we probably want to insist on closure
    Stop-Process -Id $PID
}

# Register the AppDomain's ProcessExit event for general script termination
[System.AppDomain]::CurrentDomain.add_ProcessExit({
    Write-Host "ProcessExit() triggered"
    & $cleanupAction
})

# Register for Ctrl+C handling, see also 'ConsoleBreak'
$null = Register-EngineEvent -SourceIdentifier ConsoleCancelEventHandler -Action {
    Write-Host "Ctrl+C detected"
    & $cleanupAction
}

# when set to true, don't actually minimise windows or suspend processes
$dryRun = $false
if ($args -contains "--dry-run")
{
    $dryRun = $true
}

# Define the full path to the icon files using
# the path of the folder where the script is located
if ($MyInvocation.MyCommand.Path)
{
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
}
else
{
    # We are likely a compiled executable so we need to get the path like this:
    $scriptPath = [System.IO.Path]::GetDirectoryName([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

$pauseIconPath = Join-Path -Path $scriptPath -ChildPath "/images/pause.ico"
$playIconPath  = Join-Path -Path $scriptPath -ChildPath "/images/play.ico"
$lockFilePath  = Join-Path -Path $scriptPath -ChildPath "/lock.pid"
$configPath    = Join-Path -Path $scriptPath -ChildPath "/config.yaml"


# read YAML config file
Enable-Module -Name "powershell-yaml"
$config = Get-Content -Path $configPath -Raw | ConvertFrom-Yaml
#$config | Out-Default

# unpack config into variables
$targetProcessNames = $config.targetProcessNames
$triggerProcessNames = $config.triggerProcessNames
$PollInterval = $config.triggerProcessPollInterval   #perhaps this should actually be a cmd line arg?
$showNotifications = $config.showNotifications


if ($showNotifications)
{
    Enable-Module -Name "BurntToast"
}

# change window appearance
$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host  # Clear the console to apply the new colors

Write-Output "/======================\"
Write-Output "| AutoSuspender v0.8.0 |"
Write-Output "\======================/"
Write-Debug "scriptPath: $scriptPath"
Write-Debug "PollInterval: $PollInterval"
Write-Output ""


if ($PollInterval -lt 0)
{
    throw "PollInterval must be a positive integer number of seconds (or 0 to disable polling)"
}

if ($args -contains "--resume-all")
{
    Write-Output "Resuming all processes ('--resume-all')..."
    Set-TargetProcessesState -Resume -NoDeltas
}
elseif (Test-Path -Path $lockFilePath)
{
    $pidInLockFile = Get-Content -Path $lockFilePath
    Write-Debug "Lock file exists and contains '$($pidInLockFile)'"

    if (-not (Get-Process -Id $pidInLockFile -ErrorAction SilentlyContinue))
    {
        Write-Output "Lock file exists and is stale.  Resuming all processes..."
        Set-TargetProcessesState -Resume -NoDeltas
        Remove-Item -Path $lockFilePath -Force
    }
}


# should we run once or constantly?
# e.g. use --check-once if the script will be run whenever a new process is ran on the system
# (probably run it invisibly or at least minimised so a terminal windows doesnt keep appearing)
$checkOnce = $false
if ($args -contains "--check-once")
{
    $checkOnce = $true
}

# Are there some processes that we suspended and have yet to resume?
$suspendedProcesses = $false

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
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Checking for trigger processes..."
            }
            else
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for trigger processes..."
            }
        }

        $wasIdleLastLoop = $true
        $runningTriggerProcesses = Get-Process | Where-Object { $triggerProcessNames -contains $_.Name }

        $scriptProcess = Get-Process -Id $PID
        $scriptProcessPreviousPriority = $scriptProcess.PriorityClass

        if ($runningTriggerProcesses)
        {
            $wasIdleLastLoop = $false

            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) {PriorityBoost: $($runningTriggerProcess.PriorityBoostEnabled)}"
                if ($showNotifications)
                {
                    New-BurntToastNotification -Text "$($runningTriggerProcess.Name) is running", "AutoSuspender is minimising and suspending target processes to improve performance." -AppLogo $pauseIconPath
                }
            }

            Write-Host "Setting AutoSuspender to a lower priority"
            $scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
            #$scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle   # equivalent to Task Manager "Low"

            # Minimise windows of all target processes
            # FIXME: doesn't work for certain apps (e.g. Microsoft Store apps like WhatsApp)
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
                        Write-Output "Minimised: $($proc.Name) ($($proc.Id)) [$($numWindowsMinimised) windows]"
                    }
                }
                catch
                {
                    Write-Error "!!!! Failed to minimise: $($proc.Name) ($($proc.Id)). Error: $_";
                }
            }

            # Wait a short time to ensure minimize commands are processed
            Start-Sleep -Milliseconds 250

            Set-TargetProcessesState -Suspend

            # Wait for the trigger process(es) to exit
            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) to exit..."

                # this is an example of how we might run some code async
                #$job = Start-ThreadJob -ScriptBlock {
                #        $killer = New-Object -TypeName 'Assassin'
                #        Start-Sleep 5
                #        Write-Host 'raise'
                #        $killer.Raise(0)
                #}

                $peakWorkingSet = 0
                $peakPagedMemorySize = 0

                if ($PollInterval -gt 0)
                {
                    while (!$runningTriggerProcess.HasExited)
                    {
                        $runningTriggerProcess.Refresh()
                        $peakWorkingSet = $runningTriggerProcess.PeakWorkingSet64
                        $peakPagedMemorySize = $runningTriggerProcess.PeakPagedMemorySize64

                        Write-Debug "Current peak working set: $(ConvertTo-HumanReadable -Bytes $runningTriggerProcess.PeakWorkingSet64)"
                        Write-Debug "Current paged memory: $(ConvertTo-HumanReadable -Bytes $runningTriggerProcess.PeakPagedMemorySize64)"
                        Start-Sleep -Seconds $PollInterval
                    }
                }
                else
                {
                    $runningTriggerProcess.WaitForExit()   # blocking

                    # these figures are unlikely to be correct once the process has exited
                    $peakWorkingSet = $runningTriggerProcess.PeakWorkingSet64
                    $peakPagedMemorySize = $runningTriggerProcess.PeakPagedMemorySize64
                }

                if ($showNotifications)
                {
                    New-BurntToastNotification -Text "$($runningTriggerProcess.Name) exited", "AutoSuspender is resuming target processes." -AppLogo $playIconPath
                }
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) Exited"

                Write-Host "Peak working set: $(ConvertTo-HumanReadable -Bytes $peakWorkingSet)"
                Write-Host "Peak paged memory: $(ConvertTo-HumanReadable -Bytes $peakPagedMemorySize)"

                # using Windows Performance Counters API:
                #$counterPath = "\Process($($runningTriggerProcess.Name))\Working Set - Peak"
                #$peakWSMemory = Get-Counter -Counter $counterPath -SampleInterval 1 -MaxSamples 1
                #Write-Host "Windows Performance Counters API peak WS: $(ConvertTo-HumanReadable -Bytes $peakWSMemory)"
            }

            Write-Host "Restoring AutoSuspender priority class"
            $scriptProcess.PriorityClass = $scriptProcessPreviousPriority

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so
            # this isn't a priority to fix

            Set-TargetProcessesState -Resume
            $suspendedProcesses = $false
            Remove-Item -Path $lockFilePath -Force -ErrorAction Continue

            if ($checkOnce)
            {
                break
            }
        }
        else
        {
            if ($checkOnce)
            {
                Write-Output "No trigger process detected."
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
    #Write-Error "ERROR: $_"
    Write-Error "ERROR: $($_.Exception.Message) (Line: $($_.InvocationInfo.ScriptLineNumber))"
    Write-Host "Press Enter to exit."
    Read-Host
}
finally
{
    Write-Host "Finally..."
    Reset-Environment
    Unregister-Event -SourceIdentifier ConsoleCancelEventHandler
}