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

# TODO: read the next two variable data from a separate JSON/YAML config file

# TODO: periodically print memory usage of the trigger process (every 60s?)

# TODO: print other global memory usage stats (e.g. total VM, disk cache, etc)


param (
    [int]$PollInterval = 0  # how often (in seconds) to poll the trigger process for memory data, 0 means we'll use WaitForExit instead.
)


if ($PollInterval -lt 0)
{
    throw "PollInterval must be a positive integer number of seconds (or 0 to disable polling)"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
#Set-PSDebug -Trace 2
# this will enable/disable the display of Write-Debug messages
$DebugPreference = 'Continue'   #SilentlyContinue is the default

# List of names of processes (without ".exe") to suspend: target processes
$targetProcessNames = @(
    "chrome",
    "brave",
    "firefox",
    "msedge",
    "Spotify",
    "WhatsApp",
    "Signal",
    "Minecraft",
    "notepad"   # for testing purposes, notepad is considered a process to suspend
    #"GoogleDriveFS", # seems to crash Explorer related stuff, presumably when it accesses the virtual drive
)

# List of names of processes (without ".exe") to check: trigger processes (e.g. video games)
$triggerProcessNames = @(
    "Overwatch",
    #"FortniteLauncher",
    "FortniteClient-Win64-Shipping",
    "RocketLeague",
    "gw2-64",
    "java",     #for Minecraft - FIXME: will also trigger everything else Java!
    "CalculatorApp" # for testing purposes
)
# TODO make this a hashmap like "gw2-64" => "Guild Wars 2"
# and use the value for display purposes

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
function Install-and-Import
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Module
    )

    if (-not (Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue))
    {
        try
        {
            Install-Module -Name $Module -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch
        {
            throw "Failed to install $Module module"
        }
    }

    Import-Module $Module

    if (-not (Get-Module -Name $Module))
    {
        throw "Failed to import $Module module"
    }
}


# -----------------------------------------------------------------------------
function Bytes-HumanReadable
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
function Process-Subtotal
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
                                    (Bytes-HumanReadable -Bytes $sameProcessRamTotal),
                                    (Bytes-HumanReadable -Bytes $sameProcessRamDeltaTotal),
                                    $dryRunText) -ForegroundColor Yellow
        }
        else
        {
            Write-Host ($tableFormat -f "$lastProcessName",
                        "+++++",
                        (Bytes-HumanReadable -Bytes $sameProcessRamTotal),
                        "",
                        $dryRunText) -ForegroundColor Yellow
        }
    }
}


# Suspend / resume target processes
# -----------------------------------------------------------------------------
function Target-Processes
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

    # used to track how the RAM usage of all suspended processes changed
    # over the lifetime of the trigger process (only used for -Resume operation)
    if ($Resume -and -not $NoDeltas)
    {
        $totalRamDelta = 0
        $sameProcessRamDeltaTotal = 0
    }
    else 
    {
        $sameProcessRamDeltaTotal = $null
    }

    # we use Write-Host over Write-Output as this function can be called
    # once the script is terminating and it then has no access to Write-Output pipeline

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
    # (which probably doesnt matter)
    foreach ($proc in Get-Process | Where-Object { $targetProcessNames -contains $_.Name })
    {
        #TODO: maybe investigate whether these might be useful properties
        #                        $proc.PagedMemorySize64
        #                        $proc.PriorityBoostEnabled
        #                        $proc.MainWindowTitle
        #                        $proc.MainWindowHandle
        # see also: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-8.0

        $proc.Refresh()  # refresh the memory stats - is this causing a problem?

        #$currRamUsage = $proc.WorkingSet64
        $totalRamUsage += $proc.WorkingSet64

        if ($Suspend)
        {
            $pidRamUsages[$proc.Id] = $proc.WorkingSet64  # store current RAM usage
        }
        elseif (-not $NoDeltas)
        {
            # if we are doing a -Resume and calculating deltas
            $ramUsageDelta = $proc.WorkingSet64- $pidRamUsages[$proc.Id]
            $totalRamDelta += $ramUsageDelta
        }


        if ($proc.name -ne $lastProcessName)
        {
            # if this process has a different name to the last one

            # display subtotal for the previous group of processes with the same name
            if ($lastProcessName -ne "")
            {
                Process-Subtotal `
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
            # same process name as last time. continuing adding the subtotals
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
                            (Bytes-HumanReadable -Bytes $proc.WorkingSet64),
                            (Bytes-HumanReadable -Bytes $ramUsageDelta -DisplayPlus),
                            "$($dryRunText) $($proc.MainWindowTitle)"
                        )
        }
        else
        {
            Write-Host ($tableFormat -f
                            $proc.Name,
                            $proc.Id,
                            (Bytes-HumanReadable -Bytes $proc.WorkingSet64),
                            "",
                            "$($dryRunText) $($proc.MainWindowTitle)"
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

    Process-Subtotal `
        -sameProcessCount $sameProcessCount `
        -lastProcessName $lastProcessName `
        -sameProcessRamTotal $sameProcessRamTotal `
        -sameProcessRamDeltaTotal $sameProcessRamDeltaTotal  # this will be null if untracked

    if ($Resume -and -not $NoDeltas)
    {
        Write-Host ($tableFormat -f
                    "<TOTAL>",
                    "+++++",
                    (Bytes-HumanReadable -Bytes $totalRamUsage),
                    (Bytes-HumanReadable -Bytes $totalRamDelta -DisplayPlus),
                    $dryRunText) -ForegroundColor Yellow
    }
    else
    {
        Write-Host ($tableFormat -f
            "<TOTAL>",
            "+++++",
            (Bytes-HumanReadable -Bytes $totalRamUsage),
            "-",
            $dryRunText) -ForegroundColor Yellow
    }

}



# -----------------------------------------------------------------------------
function Clean-Up
{
    # must use Write-Host here
    # Write-Output and Write-Error are not available when application is
    # shutting down

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Shutting down..."

    if ($suspendedProcesses)
    {
        Target-Processes -Resume
    }

    if (Test-Path -Path $lockFilePath)
    {
        try
        {
            Remove-Item -Path $lockFilePath -Force -ErrorAction Stop
        }
        catch
        {
            Write-Host "Error deleting ${lockFilePath}: $_"
        }
    }

    # reset window appearance?
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host  # Clear the console to apply the new colors

    Write-Host "[Goodbye] o/"
}


#prevent issues when this script runs as compiled .exe:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Install-and-Import -Module "BurntToast"
Install-and-Import -Module "powershell-yaml"

# Define cleanup actions.  NB: does not work if terminal window is closed
$cleanupAction = {
    Write-Output "Cleaning up before exit..."
    Clean-Up
    # ensures the script does indeed stop
    # optional, but if we are cleaning up, we probably want to insist on closure
    Stop-Process -Id $PID
    Start-Sleep -Seconds 2
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
$dryRunText = ""

if ($args -contains "--dry-run")
{
    $dryRun = $true
    $dryRunText = " <dry run>"
}


# Define the full path to the icon files using
# the path of the folder where the script is located
if ($MyInvocation.MyCommand.Path)
{
    # For uncompiled PowerShell scripts
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
}
else
{
    # For compiled executables
    #$scriptPath = [System.IO.Path]::GetDirectoryName([System.Reflection.Assembly]::GetExecutingAssembly().Location)
    $scriptPath = [System.IO.Path]::GetDirectoryName([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
}

$configPath    = Join-Path -Path $scriptPath -ChildPath "/config.json"
$pauseIconPath = Join-Path -Path $scriptPath -ChildPath "/images/pause.ico"
$playIconPath  = Join-Path -Path $scriptPath -ChildPath "/images/play.ico"
$lockFilePath  = Join-Path -Path $scriptPath -ChildPath "/lock.pid"
$yamlFilePath  = Join-Path -Path $scriptPath -ChildPath "/config.yaml"

# change window appearance
$Host.UI.RawUI.BackgroundColor = 'DarkMagenta'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host  # Clear the console to apply the new colors

Write-Output "/======================\"
Write-Output "| AutoSuspender v0.7.0 |$($dryRunText)"
Write-Output "\======================/"
Write-Debug "scriptPath: $scriptPath"
Write-Debug "PollInterval: $PollInterval"
Write-Output ""
# TODO get unicode box drawing chars working properly


#Write-Output "Reading config.json..."
#$config = Get-Content -Path $configPath | ConvertFrom-Json
#Write-Output $config.TriggerProcesses

# YAML file read
#$config = Get-Content -Path $yamlFilePath -Raw | ConvertFrom-Yaml
#$config | Out-Default
##$config | Format-List -Property * -Force -Expand Both | Out-String -Width 1000
#Start-Sleep -Seconds 2


if ($args -contains "--resume-all")
{
    Write-Output "Resuming all processes ('--resume-all')..."
    Target-Processes -Resume -NoDeltas
}
elseif (Test-Path -Path $lockFilePath)
{
    $pidInLockFile = Get-Content -Path $lockFilePath
    Write-Debug "Lock file exists and contains '$($pidInLockFile)'"

    if (-not (Get-Process -Id $pidInLockFile -ErrorAction SilentlyContinue))
    {
        Write-Output "Lock file exists and is stale.  Resuming all processes..."
        Target-Processes -Resume -NoDeltas
        Remove-Item -Path $lockFilePath -Force
    }
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

        $scriptProcess = Get-Process -Id $PID
        $scriptProcessPreviousPriority = $scriptProcess.PriorityClass

        if ($runningTriggerProcesses)
        {
            Write-Host "Setting AutoSuspender to a lower priority"
            $scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
            #$scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle

            $wasIdleLastLoop = $false

            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                $priorityBoost = $runningTriggerProcess.PriorityBoostEnabled
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) {PriorityBoostEnabled: $($priorityBoost)}"
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

            Target-Processes -Suspend

            # "peak peak" is not a typo ;)
            $peakPeakWorkingSet = 0
            $peakPeakPagesMemorySize = 0

            # Wait for the trigger process(es) to exit
            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) to exit..."

                # this is how we might run some code async
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

                        Write-Debug "Current peak working set: $(Bytes-HumanReadable -Bytes $runningTriggerProcess.PeakWorkingSet64)"
                        Write-Debug "Current paged memory: $(Bytes-HumanReadable -Bytes $runningTriggerProcess.PeakPagedMemorySize64)"
                        Start-Sleep -Seconds $PollInterval
                    }
                }
                else 
                {
                    $runningTriggerProcess.WaitForExit()   # blocking
                    $peakWorkingSet = $runningTriggerProcess.PeakWorkingSet64
                    $peakPagedMemorySize = $runningTriggerProcess.PeakPagedMemorySize64
                }

                New-BurntToastNotification -Text "$($runningTriggerProcess.Name) exited", "AutoSuspender is resuming target processes." -AppLogo $playIconPath
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) Exited"

                Write-Host "Peak working set: $(Bytes-HumanReadable -Bytes $peakWorkingSet)"
                Write-Host "Peak paged memory: $(Bytes-HumanReadable -Bytes $peakPagedMemorySize)"

                #$counterPath = "\Process($($runningTriggerProcess.Name))\Working Set - Peak"
                #$peakWSMemory = Get-Counter -Counter $counterPath -SampleInterval 1 -MaxSamples 1
                #Write-Host "Windows Performance Counters API peak WS: $(Bytes-HumanReadable -Bytes $peakWSMemory)"
            }

            Write-Host "Restoring AutoSuspender priority to previous value"
            $scriptProcess.PriorityClass = $scriptProcessPreviousPriority

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so
            # this isn't a priority to fix

            Target-Processes -Resume
            $suspendedProcesses = $false
            Remove-Item -Path $lockFilePath -Force -ErrorAction SilentlyContinue

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
    #Write-Error "ERROR: $_"
    Write-Error "ERROR: $($_.Exception.Message) (Line: $($_.InvocationInfo.ScriptLineNumber))"
    Write-Host "Press Enter to exit."
    Read-Host
}
finally
{
    Write-Host "Finally..."
    Start-Sleep -Seconds 1
    Clean-Up
    Unregister-Event -SourceIdentifier ConsoleCancelEventHandler
}