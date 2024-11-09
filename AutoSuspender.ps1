# AutoSuspender
#   A PowerShell script by Ben Kennish (ben@kennish.net)

# Automatically suspend chosen target processes (and minimise their windows)
# whenever chosen trigger processes (e.g. video games) are running, then
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
# - Close/suspend unneeded game launchers (only those not used to launch any current game?)
#
# TODO: print other global memory usage stats (e.g. total VM, disk cache, etc)

# Deal with given command line arguments
# TODO: exit on getting unrecognised command line arguments
param (
    [switch]$Help,
    [switch]$DryRun,
    [switch]$ResumeAll,
    [switch]$CheckOnce,
    [switch]$Debug,
    [int]$TriggerProcessPollInterval = 0
)

$Version = '0.8.5'

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Debug)
{
    $DebugPreference = 'Continue'    # this will enable/disable the display of Write-Debug messages, "SilentlyContinue" is the default
    $ErrorActionPreference = "Stop"  # should force instant error messages
    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    $PSDefaultParameterValues['*:Verbose'] = $true
    Set-PSDebug -Trace 2
}


# Hashtable of known launchers
# key: process name, value: descriptive name
# TODO: maybe this could go in the config file?
# TODO: perhaps we can have some optimisation code specific to the different launchers
$launchers = @{
    'steam'             = 'Steam'
    'epicgameslauncher' = 'Epic Games Launcher'
    'battle.net'        = 'Battle.net'
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


# Helper function to import a module, installing it first if necessary
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


# Convert a number of bytes into a more human readable string format
# -----------------------------------------------------------------------------
function ConvertTo-HumanReadable
{
    param (
        [Parameter(Mandatory=$true)] [int64]$Bytes,
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


# Display a subtotal row for the previous processes 
# if there was more than 1 with same name
# -----------------------------------------------------------------------------
function Write-Subtotal
{
    param (
        [Parameter(Mandatory = $true)] [int]$SameProcessCount,
        [Parameter(Mandatory = $true)] [string]$LastProcessName,
        [Parameter(Mandatory = $true)] [int64]$SameProcessRamTotal,
        [int64]$SameProcessRamDeltaTotal
    )

    if ($SameProcessCount -gt 1)
    {
        # only show subtotal when there is 2+ processes
        if ($null -ne $SameProcessRamDeltaTotal)
        {
            Write-Host ($tableFormat -f "$LastProcessName",
                        "+++++",
                        (ConvertTo-HumanReadable -Bytes $SameProcessRamTotal),
                        (ConvertTo-HumanReadable -Bytes $SameProcessRamDeltaTotal),
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

# return the colour to display a number of bytes according to certain rules
function Get-BytesColour
{
    param (
        [Parameter(Mandatory = $true)] [int64]$Bytes,
        [switch]$NegativeIsPositive,  # if set, the more negative a number is, the better it is.
        [string]$BadColour = "Red"   # what colour to use if the number is bad
    )

    if ($NegativeIsPositive -and $Bytes -gt 0)
    {
        return $BadColour
    }
    if (-not $NegativeIsPositive -and $Bytes -lt 0)
    {
        return $BadColour
    }

    # 1st element : what colour to use for Bytes
    # 2nd element : what colour to use for KBs
    # etc  
    #              B        KB      MB       GB        TB         PB
    $colours = @("Gray", "White", "Cyan", "Green", "Magenta", "Magenta")
    $unitIndex = 0

    while ([Math]::Abs($Bytes) -ge 1024 -and $unitIndex -lt $colours.Length - 1)
    {
        $Bytes /= 1024
        $unitIndex++
    }
    return $colours[$unitIndex]

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
        [switch]$NoDeltas,

        [string]$Launcher = ""
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
        $NoDeltas = $true   # set NoDeltas to true so we can use this for tracking
        $sameProcessRamDeltaTotal = $null
    }

    # using Write-Host not Write-Output as this function can be called while
    # the script is terminating and then has no access to Write-Output pipeline

    if ($Suspend)
    {
        # create a lock file to indicate if a script terminated before it could resume processes
        $PID | Out-File -FilePath $lockFilePath -Force
    }

    if ($NoDeltas)
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
    foreach ($proc in Get-Process | Where-Object { $config.targetProcessNames -contains $_.Name })
    {
        #TODO: these might be useful properties:
        #        $proc.PagedMemorySize64
        #        $proc.PriorityBoostEnabled
        #        $proc.MainWindowTitle
        #        $proc.MainWindowHandle
        # see also: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-8.0

        $proc.Refresh()  # refresh the memory stats for the process

        # ignore processes that aren't running anymore
        if ($proc.HasExited)
        {
            Write-Debug "PID $($proc.Id) has already exited. Ignoring."
            continue
        }

        if ($Launcher -and ($proc.Name -eq $Launcher))
        {
            Write-Debug "$($proc.Name) ignored as it is the launcher for the trigger process"
            
            Write-Host ($tableFormat -f
                $proc.Name,
                $proc.Id,
                (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64),
                "",
                "<Ignoring Launcher>"
            ) -ForegroundColor DarkGray

            continue
        }

        # TODO: actually display this table using the Format-Table cmdlet like this...
        <#
        Get-Process | Format-Table @{ Label = "PID"; Expression={$_.Id}}, @{ Label = "Name"; Expression={$_.Name}},
        @{ Label = "RAM"; Expression={
            if ($_.WS -gt 100MB) { Write-Host -ForegroundColor Red $_.WS } else { $_.WS }
        }}
        #>      

        $totalRamUsage += $proc.WorkingSet64

        if ($Suspend)
        {
            $pidRamUsages[$proc.Id] = $proc.WorkingSet64  # store current RAM usage before we suspend
        }
        
        if (-not $NoDeltas)
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
                    -SameProcessCount $sameProcessCount `
                    -LastProcessName $lastProcessName `
                    -SameProcessRamTotal $sameProcessRamTotal `
                    -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal  # this will be null if untracked
            }

            $lastProcessName = $proc.Name
            $sameProcessCount = 1
            $sameProcessRamTotal = $proc.WorkingSet64

            if (-not $NoDeltas)
            {
                $sameProcessRamDeltaTotal = $ramUsageDelta
            }
        }
        else
        {
            # this process has same name as last one. continuing adding the subtotals
            $sameProcessCount++
            $sameProcessRamTotal += $proc.WorkingSet64

            if (-not $NoDeltas)
            {
                $sameProcessRamDeltaTotal += $ramUsageDelta
            }
        }

        $windowTitle = ""
        if ($proc.MainWindowTitle)
        {
            $windowTitle = "[$($proc.MainWindowTitle)]"
        }

        if (-not $NoDeltas)
        {
            Write-Host ($tableFormat -f
                            $proc.Name,
                            $proc.Id,
                            (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64),
                            (ConvertTo-HumanReadable -Bytes $ramUsageDelta -DisplayPlus),
                            $windowTitle
                        )  -ForegroundColor (Get-BytesColour -Bytes $ramUsageDelta -NegativeIsPositive)
        }
        else
        {
            Write-Host ($tableFormat -f
                            $proc.Name,
                            $proc.Id,
                            (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64),
                            "",
                            $windowTitle
                        )  -ForegroundColor (Get-BytesColour -Bytes $proc.WorkingSet64)
        }

        if (!$DryRun)
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

                # NB: remember Write-Error won't work from within the script's finally block
                Write-Host "ERROR: Failed to $($verb) $($proc.Name) ($($proc.Id)):"
                Write-Host "$_"
            }
        }

        $lastProcessName = $proc.name
    }

    Write-Subtotal `
        -SameProcessCount $sameProcessCount `
        -LastProcessName $lastProcessName `
        -SameProcessRamTotal $sameProcessRamTotal `
        -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal  # this will be null if untracked

    if (-not $NoDeltas)
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
        Set-TargetProcessesState -Resume -Launcher $launcher
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
    #$Host.UI.RawUI.BackgroundColor = 'Black'
    #$Host.UI.RawUI.ForegroundColor = 'White'

    Write-Host "[Goodbye] o/"
}


# Rainbowified text!
# -----------------------------------------------------------------------------
function Write-RainbowText
{
    param (
        [Parameter(Mandatory = $true)][string]$Text
    )

    # Define the colors for each character position
    $colors = @(
        'Red',
        'Yellow',
        'Green',
        'Cyan',
        'Blue',
        'Magenta'
    )

    # Loop over each character in the input string
    for ($i = 0; $i -lt $Text.Length; $i++) 
    {
        # Determine the color to use based on the character index
        $color = $colors[$i % $colors.Length]
        # Print the character with the specified color
        Write-Host -NoNewline -ForegroundColor $color $Text[$i]
    }
}


# Search back through a process's parents (and older ancestor processes) 
# for a recognised launcher
# returns the process name of the launcher (e.g. Steam, EpicGamesLauncher) else null
# -----------------------------------------------------------------------------
function Find-Launcher
{
    param (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process
    )
    
    # Start with the provided process
    $currentProcess = $Process

    # Iterate backwards through the parent processes
    while ($currentProcess)
    {
        try 
        {
            # Check if the current process is in the launcher hashtable
            if ($launchers.ContainsKey($currentProcess.Name.ToLower()))
            {
                Write-Debug "Found launcher: $($currentProcess.Name) ($($launchers[$currentProcess.Name.ToLower()])) for process: $($Process.Name)"
                return $currentProcess.Name
            }

            # Get the parent process ID
            $parentProcessId = (Get-WmiObject Win32_Process -Filter "ProcessId = $($currentProcess.Id)").ParentProcessId

            # Break if there is no parent (reached the top of the process tree)
            if (-not $parentProcessId)
            {
                Write-Debug "No parent process found for '$($Process.Name)'."
                return
            }

            # Get the parent process
            $currentProcess = Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue

            if (-not $currentProcess)
            {
                Write-Debug "Parent process (PID: $parentProcessId) no longer running for '$($process.Name)'."
                return
            }

            # Optionally output the current checking process
            Write-Debug "Checking parent process: $($currentProcess.Name)"
        }
        catch 
        {
            # Get the call stack
            $callStack = Get-PSCallStack        
            Write-Error "An error occurred while retrieving information about the process: $($currentProcess.Name) on line $($callStack[0].ScriptLineNumber) : $_"
            return
        }
    }

    Write-Debug "No launcher found for game: $($gameProcess.Name)."
    return $null
}


function Write-Usage
{
    Write-Host ""
    Write-Host "AutoSuspender $Version" -ForegroundColor Yellow
    Write-Host ""
    Write-Host @"
Whenever chosen trigger processes (e.g. video games) are running,
AutoSuspender automatically suspends chosen target processes (e.g. web
browsers and instant messaging apps), and automatically resumes them when the
trigger process ends.

Suspended processes cannot use any CPU and Windows is more likely to move their
memory from fast RAM (their "working set") to the slower pagefile on disk,
leaving more of the RAM available for the trigger process (e.g. video game).

When the trigger process closes, AutoSuspender will report how much the RAM
usage ("working set") of the target processes dropped during their suspension.

Command line arguments
----------------------

-Dry-Run   : Enables dry-run mode; the script doesn't actually suspend or
resume any processes or minimise windows but does everything else. Useful for
testing and measuring performance benefits of using AutoSuspender.

-ResumeAll   : Resumes all target processes then run as normal.  Handy for when
a previous invocation of the script failed to resume everything for some reason.

-CheckOnce   : Checks for trigger processes only once, exiting immediately if
none are running.  If one is running, performs usual operations then exits when
the trigger process exits (after resuming the target processes).  You might use
this if you arrange for the script to run every time Windows runs a new process.

-TriggerProcessPollInterval #   : if # is a positive integer, AutoSuspender
will poll the memory usage of the trigger process every # seconds.  This can
be useful in gathering information but can have a small performance impact so
is disabled by default.
"@

}

# =============================================================================
# =============================================================================

# this prevents issues with external PS code when this script is compiled to a .exe:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

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


if ($Help)
{
    Write-Usage
    exit 0
}

# Check if any unexpected arguments were provided
# (they get leftover within $args)
if ($args.Count -gt 0)
{
    Write-Error "Unexpected argument(s): $($args -join ', ')"
    Write-Usage
    exit 1
}



# a hash table used to map process PIDs to RAM (bytes) usages
# used to save RAM usage of target processes just before they are suspended
$pidRamUsages = @{}

# Formatting string for the table printed upon suspending/resuming target processes
# Process, PID, RAM, deltaRAM, Notes
$tableFormat = "{0,-17} {1,-6} {2,10} {3,11} {4,-10}"
# TODO: maybe the alignment number of the Process name could depend on the maximum running process name length?

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

$lockFilePath  = Join-Path -Path $scriptPath -ChildPath "/lock.pid"
$configPath    = Join-Path -Path $scriptPath -ChildPath "/config.yaml"
$templatePath  = Join-Path -Path $scriptPath -ChildPath "/config-template.yaml"
$pauseIconPath = Join-Path -Path $scriptPath -ChildPath "/images/pause.ico"
$playIconPath  = Join-Path -Path $scriptPath -ChildPath "/images/play.ico"

# read YAML config file
Enable-Module -Name "powershell-yaml"

$configYamlHeader = @"
# AutoSuspender config file (YAML format)
# Generated originally from a v$Version template
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"@

if (-not (Test-Path -Path $configPath))
{    
    # read in the text of the templateFile, remove the header, replace with our header, then save 
    # (?s) dotall mode to make . match newline characters   "(?s)# @=.*=@"
    ((Get-Content -Path $templatePath -Raw) -replace "(?s)# @=+\s.*?=+@", $configYamlHeader) | Out-File -FilePath $configPath -Force
}

$config = Get-Content -Path $configPath -Raw | ConvertFrom-Yaml

if ($config.showNotifications)
{
    Enable-Module -Name "BurntToast"
}

# change window appearance
#$Host.UI.RawUI.BackgroundColor = 'Black'
#$Host.UI.RawUI.ForegroundColor = 'White'
#Clear-Host  # Clear the console to apply the new colors

Write-Host "/===============\"
Write-Host -NoNewline "| "
Write-RainbowText "AutoSuspender"
Write-Host " |"
Write-Host "\===============/"
Write-Host "Running v$Version"
if ($DryRun)
{
    Write-Host "Dry Run Enabled!  No suspending, resuming, or minimising will occur" -ForegroundColor Red
}
Write-Debug "scriptPath: $scriptPath"
Write-Debug "TriggerProcessPollInterval: $TriggerProcessPollInterval"
Write-Host ""

# TODO: print tables using Format-Table like this:
# Get-Process | Sort-Object -Property BasePriority | Format-Table -GroupBy BasePriority -Wrap

if ($TriggerProcessPollInterval -lt 0)
{
    throw "PollInterval must be a positive integer number of seconds (or 0 to disable polling)"
}


if (Test-Path -Path $lockFilePath)
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
elseif ($ResumeAll)
{
    #NB: if lock file does exist and points to an active process, 
    # we will NOT reach here, even if -ResumeAll is passed

    Write-Output "Resuming all processes ('-ResumeAll')..."
    Set-TargetProcessesState -Resume -NoDeltas
}


# e.g. use -CheckOnce if the script will be run whenever a new process is ran on the system
# (probably run it invisibly or at least minimised so a terminal windows doesnt keep appearing)


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
            if ($CheckOnce)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Checking for trigger processes..."
            }
            else
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for trigger processes..."
            }
        }

        $wasIdleLastLoop = $true
        $runningTriggerProcesses = Get-Process | Where-Object { $config.triggerProcessNames -contains $_.Name }

        if ($config.lowPriorityWaiting)
        {
            $scriptProcess = Get-Process -Id $PID
            $scriptProcessPreviousPriority = $scriptProcess.PriorityClass
        }

        if ($runningTriggerProcesses)
        {
            $wasIdleLastLoop = $false
            $launcher = ""

            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) {PriorityBoost: $($runningTriggerProcess.PriorityBoostEnabled)}"
                if ($config.showNotifications)
                {
                   New-BurntToastNotification -Text "$($runningTriggerProcess.Name) is running", "AutoSuspender is minimising and suspending target processes to improve performance." -AppLogo $pauseIconPath
                }
            
                $launcher = Find-Launcher -Process $runningTriggerProcess
                if ($launcher)
                {
                    Write-Output "**** Detected running using launcher '$launcher' ($($launchers[$launcher]))"
                    #TODO: insert launcher specific configuration/optimisation here
                }
            }

            if ($config.lowPriorityWaiting)
            {
                Write-Host "Setting AutoSuspender to a lower priority"
                $scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
                #$scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle   # equivalent to Task Manager "Low"
            }

            # Minimise windows of all target processes
            # FIXME: doesn't work for certain apps (e.g. Microsoft Store apps like WhatsApp)
            foreach ($proc in Get-Process | Where-Object { $config.targetProcessNames -contains $_.Name })
            {
                try
                {
                    $numWindowsMinimised = 0;
                    if (!$DryRun)
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

            Set-TargetProcessesState -Suspend -Launcher $launcher

            # Wait for the trigger process(es) to exit
            foreach ($runningTriggerProcess in $runningTriggerProcesses)
            {
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) to exit..."

                $peakWorkingSet = 0
                $peakPagedMemorySize = 0

                if ($TriggerProcessPollInterval -gt 0)
                {
                    while (!$runningTriggerProcess.HasExited)
                    {
                        $runningTriggerProcess.Refresh()
                        $peakWorkingSet = $runningTriggerProcess.PeakWorkingSet64
                        $peakPagedMemorySize = $runningTriggerProcess.PeakPagedMemorySize64

                        Write-Debug "$($runningTriggerProcess.Name) current peak working set: $(ConvertTo-HumanReadable -Bytes $runningTriggerProcess.PeakWorkingSet64)"
                        Write-Debug "$($runningTriggerProcess.Name) current paged memory: $(ConvertTo-HumanReadable -Bytes $runningTriggerProcess.PeakPagedMemorySize64)"
                        Start-Sleep -Seconds $TriggerProcessPollInterval
                    }
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) exited"
                    Write-Host "$($runningTriggerProcess.Name) peak working set: $(ConvertTo-HumanReadable -Bytes $peakWorkingSet)"
                    Write-Host "$($runningTriggerProcess.Name) paged memory: $(ConvertTo-HumanReadable -Bytes $peakPagedMemorySize)"
                }
                else
                {
                    $runningTriggerProcess.WaitForExit()   # blocking

                    # these figures are unreliable once the process has exited
                    # as Windows clears the stats for terminated processes
                    #$peakWorkingSet = $runningTriggerProcess.PeakWorkingSet64
                    #$peakPagedMemorySize = $runningTriggerProcess.PeakPagedMemorySize64

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) Exited"
                }

                # using Windows Performance Counters API:
                #$counterPath = "\Process($($runningTriggerProcess.Name))\Working Set - Peak"
                #$peakWSMemory = Get-Counter -Counter $counterPath -SampleInterval 1 -MaxSamples 1
                #Write-Host "Windows Performance Counters API peak WS: $(ConvertTo-HumanReadable -Bytes $peakWSMemory)"
            }

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] **** All trigger processes have exited"
           
            if ($config.lowPriorityWaiting)
            {
                Write-Host "Restoring AutoSuspender priority class"
                $scriptProcess.PriorityClass = $scriptProcessPreviousPriority
            }

            if ($config.showNotifications)
            {
                # FIXME: will only give the name of the last process to exit
                New-BurntToastNotification -Text "$($runningTriggerProcess.Name) exited", "AutoSuspender is resuming target processes." -AppLogo $playIconPath
            }
            

            # FIXME: if you open a game and then you open another game before closing the first, closing the first
            # will result in resuming the suspended processes and then, 2s later, suspending them all again
            # which isn't very efficient.  However most people don't run multiple games at once so
            # this isn't a priority to fix

            Set-TargetProcessesState -Resume -Launcher $launcher
            $suspendedProcesses = $false
            Remove-Item -Path $lockFilePath -Force -ErrorAction Continue

            if ($CheckOnce)
            {
                break
            }
        }
        else
        {
            if ($CheckOnce)
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
    Start-Sleep -Seconds 2
}