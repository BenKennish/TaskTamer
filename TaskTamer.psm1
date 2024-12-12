<#
TaskTamer
   A PowerShell project by Ben Kennish (ben@kennish.net)

Automatically tames / throttles chosen target processes whenever chosen trigger processes (e.g. video games) are running, then automatically restores the target processes when the trigger process closes.

you can manually import this module using:
 Import-Module -Name ".\TaskTamer.psd1" -Force

----------- TODO list --------------

TODO: allow defining a whitelist of processes NOT to suspend and we suspend everything else
       (running as the user, won't include SYSTEM processes)
       NOTE: very likely to suspend things that will cause problems tho

TODO: if user gives focus to any suspended process (before game has been closed), resume it temporarily.
      this gets quite complicated to do in a way that doesn't potentially increase load on the system
      as it can require repeatedly polling in a while() loop
      OR perhaps just detect when a game loses focus and then unsuspend everything and resuspend them when it gains focus again
      OR they could just manually ctrl-C the script and then run it again before restoring the game app

TODO: if user presses a certain key while it's waiting for a trigger process to close, we could temporarily resume the target processes and then suspend them again when they press the key again (or they give focus to the trigger process)

TODO: other ways to improve performance
- run user configurable list of commands when detecting a game  e.g. wsl --shutdown
- adjust windows visual settings
      Set registry key for best performance in visual effects
      Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 2
-Set Power Plan to High Performance
   powercfg /setactive SCHEME_MIN
- Example for setting affinity
   $process = Get-Process -Name 'SomeProcess'
   $process.ProcessorAffinity = 0x0000000F # Adjust based on available cores

TODO: auto scan for trigger apps or allow users to select them from the shortcuts within start Menu

#>

<#
.SYNOPSIS
Runs TaskTamer to monitor trigger processes (e.g. video games), tame/throttle target processes (e.g. suspending them) while trigger processes are running, and restore them when the trigger processes close.

.DESCRIPTION
Whenever chosen "trigger" processes (e.g. video games) are running, TaskTamer automatically throttles/tames chosen "target" processes (e.g. web browsers, instant messaging apps, and game launchers), and automatically restores them when the trigger process ends.

The precise nature of the throttle/taming can be defined in the config file (%LOCALAPPDATA%\TaskTamer\config.yaml), including a choice of suspending a process (the default), setting it to Low priority, closing it, or doing nothing.  Target processes can also have their windows minimized, have their RAM usage ("working set") trimmed, and be defined as a launcher which means they will not be affected if they were responsible for launching the trigger process.

Suspended target processes are effectively frozen and therefore can't slow down the trigger process (or any other running process) by using CPU or accessing the disk or network in the background. Windows is also more likely to move memory used by target processes from fast RAM to the slower pagefile on disk, which leaves more speedy RAM available for the trigger process to use.

When the trigger process closes, TaskTamer will report how much the RAM usage of the target processes (known as their "working set") decreased during their suspension.

TaskTamer can perform other tricks using the config file (see [Configuration] in README.md) and through various parameters.

.PARAMETER ResumeAll
Immediately resumes all target processes then run as normal. Handy for when a previous launch of the function failed to resume everything for some reason.

.PARAMETER PollTriggers
Poll the status of the trigger process, rather than waiting to be told by Windows when it has stopped, which allows mointoring memory usage. This can be useful for gathering benchmarking data, but it can have a small performance impact so is disabled by default.

.PARAMETER CheckOnce
Checks for trigger processes only once, exiting immediately if none are running. If one is running, performs usual operations then exits when the trigger process exits (after resuming the target processes). Useful if you arrange for the function to run every time Windows runs a new process.

.PARAMETER WhatIf
Enables "what if" mode; the function doesn't actually take any action on target processes but does everything else. Useful for testing and measuring performance benefits of using TaskTamer.

.INPUTS
None
    This function does not accept pipeline input.
.OUTPUTS
None
    This function does not produce any output other than that sent to the console with Write-Host
.EXAMPLE
Invoke-TaskTamer
Run TaskTamer (waiting for a trigger process to run, and then throttling the target processes)
.EXAMPLE
TaskTamer
Also runs TaskTamer like above (it's an alias for Invoke-TaskTamer)
.EXAMPLE
Invoke-TaskTamer -ResumeAll
Resume all target processes and then run as normal
.NOTES
AUTHOR: Ben Kennish
LICENSE: GPL-3.0
.LINK
https://github.com/BenKennish/TaskTamer
#>
function Invoke-TaskTamer
{
    # these are our command line arguments
    [CmdletBinding()]
    [Alias("TaskTamer")]
    param (
        [switch]$ResumeAll,
        [switch]$PollTriggers,
        [switch]$CheckOnce,
        [switch]$WhatIf
    )

    $moduleManifestPath = Join-Path -Path $PSScriptRoot -ChildPath "$(Split-Path -Leaf $PSScriptRoot).psd1"
    $moduleData = Import-PowerShellDataFile -Path $moduleManifestPath
    $Version = $moduleData.ModuleVersion

    $lockFilePath = Join-Path -Path $env:TEMP -ChildPath "\TaskTamer.lock.pid"
    $previousEnv = @{}  # HashTable used to store data about the previous environment

    function Initialize-Environment
    {
        Set-StrictMode -Version Latest   # stricter rules = cleaner code  :)

        if (Test-Path -Path $lockFilePath)
        {
            $pidInLockFile = Get-Content -Path $lockFilePath
            Write-Verbose "Lock file exists and contains '$($pidInLockFile)'"

            if ($pidInLockFile -and
                    (($pidInLockFile -eq $PID) -or
                -not (Get-Process -Id $pidInLockFile -ErrorAction SilentlyContinue)))
            {
                Write-Output "Previous TaskTamer didn't close properly.  Assuming crash and resuming all processes..."

                $columnHeadings = @("NAME", "PID", "RAM", "WINDOW")
                $columnFormats = @("{0,-17}", "{0,-6}", "{0,10}", "{0,-10}")
                Set-TargetProcessesState -Restore -NoDeltas |
                Format-TableFancy -ColumnHeadings $columnHeadings -ColumnFormats $columnFormats

                Remove-Item -Path $lockFilePath -Force
            }
            else
            {
                Write-Host "TaskTamer is already running.  Exiting..." -ForegroundColor Red
                Start-Sleep -Seconds 1
                return $false
            }
        }

        $previousEnv['ErrorView'] = $ErrorView
        $ErrorView = "DetailedView"  # leverages Get-Error to get much more detailed information for the error.

        # default behavior for non-terminating errors (i.e., errors that don’t normally stop execution, like warnings)
        # global preference variable that affects all cmdlets and functions that you run after this line is executed.
        $previousEnv['ErrorActionPreference'] = $ErrorActionPreference
        $ErrorActionPreference = "Stop"

        # modifies the default value of the -ErrorAction parameter for every cmdlet that has the -ErrorAction parameter
        $previousEnv['DefaultErrorAction'] = $PSDefaultParameterValues['*:ErrorAction']
        $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

        # everyone loves UTF-8, right?
        $previousEnv['Console::OutputEncoding'] = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8

        $previousEnv['OutputEncoding'] = $OutputEncoding
        $OutputEncoding = [System.Text.Encoding]::UTF8

        $previousEnv['WindowTitle'] = $host.UI.RawUI.WindowTitle

        return $true

    }

    if (-not (Initialize-Environment))
    {
        return
    }

    # clean up function to call later
    # -----------------------------------------------------------------------------
    function Reset-Environment
    {
        # must use Write-Host here
        # Write-Output and Write-Error are not available when application is
        # shutting down

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] TaskTamer is shutting down..."

        if ($suspendedProcesses)
        {
            # $launcher is the global var that should be set when $suspendedProcesses is true
            Set-TargetProcessesState -Restore -Launcher $launcher
        }

        if (Test-Path -Path $lockFilePath)
        {
            try
            {
                Remove-Item -Path $lockFilePath -Force -ErrorAction Continue
            }
            catch
            {
                Write-Host "Error deleting ${lockFilePath}: $_" -ForegroundColor Red
            }
        }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Restoring original environment..."
        Set-StrictMode -Off  # not strictly necessary but "just in cases"
        $ErrorView = $previousEnv['ErrorView']
        $ErrorActionPreference = $previousEnv['ErrorActionPreference']

        if ($null -eq $previousEnv['DefaultErrorAction'])
        {
            $PSDefaultParameterValues.Remove('*:ErrorAction')
        }
        else
        {
            $PSDefaultParameterValues['*:ErrorAction'] = $previousEnv['DefaultErrorAction']
        }

        [Console]::OutputEncoding = $previousEnv['Console::OutputEncoding']
        $OutputEncoding = $previousEnv['OutputEncoding']
        if ($previousEnv['WindowTitle'])
        {
            $host.UI.RawUI.WindowTitle = $previousEnv['WindowTitle']
        }


        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] (Goodbye)> o/"

        Start-Sleep -Milliseconds 500
    }


    # Are there some processes that we suspended and have yet to resume?
    $suspendedProcesses = $false

    # retrive the path of the folder where the script/module is located
    if (-not ([System.AppDomain]::CurrentDomain.FriendlyName -like "*.exe"))
    {
        Write-Verbose "Running interpreted"

        if ($null -ne $MyInvocation.MyCommand.Module)
        {
            # running as module (.psm1)
            $fullScriptPath = $MyInvocation.MyCommand.Module.Path
        }
        else
        {
            # running as script (.ps1)
            $fullScriptPath = $MyInvocation.MyCommand.Path
        }

        $scriptFolder = Split-Path -Parent $fullScriptPath
    }
    else
    {
        Write-Verbose "Running compiled"
        # if we try to use the code above when running interpreted, the paths are those for powershell.exe
        # rather than the script

        # this prevents issues with external PS code when this script is compiled to a .exe:
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

        # We are likely a compiled executable so we need to get the path like this:
        $fullScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $scriptFolder = [System.IO.Path]::GetDirectoryName($fullScriptPath)
    }


    $appDataPath = "$env:LOCALAPPDATA\TaskTamer"
    $configPath = Join-Path -Path $appDataPath -ChildPath "\config.yaml"

    $templatePath = Join-Path -Path $scriptFolder -ChildPath "\config-template.yaml"
    $pauseIconPath = Join-Path -Path $scriptFolder -ChildPath "\images\pause.ico"
    $playIconPath = Join-Path -Path $scriptFolder -ChildPath "\images\play.ico"

    $shortcutPath = Join-Path -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs" -ChildPath "TaskTamer.lnk"

    # the actual characters (in the comments to the right)
    # cannot be used because PowerShell 5.1 interpreter doesn't
    # like reading in unicode characters during syntax checking
    # (the ones in the comments here are ignored by it)
    $BoxDrawingChars = @{
        TopLeft     = [char]0x250C  # ┌
        TopRight    = [char]0x2510  # ┐
        BottomLeft  = [char]0x2514  # └
        BottomRight = [char]0x2518  # ┘
        Horizontal  = [char]0x2500  # ─
        Vertical    = [char]0x2502  # │
        TTop        = [char]0x252C  # ┬
        TBottom     = [char]0x2534  # ┴
        TLeft       = [char]0x251C  # ├
        TRight      = [char]0x2524  # ┤
        Cross       = [char]0x253C  # ┼
    }

    # Add necessary .NET assemblies for API calls
    # using Add-Type cmdlet (C# code)
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class ProcessManager
    {
        // suspend/resume functionality...

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private const int THREAD_SUSPEND_RESUME = 0x0002;


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


        // minimize windows functionality...

        // Define constants for use with ShowWindow()
        private const int SW_MINIMIZE = 6;
        private const int SW_RESTORE = 9;


        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);
        // Checks if window is minimized (iconified)

        [DllImport("user32.dll")]
        public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        // Delegate for enumerating windows
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern IntPtr GetParent(IntPtr hWnd);


        // minimize all the user-facing windows of a specific process
        // would be more efficient to provide it an array of PIDs and run only once
        public static int MinimizeProcessWindows(int pid)
        {
            int numWindowsMinimized = 0;

            EnumWindows((hWnd, lParam) =>
            {
                int processId;
                GetWindowThreadProcessId(hWnd, out processId);

                // if the window belongs to the process we are interested in
                if (processId == pid)
                {
                    // minimize top-level windows that are visible and not already minimized
                    if (IsTopLevelWindow(hWnd) && IsWindowVisible(hWnd) && !IsIconic(hWnd))
                    {
                        if (ShowWindow(hWnd, SW_MINIMIZE))
                        {
                            numWindowsMinimized++;
                        }
                        else
                        {
                            Console.WriteLine("Process "+pid+" Window "+hWnd+" failed to minimise");
                        }
                    }
                }
                return true;
            }, IntPtr.Zero);

            return numWindowsMinimized;
        }


        // Helper function to check if the window is a top-level window
        private static bool IsTopLevelWindow(IntPtr hWnd)
        {
            IntPtr hParent = GetParent(hWnd);
            return hParent == IntPtr.Zero; // If the parent is null, it's a top-level window
        }



        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

        // force OS to decrease a process' working set
        public static void TrimWorkingSet(int pid)
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);

            // When both dwMinimumWorkingSetSize and dwMaximumWorkingSetSize are set to -1, Windows will
            // automatically trim the process’s working set to the bare minimum required to keep it
            // running. This operation is often referred to as trimming the working set.

            bool res = SetProcessWorkingSetSize(process.Handle, (IntPtr)(-1), (IntPtr)(-1));

            if (!res)
            {
                int errorCode = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(errorCode, "Failed to trim the working set for PID "+pid);
            }
        }

    }

"@



    # Convert a number of bytes into a more human readable string format
    # -------------------------------------------------------------------
    function ConvertTo-HumanReadable
    {
        param (
            [Parameter(Mandatory = $true)] [int64]$Bytes,
            [int]$DecimalDigits = 2,
            [switch]$DisplayPlus
        )

        $units = @("B", "KB", "MB", "GB", "TB", "PB")
        $unitIndex = 0

        if ($Bytes -eq 0)
        {
            return "0 B"
        }

        # we use a float variable so it keeps fractional part
        [float]$value = $Bytes

        while ([Math]::Abs($value) -ge 1024 -and $unitIndex -lt $units.Length - 1)
        {
            $value /= 1024
            $unitIndex++
        }

        $formattedResult = "{0:N$($DecimalDigits)} {1}" -f $value, $units[$unitIndex]

        if ($DisplayPlus -and $Bytes -gt 0)
        {
            $formattedResult = "+$formattedResult"
        }

        return $formattedResult
    }



    # extract the width from any "format" -f $data string  (e.g. "{2,-10}" returns 10)
    function Get-FormatWidth
    {
        param (
            [string]$Format
        )

        # Extract the column width using a more flexible regular expression
        # Match pattern: {index,width:format} or {index,width} or {index:format} or {index}
        if ($Format -match '\{\d+,(?<width>-?\d+)')
        {
            # Extract and return the width as an absolute integer
            return [math]::Abs([int]$matches['width'])
        }
        elseif ($Format -match '\{\d+\}')
        {
            # If there is no width but the pattern is a valid positional `{index}`
            Write-Error "No width specified in format string: $Format"
            return $null
        }
        else
        {
            Write-Error "Invalid format string provided: $Format"
            return $null
        }
    }



    # pipeline function to create a fancy table including colours
    function Format-TableFancy
    {
        param
        (
            # pipeline feeds in row-by-row
            [Parameter(ValueFromPipeline = $true)]
            [Object[]]$Row,

            [Parameter(Mandatory = $true)]
            [string[]]$ColumnHeadings, # Array of column header text
            # because this is a mandatory attribute, none of the array elements can be empty strings
            # so just pass a space (" ") if you don't want a visible heading

            [Parameter(Mandatory = $true)]
            [string[]]$ColumnFormats, # Array of -f format strings to use for each column

            [string]$ColumnSeparator = $BoxDrawingChars.Vertical
        )

        begin
        {

            if ($ColumnHeadings.Length -ne $ColumnFormats.Length)
            {
                Write-Error "Error: ColumnHeadings and ColumnFormats have different lengths: $(ColumnHeadings.Length) vs $($ColumnFormats.Length)"
                return 1
            }

            # Print column headers
            $headerRow = @()
            $headerUnderlineRow = @()

            for ($i = 0; $i -lt $ColumnHeadings.Length; $i++)
            {
                $width = Get-FormatWidth -Format $ColumnFormats[$i]
                $headerCell = ($ColumnFormats[$i] -f $ColumnHeadings[$i])
                $headerUnderlineCell = ($ColumnFormats[$i] -f [String]::new($BoxDrawingChars.Horizontal, $width))
                $headerRow += $headerCell
                $headerUnderlineRow += $headerUnderlineCell
            }

            Write-Host ($headerRow -join $ColumnSeparator) -ForegroundColor Yellow
            Write-Host ($headerUnderlineRow -join [String]::new($BoxDrawingChars.Cross))

        }

        process
        {
            try
            {
                if ($Row.Length -ne $ColumnHeadings.Length)
                {
                    Write-Host "The number of values in the row ($($Row.Length)) does not match the number of columns defined ($($ColumnHeadings.Length))."
                    return 1
                }

                # Loop through the cells and apply format and color to individual cells
                for ($i = 0; $i -lt $Row.Length; $i++)
                {
                    $cell = $Row[$i]

                    if ($i -gt 0)
                    {
                        Write-Host $ColumnSeparator -NoNewline
                    }

                    $writeHostParams = @{}

                    if ($cell -is [PSObject])
                    {
                        if ($cell.PSObject.Properties['ForegroundColor'])
                        {
                            $writeHostParams['-ForegroundColor'] = $cell.ForegroundColor
                        }

                        if ($cell.PSObject.Properties['BackgroundColor'])
                        {
                            $writeHostParams['-BackgroundColor'] = $cell.BackgroundColor
                        }

                        if (-not $cell.PSObject.Properties['data'])
                        {
                            Write-Error "cell is missing data property"
                            return
                        }
                        $cellData = $cell.data
                    }
                    elseif ($cell -is [string])
                    {
                        Write-Verbose "cell is a string, not an object"
                        $cellData = $cell
                    }
                    else
                    {
                        Write-Error "cell is neither an object nor a string"
                        return
                    }

                    # Format the cell using its respective column format string
                    $formattedCellData = $ColumnFormats[$i] -f $cellData

                    Write-Host $formattedCellData -NoNewline @writeHostParams
                }

                # Start a new line after printing the entire row
                Write-Host ""
            }
            catch
            {
                throw "ERROR: $_ on line: $($_.InvocationInfo.ScriptLineNumber), message: $($_.Exception.Message), in: $($_.InvocationInfo.ScriptName), at position: $($_.InvocationInfo.OffsetInLine)"
            }
        }

        end
        {
            $footerUnderlineRow = @()

            for ($i = 0; $i -lt $ColumnHeadings.Length; $i++)
            {
                $width = Get-FormatWidth -Format $ColumnFormats[$i]
                $footerUnderlineCell = ($ColumnFormats[$i] -f [String]::new($BoxDrawingChars.Horizontal, $width))
                $footerUnderlineRow += $footerUnderlineCell
            }
            Write-Host ($footerUnderlineRow -join [String]::new($BoxDrawingChars.TBottom))
        }


    }



    # Display a subtotal row for the previous processes
    # if there was more than 1 with same name
    #
    # -----------------------------------------------------------------------------
    function Write-Subtotal
    {
        param (
            [Parameter(Mandatory = $true)] [int]$SameProcessCount,
            [Parameter(Mandatory = $true)] [string]$LastProcessName,
            [Parameter(Mandatory = $true)] [int64]$SameProcessRamTotal,
            [Nullable[int64]]$SameProcessRamDeltaTotal = $null,
            [string]$ForegroundColor = "",
            [switch]$Launcher
        )

        if ($ForegroundColor -eq "")
        {
            if ($targetProcessesConfig[$LastProcessName]['show_subtotal_only'])
            {
                $ForegroundColor = "Gray"
            }
            else
            {
                $ForegroundColor = "Yellow"
            }
        }

        if ($SameProcessCount -gt 1 -or $targetProcessesConfig[$LastProcessName]['show_subtotal_only'])
        {
            # only show subtotal when there is 2+ processes or if we are only showing subtotals (so we want to show the 'subtotal' for 1 process too)
            if ($null -ne $SameProcessRamDeltaTotal)
            {
                if ($Launcher)
                {
                    $row = @(
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = $LastProcessName },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "TOTAL:" },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamTotal) },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamDeltaTotal -DisplayPlus) },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = "<Ignored Launcher>" }
                    )
                }
                else
                {
                    $row = @(
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = $LastProcessName },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "TOTAL:" },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamTotal) },
                        [PSCustomObject] @{ ForegroundColor = (Get-BytesColour -Bytes $SameProcessRamDeltaTotal -NegativeIsPositive); Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamDeltaTotal -DisplayPlus) },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "" }
                    )
                }
            }
            else
            {
                if ($Launcher)
                {
                    # this may not get hit at all anymore as we are excluding launchers from display in the table
                    $row = @(
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = $LastProcessName },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "TOTAL:" },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamTotal) },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = "<Ignored Launcher>" }
                    )
                }
                else
                {
                    $row = @(
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = $LastProcessName },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "TOTAL:" },
                        [PSCustomObject] @{ ForegroundColor = (Get-BytesColour -Bytes $SameProcessRamTotal); Data = (ConvertTo-HumanReadable -Bytes $SameProcessRamTotal) },
                        [PSCustomObject] @{ ForegroundColor = $ForegroundColor; Data = "" }
                    )
                }
            }
            Write-Output -NoEnumerate $row
        }
    }

    # return the colour in which to display a number of bytes according to certain rules
    function Get-BytesColour
    {
        param (
            [Parameter(Mandatory = $true)] [int64]$Bytes,
            [switch]$NegativeIsPositive # if set, the more negative a number is, the better it is.
        )

        if ($NegativeIsPositive -and $Bytes -gt 0)
        {
            return "Red"
        }
        if (-not $NegativeIsPositive -and $Bytes -lt 0)
        {
            return "Red"
        }

        $colours = @("DarkGray", "Gray", "Cyan", "Green", "Magenta")
        $unitIndex = 0

        # TODO: you could make this standardised using different powers of 10
        if ([Math]::Abs($bytes) -ge 1024 * 1024)  # >= 1MB
        {
            $unitIndex++
        }
        if ([Math]::Abs($bytes) -ge 10 * 1024 * 1024) # >= 10MB
        {
            $unitIndex++
        }
        if ([Math]::Abs($bytes) -ge 100 * 1024 * 1024) # >= 100MB
        {
            $unitIndex++
        }
        if ([Math]::Abs($bytes) -ge 1024 * 1024 * 1024) # >= 1GB
        {
            $unitIndex++
        }

        return $colours[$unitIndex]

    }


    # Suspend / resume target processes
    # other approved verbs, "Optimize", "Limit"
    #
    # TODO: i think we want to send arrays of processes with the same name to this
    # function.  it'll make subtotalling easier and also terminating.
    # -----------------------------------------------------------------------------
    function Set-TargetProcessesState
    {
        [CmdletBinding(DefaultParameterSetName = 'Throttle')]
        param (
            [string]$Launcher = "",

            [Parameter(ParameterSetName = 'Throttle', Mandatory = $true)]
            [switch]$Throttle,

            [Parameter(ParameterSetName = 'Restore', Mandatory = $true)]
            [switch]$Restore,
            [Parameter(ParameterSetName = 'Restore')]
            [switch]$NoDeltas
        )

        $totalRamUsage = 0

        # vars that track groups of proccesses with the same name
        $lastProcessName = ""
        $sameProcessCount = 0
        $sameProcessRamTotal = 0
        $sameProcessRamDeltaTotal = $null

        # used to track how the RAM usage of target processes changed during their suspension
        if ($Restore -and -not $NoDeltas)
        {
            $totalRamDelta = 0
            $sameProcessRamDeltaTotal = 0
        }
        else
        {
            $NoDeltas = $true  # force NoDeltas to true (so its not unset when $Throttle)
        }

        # using Write-Host not Write-Output as this function can be called while
        # the script is terminating and then has no access to Write-Output pipeline

        # NB: for a -Restore, we don't look at suspendedProcesses array but just do another process scan
        # this might result in trying to resume new processes that weren't suspended (by us)
        # (probably doesn't matter but it's not very elegant)


        # TODO: group into processes that have the same name
        $runningTargetProcesses = Get-Process | Where-Object { $targetProcessesConfig.ContainsKey($_.Name) }

        foreach ($proc in $runningTargetProcesses)
        {
            #TODO: these might be useful properties:
            #        $proc.PagedMemorySize64
            #        $proc.PriorityBoostEnabled
            #        $proc.MainWindowTitle
            #        $proc.MainWindowHandle
            # see also: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process?view=net-8.0


            # sanity checking to make sure we aren't about to suspend a trigger process
            # $runningTriggerProcesses.Name returns an array of all process names
            #
            # TODO: think about the reliability of this
            # e.g. what if a new trigger process starts between the first one and this test
            #
            # should we just check that no processes are defined as both trigger and target?

            #$runningTriggerProcesses will be falsey if we are doing a instant resume at start ("-ResumeAll")

            if ($runningTriggerProcesses -and $runningTriggerProcesses.Name -contains $proc.Name)
            {
                Write-Warning "Ignoring target process $($proc.Name) ($($proc.Id)) as it is one of the running trigger processes."
                continue  # to next target process
            }

            $proc.Refresh()  # refresh the stats for the process

            if ($proc.HasExited)
            {
                Write-Verbose "Ignoring PID $($proc.Id) as already exited."
                #TODO: write info and account for exited processes with ram deltas
                # because their memory usage is not 0 bytes
                continue
            }

            if ($Throttle)
            {
                # store current RAM usage for this PID before we suspend it
                if (-not $processHistory[$proc.Id]) { $processHistory[$proc.Id] = @{} }
                $processHistory[$proc.Id]['workingSet'] = $proc.WorkingSet64
            }

            # ignore launcher processes completely when resuming
            if ($Restore -and $proc.Name -eq $Launcher)
            {
                continue
            }

            # if this process has a different name to the last one
            if ($proc.Name -ne $lastProcessName)
            {
                if ($lastProcessName -ne "")   # if this isn't the very first process
                {
                    # display subtotal for the previous group of processes with the same name
                    if ($lastProcessName -eq $Launcher)
                    {
                        Write-Subtotal `
                            -SameProcessCount $sameProcessCount `
                            -LastProcessName $lastProcessName `
                            -SameProcessRamTotal $sameProcessRamTotal `
                            -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal `
                            -ForegroundColor "DarkGray" `
                            -Launcher
                    }
                    else
                    {
                        Write-Subtotal `
                            -SameProcessCount $sameProcessCount `
                            -LastProcessName $lastProcessName `
                            -SameProcessRamTotal $sameProcessRamTotal `
                            -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal
                    }

                }

                # store info on this new process name group
                $lastProcessName = $proc.Name
                $sameProcessCount = 1
                $sameProcessRamTotal = $proc.WorkingSet64

                if (-not $NoDeltas)
                {
                    if (-not $processHistory[$proc.Id]) { $processHistory[$proc.Id] = @{} }
                    $sameProcessRamDeltaTotal = $proc.WorkingSet64 - ($processHistory[$proc.Id]['workingSet'])
                }
            }
            else
            {
                # this process has same name as last one. continuing adding the subtotals
                $sameProcessCount++
                $sameProcessRamTotal += $proc.WorkingSet64

                if (-not $NoDeltas)
                {
                    if (-not $processHistory[$proc.Id]) { $processHistory[$proc.Id] = @{} }
                    $sameProcessRamDeltaTotal += ($proc.WorkingSet64 - $processHistory[$proc.Id]['workingSet'])
                }
            }

            # this process is a launcher that was used to spawn the trigger process
            if ($proc.Name -eq $Launcher)
            {
                Write-Verbose "$($proc.Name) ignored - launcher for trigger process"

                if ($NoDeltas)
                {
                    $row = @(
                        [PSCustomObject] @{ Data = $proc.Name },
                        [PSCustomObject] @{ Data = $proc.Id },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64) },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = "<Ignoring Launcher: $($launchers[$Launcher])>" }
                    )
                }
                else
                {
                    $row = @(
                        [PSCustomObject] @{ Data = $proc.Name },
                        [PSCustomObject] @{ Data = $proc.Id },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64) },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = "n/a" },
                        [PSCustomObject] @{ ForegroundColor = "DarkGray"; Data = "<Ignored Launcher: $($launchers[$Launcher])>" }
                    )
                }

                if (-not $targetProcessesConfig[$proc.Name]['show_subtotal_only'])
                {
                    Write-Output -NoEnumerate $row
                }
                continue # to next process
            }

            $totalRamUsage += $proc.WorkingSet64
            if (-not $NoDeltas)
            {
                if (-not $processHistory[$proc.Id]) { $processHistory[$proc.Id] = @{} }
                $totalRamDelta += ($proc.WorkingSet64 - $processHistory[$proc.Id]['workingSet'])
            }

            $windowTitle = ""
            if ($proc.MainWindowTitle)
            {
                $windowTitle = "[$($proc.MainWindowTitle)]"
            }

            if ($NoDeltas)
            {
                $row = @(
                    [PSCustomObject] @{ Data = $proc.Name },
                    [PSCustomObject] @{ Data = $proc.Id },
                    [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64); ForegroundColor = (Get-BytesColour -Bytes $proc.WorkingSet64) },
                    [PSCustomObject] @{ Data = $windowTitle }
                )
            }
            else
            {
                $row = @(
                    [PSCustomObject] @{ Data = $proc.Name },
                    [PSCustomObject] @{ Data = $proc.Id },
                    [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes $proc.WorkingSet64) },
                    [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes ($proc.WorkingSet64 - $processHistory[$proc.id]['workingSet']) -DisplayPlus); ForegroundColor = (Get-BytesColour -Bytes ($proc.WorkingSet64 - $processHistory[$proc.id]['workingSet']) -NegativeIsPositive) },
                    [PSCustomObject] @{ Data = $windowTitle }
                )
            }
            if (-not $targetProcessesConfig[$proc.Name]['show_subtotal_only'])
            {
                Write-Output -NoEnumerate $row
            }

            if (!$WhatIf)
            {
                switch ($targetProcessesConfig[$proc.Name]['action'])
                {
                    # valid values: suspend, close, deprioritize, close, none
                    'suspend'
                    {
                        if ($Throttle)
                        {
                            [ProcessManager]::SuspendProcess($proc.Id)
                        }
                        elseif ($Restore)
                        {
                            [ProcessManager]::ResumeProcess($proc.Id)
                        }
                    }
                    'deprioritize'
                    {
                        if ($Throttle)
                        {
                            # keep track of previous priority so we can restore it
                            if (-not $processHistory[$proc.Id]) { $processHistory[$proc.Id] = @{} }
                            $processHistory[$proc.Id]['priority'] = $proc.PriorityClass
                            Write-Verbose "$($proc.Name) ($($proc.Id)) has priority: $($proc.PriorityClass)"
                            $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
                        }
                        else
                        {
                            Write-Verbose "$($proc.Name) ($($proc.Id)) to previous priority..."
                            $proc.PriorityClass = $processHistory[$proc.Id]['priority']
                        }
                    }
                    'close'
                    {
                        # TODO: we only want to close the parent process and let it close the children
                        # TODO: (optionally?) rerun the process
                        # (store the cmd line before closing)
                        <#
                        if ($Throttle)
                        {
                            Write-Verbose "Stopping process $($proc.Id)..."
                            Stop-Process -Id $proc.Id
                        }
                        #>

                        Write-Warning "Unable to 'close' $($proc.Name) ($($proc.Id)) : unimplemented."
                    }
                    'none'
                    {
                        Write-Verbose "Doing nothing to process '$($proc.Name) ($($proc.Id))' as action='none'."
                    }
                    default
                    {
                        throw "Unknown action '$($targetProcessesConfig[$proc.Name]['action'])' defined for process '$($proc.Name)'"
                    }
                }

                if ($Throttle -and $targetProcessesConfig[$proc.Name]['trim_working_set'])
                {
                    [ProcessManager]::TrimWorkingSet($proc.Id)
                    Start-Sleep -Milliseconds 200
                    $proc.Refresh()
                    Write-Host "$($proc.Name) ($($proc.Id)) RAM trimmed to $(ConvertTo-HumanReadable -Bytes $proc.WorkingSet64)" -ForegroundColor Magenta
                }
            }

            $lastProcessName = $proc.Name
        }

        # write subtotal row for the last process group (if there were >1 processes)
        if ($lastProcessName -eq $Launcher)
        {
            Write-Subtotal `
                -SameProcessCount $sameProcessCount `
                -LastProcessName $lastProcessName `
                -SameProcessRamTotal $sameProcessRamTotal `
                -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal `
                -ForegroundColor "DarkGray" `
                -Launcher
        }
        else
        {
            Write-Subtotal `
                -SameProcessCount $sameProcessCount `
                -LastProcessName $lastProcessName `
                -SameProcessRamTotal $sameProcessRamTotal `
                -SameProcessRamDeltaTotal $sameProcessRamDeltaTotal
        }

        # write final total row
        if (-not $NoDeltas)
        {
            $row = @(
                [PSCustomObject] @{ Data = "<TOTAL>"; ForegroundColor = "Yellow" },
                [PSCustomObject] @{ Data = "+++++"; ForegroundColor = "Yellow" },
                [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes $totalRamUsage); ForegroundColor = "Yellow"; },
                [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes $totalRamDelta -DisplayPlus); ForegroundColor = (Get-BytesColour -Bytes $totalRamDelta -NegativeIsPositive) },
                [PSCustomObject] @{ Data = ""; ForegroundColor = "Yellow" }
            )
            Write-Output -NoEnumerate $row
        }
        else
        {
            $row = @(
                [PSCustomObject] @{ Data = "<TOTAL>"; ForegroundColor = "Yellow"; },
                [PSCustomObject] @{ Data = "+++++"; ForegroundColor = "Yellow" },
                [PSCustomObject] @{ Data = (ConvertTo-HumanReadable -Bytes $totalRamUsage); ForegroundColor = (Get-BytesColour -Bytes $totalRamUsage) },
                [PSCustomObject] @{ Data = ""; ForegroundColor = "Yellow" }
            )
            Write-Output -NoEnumerate $row
        }

    }


    # Text from a unicorn's arsehole!
    # -----------------------------------------------------------------------------
    function Write-HostRainbow
    {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Text
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
    # returns the process name of the launcher that's running
    # (e.g. Steam, EpicGamesLauncher) else $null
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
                    Write-Verbose "Found launcher: $($currentProcess.Name) ($($launchers[$currentProcess.Name.ToLower()])) for process: $($Process.Name)"
                    return $currentProcess.Name
                }

                # Get the parent process ID
                $parentProcessId = (Get-WmiObject Win32_Process -Filter "ProcessId = $($currentProcess.Id)").ParentProcessId

                # Break if there is no parent (reached the top of the process tree)
                if (-not $parentProcessId)
                {
                    Write-Verbose "No parent process found for '$($Process.Name)'."
                    return
                }

                # Get the parent process
                $currentProcess = Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue

                if (-not $currentProcess)
                {
                    Write-Verbose "Parent process (PID: $parentProcessId) no longer running for '$($process.Name)'."
                    return
                }

                # Optionally output the current checking process
                Write-Verbose "Checking parent process: $($currentProcess.Name)"
            }
            catch
            {
                # Get the call stack
                $callStack = Get-PSCallStack
                throw "An error occurred while retrieving information about the process: $($currentProcess.Name) on line $($callStack[0].ScriptLineNumber) : $_"
            }
        }

        Write-Verbose "No launcher found for game: $($gameProcess.Name)."
        return $null
    }

    # if there are any keys in the read buffer, keep reading them
    # until either the character $KeyCharacter is found, or until
    # there are no more keys in the buffer.
    # returns $true if $KeyCharacter was found, else $false
    #
    function Test-KeyPress
    {
        param (
            [Parameter(Mandatory = $true)]
            [char]$KeyCharacter
        )

        while ([Console]::KeyAvailable)
        {
            $keyPressed = [Console]::ReadKey($true)

            if ($keyPressed.KeyChar -eq $KeyCharacter)
            {
                return $true
            }
        }
        return $false
    }


    # wait for the supplied number of seconds for the user to press the supplied character
    # return true if they pressed it or false if they didn't
    function Wait-ForKeyPress
    {
        param (
            [Parameter(Mandatory = $true)]
            [int]$Seconds,

            [Parameter(Mandatory = $true)]
            [char]$KeyCharacter,

            [switch]$WaitFullDuration
            # if set, we don't poll but just report if key was pressed at end
            # can lead to unresponsive feeling if $Seconds is high
        )

        if ($WaitFullDuration)
        {
            # sleep the whole duration
            Start-Sleep -Seconds $Seconds
            return Test-KeyPress -KeyCharacter $KeyCharacter
        }
        else
        {
            $endTime = (Get-Date).AddSeconds($Seconds)

            while ((Get-Date) -lt $endTime)
            {
                if (Test-KeyPress -KeyCharacter $KeyCharacter)
                {
                    return $true
                }
                Start-Sleep -Milliseconds 200  # polling interval 200ms
            }
        }
        return $false

    }



    # Function to validate if a TargetPath (e.g. within a Windows Shortcut) has an existing target file
    # the Target Path might have quotation marks around and spaces within the first argument
    # and might include additional command line arguments
    <#
    function Test-CmdLineTarget
    {
        param (
            [string]$CmdLine
        )

        Write-Verbose "Test-CmdLineTarget testing..."
        Write-Verbose $CmdLine

        # Use PowerShell's command-line parsing to properly handle quoted paths
        #$cmdArgs = [System.Management.Automation.CommandLine]::ParseCommandLine($CmdLine)

        # Create the ProcessStartInfo object
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.Arguments = $CmdLine

        # Parse the arguments
        # FIXME: this doesnt work properly when there are quoted args with surrounding " marks
        $cmdArgs = $startInfo.Arguments.Split(' ')

        Write-Host "Parsed Arguments:"
        Write-Host $cmdArgs

        # The first element of $cmdArgs should be the target file
        $targetFile = $cmdArgs[0]
        Write-Verbose "targetFile: $targetFile"

        # Check if the file exists
        if (Test-Path $targetFile)
        {
            return $true
        }
        return $false
    }
    #>



    # merge two hashmaps into a new one
    #
    # in PowerShell 7 we'd just use the '+' operator
    function Merge-Hashmaps
    {
        param (
            [Parameter(Mandatory = $true)]
            [Hashtable]$Default,

            [Parameter(Mandatory = $true)]
            [AllowNull()]
            [Hashtable]$Override
        )

        # necessary as Hashtables are passed by reference
        $merged = $Default.Clone()

        if ($null -ne $Override)
        {
            foreach ($key in $Override.Keys)
            {
                $merged[$key] = $Override[$key]
            }
        }
        return $merged
    }

    # =============================================================================
    # =============================================================================

    # =============================================================================

    # =============================================================================
    # =============================================================================

    $cleanupAction = {
        Write-Verbose "Cleaning up..."
        Reset-Environment

        # not sure whether this is strictly necessary but it doesn't hurt
        Unregister-Event -SourceIdentifier PowerShell.Exiting -ErrorAction Continue

        # ensures the script does indeed stop now
        # optional, but if we are cleaning up, we probably want to insist on closure
        Stop-Process -Id $PID
    }

    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Verbose "[PowerShell.Exiting] event triggered"
        & $cleanupAction
    }

    $title = "TaskTamer v$Version"
    $host.UI.RawUI.WindowTitle = $title

    $boxLength = $title.Length + 2

    # Draw the pretty name box
    Write-Host ("{0}{1}{2}" -f
        $BoxDrawingChars.TopLeft,
            ([String]::new($BoxDrawingChars.Horizontal, $boxLength)),
        $BoxDrawingChars.TopRight) -ForegroundColor Yellow

    Write-Host ($BoxDrawingChars.Vertical + " ") -NoNewLine -ForegroundColor Yellow
    Write-HostRainbow $title
    Write-Host (" " + $BoxDrawingChars.Vertical) -ForegroundColor Yellow

    Write-Host ("{0}{1}{2}" -f
        $BoxDrawingChars.BottomLeft,
            ([String]::new($BoxDrawingChars.Horizontal, $boxLength)),
        $BoxDrawingChars.BottomRight) -ForegroundColor Yellow

    # Check if any unexpected arguments were provided
    # (they get leftover within $args)
    if ($args.Count -gt 0)
    {
        Write-Error "Unexpected argument(s): $($args -join ', ')" -ErrorAction Continue
        Write-Usage
        return
    }

    # a hash table used to map process PIDs of target processes to information about them prior to being tamed/throttled
    # e.g. $processHistory[1234]['workingSet'] stores the working set RAM (bytes) usage of PID 1234
    # FIXME: this should really be a hashmap of objects!
    $processHistory = @{}

    # create start menu shortcut if not already present
    if (-not (Test-Path -Path $shortcutPath))
    {
        $shell = New-Object -ComObject WScript.Shell
        $shortcutLink = $shell.CreateShortcut($shortcutPath)

        $powerShellPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\WindowsPowerShell\v1.0\powershell.exe"

        $shortcutLink.TargetPath = $powerShellPath
        $shortcutLink.Arguments = "-ExecutionPolicy Bypass -NoProfile -Command `"Invoke-TaskTamer`""

        $shortcutLink.WorkingDirectory = $scriptFolder
        $shortcutLink.IconLocation = $pauseIconPath
        $shortcutLink.Save()
        Write-Host "Windows shortcut created at $shortcutPath"

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
        $shell = $null
    }

    # Create $appDataPath if necessary
    if (-not (Test-Path -Path $appDataPath))
    {
        New-Item -Path $appDataPath -ItemType Directory | Out-Null
    }

    $configYamlHeader = @"
# TaskTamer config file (YAML format)
# Generated originally from a v$Version template
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"@

    if (-not (Test-Path -Path $configPath))
    {
        # read in the text of the templateFile, remove the header, replace with our header, then save
        # (?s) dotall mode to make . match newline characters

        Write-Host "Creating $configPath from config-template.yaml..." -ForegroundColor Yellow
            ((Get-Content -Path $templatePath -Raw) -replace "(?s)# @=+\s.*?=+@", $configYamlHeader) | Out-File -FilePath $configPath -Force
    }


    $config = Get-Content -Path $configPath -Raw | ConvertFrom-Yaml

    if ($config -isnot [Hashtable])
    {
        throw "Config YAML file conversion created $($config.GetType().Name), expected Hashtable"
    }

    # TODO: sanity check the presence of certain config parameters?
    # TODO: flag up any unrecognised config parameters?

    # build merged config hashtable for target processes using defaults
    $targetProcessesConfig = @{}

    $config['target_processes'].Keys | ForEach-Object {
        $targetProcessesConfig[$_] = Merge-Hashmaps -Default $config['target_process_defaults'] -Override $config['target_processes'][$_]
    }

    Write-Verbose "targetProcessesConfig (merged)..."
    Write-Verbose ($targetProcessesConfig | ConvertTo-Yaml)


    $launchers = @{}
    $targetProcessesConfig.Keys | Where-Object { $targetProcessesConfig[$_]['is_launcher'] -eq $true } | ForEach-Object { $launchers[$_] = $_ }
    # TODO: set the value to a nice descriptive name for the launcher?

    Write-Verbose '$launchers:'
    Write-Verbose ($launchers | ConvertTo-Json)


    if ($config['show_notifications'])
    {
        #Enable-Module -Name "BurntToast"
        $notificationsHeader = New-BTHeader -Id 'TaskTamer' -Title 'TaskTamer'
    }

    if ($WhatIf)
    {
        Write-Host "ATTENTION: 'What If' mode enabled!  No suspending, resuming, or minimising will occur" -ForegroundColor Red
    }
    Write-Verbose "scriptPath: $scriptFolder"
    Write-Verbose "PollTriggers: $PollTriggers"
    Write-Host ""

    # we set this variable before potentially calling for a -Restore
    # to avoid an error
    $runningTriggerProcesses = @()


    try
    {
        # create lockfile with our PID in
        $PID | Out-File -FilePath $lockFilePath -Force

        if ($ResumeAll)
        {
            Write-Output "Resuming all processes ('-ResumeAll')..."
            $columnHeadings = @("NAME", "PID", "RAM", "WINDOW")
            $columnFormats = @("{0,-17}", "{0,-6}", "{0,10}", "{0,-10}")
            Set-TargetProcessesState -Restore -NoDeltas | Format-TableFancy -ColumnHeadings $columnHeadings -ColumnFormats $columnFormats
        }

        # did we sit idle last time around the while() loop?
        $wasIdleLastLoop = $false

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
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Listening for trigger processes {Press Q to Quit}..."
                }
            }

            $wasIdleLastLoop = $true

            # NB: hashtables are case insensitive w.r.t. their keys by default
            $runningTriggerProcesses = Get-Process | Where-Object { $config['trigger_processes'].ContainsKey($_.Name) }

            if ($runningTriggerProcesses)
            {
                $wasIdleLastLoop = $false
                $launcher = ""

                foreach ($runningTriggerProcess in $runningTriggerProcesses)
                {
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Trigger process detected: $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id))"

                    if (-not $runningTriggerProcess.PriorityBoostEnabled)
                    {
                        Write-Warning "This trigger process is not runining with PriorityBoost enabled"
                    }

                    if ($config['show_notifications'])
                    {
                        New-BurntToastNotification -Text "$($runningTriggerProcess.Name) is running", "Minimising and suspending target processes to improve performance." -AppLogo $pauseIconPath -UniqueIdentifier "TaskTamer" -Sound IM -Header $notificationsHeader
                    }

                    $launcher = Find-Launcher -Process $runningTriggerProcess
                    if ($launcher)
                    {
                        Write-Output "**** Detected running using launcher '$launcher' ($($launchers[$launcher]))"
                        #TODO: insert launcher specific configuration/optimisation here?
                    }
                }

                if ($config['low_priority_waiting'])
                {
                    $scriptProcess = Get-Process -Id $PID
                    $scriptProcessPreviousPriority = $scriptProcess.PriorityClass

                    Write-Host "Setting TaskTamer to a lower priority"
                    $scriptProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
                    # ProcessPriorityClass]::Idle is what Task Manager calls "Low"
                }

                # Minimise windows of all target processes
                # FIXME: doesn't work for certain apps (e.g. Microsoft Store apps like WhatsApp)
                Write-Host "Minimising target process windows..."


                foreach ($proc in Get-Process | Where-Object { $targetProcessesConfig.ContainsKey($_.Name) -and $targetProcessesConfig[$_.Name]['minimize'] })
                {

                    try
                    {
                        $numWindowsMinimised = 0;
                        if (!$WhatIf)
                        {
                            try
                            {
                                $numWindowsMinimised = [ProcessManager]::MinimizeProcessWindows($proc.Id)
                                if ($numWindowsMinimised)
                                {
                                    Write-Output "Minimised: $($proc.Name) ($($proc.Id)) [$($numWindowsMinimised) windows]"
                                }
                            }
                            catch
                            {
                                Write-Verbose "Error minimising windows for PID $($proc.ID): $_"
                            }
                        }
                    }
                    catch
                    {
                        Write-Error "!!!! Failed to minimise: $($proc.Name) ($($proc.Id)). Error: $_";
                    }
                }

                # Wait a short time before suspending to ensure minimize commands have been processed
                Start-Sleep -Milliseconds 250

                Write-Host "Suspending target processes..."
                $columnHeadings = @("NAME", "PID", "RAM", "WINDOW")
                $columnFormats = @("{0,-17}", "{0,-6}", "{0,10}", "{0,-10}")

                Set-TargetProcessesState -Throttle -Launcher $launcher | Format-TableFancy -ColumnHeadings $columnHeadings -ColumnFormats $columnFormats

                if ($PollTriggers)
                {
                    Write-Verbose "Polling the trigger processes to get their memory usage"
                }

                # Wait for the trigger process(es) to exit
                foreach ($runningTriggerProcess in $runningTriggerProcesses)
                {
                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** Waiting for trigger process $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) to exit..."

                    if ($PollTriggers)
                    {
                        $peakWorkingSet = 0
                        $peakPagedMemorySize = 0

                        while (!$runningTriggerProcess.HasExited)
                        {
                            $runningTriggerProcess.Refresh()

                            # we use 'Max' just in case we end up running this just after the process has exited
                            $peakWorkingSet = [Math]::Max($runningTriggerProcess.PeakWorkingSet64, $peakWorkingSet)
                            $peakPagedMemorySize = [Math]::Max($runningTriggerProcess.PeakPagedMemorySize64, $peakPagedMemorySize)

                            Write-Debug "$($runningTriggerProcess.Name) Peak WS: $(ConvertTo-HumanReadable -Bytes $peakWorkingSet)"
                            Write-Debug "$($runningTriggerProcess.Name) Peak Paged: $(ConvertTo-HumanReadable -Bytes $peakPagedMemorySize)"

                            Start-Sleep -Seconds 2  #hardcoded now
                        }

                        Write-Host "$($runningTriggerProcess.Name) Peak WS: $(ConvertTo-HumanReadable -Bytes $peakWorkingSet)"
                        Write-Host "$($runningTriggerProcess.Name) Peak Paged: $(ConvertTo-HumanReadable -Bytes $peakPagedMemorySize)"
                    }
                    else
                    {
                        $runningTriggerProcess.WaitForExit()
                    }

                    Write-Output "[$(Get-Date -Format 'HH:mm:ss')] **** $($runningTriggerProcess.Name) ($($runningTriggerProcess.Id)) exited"

                    # FIXME: if there is more than one trigger process running, we will checking the memory stats of them in order
                    # and once the first exits, the others might exit too and their stats will be invalid
                }

                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] **** All trigger processes have exited"

                if ($config['low_priority_waiting'])
                {
                    Write-Host "Restoring TaskTamer priority class"
                    $scriptProcess.PriorityClass = $scriptProcessPreviousPriority
                }

                # ---------------------------------------------------------------------------------------------------

                if ($config['show_notifications'])
                {
                    # FIXME: will only give the name of the last trigger process to exit
                    New-BurntToastNotification -Text "$($runningTriggerProcess.Name) exited", "Resuming target processes." -AppLogo $playIconPath -UniqueIdentifier "TaskTamer" -Sound IM -Header $notificationsHeader
                }

                # FIXME: if you open a game and then you open another game before closing the first, closing the first
                # will result in resuming the suspended processes and then, 2s later, suspending them all again
                # which isn't very efficient.  However most people don't run multiple games at once so
                # this isn't a priority to fix

                Write-Host "Restoring target processes..."

                $columnHeadings = @("NAME", "PID", "RAM", "CHANGE", "WINDOW")
                $columnFormats = @("{0,-17}", "{0,-6}", "{0,10}", "{0,11}", "{0,-10}")
                Set-TargetProcessesState -Restore -Launcher $launcher | Format-TableFancy -ColumnHeadings $columnHeadings -ColumnFormats $columnFormats

                $suspendedProcesses = $false

                # Overwatch config file patch for 'BroadcastMarginLeft'
                #
                # TODO: get OW2 to create a fresh .ini then examine to see if it's \r\n or \n
                # also check UTF-8 with or without BOM
                #
                # ---------------------------------------------------------------------------------------------------
                if ($config['overwatch2_config_patch'] -and ($runningTriggerProcess.Name -eq "Overwatch"))
                {
                    try
                    {
                        $ow2ConfigFile = Join-Path -Path ([System.Environment]::GetFolderPath('MyDocuments')) -ChildPath "\Overwatch\Settings\Settings_v0.ini"
                        Write-Host "overwatch2ConfigPatch set. Examining $ow2ConfigFile (in 5s)..."

                        # sleep to give extra time for OW2 to save and release lock on the file
                        Start-Sleep -Seconds 5

                        $contents = Get-Content -Raw -Encoding UTF8 -Path $ow2ConfigFile

                        # normalise line endings to Windows style (shouldn't be necessary)
                        #$contents = $contents -replace '\r?\n', "`r`n"

                        # (?m) enables multiline mode
                        # https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options#multiline-mode
                        # but $ will not recognize the carriage return/line feed character combination (\r\n) as $ always ignores any carriage return (\r).
                        # To end your match with either \r\n or \n, use the subexpression \r?$ instead of just $. Note that this will make the \r part of the match.
                        $regex = '(?m)^BroadcastMarginLeft\s*=\s*".*?"(\r?)$'
                        $replacement = 'BroadcastMarginLeft = "1.000000"$1'

                        <#
                        Write-Host "Regex match details:"
                        if ($contents -match $regex)
                        {
                            Write-Host "Match found!"
                            $Matches | Out-Host
                        }
                        else
                        {
                            Write-Host "No match found."
                        }
                        #>

                        $newContents = $contents -replace $regex, $replacement

                        if ($contents -ne $newContents)
                        {
                            # FIXME: bug w.r.t. ShowIntro = "0" ended up on the ini file repeated times
                            # but possibly it was caused by writing conflict between Overwatch and this function
                            Write-Host "**** Patching $ow2ConfigFile to fix 'BroadcastMarginLeft'..."

                            # FIXME: will create a BOM
                            $newContents | Out-File -Encoding UTF8 -FilePath $ow2ConfigFile
                            #Set-Content -Path $ow2ConfigFile -Value $newContents -Encoding UTF8
                        }
                        else
                        {
                            Write-Host "No patching required"
                        }
                    }
                    catch
                    {
                        Write-Host "Error: $($_.Exception.Message)"
                        Write-Host "At line: $($_.InvocationInfo.ScriptLineNumber) in $($_.InvocationInfo.ScriptName)"
                        Write-Host $_.InvocationInfo.Line
                    }
                }

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
                Write-Output "[$(Get-Date -Format 'HH:mm:ss')] Sleeping for 3 seconds... {Press Q to Quit}"
            }

            if (Wait-ForKeyPress -Seconds 3 -KeyCharacter "Q")
            {
                break # out of while()
            }
        }
    }
    catch
    {
        Write-Host "Caught an error! : $_"
        #Write-Host "Error occurred at line: $($PSCmdlet.MyInvocation.ScriptLineNumber)"
        #Write-Host "Detailed Error Info:"

        Write-Host "Line: $($_.InvocationInfo.ScriptLineNumber)"
        Write-Host "Command: $($_.InvocationInfo.InvocationName)"
        Write-Host $_
    }
    finally
    {
        Write-Host "Finally...."
        Reset-Environment
    }
}
