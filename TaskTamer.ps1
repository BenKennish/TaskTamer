# Wrapper around the Invoke-TaskTamer function of the TaskTamer module

# Enable strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Setup logging
$logPath = Join-Path $env:LOCALAPPDATA 'TaskTamer\logs'
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}
$logFile = Join-Path $logPath "TaskTamer-$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $Message" | Add-Content -Path $logFile
}

# Configure PSReadLine for better console experience
if (Get-Module -Name PSReadLine) {
    Set-PSReadLineOption -Colors @{
        Command   = 'Yellow'
        Number    = 'Green'
        Member    = 'Cyan'
        Operator  = 'Magenta'
        Type      = 'Blue'
        Variable  = 'Red'
        Parameter = 'Gray'
    }
}

try {
    Write-Log "Starting TaskTamer"
    
    # Get the folder path of this script
    $scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    Write-Log "Script directory: $scriptDirectory"

    # Import the module from the same folder
    $modulePath = Join-Path -Path $scriptDirectory -ChildPath "TaskTamer.psd1"
    Write-Log "Importing module from: $modulePath"
    Import-Module -Name $modulePath -Force -Verbose

    # Call the exported function with all the arguments passed to this script
    Write-Log "Invoking TaskTamer with arguments: $args"
    Invoke-TaskTamer @args
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    throw
}
finally {
    Write-Log "TaskTamer execution completed"
}