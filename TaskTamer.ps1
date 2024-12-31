# Wrapper around the Invoke-TaskTamer function of the TaskTamer module

# Get the folder path of this script
$scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

# Import the module from the same folder
$modulePath = Join-Path -Path $scriptDirectory -ChildPath "TaskTamer.psd1"
Import-Module -Name $modulePath -Force -Verbose

# Call the exported function with all the arguments passed to this script
Invoke-TaskTamer @args