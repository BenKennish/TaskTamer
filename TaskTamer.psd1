@{
    RootModule           = 'TaskTamer.psm1'
    ModuleVersion        = '0.15.0'
    CompatiblePSEditions = @('Desktop')
    GUID                 = '8c78f3c8-af9d-4e51-8942-4d88b6ae3a10'
    Author               = 'Ben Kennish'
    CompanyName          = 'Ben Kennish'
    Copyright            = 'Copyright (c) 2024 Ben Kennish. Licensed under the GPL-3.0 License.'
    Description          = "Whenever chosen 'trigger' processes (e.g. video games) are running, TaskTamer automatically throttles/tames chosen 'target' processes (e.g. web browsers, instant messaging apps, and game launchers), and automatically restores them when the trigger process ends.

The precise nature of the throttle/taming can be defined in the config file, including a choice of suspending a process (the default), setting it to Low priority, closing it, or doing nothing.  Target processes can also have their windows minimized, have their RAM usage ('working set') trimmed, and be defined as a launcher which means they will not be affected if they were responsible for launching the trigger process.

Suspended target processes are effectively frozen and therefore can't slow down the trigger process (or any other running process) by using CPU or accessing the disk or network in the background. Windows is also more likely to move memory used by target processes from fast RAM to the slower pagefile on disk, which leaves more speedy RAM available for the trigger process to use."

    PowerShellVersion    = '5.1'
    RequiredModules      = @('powershell-yaml', 'BurntToast')
    FunctionsToExport    = @('Invoke-TaskTamer', 'Get-TaskTamerStatus', 'Get-TaskTamerMetrics')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('TaskTamer')
    FileList             = @("TaskTamer.psm1", "config-template.yaml", "README.md", "LICENSE.md", "images\play.ico", "images\pause.ico")
    PrivateData          = @{
        PSData = @{
            LicenseUri   = 'https://www.gnu.org/licenses/gpl-3.0.html#license-text'
            ProjectUri   = 'https://github.com/BenKennish/TaskTamer/'
            ReleaseNotes = @'
Version 0.15.0:
- Added error handling and logging
- Added performance metrics collection
- Improved configuration validation
- Added Get-TaskTamerStatus and Get-TaskTamerMetrics cmdlets
'@
        }
    }
    HelpInfoURI          = 'https://github.com/BenKennish/TaskTamer/'
}