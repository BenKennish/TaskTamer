@{
    # manifest for module 'TaskTamer'
    #
    # Generated by: Ben Kennish
    # Generated on: 30/11/2024
    #

    # Script module or binary module file associated with this manifest.
    RootModule           = 'TaskTamer.psm1'

    # Version number of this module.
    ModuleVersion        = '0.13.3'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop')

    # ID used to uniquely identify this module
    GUID                 = '8c78f3c8-af9d-4e51-8942-4d88b6ae3a10'

    # Author of this module
    Author               = 'Ben Kennish'

    # Company or vendor of this module
    CompanyName          = 'Ben Kennish'

    # Copyright statement for this module
    Copyright            = 'Copyright (c) 2024 Ben Kennish. Licensed under the GPL-3.0 License.'

    # Description of the functionality provided by this module
    Description          = "Whenever chosen 'trigger' processes (e.g. video games) are running, TaskTamer automatically throttles/tames chosen 'target' processes (e.g. web browsers, instant messaging apps, and game launchers), and automatically restores them when the trigger process ends.

The precise nature of the throttle/taming can be defined in the config file, including a choice of suspending a process (the default), setting it to Low priority, closing it, or doing nothing.  Target processes can also have their windows minimized, have their RAM usage ('working set') trimmed, and be defined as a launcher which means they will not be affected if they were responsible for launching the trigger process.

Suspended target processes are effectively frozen and therefore can't slow down the trigger process (or any other running process) by using CPU or accessing the disk or network in the background. Windows is also more likely to move memory used by target processes from fast RAM to the slower pagefile on disk, which leaves more speedy RAM available for the trigger process to use."

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    #DotNetFrameworkVersion = '4.8'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules      = @('powershell-yaml', 'BurntToast')

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @('Start-TaskTamer')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList             = @("TaskTamer.psm1", "config-template.yaml", "README.md", "LICENSE.md", "images\play.ico", "images\pause.ico")

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            LicenseUri   = 'https://www.gnu.org/licenses/gpl-3.0.html#license-text'

            # A URL to the main website for this project.
            # ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial PS Gallery release of TaskTamer'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI          = 'https://github.com/BenKennish/TaskTamer/'

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}
