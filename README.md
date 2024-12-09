# TaskTamer

## How It Boosts Performance

Whenever chosen _"trigger"_ processes (e.g. video games) are running, **TaskTamer** automatically throttles/tames chosen _"target"_ processes (e.g. web browsers, instant messaging apps, and game launchers), and automatically restores them when the trigger process ends.

The precise nature of the throttle/taming can be defined in the config file, including a choice of suspending a process (the default), setting it to Low priority, closing it, or doing nothing.  Target processes can also have their windows minimized, have their RAM usage ("working set") trimmed, and be defined as a launcher which means they will not be affected if they were responsible for launching the trigger process.

Suspended target processes are effectively frozen and therefore can't slow down the trigger process (or any other running process) by using CPU or accessing the disk or network in the background. Windows is also more likely to move memory used by target processes from fast RAM to the slower pagefile on disk, which leaves more speedy RAM available for the trigger process to use.

When the trigger process closes, TaskTamer will report how much the RAM usage of the target processes (known as their "working set") decreased during their suspension.

TaskTamer can perform other tricks using the config file (see [Configuration](#configuration)) and through various [Parameters](#Parameters)

## Installation

This project is hosted as a module in the Powershell Gallery so it can be retrieved and used very easily.

Open a Windows PowerShell terminal (hit the Windows Key on keyboard, type "windows powershell", hit enter) and run the following commands, hitting "y" and enter when prompted.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Install-Module -Name TaskTamer -Scope CurrentUser
```

## Running

Once the module is installed, you can run TaskTamer (from the PowerShell terminal) as follows:

```powershell
Invoke-TaskTamer
```

Once you've run this for the first time, you will find a shortcut in your Start Menu called "Task Tamer" which you can use to run it more easily in future.

There are some [Parameters](#Parameters) that you can use to pass to `Invoke-TaskTamer` to alter the operation.

## Configuration

You can configure the module by modifying the `config.yaml` file.   You will find this in `%LOCALAPPDATA%\TaskTamer` after you run TaskTamer for the first time.  Whenever you run it, `config.yaml` is autocreated (if it doesn't already exist) using `config-template.yaml` as a template. So just run `Invoke-TaskTamer` once before configuring it.

Keep the spacing and formatting in `config.yaml` as it is otherwise TaskTamer won't be able to read it properly.

## Parameters

Here are the optional parameters that alter the way the TaskTamer operates.  You can also see them by running `Help Invoke-TaskTamer`.

| Parameter           | Description                                                                                                                                                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| &#8209;WhatIf       | Enables "what if" mode; the script doesn't actually take any action on target processes but does everything else. Useful for testing and measuring performance benefits of using TaskTamer.                                                                                                       |
| &#8209;ResumeAll    | Immediately resumes all target processes then run as normal. Handy for when a previous launch of the script failed to resume everything for some reason.                                                                                                                                          |
| &#8209;CheckOnce    | Checks for trigger processes only once, exiting immediately if none are running. If one is running, performs usual operations then exits when the trigger process exits (after resuming the target processes). Useful if you arrange for the script to run every time Windows runs a new process. |
| &#8209;PollTriggers | Poll the status of the trigger process, rather than waiting to be told by Windows when it has stopped, which allows mointoring memory usage. This can be useful for gathering benchmarking data, but it can have a small performance impact so is disabled by default.                            |
| &#8209;Verbose      | The script will be more descriptive about what's going on.                                                                                                                                                                                                                                        |
| &#8209;Debug        | Enables debugging mode, useful for anyone wishing to fix bugs in the script.                                                                                                                                                                                                                      |

## Uninstalling ##

To uninstall TaskTamer, run this command in PowerShell:

```powershell
Uninstall-Module -Name TaskTamer -AllVersions
```

You can also optionally delete the folder `%LOCALAPPDATA%\TaskTamer`.


## Source Code

This project has a [public GitHub repo](https://github.com/BenKennish/TaskTamer/).
