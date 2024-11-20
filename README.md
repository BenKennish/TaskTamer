# AutoSuspender

## How It Boosts Performance

Whenever chosen _"trigger"_ processes (e.g. video games) are running,
**AutoSuspender** automatically suspends chosen _"target"_ processes (e.g. web
browsers, instant messaging apps, and game launchers), and automatically
resumes them when the trigger process ends.

Suspended target processes are effectively frozen / sleeping and therefore
can't slow down the trigger process by using CPU or accessing the disk or
network in the background. Windows is also more likely to move memory used by
target processes from fast RAM to the slower pagefile on disk, which leaves more
speedy RAM available for the trigger process to use.

When the trigger process closes, AutoSuspender will report how much the RAM
usage of the target processes (known as their "working set") decreased during
their suspension.

AutoSuspender can perform other tricks using the config file (see
[Configuration](#configuration)) and through various
[Command line arguments](#command-line-arguments)

## Installation

Download the _"Source code (zip)"_ file from the "Latest" release on the
[Releases page](https://github.com/BenKennish/AutoSuspender/releases).
Open the zip file and extract the single "AutoSuspender-x.y.z" folder inside to
somewhere like your desktop or `C:\Users\`_yourUsername_`\AppData\Local`.
If you try to extract it somewhere and it asks for Administrator permission,
extract it somewhere else.

Run `AutoSuspender.bat` from that folder to start the script.

If you want to create a .exe file from the script, run `compile.bat`.

## Configuration

You can configure the script by modifying the `config.yaml` file. Whenever you
run the script, `config.yaml` is autocreated (if it doesn't already exist)
using `config-template.yaml` as a template. So just run the script once before
configuring it.

Keep the spacing and formatting in `config.yaml` as it is otherwise the script
won't be able to read it properly.

## Command Line Arguments

There are some optional command line arguments that temporarily change the way the script operates.

| Command Line Argument (you can use more than one) | Description                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-WhatIf`                                         | Enables "what if" mode; the script doesn't actually suspend or resume any processes or minimise windows but does everything else. Useful for testing and measuring performance benefits of using AutoSuspender.                                                                                               |
| `-ResumeAll`                                      | Resumes all target processes then run as normal. Handy for when a previous invocation of the script failed to resume everything for some reason.                                                                                                                                                              |
| `-CheckOnce`                                      | Checks for trigger processes only once, exiting immediately if none are running. If one is running, performs usual operations then exits when the trigger process exits (after resuming the target processes). You might use this if you arrange for the script to run every time Windows runs a new process. |
| `-GetTriggerProcessStats`                         | Poll the status of the trigger process, rather than waiting to be told by Windows when it has stopped. This method enables checking memory usage which can be useful for gathering bencmarking data, but it can have a small performance impact so is disabled by default.                                    |
| `-TrimWorkingSet`                                 | Trim the working set of all target processes immediately after they are suspended. Although this can free up a lot of RAM for the trigger process, the target processes will likely be considerably slower once resumed, regardless of whether the trigger process used or benefited from the RAM.            |
| `-Help`                                           | Displays a short description of AutoSuspender and a list of possible command line arguments                                                                                                                                                                                                                   |
| `-Verbose`                                        | The script will be more talkative about what's going on.                                                                                                                                                                                                                                                      |
| `-Debug`                                          | Enables debugging mode, useful for anyone wishing to fix bugs in the script.                                                                                                                                                                                                                                  |
