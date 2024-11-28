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
somewhere like your desktop or

<pre>C:\Users\<em>your-username</em>\AppData\Local</pre>

If you try to extract it somewhere and it asks for Administrator permission,
you will need extract it somewhere else.

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

| Argument            | Description                                                                                                                                                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| &#8209;Help         | Displays a short description of AutoSuspender and a list of these possible command line arguments, then exits.                                                                                                                                                                                    |
| &#8209;WhatIf       | Enables "what if" mode; the script doesn't actually take any action on target processes but does everything else. Useful for testing and measuring performance benefits of using AutoSuspender.                                                                                                   |
| &#8209;ResumeAll    | Immediately resumes all target processes then run as normal. Handy for when a previous launch of the script failed to resume everything for some reason.                                                                                                                                          |
| &#8209;CheckOnce    | Checks for trigger processes only once, exiting immediately if none are running. If one is running, performs usual operations then exits when the trigger process exits (after resuming the target processes). Useful if you arrange for the script to run every time Windows runs a new process. |
| &#8209;PollTriggers | Poll the status of the trigger process, rather than waiting to be told by Windows when it has stopped, which allows mointoring memory usage. This can be useful for gathering benchmarking data, but it can have a small performance impact so is disabled by default.                            |
| &#8209;Verbose      | The script will be more descriptive about what's going on.                                                                                                                                                                                                                                        |
| &#8209;Debug        | Enables debugging mode, useful for anyone wishing to fix bugs in the script.                                                                                                                                                                                                                      |
