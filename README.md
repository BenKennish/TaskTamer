# AutoSuspender

Whenever chosen _trigger_ processes (e.g. video games) are running,
AutoSuspender automatically suspends chosen _target_ processes (e.g. web
browsers and instant messaging apps), and automatically resumes them when the
trigger process ends.

Suspended target processes are effectively frozen / sleeping and therefore
can't slow down the trigger process by using the CPU in the background.
Windows is also more likely to move memory used by target processes from fast
RAM (known as their "working set") to the slower pagefile on disk, which leaves
more lovely speedy RAM available for the trigger process (e.g. video game) to
use.

When the trigger process closes, AutoSuspender will report how much the RAM
usage of the target processes dropped during their suspension.

It can also keep track of the trigger processes memory usage using the
`-TriggerProcessPollInterval` command line argument.

## Installation

Download the release .zip file. Extract this into a new folder somewhere.
This could be anywhere, e.g. a folder on your desktop, but I recommend:

`%localappdata%\AutoSuspender`
(e.g. `C:\Users\Ben\AppData\Local\AutoSuspender`)

Run `AutoSuspender.bat` to start the script.

If you want to create a .exe file from the script, run `compile.bat`.

## Configuration

You can configure the script by modifying the `config.yaml` file. When you run
the script, `config.yaml` is autocreated from `config-template.yaml` if it
doesn't already exist. So just run the script once before configuring it.

Keep the spacing and formatting in `config.yaml` as it is otherwise the script
won't be able to read it properly.

## Command line arguments

There are some optional command line arguments that change the way the script operates.

`-WhatIf` : Enables "what if" mode; the script doesn't actually suspend or
resume any processes or minimise windows but does everything else. Useful for
testing and measuring performance benefits of using AutoSuspender.

`-ResumeAll` : Resumes all target processes then run as normal. Handy for when
a previous invocation of the script failed to resume everything for some reason.

`-CheckOnce` : Checks for trigger processes only once, exiting immediately if
none are running. If one is running, performs usual operations then exits when
the trigger process exits (after resuming the target processes). You might use
this if you arrange for the script to run every time Windows runs a new process.

`-TriggerProcessPollInterval #` : if `#` is a positive integer, AutoSuspender
will poll the memory usage of the trigger process every `#` seconds. This can
be useful for gathering bencmarking data but can have a small performance
impact so is disabled by default.

`-TrimWorkingSet` : Trim the working set of all target processes immediately
after they are suspended.

`-Help` : Displays short description of AutoSuspender and a list of possible
command line arguments

`-Debug` : Enables debugging mode, making the script a lot more verbose.
