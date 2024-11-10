# AutoSuspender

Whenever chosen _trigger_ processes (e.g. video games) are running,
AutoSuspender automatically suspends chosen _target_ processes (e.g. web
browsers and instant messaging apps), and automatically resumes them when the
trigger process ends.

Suspended processes cannot use any CPU and Windows is more likely to move their
memory from fast RAM (their "working set") to the slower pagefile on disk,
leaving more of the RAM available for the trigger process (e.g. video game).

When the trigger process closes, AutoSuspender will report how much the RAM
usage ("working set") of the target processes dropped during their suspension.

It can also keep track of the trigger processes memory usage using the
`-TriggerProcessPollInterval` command line argument

## Installation

Download the release .zip file.  Extract this into a new folder somewhere.
This could be anywhere, e.g. a folder on your desktop, but I recommend:

`%localappdata%\AutoSuspender`
(e.g. `C:\Users\Ben\AppData\Local\AutoSuspender`)

Run `AutoSuspender.bat` to start the script.

If you want to create a .exe file from the script, run `compile.bat`.

## Configuration

The `config.yaml` file is used to configure the script.  The file is
autocreated from `config-template.yaml` by the script if it doesn't exist.
Keep the spacing and formatting as is otherwise the script won't be able to
read it properly.

## Command line arguments

There are some optional command line arguments that change the way the script operates.

`-Dry-Run` : Enables dry-run mode; the script doesn't actually suspend or
resume any processes or minimise windows but does everything else. Useful for
testing and measuring performance benefits of using AutoSuspender.

`-ResumeAll` : Resumes all target processes then run as normal.  Handy for when
a previous invocation of the script failed to resume everything for some reason.

`-CheckOnce` : Checks for trigger processes only once, exiting immediately if
none are running.  If one is running, performs usual operations then exits when
the trigger process exits (after resuming the target processes).  You might use
this if you arrange for the script to run every time Windows runs a new process.

`-TriggerProcessPollInterval #` : if `#` is a positive integer, AutoSuspender
will poll the memory usage of the trigger process every `#` seconds.  This can
be useful in gathering information but can have a small performance impact so
is disabled by default.

`-TrimWorkingSet` : Trim the working set of all target processes immediately 
after they are suspended.

`-Help` : Displays short description of AutoSuspender and a list of possible
command line arguments

`-Debug` : Enables debugging mode, making the script a lot more verbose.