# AutoSuspender

Automatically suspend chosen _target_ processes, minimising their windows 
first, whenever chosen _trigger_ processes (e.g. video games) are running, and 
automatically resume the target processes when the trigger process closes.

Suspended processes cannot use any CPU, and Windows is more likely to move 
memory of suspended processes (especially those with minimised windows) from 
RAM (their "working set") to the pagefile on disk, leaving more of the fast RAM 
available for the trigger process (e.g. the video game).

When the trigger process closes, AutoSuspender will report how much the RAM 
usage (working set) of the target processes dropped during their suspension.

## Installation

Extract the files into a new folder somewhere.  This could be anywhere, e.g. a 
folder on your desktop, but I recommend creating it somewhere like:

`%localappdata%\AutoSuspender`


Double click `AutoSuspender.bat` to run the script 

If you want to create a .exe file from the script, double click `compile.bat`.

## Configuration

Follow these steps to configure the list of process names that are defined as 
trigger / target processes...

Open the script (AutoSuspender.ps1) in a text editor, e.g. notepad.

You can add names to $targetProcessNames for the target processes (the ones 
that will be suspended).  This is the name of the .exe file (e.g. gw2-64.exe) 
but without the ".exe" bit on the end (so "gw2-64" in this example).

You can add names to $triggerProcessNames for the trigger process names (e.g. 
games).