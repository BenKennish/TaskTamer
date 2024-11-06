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

Download the release .zip file.  Extract this into a new folder somewhere.  
This could be anywhere, e.g. a folder on your desktop, but I recommend:

`%localappdata%\AutoSuspender` (e.g. C:\Users\Ben\AppData\Local\AutoSuspender)

Run `AutoSuspender.bat` to start the script.

If you want to create a .exe file from the script, double click `compile.bat`.

## Configuration

Edit the config.yaml file to configure the script.  Keep the spacing and formatting as is
otherwise the script won't be able to read it properly.