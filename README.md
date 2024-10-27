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