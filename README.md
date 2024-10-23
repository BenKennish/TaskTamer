# suspender

Automatically suspend blacklisted processes (and minimise their windows) 
whenever certain trigger processes (e.g. video games) are running, and then 
resume them when the trigger process closes.

Suspended processes cannot use any CPU and Windows is more likely to move their 
memory from RAM (their 'working set') to the pagefile on disk, leaving more of the fast RAM for the trigger process/video game.