@echo off
setlocal 

:: this batch file is just a wrapper around the powershell script
:: because, by default, powershell scripts cannot be executed directly

if "%1"=="/nofork" (
    echo "Running PowerShell script within this batch file ('/nofork')"
    :: run the powershell script and pass all arguments 
    :: (except the "/sameprocess")
    ::
    :: if we use this mode it allows us to see final output that the script 
    :: might produce, e.g. error msg, however, use of ctrl-C causes an annoying
    :: "Terminate batch job (Y/N)?" prompt
    powershell -ExecutionPolicy Bypass -File "AutoSuspender.ps1" %2 %3 %4 %5 %6 %7 %8 %9
) else (
    :: run the powershell script (in a separate window) and pass all arguments
    start "" powershell -ExecutionPolicy Bypass -File "AutoSuspender.ps1" %*
)

endlocal
exit /b