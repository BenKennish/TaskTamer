@echo off
setlocal 

:: this batch file is just a wrapper around the powershell script
:: because, by default, powershell scripts cannot be executed directly

:: run the powershell script (in a separate window) and pass all arguments
:: start "" powershell -ExecutionPolicy Bypass -File "AutoSuspender.ps1" %*

:: OR

:: run the powershell script and pass all arguments
powershell -ExecutionPolicy Bypass -File "AutoSuspender.ps1" %*
:: powershell -ExecutionPolicy Bypass -Command "try { .\AutoSuspender.ps1 } catch { exit 0 }"
:: powershell -ExecutionPolicy Bypass -Command "& {try {.\AutoSuspender.ps1} catch {exit 0}}"

::endlocal
exit /b