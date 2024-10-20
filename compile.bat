@echo off

:: this batch file is just a wrapper around the powershell script
:: because, by default, powershell scripts cannot be executed directly

:: run the powershell script (in a separate window) and pass all arguments
start "" powershell -ExecutionPolicy Bypass -File "compile.ps1" %*