@echo off

:: this batch file is just a wrapper around the powershell script
:: because, by default, powershell scripts cannot be executed directly

:: run the powershell script and pass all arguments
powershell -ExecutionPolicy Bypass -File "compile.ps1" %*