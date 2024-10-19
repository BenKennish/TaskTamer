@echo off

:: run the powershell script and pass all arguments
start "" powershell -ExecutionPolicy Bypass -File "suspender.ps1" %*
