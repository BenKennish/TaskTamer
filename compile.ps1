# Compile the PowerShell script into a native .exe
# Feel free to use suspender.bat or even launch the suspender.ps1 script directly if you prefer


if (Test-Path "AutoSuspender.exe")
{
    Write-Output "AutoSuspender.exe already exists.  Removing..."
    Remove-Item -Path "AutoSuspender.exe" -Force
}

$compilerAlreadyInstalled = $false

if (-not (Get-Module -ListAvailable -Name PS2EXE))
{
    Write-Output "Installing PS2EXE compiler for current user..."
    Install-Module -Scope CurrentUser -Name PS2EXE -Force
}
else
{
    $compilerAlreadyInstalled = $true
    Write-Output "PS2EXE is already available for use."
}

# compile
Write-Output "Compiling..."
Invoke-PS2EXE -InputFile "AutoSuspender.ps1" -OutputFile "AutoSuspender.exe" -IconFile "images\pause.ico"


if (-not ($compilerAlreadyInstalled))
{
    # remove compiler if we just installed it
    Write-Output "Removing PS2EXE..."
    Start-Sleep -Milliseconds 1500
    Uninstall-Module -Name PS2EXE -Force
}
