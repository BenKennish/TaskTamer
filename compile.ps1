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
Invoke-PS2EXE -InputFile "AutoSuspender.ps1" -OutputFile "AutoSuspender.exe" -IconFile "images\pause.ico" -Verbose -description "Whenever chosen 'trigger' processes (e.g. video games) are running, AutoSuspender automatically suspends chosen 'target' processes (e.g. web browsers, instant messaging apps, and game launchers), and automatically resumes them when the trigger process ends."  -title "AutoSuspender"


if (-not ($compilerAlreadyInstalled))
{
    # remove compiler if we just installed it
    Write-Output "Removing PS2EXE..."
    Start-Sleep -Milliseconds 1500
    Uninstall-Module -Name PS2EXE -Force
}
