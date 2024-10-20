# Compile the PowerShell script into a native .exe
# Feel free to use suspender.bat or even launch the suspender.ps1 script directly if you prefer

if (-not (Test-Path "suspender.exe")) {

    if (-not (Get-Module -ListAvailable -Name PS2EXE)) {
        Write-Output "Installing PS2EXE for current user..."
        # install the PS2EXE 'compiler' for the current user
        Install-Module -Scope CurrentUser -Name PS2EXE -Force
    } else {
        Write-Output "PS2EXE is already available for use."
    }

    # compile
    Write-Output "Compiling..."
    Invoke-PS2EXE -InputFile "suspender.ps1" -OutputFile "suspender.exe" -IconFile "pause.ico"

} else {

    Write-Output "suspender.exe already exists. Exiting."
}

Start-Sleep -Seconds 2