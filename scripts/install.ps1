# eBPF Guardian Windows Installer
# Usage: powershell -ExecutionPolicy Bypass -Command "& {iwr -useb https://raw.githubusercontent.com/ebpf-guardian/cli/main/scripts/install.ps1 | iex}"

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\ebguard",
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing eBPF Guardian..." -ForegroundColor Green

# Create install directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Determine download URL
if ($Version -eq "latest") {
    $ApiUrl = "https://api.github.com/repos/ebpf-guardian/cli/releases/latest"
    $Release = Invoke-RestMethod -Uri $ApiUrl
    $DownloadUrl = ($Release.assets | Where-Object { $_.name -eq "ebguard-windows-x86_64.zip" }).browser_download_url
    $Version = $Release.tag_name
} else {
    $DownloadUrl = "https://github.com/ebpf-guardian/cli/releases/download/$Version/ebguard-windows-x86_64.zip"
}

Write-Host "Downloading eBPF Guardian $Version..." -ForegroundColor Yellow

# Download and extract
$TempFile = "$env:TEMP\ebguard.zip"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -UseBasicParsing

Write-Host "Extracting..." -ForegroundColor Yellow
Expand-Archive -Path $TempFile -DestinationPath $InstallDir -Force

# Clean up
Remove-Item $TempFile

# Add to PATH for current session
$env:PATH = "$InstallDir;$env:PATH"

# Add to user PATH permanently
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$CurrentPath", "User")
    Write-Host "Added to user PATH. You may need to restart your terminal." -ForegroundColor Yellow
}

Write-Host "✅ eBPF Guardian installed successfully!" -ForegroundColor Green
Write-Host "Run 'ebguard --help' to get started." -ForegroundColor Cyan

# Test installation
try {
    & "$InstallDir\ebguard.exe" --version
} catch {
    Write-Warning "Installation completed but ebguard.exe could not be executed. You may need to restart your terminal."
}