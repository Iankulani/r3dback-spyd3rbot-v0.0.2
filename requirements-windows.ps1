# Spider Bot Pro - Windows Requirements Installer
# Run in PowerShell as Administrator

Write-Host "🕸️  Spider Bot Pro - Windows Requirements Installer" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ Please run as Administrator" -ForegroundColor Red
    exit 1
}

# Install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "📦 Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install system packages
Write-Host "📦 Installing system packages..." -ForegroundColor Yellow

$packages = @(
    'python',
    'python-pip',
    'nmap',
    'curl',
    'wget',
    'traceroute',
    'whois',
    'git',
    'nodejs',
    'googlechrome',
    'chromedriver',
    'openjdk11',
    'sqlite',
    'nginx',
    'supervisor'
)

foreach ($package in $packages) {
    Write-Host "Installing $package..." -ForegroundColor Yellow
    choco install $package -y
}

# Install Python requirements
Write-Host "📦 Installing Python packages..." -ForegroundColor Yellow
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Create directories
Write-Host "📁 Creating directories..." -ForegroundColor Yellow
$directories = @(
    "$env:USERPROFILE\.spiderbot_pro",
    "$env:USERPROFILE\reports",
    "$env:USERPROFILE\scan_results",
    "$env:USERPROFILE\alerts",
    "$env:USERPROFILE\monitoring",
    "$env:USERPROFILE\backups",
    "$env:USERPROFILE\temp",
    "$env:USERPROFILE\scripts",
    "$env:USERPROFILE\nikto_results",
    "$env:USERPROFILE\whatsapp_session",
    "C:\ProgramData\spiderbot",
    "C:\ProgramData\spiderbot\logs"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Set environment variables
Write-Host "🔧 Setting environment variables..." -ForegroundColor Yellow
[System.Environment]::SetEnvironmentVariable('SPIDERBOT_HOME', "$env:USERPROFILE\.spiderbot_pro", 'User')
[System.Environment]::SetEnvironmentVariable('SPIDERBOT_CONFIG', "$env:USERPROFILE\.spiderbot_pro\config.json", 'User')

# Create startup script
Write-Host "📝 Creating startup script..." -ForegroundColor Yellow
$startupScript = @"
@echo off
cd %USERPROFILE%
python spiderbot_pro.py
"@
$startupScript | Out-File -FilePath "$env:USERPROFILE\start_spiderbot.bat" -Encoding ascii

Write-Host "✅ Windows requirements installed successfully!" -ForegroundColor Green
Write-Host "📁 Installation location: %USERPROFILE%" -ForegroundColor Cyan
Write-Host "🚀 Run: start_spiderbot.bat" -ForegroundColor Green