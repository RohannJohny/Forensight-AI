<#
.SYNOPSIS
    Forensight AI - Windows Fresh Machine Setup Script
.DESCRIPTION
    Automates environment verification, venv creation, dependency installation,
    forensic tool configuration, smoke tests, and readiness reporting.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Forensight AI - Fresh Machine Setup (Windows)         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Python
Write-Host "`n[1/6] Checking Python installation..." -ForegroundColor Yellow
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Write-Error "Python 3 is not found in PATH. Please install Python 3.10+ from python.org."
}
$PyVersion = & python --version
Write-Host "[+] Found $PyVersion" -ForegroundColor Green

# 2. Setup Virtual Environment
Write-Host "`n[2/6] Verifying/Creating Python virtual environment (.venv)..." -ForegroundColor Yellow
if (-not (Test-Path ".venv")) {
    & python -m venv .venv
    Write-Host "[+] Created .venv virtual environment." -ForegroundColor Green
} else {
    Write-Host "[+] Virtual environment .venv already exists." -ForegroundColor Green
}

$VenvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment python not found at $VenvPython"
}

# 3. Install Python Dependencies
Write-Host "`n[3/6] Installing Python dependencies..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r requirements.txt
Write-Host "[+] Dependencies verified." -ForegroundColor Green

# 4. Verify Environment
Write-Host "`n[4/6] Running environment verification..." -ForegroundColor Yellow
& $VenvPython setup\verify_environment.py

# 5. Discover & Configure Forensic Tools
Write-Host "`n[5/6] Discovering forensic tools and running smoke tests..." -ForegroundColor Yellow
& $VenvPython setup\configure_tools.py

# 6. Basic Test Run
Write-Host "`n[6/6] Running validation test suite..." -ForegroundColor Yellow
$PytestExe = Join-Path (Get-Location) ".venv\Scripts\pytest.exe"
if (Test-Path $PytestExe) {
    & $PytestExe tests -v
} else {
    & $VenvPython -m pytest tests -v
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "   Forensight AI Setup Complete!                         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "To start the API:      .venv\Scripts\uvicorn app.main:app --reload"
Write-Host "To run CLI:            .venv\Scripts\python -m app.cli --help"
