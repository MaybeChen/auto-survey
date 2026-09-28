$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw "Python was not found in PATH. Install Python 3.11+ and enable 'Add python.exe to PATH'."
}

python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
& .\.venv\Scripts\python.exe -c "import src; print('Verified Python package:', src.__file__)"
& .\.venv\Scripts\api-survey.exe --help | Out-Null
New-Item -ItemType Directory -Force -Path logs | Out-Null
if (-not (Test-Path config.yaml)) {
  Copy-Item config\config.windows.example.yaml config.yaml
  Write-Host "Created config.yaml. Edit storage.root and capture.interface before installing tasks."
}
Write-Host "Installation complete. Run '.\.venv\Scripts\api-survey.exe --config config.yaml list-interfaces', edit config.yaml, then run install_task.ps1 as administrator."
