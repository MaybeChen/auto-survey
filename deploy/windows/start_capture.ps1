$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
New-Item -ItemType Directory -Force -Path logs | Out-Null
& .\.venv\Scripts\python.exe -m src.capture_service --config config.yaml *>> logs\capture.log
exit $LASTEXITCODE
