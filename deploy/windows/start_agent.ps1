$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
New-Item -ItemType Directory -Force -Path logs | Out-Null
& .\.venv\Scripts\api-survey.exe --config config.yaml watch *>> logs\agent.log
exit $LASTEXITCODE
