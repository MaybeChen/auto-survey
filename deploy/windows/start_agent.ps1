$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
& .\.venv\Scripts\api-survey.exe --config config.yaml watch *>> logs\agent.log
exit $LASTEXITCODE
