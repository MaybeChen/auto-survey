$ErrorActionPreference = "Stop"
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
New-Item -ItemType Directory -Force -Path logs | Out-Null
Write-Host "Install Wireshark with Npcap, copy config.windows.example.yaml to config.yaml, then run install_task.ps1 as administrator."
