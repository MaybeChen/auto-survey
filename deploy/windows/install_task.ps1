#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path (Join-Path $Root "config.yaml"))) {
  throw "config.yaml does not exist. Run install.ps1 and configure it first."
}

foreach ($Name in @("Capture", "Agent")) {
  $Script = Join-Path $Root "deploy\windows\start_$($Name.ToLower()).ps1"
  $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`""
  $Trigger = New-ScheduledTaskTrigger -AtStartup
  $Settings = New-ScheduledTaskSettingsSet -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
  Register-ScheduledTask -TaskName "API Survey $Name" -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName "API Survey $Name"
  Write-Host "Installed and started: API Survey $Name"
}
