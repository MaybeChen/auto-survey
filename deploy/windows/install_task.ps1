$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($Name in @("Capture", "Agent")) {
  $Script = Join-Path $Root "deploy\windows\start_$($Name.ToLower()).ps1"
  $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Script`""
  $Trigger = New-ScheduledTaskTrigger -AtStartup
  $Settings = New-ScheduledTaskSettingsSet -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "API Survey $Name" -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force
}
