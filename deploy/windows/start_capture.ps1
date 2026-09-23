$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
$Config = Get-Content config.yaml | ConvertFrom-Yaml
$Out = Join-Path $Config.storage.root "capture\incoming\traffic.pcapng"
& "C:\Program Files\Wireshark\dumpcap.exe" -i $Config.capture.interface -s 0 -B 64 -b "duration:$($Config.capture.duration_seconds)" -b "filesize:$($Config.capture.filesize_kb)" -b "files:$($Config.capture.files)" -w $Out *>> logs\capture.log
exit $LASTEXITCODE
