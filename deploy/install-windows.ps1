# Richtet SG9 unter Windows als Hintergrunddienst ein (startet beim Hochfahren, ohne Anmeldung).
# Ausführen in einer PowerShell "Als Administrator":
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Exe .\sg9-2.3.1-windows-amd64.exe
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [string]$Target = "$env:ProgramFiles\SG9",
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$task = "SG9 Server"

if ($Uninstall) {
  Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName "SG9*" -ErrorAction SilentlyContinue
  Write-Host "SG9-Dienst entfernt. Daten in $Target bleiben erhalten."
  return
}

New-Item -ItemType Directory -Force $Target | Out-Null
Copy-Item $Exe "$Target\sg9.exe" -Force

# Firewall: eine Regel für das Programm statt für einzelne Ports.
# So funktionieren alle Ports, die du in der Verwaltung einstellst, ohne dieses Skript erneut auszuführen.
Remove-NetFirewallRule -DisplayName "SG9*" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SG9 Server" -Direction Inbound -Program "$Target\sg9.exe" -Protocol TCP -Action Allow | Out-Null

$action  = New-ScheduledTaskAction -Execute "$Target\sg9.exe" -Argument "-data `"$Target\sg9-data`" -quiet" -WorkingDirectory $Target
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep 2

Write-Host "SG9 läuft. Verwaltung: http://localhost:8021"
$pw = $null
Write-Host "Beim ersten Öffnen legst du dort dein Passwort fest."
Write-Host "Ports stellst du in der Verwaltung unter Einstellungen -> Dienste und Ports ein. Die Firewall lässt alle Ports von SG9 durch."
