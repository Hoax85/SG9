# Richtet SG9 unter Windows als echten Windows-Dienst ein (startet beim Hochfahren, ohne Anmeldung).
# Ausführen in einer PowerShell "Als Administrator":
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Exe .\sg9-windows-amd64.exe
# Entfernen:
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall
param(
  [string]$Exe,
  [string]$Target = "$env:ProgramFiles\SG9",
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

if ($Uninstall) {
  if (Test-Path "$Target\sg9.exe") { & "$Target\sg9.exe" -uninstall-service -data "$Target\sg9-data" }
  # ältere Versionen liefen als geplante Aufgabe
  Unregister-ScheduledTask -TaskName "SG9 Server" -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName "SG9*" -ErrorAction SilentlyContinue
  Write-Host "SG9-Dienst entfernt. Deine Daten in $Target\sg9-data bleiben erhalten."
  return
}
if (-not $Exe) { throw "Bitte mit -Exe den Pfad zur sg9-…-windows-amd64.exe angeben." }

# Läuft schon eine Version? Dann zuerst stoppen, damit die Datei ersetzt werden kann.
if (Get-Service -Name SG9 -ErrorAction SilentlyContinue) {
  Stop-Service SG9 -ErrorAction SilentlyContinue
  & "$Target\sg9.exe" -uninstall-service -data "$Target\sg9-data" | Out-Null
}
Unregister-ScheduledTask -TaskName "SG9 Server" -Confirm:$false -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force $Target | Out-Null
Copy-Item $Exe "$Target\sg9.exe" -Force

# Firewall: eine Regel für das Programm statt für einzelne Ports.
# So funktionieren alle Ports, die du in der Verwaltung einstellst, ohne dieses Skript erneut auszuführen.
Remove-NetFirewallRule -DisplayName "SG9*" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SG9 Server" -Direction Inbound -Program "$Target\sg9.exe" -Protocol TCP -Action Allow | Out-Null

& "$Target\sg9.exe" -install-service -data "$Target\sg9-data"
Start-Sleep 2

Write-Host ""
Write-Host "SG9 läuft als Windows-Dienst. Verwaltung: http://localhost:8021"
Write-Host "Beim ersten Öffnen legst du dort dein Passwort fest."
Write-Host "Den Dienst siehst du unter services.msc als 'SG9 Datei-Server'."
