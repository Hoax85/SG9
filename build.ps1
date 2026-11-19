# Baut SG9 für Windows, Linux und macOS in den Ordner dist\ (PowerShell, Go muss installiert sein).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$Version = if ($env:VERSION) { $env:VERSION } else { "2.4.0" }
New-Item -ItemType Directory -Force dist | Out-Null
Remove-Item dist\* -Force -ErrorAction SilentlyContinue

$targets = @(
  @("windows","amd64",".exe"), @("windows","arm64",".exe"),
  @("linux","amd64",""), @("linux","arm64",""), @("linux","arm",""),
  @("darwin","amd64",""), @("darwin","arm64","")
)
$env:CGO_ENABLED = "0"; $env:GOARM = "7"
foreach ($t in $targets) {
  $env:GOOS = $t[0]; $env:GOARCH = $t[1]
  $out = "dist\sg9-$Version-$($t[0])-$($t[1])$($t[2])"
  Write-Host "-> $out"
  go build -mod=vendor -trimpath -ldflags "-s -w -X main.version=$Version -X main.updateRepo=$($env:SG9_REPO)" -o $out .
  if ($LASTEXITCODE -ne 0) { throw "Build für $($t[0])/$($t[1]) fehlgeschlagen" }
}
Remove-Item Env:GOOS, Env:GOARCH
Write-Host "Fertig. Dateien in dist\"
