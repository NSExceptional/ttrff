# packaging/build-artifact.ps1 -- build the portable Windows artifact for Scoop.
#
# Zips exactly what the tray + injector need at runtime (the Windows counterpart of the Homebrew
# formula's libexec.install list): tray/, frida/ (the injector + runner; the macOS-only signed
# runner binary is EXCLUDED -- Windows runs the injector under the venv's pip frida), scripts/
# (tt-mod-stop.cmd), the RE data tables, and modset.json. Plus packaging/bin/ttrff.cmd as the
# launcher at bin/ttrff.cmd.
#
# Output: dist/ttrff-windows.zip  (Scoop manifest's url + hash point at this artifact)
param(
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot        # repo root (packaging/..)
$stage = Join-Path $repo "dist\stage\ttrff"

if (Test-Path "$repo\dist") { Remove-Item -Recurse -Force "$repo\dist" }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# --- runtime tree (mirrors the brew formula's libexec.install) ---
$dirs = @("tray", "frida", "scripts")
foreach ($d in $dirs) {
    Copy-Item -Recurse (Join-Path $repo $d) (Join-Path $stage $d)
}
# macOS-only pieces stay out of the Windows artifact
Remove-Item -Force -ErrorAction SilentlyContinue `
    (Join-Path $stage "frida\ttr-frida-runner"), `
    (Join-Path $stage "frida\run-injector.sh"), `
    (Join-Path $stage "frida\.runner-env"), `
    (Join-Path $stage "frida\debugger.entitlements")
# window-driver helpers are macOS OCR tooling; keep only the stop script on Windows
Get-ChildItem (Join-Path $stage "scripts") -Exclude "tt-mod-stop.cmd" |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
# never ship bytecode caches (local builds may have them from test runs)
Get-ChildItem $stage -Recurse -Directory -Filter "__pycache__" |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# --- data tables + modset ---
$files = @("modset.json", "offsets.json", "capi-symbols.json", "capi-symbols2.json")
foreach ($f in $files) {
    Copy-Item (Join-Path $repo $f) (Join-Path $stage $f)
}

# --- launcher ---
New-Item -ItemType Directory -Force -Path (Join-Path $stage "bin") | Out-Null
Copy-Item (Join-Path $repo "packaging\bin\ttrff.cmd") (Join-Path $stage "bin\ttrff.cmd")
# the no-console launcher used by the Start Menu shortcut (Windows Search / Start Menu)
Copy-Item (Join-Path $repo "packaging\bin\ttrff.vbs") (Join-Path $stage "bin\ttrff.vbs")

# --- zip ---
$zip = Join-Path $repo "$OutDir\ttrff-windows.zip"
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
Write-Output "artifact: $zip"
Write-Output "sha256:   $hash"
Write-Output "size:     $([math]::Round((Get-Item $zip).Length/1KB,1)) KB"
