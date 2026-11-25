[CmdletBinding()]
param(
    [ValidateSet('onedir', 'onefile', 'both')]
    [string]$Mode = 'both',
    [string]$PythonPath,
    [switch]$SkipDependencyInstall,
    [switch]$SkipSigning
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSCommandPath
$python = $PythonPath
if (-not $python) {
    $python = Join-Path $projectRoot '.venv-windows\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        $python = Join-Path $projectRoot '.venv\Scripts\python.exe'
    }
}

if (-not (Test-Path -LiteralPath $python)) {
    throw "Virtualenv .venv not found. Please setup environment first."
}

if (-not $SkipDependencyInstall) {
    Write-Host "Checking build dependencies..." -ForegroundColor Cyan
    & $python -m pip install -r (Join-Path $projectRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}

$specPath = Join-Path $projectRoot 'FreetonVPN.spec'
if (-not (Test-Path -LiteralPath $specPath)) {
    throw "Spec file not found: $specPath"
}

# --- Authenticode Code Signing Function ---
function Invoke-FreetonSigning {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { return }
    if ($SkipSigning) {
        Write-Host "Skipping code signing (-SkipSigning set)." -ForegroundColor Yellow
        return
    }

    Write-Host "Authenticode Signing: $FilePath" -ForegroundColor Cyan
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -match 'CN=pishun' } | Select-Object -First 1
    if (-not $cert) {
        Write-Host "Creating local Code Signing certificate (CN=pishun)..." -ForegroundColor Yellow
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=pishun" `
            -FriendlyName "Freeton VPN Publisher (pishun)" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(5) `
            -HashAlgorithm "SHA256"
    }

    try {
        $sig = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" -ErrorAction Stop
        Write-Host "  -> Signed with timestamp: $($sig.Status)" -ForegroundColor Green
    } catch {
        $sig = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $cert -HashAlgorithm SHA256
        Write-Host "  -> Signed (offline): $($sig.Status)" -ForegroundColor Green
    }
}

# --- BUILD ONEDIR ---
if ($Mode -eq 'onedir' -or $Mode -eq 'both') {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host "Building Mode: --onedir (Clean standalone folder, zero dropper)" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
    
    $env:FREETON_BUILD_MODE = 'onedir'
    & $python -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath (Join-Path $projectRoot 'dist') `
        --workpath (Join-Path $projectRoot 'build') `
        $specPath

    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller onedir build failed.' }

    $onedirExe = Join-Path $projectRoot 'dist\FreetonVPN\FreetonVPN.exe'
    Invoke-FreetonSigning -FilePath $onedirExe

    # Sign node.exe if bundled inside internal driver
    $bundledNode = Join-Path $projectRoot 'dist\FreetonVPN\_internal\playwright\driver\node.exe'
    if (Test-Path -LiteralPath $bundledNode) {
        Invoke-FreetonSigning -FilePath $bundledNode
    }

    # Compress onedir folder to ZIP
    $zipPath = Join-Path $projectRoot 'dist\FreetonVPN-v2.4.3-windows-x64-portable.zip'
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -Force $zipPath }
    Write-Host "Compressing onedir to portable ZIP: $zipPath" -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $projectRoot 'dist\FreetonVPN\*') -DestinationPath $zipPath -Force
    Write-Host "Portable ZIP created successfully!" -ForegroundColor Green
}

# --- BUILD ONEFILE ---
if ($Mode -eq 'onefile' -or $Mode -eq 'both') {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host "Building Mode: --onefile (Single standalone EXE, scripts filtered)" -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green

    $env:FREETON_BUILD_MODE = 'onefile'
    & $python -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath (Join-Path $projectRoot 'dist') `
        --workpath (Join-Path $projectRoot 'build') `
        $specPath

    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller onefile build failed.' }

    $onefileExe = Join-Path $projectRoot 'dist\FreetonVPN.exe'
    Invoke-FreetonSigning -FilePath $onefileExe
}

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "Build Summary:" -ForegroundColor Green
if (Test-Path (Join-Path $projectRoot 'dist\FreetonVPN\FreetonVPN.exe')) {
    Write-Host "  • onedir:   $(Join-Path $projectRoot 'dist\FreetonVPN\FreetonVPN.exe')" -ForegroundColor Cyan
}
if (Test-Path (Join-Path $projectRoot 'dist\FreetonVPN-v2.4.3-windows-x64-portable.zip')) {
    Write-Host "  • ZIP:      $(Join-Path $projectRoot 'dist\FreetonVPN-v2.4.3-windows-x64-portable.zip')" -ForegroundColor Cyan
}
if (Test-Path (Join-Path $projectRoot 'dist\FreetonVPN.exe')) {
    Write-Host "  • onefile:  $(Join-Path $projectRoot 'dist\FreetonVPN.exe')" -ForegroundColor Cyan
}
Write-Host "=======================================================" -ForegroundColor Green

