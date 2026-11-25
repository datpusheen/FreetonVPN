$ErrorActionPreference = "Stop"

$extensionRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $extensionRoot
$outputRoot = Join-Path $repoRoot "dist\browser-extension"
$shared = Join-Path $extensionRoot "shared"
$manifestRoot = Join-Path $extensionRoot "manifests"
$bcryptBundle = Join-Path $extensionRoot "node_modules\bcryptjs\umd\index.js"
$openPgpBundle = Join-Path $extensionRoot "node_modules\openpgp\dist\openpgp.min.js"
$bcryptLicense = Join-Path $extensionRoot "node_modules\bcryptjs\LICENSE"
$openPgpLicense = Join-Path $extensionRoot "node_modules\openpgp\LICENSE"

foreach ($dependencyFile in @($bcryptBundle, $openPgpBundle, $bcryptLicense, $openPgpLicense)) {
    if (-not (Test-Path -LiteralPath $dependencyFile)) {
        throw "Thiếu dependency build-time: $dependencyFile. Chạy npm install trong browser-extension trước."
    }
}

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

foreach ($browserName in @("chromium", "firefox")) {
    $packageDir = Join-Path $outputRoot $browserName
    if (Test-Path -LiteralPath $packageDir) {
        Remove-Item -LiteralPath $packageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    foreach ($fileName in @("background.js", "diagnostics.js", "login.css", "login.html", "login.js", "popup.css", "popup.html", "popup.js", "proton-srp.js", "verification-bridge.js")) {
        Copy-Item -LiteralPath (Join-Path $shared $fileName) -Destination $packageDir
    }
    Copy-Item -LiteralPath (Join-Path $manifestRoot "$browserName.json") -Destination (Join-Path $packageDir "manifest.json")
    Copy-Item -LiteralPath $bcryptBundle -Destination (Join-Path $packageDir "bcrypt.js")
    Copy-Item -LiteralPath $openPgpBundle -Destination (Join-Path $packageDir "openpgp.js")
    Copy-Item -LiteralPath $bcryptLicense -Destination (Join-Path $packageDir "LICENSE-bcryptjs.txt")
    Copy-Item -LiteralPath $openPgpLicense -Destination (Join-Path $packageDir "LICENSE-openpgp.txt")

    $archivePath = Join-Path $outputRoot "Freeton-Browser-VPN-$browserName.zip"
    $legacyArchivePath = Join-Path $outputRoot "Freeton-Node-Checker-$browserName.zip"
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if (Test-Path -LiteralPath $legacyArchivePath) {
        Remove-Item -LiteralPath $legacyArchivePath -Force
    }
    Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $archivePath -CompressionLevel Optimal
}

Write-Host "Extension packages created in $outputRoot"
