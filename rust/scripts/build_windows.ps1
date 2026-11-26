[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$ForceWireGuardRebuild,
    [string]$Version,
    [string]$ReleaseDate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pinned upstream WireGuard dependencies (verified against official WireGuard tags/hashes)
$WireGuardWindowsRepo   = 'https://github.com/WireGuard/wireguard-windows.git'
$WireGuardWindowsTag    = 'v1.1.1'
$WireGuardWindowsCommit = 'f0605c3e3dcc5ff801e19158fd6255378b99e17c'

$WireGuardNtVersion     = '1.1'
$WireGuardNtUrl         = 'https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip'
$WireGuardNtSha256      = 'dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace'

$GitHubRepoSlug         = 'datpusheen/FreetonVPN'

$repoRoot  = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$rustRoot  = Join-Path $repoRoot 'rust'
$buildRoot = Join-Path $rustRoot 'build'
$assetsBin = Join-Path $rustRoot 'assets\bin'
$distDir   = Join-Path $repoRoot 'dist'

# Ensure Cargo and Go are discoverable on PATH
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$goBin    = 'C:\Program Files\Go\bin'
$extraPath = @()
if (Test-Path -LiteralPath $cargoBin) { $extraPath += $cargoBin }
if (Test-Path -LiteralPath $goBin) { $extraPath += $goBin }
if ($extraPath.Count -gt 0) {
    $env:PATH = (($extraPath -join ';') + ';' + $env:PATH)
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [string]$WorkingDirectory = $repoRoot
    )
    Push-Location $WorkingDirectory
    try {
        & $Exe @Args
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')"
        }
    } finally {
        Pop-Location
    }
}

function Assert-PeMachineAmd64 {
    param([Parameter(Mandatory = $true)][string]$FilePath)
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "Not a valid PE/MZ binary: $FilePath"
    }
    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -le 0 -or ($peOffset + 6) -gt $bytes.Length) {
        throw "Invalid PE header offset in: $FilePath"
    }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "Invalid PE signature in: $FilePath"
    }
    $machine = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0x8664) {
        throw ("Expected x64 PE machine 0x8664 in {0}, got 0x{1:X4}" -f $FilePath, $machine)
    }
}

function Resolve-AppVersion {
    $libRsPath = Join-Path $rustRoot 'freeton-core\src\lib.rs'
    $libContent = Get-Content -LiteralPath $libRsPath -Raw -Encoding UTF8
    if ($libContent -notmatch 'pub\s+const\s+APP_VERSION:\s*&str\s*=\s*"([^"]+)"') {
        throw "Could not parse APP_VERSION from $libRsPath"
    }
    $coreVersion = $Matches[1].Trim()

    $workspaceToml = Get-Content -LiteralPath (Join-Path $rustRoot 'Cargo.toml') -Raw -Encoding UTF8
    if ($workspaceToml -match '(?m)^version\s*=\s*"([^"]+)"') {
        $cargoVersion = $Matches[1].Trim()
        if ($cargoVersion -ne $coreVersion) {
            throw "Version mismatch: Cargo.toml ($cargoVersion) != freeton-core APP_VERSION ($coreVersion)"
        }
    }

    if ($Version) {
        $requestedVersion = $Version.Trim()
        if ($requestedVersion -ne $coreVersion) {
            throw "Version mismatch: -Version ($requestedVersion) != freeton-core APP_VERSION ($coreVersion). Update rust/Cargo.toml and rust/freeton-core/src/lib.rs first."
        }
        return $requestedVersion
    }
    return $coreVersion
}

function Normalize-FourPartVersion {
    param([Parameter(Mandatory = $true)][string]$Ver)
    $parts = @($Ver.TrimStart('v', 'V').Split('.') | ForEach-Object {
        if ($_ -match '^(\d+)') { [int]$Matches[1] } else { 0 }
    })
    while ($parts.Count -lt 4) { $parts += 0 }
    return ($parts[0..3] -join '.')
}

function Resolve-MakeNsis {
    $cmd = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @(
        'C:\Program Files (x86)\NSIS\makensis.exe',
        'C:\Program Files\NSIS\makensis.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'NSIS makensis.exe not found. Please install NSIS.'
}

function Stage-TunnelDll {
    Write-Host "`n=== [1/4] Staging tunnel.dll (wireguard-windows $WireGuardWindowsTag) ===" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $buildRoot, $assetsBin | Out-Null

    $wgDir = Join-Path $buildRoot 'wireguard-windows'
    $needsClone = $true
    if (Test-Path -LiteralPath (Join-Path $wgDir '.git')) {
        $head = (& git -C $wgDir rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $head -and $head.Trim() -eq $WireGuardWindowsCommit) {
            $needsClone = $false
        } else {
            Write-Host "Updating cached wireguard-windows checkout to $WireGuardWindowsTag..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force $wgDir
        }
    } elseif (Test-Path -LiteralPath $wgDir) {
        Remove-Item -Recurse -Force $wgDir
    }

    if ($needsClone) {
        Write-Host "Cloning $WireGuardWindowsRepo ($WireGuardWindowsTag)..." -ForegroundColor Gray
        Invoke-Checked -Exe 'git' -Args @('clone', '--branch', $WireGuardWindowsTag, '--depth', '1', $WireGuardWindowsRepo, $wgDir)
        $clonedHead = (& git -C $wgDir rev-parse HEAD).Trim()
        if ($clonedHead -ne $WireGuardWindowsCommit) {
            throw "wireguard-windows commit mismatch for tag ${WireGuardWindowsTag}: expected $WireGuardWindowsCommit, got $clonedHead"
        }
    }

    $embedDir = Join-Path $wgDir 'embeddable-dll-service'
    $builtTunnelDll = Join-Path $embedDir 'amd64\tunnel.dll'
    if ($ForceWireGuardRebuild -and (Test-Path -LiteralPath $builtTunnelDll)) {
        Remove-Item -Force $builtTunnelDll
    }

    if ($ForceWireGuardRebuild -or -not (Test-Path -LiteralPath $builtTunnelDll)) {
        Write-Host "Running wireguard-windows embeddable-dll-service\build.bat..." -ForegroundColor Gray
        $cleanSysPath = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot",
            "$env:SystemRoot\System32\Wbem",
            "$env:SystemRoot\System32\WindowsPowerShell\v1.0"
        ) -join ';'

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = "$env:SystemRoot\System32\cmd.exe"
        $psi.Arguments = '/c build.bat'
        $psi.WorkingDirectory = $embedDir
        $psi.UseShellExecute = $false
        $psi.Environment['PATH'] = $cleanSysPath

        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) {
            throw "embeddable-dll-service\build.bat failed with exit code $($proc.ExitCode)"
        }
    } else {
        Write-Host "Using cached $builtTunnelDll" -ForegroundColor DarkGray
    }

    if (-not (Test-Path -LiteralPath $builtTunnelDll)) {
        throw "Expected tunnel.dll was not produced at $builtTunnelDll"
    }
    Assert-PeMachineAmd64 -FilePath $builtTunnelDll

    $stagedTunnel = Join-Path $assetsBin 'tunnel.dll'
    Copy-Item -LiteralPath $builtTunnelDll -Destination $stagedTunnel -Force
    $hash = (Get-FileHash -LiteralPath $stagedTunnel -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Staged tunnel.dll -> $stagedTunnel (sha256=$hash)" -ForegroundColor Green
}

function Stage-WireGuardNtDll {
    Write-Host "`n=== [2/4] Staging wireguard.dll (wireguard-nt $WireGuardNtVersion) ===" -ForegroundColor Cyan
    $ntRoot = Join-Path $buildRoot 'wireguard-nt'
    $zipPath = Join-Path $ntRoot "wireguard-nt-$WireGuardNtVersion.zip"
    $extractDir = Join-Path $ntRoot 'extracted'
    New-Item -ItemType Directory -Force -Path $ntRoot, $assetsBin | Out-Null

    $needDownload = $true
    if (Test-Path -LiteralPath $zipPath) {
        $cachedHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($cachedHash -eq $WireGuardNtSha256) {
            $needDownload = $false
            Write-Host "Using verified cached $zipPath" -ForegroundColor DarkGray
        } else {
            Write-Host "Cached wireguard-nt archive hash mismatch; re-downloading..." -ForegroundColor Yellow
            Remove-Item -Force $zipPath
        }
    }

    if ($needDownload) {
        Write-Host "Downloading $WireGuardNtUrl..." -ForegroundColor Gray
        Invoke-WebRequest -UseBasicParsing -Uri $WireGuardNtUrl -OutFile $zipPath
        $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $WireGuardNtSha256) {
            Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
            throw "SHA-256 mismatch for $WireGuardNtUrl! Expected $WireGuardNtSha256, got $actualHash"
        }
        Write-Host "Verified wireguard-nt archive SHA-256: $actualHash" -ForegroundColor Green
    }

    if (Test-Path -LiteralPath $extractDir) {
        Remove-Item -Recurse -Force $extractDir
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

    $candidatePaths = @(
        (Join-Path $extractDir 'wireguard-nt\bin\amd64\wireguard.dll'),
        (Join-Path $extractDir 'bin\amd64\wireguard.dll')
    )
    $sourceDll = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $sourceDll) {
        throw "Could not find amd64 wireguard.dll inside $extractDir"
    }
    Assert-PeMachineAmd64 -FilePath $sourceDll

    $stagedNt = Join-Path $assetsBin 'wireguard.dll'
    Copy-Item -LiteralPath $sourceDll -Destination $stagedNt -Force
    $dllHash = (Get-FileHash -LiteralPath $stagedNt -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Staged wireguard.dll -> $stagedNt (sha256=$dllHash)" -ForegroundColor Green
}

function Build-RustWorkspace {
    Write-Host "`n=== [3/4] Testing & Building Rust Workspace ===" -ForegroundColor Cyan
    $manifestPath = Join-Path $rustRoot 'Cargo.toml'
    if (-not $SkipTests) {
        Invoke-Checked -Exe 'cargo' -Args @('test', '--manifest-path', $manifestPath, '--workspace')
    } else {
        Write-Host 'Skipping cargo test (-SkipTests specified).' -ForegroundColor Yellow
    }

    Invoke-Checked -Exe 'cargo' -Args @('build', '--manifest-path', $manifestPath, '--release')

    foreach ($binName in @('FreetonVPN.exe', 'FreetonVPNService.exe')) {
        $binPath = Join-Path $rustRoot "target\release\$binName"
        if (-not (Test-Path -LiteralPath $binPath)) {
            throw "Expected release binary missing: $binPath"
        }
        Assert-PeMachineAmd64 -FilePath $binPath
        Write-Host "Built $binPath ($([Math]::Round((Get-Item $binPath).Length / 1MB, 2)) MB)" -ForegroundColor Green
    }
}

function Build-InstallerAndManifest {
    param(
        [Parameter(Mandatory = $true)][string]$AppVersion,
        [Parameter(Mandatory = $true)][string]$EffectiveDate
    )
    Write-Host "`n=== [4/4] Building NSIS Installer & Updating version-rust.json ===" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $distDir | Out-Null

    $makensis = Resolve-MakeNsis
    $nsiPath = Join-Path $rustRoot 'installer\freeton.nsi'
    $viVersion = Normalize-FourPartVersion -Ver $AppVersion

    Invoke-Checked -Exe $makensis -Args @(
        "/DAPP_VERSION=$AppVersion",
        "/DAPP_VI_VERSION=$viVersion",
        $nsiPath
    )

    $installerPath = Join-Path $distDir 'FreetonVPN-Setup-x64.exe'
    if (-not (Test-Path -LiteralPath $installerPath)) {
        throw "Installer was not generated at $installerPath"
    }

    $installerBytes = (Get-Item -LiteralPath $installerPath).Length
    $installerSha256 = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $shaFilePath = "$installerPath.sha256"

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($shaFilePath, "$installerSha256  FreetonVPN-Setup-x64.exe`n", $utf8NoBom)

    $manifestPath = Join-Path $repoRoot 'version-rust.json'
    $changelog = @(
        '⚡ Viết lại hoàn toàn bằng Rust gốc (x64) — khởi động tức thì, siêu nhẹ, không cần runtime ngoài',
        '🛡️ Tích hợp dịch vụ nền FreetonVPNService và WireGuardNT (tunnel.dll + wireguard.dll) — bật/tắt VPN không hỏi UAC',
        '🔐 Xác thực Proton SRP & OpenPGP thuần Rust, hỗ trợ 2FA và cửa sổ CAPTCHA WebView2 tích hợp',
        '🔄 Cập nhật tự động kiểm tra SHA-256 nghiêm ngặt trước khi chạy trình cài đặt'
    )
    $mandatory = $false
    $minSupported = $AppVersion
    $title = "Freeton VPN Desktop Client v$AppVersion"

    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $existing = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $changelogProp = $existing.PSObject.Properties['changelog']
            if ($changelogProp -and $changelogProp.Value -and @($changelogProp.Value).Count -gt 0) {
                $changelog = @($changelogProp.Value)
            }
            $mandatoryProp = $existing.PSObject.Properties['mandatory']
            if ($mandatoryProp -and $null -ne $mandatoryProp.Value) {
                $mandatory = [bool]$mandatoryProp.Value
            }
            $minSupportedProp = $existing.PSObject.Properties['min_supported_version']
            if ($minSupportedProp -and $minSupportedProp.Value) {
                $minSupported = [string]$minSupportedProp.Value
            }
            $versionProp = $existing.PSObject.Properties['version']
            $titleProp = $existing.PSObject.Properties['title']
            if ($versionProp -and ([string]$versionProp.Value -eq $AppVersion) -and $titleProp -and $titleProp.Value) {
                $title = [string]$titleProp.Value
            }
        } catch {
            Write-Host "Existing version-rust.json could not be parsed cleanly; regenerating defaults." -ForegroundColor Yellow
        }
    }

    $manifestObj = [ordered]@{
        version               = $AppVersion
        release_date          = $EffectiveDate
        title                 = $title
        changelog             = $changelog
        download_url          = "https://github.com/$GitHubRepoSlug/releases/download/v$AppVersion/FreetonVPN-Setup-x64.exe"
        file_size_bytes       = [int64]$installerBytes
        sha256                = $installerSha256
        mandatory             = $mandatory
        min_supported_version = $minSupported
    }

    $manifestJson = ($manifestObj | ConvertTo-Json -Depth 4) + "`n"
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, $utf8NoBom)

    Write-Host "Installer: $installerPath ($installerBytes bytes)" -ForegroundColor Green
    Write-Host "SHA-256:   $installerSha256 ($shaFilePath)" -ForegroundColor Green
    Write-Host "Manifest:  $manifestPath updated for v$AppVersion" -ForegroundColor Green
}

$appVersion = Resolve-AppVersion
$effectiveDate = if ($ReleaseDate) { $ReleaseDate.Trim() } else { (Get-Date).ToString('yyyy-MM-dd') }

Stage-TunnelDll
Stage-WireGuardNtDll
Build-RustWorkspace
Build-InstallerAndManifest -AppVersion $appVersion -EffectiveDate $effectiveDate
