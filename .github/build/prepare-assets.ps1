[CmdletBinding()]
param(
    [switch]$IncludeWintun
)

$ErrorActionPreference = 'Stop'
$resources = Join-Path (Get-Location) 'resources'
New-Item -ItemType Directory -Force $resources | Out-Null

$geodatBase = 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release'
foreach ($name in 'geoip.dat', 'geosite.dat') {
    $asset = Join-Path $resources $name
    $checksum = (Invoke-WebRequest "$geodatBase/$name.sha256sum").Content.Trim().Split([char[]]" `t")[0].ToLowerInvariant()
    $current = if (Test-Path -LiteralPath $asset) {
        (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($current -ne $checksum) {
        $download = "$asset.download"
        Invoke-WebRequest "$geodatBase/$name" -OutFile $download
        $downloadHash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($downloadHash -ne $checksum) {
            throw "SHA256 mismatch for downloaded $name"
        }
        Move-Item -LiteralPath $download -Destination $asset -Force
    }
    if ((Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant() -ne $checksum) {
        throw "SHA256 mismatch for $name"
    }
}

if ($IncludeWintun) {
    $wintunVersion = '0.14.1'
    $wintunHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
    $temporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
    $archive = Join-Path $temporaryRoot "wintun-$wintunVersion.zip"
    $expanded = Join-Path $temporaryRoot "wintun-$wintunVersion"
    Invoke-WebRequest "https://www.wintun.net/builds/wintun-$wintunVersion.zip" -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $wintunHash) {
        throw 'SHA256 mismatch for Wintun archive'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded -Force
    Copy-Item -LiteralPath (Join-Path $expanded 'wintun') -Destination $resources -Recurse -Force
    foreach ($relativePath in 'wintun/LICENSE.txt', 'wintun/bin/amd64/wintun.dll', 'wintun/bin/x86/wintun.dll', 'wintun/bin/arm64/wintun.dll') {
        if (-not (Test-Path -LiteralPath (Join-Path $resources $relativePath))) {
            throw "Missing prepared Wintun asset: $relativePath"
        }
    }
}
