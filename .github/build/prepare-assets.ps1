[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$resources = Join-Path (Get-Location) 'resources'
New-Item -ItemType Directory -Force $resources | Out-Null

# Immutable public fixture input; update explicitly when the test baseline changes.
$geodatRevision = 'e4e6584208db6bcdfa340adabf2de509aae5c64f'
$geodatBase = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/$geodatRevision"
foreach ($name in 'geoip.dat', 'geosite.dat') {
    $asset = Join-Path $resources $name
    $checksum = (Invoke-WebRequest "$geodatBase/$name.sha256sum").Content.Trim().Split([char[]]" `t")[0].ToLowerInvariant()
    if ($checksum -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid SHA256 for $name"
    }
    $current = if (Test-Path -LiteralPath $asset) {
        (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($current -ne $checksum) {
        $download = "$asset.download"
        Invoke-WebRequest "$geodatBase/$name" -OutFile $download
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $checksum) {
            throw "SHA256 mismatch for downloaded $name"
        }
        Move-Item -LiteralPath $download -Destination $asset -Force
    }
    if ((Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant() -ne $checksum) {
        throw "SHA256 mismatch for $name"
    }
}
