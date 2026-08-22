$ErrorActionPreference = "Stop"

$Repository = if ($env:WIRELINT_REPOSITORY) { $env:WIRELINT_REPOSITORY } else { "Raskinkamar/WireLinter" }
$InstallDir = if ($env:WIRELINT_INSTALL_DIR) { $env:WIRELINT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "WireLinter\bin" }
$ApiUrl = if ($env:WIRELINT_API_URL) { $env:WIRELINT_API_URL.TrimEnd('/') } else { "https://api.github.com/repos/$Repository" }
$DownloadUrl = if ($env:WIRELINT_DOWNLOAD_URL) { $env:WIRELINT_DOWNLOAD_URL.TrimEnd('/') } else { "https://github.com/$Repository/releases/download" }

$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($Arch) {
    "x64" { $GoArch = "amd64" }
    "arm64" { $GoArch = "arm64" }
    default { throw "wirelint install: unsupported architecture: $Arch" }
}

if ($env:WIRELINT_VERSION) {
    $Version = $env:WIRELINT_VERSION.TrimStart('v')
} else {
    $Release = Invoke-RestMethod -Uri "$ApiUrl/releases/latest"
    $Version = [string]$Release.tag_name
    $Version = $Version.TrimStart('v')
    if (-not $Version) { throw "wirelint install: could not determine the latest release" }
}

$Archive = "wirelint_${Version}_windows_${GoArch}.zip"
$Base = if ($env:WIRELINT_RELEASE_BASE_URL) { $env:WIRELINT_RELEASE_BASE_URL.TrimEnd('/') } else { "$DownloadUrl/v$Version" }
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wirelint-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $TempDir | Out-Null
    $ArchivePath = Join-Path $TempDir $Archive
    $ChecksumsPath = Join-Path $TempDir "SHA256SUMS"
    Write-Host "Installing WireLinter $Version for windows/$GoArch..."
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Archive" -OutFile $ArchivePath
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/SHA256SUMS" -OutFile $ChecksumsPath

    $Line = Get-Content $ChecksumsPath | Where-Object { $_ -match "^[0-9a-fA-F]+\s+$([regex]::Escape($Archive))$" } | Select-Object -First 1
    if (-not $Line) { throw "wirelint install: release checksum is missing for $Archive" }
    $Expected = ($Line -split '\s+')[0].ToLowerInvariant()
    $Actual = (Get-FileHash $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) { throw "wirelint install: SHA-256 checksum mismatch" }

    $ExtractDir = Join-Path $TempDir "extract"
    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force (Join-Path $ExtractDir "wirelint.exe") (Join-Path $InstallDir "wirelint.exe")
    Write-Host "Installed $(Join-Path $InstallDir 'wirelint.exe')"

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathParts = @($UserPath -split ';' | Where-Object { $_ })
    if ($PathParts -notcontains $InstallDir) {
        $NewPath = (@($PathParts) + $InstallDir) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        $env:Path = "$InstallDir;$env:Path"
        Write-Host "Added $InstallDir to your user PATH. Open a new terminal to use it there."
    }
    if ($env:WIRELINT_SKIP_RUN -ne "1") {
        & (Join-Path $InstallDir "wirelint.exe") version
    }
    Write-Host "Try it: wirelint demo"
} finally {
    if (Test-Path $TempDir) { Remove-Item -Recurse -Force $TempDir }
}
