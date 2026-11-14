param(
    [ValidateSet('Build','Runtime')][string]$Mode = 'Build',
    [string]$Workspace,
    [string]$ResultFile,
    [ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Revision,
    [switch]$Library
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$SourceRevision = $Revision

function Invoke-Native([string]$File, [string[]]$Arguments) {
    # PowerShell 5 treats native stderr as errors; use the process exit code.
    $ErrorActionPreference = 'Continue'
    & $File @Arguments 2>&1 | ForEach-Object { Write-Host "$_" }
    if ($LASTEXITCODE -ne 0) { throw "$File failed (exit $LASTEXITCODE)." }
}
function Test-Download([string]$Path, [string]$Digest, [string]$Publisher) {
    if ($Digest) {
        $hasher = [Security.Cryptography.SHA256]::Create()
        $inputStream = [IO.File]::OpenRead($Path)
        try { $hash = [BitConverter]::ToString($hasher.ComputeHash($inputStream)).Replace('-', '') }
        finally { $inputStream.Dispose(); $hasher.Dispose() }
        if ($hash -ne $Digest.Replace('sha256:', '')) { throw 'Downloaded file failed its SHA-256 check.' }
    } else {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $Publisher) { throw 'The publisher signature could not be verified.' }
    }
}
function Get-Download([string]$Url, [string]$Name, [string]$Digest, [string]$Publisher) {
    if (-not $Url.StartsWith('https://') -or $Name -ne [IO.Path]::GetFileName($Name)) { throw 'Invalid download URL or file name.' }
    $path = Join-Path $Workspace "downloads/$Name"
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    if (Test-Path -LiteralPath $path) {
        try { Test-Download $path $Digest $Publisher; return $path }
        catch { Remove-Item -LiteralPath $path -Force }
    }
    $urls = @($Url)
    if ($Url -match '^https://downloads.sourceforge.net/project/boost/boost/([0-9.]+)/([^/]+)$') {
        $urls += "https://archives.boost.io/release/$($Matches[1])/source/$($Matches[2])"
    }
    if ($Url -match '^https://github.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^/?]+)$') {
        $repo = $Matches[1]; $tag = $Matches[2]; $assetName = [uri]::UnescapeDataString($Matches[3])
        try {
            $releaseInfo = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/tags/$tag" -Headers @{'User-Agent'='Microchip-faf-re-builder'}
            $asset = @($releaseInfo.assets | Where-Object name -eq $assetName)
            if ($asset.Count -eq 1) { $urls += $asset[0].url }
        } catch { Write-Host 'GitHub asset API unavailable; using the release download route.' }
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        foreach ($base in $urls) {
            try {
                $request = if ($attempt -eq 1) { $base } elseif ($base.Contains('?')) { "$base&microchip_retry=$attempt" } else { "$base`?microchip_retry=$attempt" }
                Write-Host "Downloading $Name (attempt $attempt/3)..."
                $headers = @{'User-Agent'='Microchip-faf-re-builder'}
                if ($base.StartsWith('https://api.github.com/')) { $headers.Accept = 'application/octet-stream' }
                Invoke-WebRequest -Uri $request -Headers $headers -OutFile "$path.partial" -UseBasicParsing -TimeoutSec 1800
                Test-Download "$path.partial" $Digest $Publisher
                Move-Item -LiteralPath "$path.partial" -Destination $path -Force
                return $path
            } catch {
                Write-Host "Download not accepted: $($_.Exception.Message)"
                if (Test-Path -LiteralPath "$path.partial") { Remove-Item -LiteralPath "$path.partial" -Force }
            }
        }
    }
    throw "Could not download and verify $Name after three attempts. Check your connection and try again."
}
function Install-Elevated([string]$File, [string]$Arguments) {
    Write-Host "Installing $(Split-Path $File -Leaf). Approve the Windows administrator prompt if shown."
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Verb RunAs -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -eq 3010 -or $process.ExitCode -eq 1641) { throw 'A prerequisite requires a Windows restart. Restart, then click Install faf-re again to resume.' }
    if ($process.ExitCode -ne 0) { throw "Prerequisite installation failed (exit $($process.ExitCode)). See the installer log." }
}
function Find-VS {
    $where = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $where)) { return $null }
    return (& $where -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.VC.ATL Microsoft.VisualStudio.Component.VC.CMake.Project -property installationPath | Select-Object -First 1)
}
function Ensure-VS {
    $vs = Find-VS
    $sdk = @("${env:ProgramFiles(x86)}/Windows Kits/10/Include/*/um/Windows.h" | Resolve-Path -ErrorAction SilentlyContinue)
    if (-not $vs -or $sdk.Count -eq 0) {
        $installer = Get-Download 'https://aka.ms/vs/17/release/vs_BuildTools.exe' 'vs_BuildTools.exe' '' 'Microsoft Corporation'
        Install-Elevated $installer '--passive --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add Microsoft.VisualStudio.Component.VC.ATL --add Microsoft.VisualStudio.Component.VC.CMake.Project --add Microsoft.VisualStudio.Component.Windows11SDK.26100'
        $vs = Find-VS
        if (-not $vs) { throw 'Visual Studio 2022 C++ tools, ATL and CMake were not detected after installation.' }
    }
    return $vs
}
function Get-ReleaseAsset([string]$Repo, [string]$Pattern, [string]$Release = 'latest') {
    $endpoint = if ($Release -eq 'latest') { 'latest' } else { "tags/$Release" }
    $releaseInfo = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/$endpoint" -Headers @{'User-Agent'='Microchip-faf-re-builder'}
    $asset = @($releaseInfo.assets | Where-Object name -Match $Pattern)
    if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:[a-fA-F0-9]{64}$') { throw "No verified Windows installer found for $Repo." }
    return $asset[0]
}
function Find-Git {
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) { return $git.Source }
    foreach ($path in @("$env:ProgramFiles/Git/cmd/git.exe", "$env:LOCALAPPDATA/Programs/Git/cmd/git.exe")) {
        if (Test-Path -LiteralPath $path) { return $path }
    }
    return $null
}
function Ensure-UCRT {
    $library = "${env:ProgramFiles(x86)}/Windows Kits/10/Lib/10.0.22000.0/ucrt/x64/libucrt.lib"
    if (Test-Path -LiteralPath $library) { return }
    $installer = Get-Download 'https://download.microsoft.com/download/1/0/e/10e6da02-01f7-40d4-8942-b98b53b36cf9/windowssdk/winsdksetup.exe' 'winsdksetup-22000.exe' '521b6410d3fdd92adbcfe941fc24746ea340288b3767fe39026bc70907ae0322' ''
    Install-Elevated $installer '/features OptionId.DesktopCPPx64 /quiet /norestart /ceip off'
    if (-not (Test-Path -LiteralPath $library)) { throw 'SDK 22000 x64 UCRT is required for simulation math parity.' }
}
function Ensure-Git {
    $git = Find-Git
    if (-not $git) {
        $asset = Get-ReleaseAsset 'git-for-windows/git' '^Git-.*-64-bit.exe$'
        $installer = Get-Download $asset.browser_download_url $asset.name $asset.digest ''
        Install-Elevated $installer '/VERYSILENT /NORESTART /NOCANCEL /SP-'
        $git = Find-Git
        if (-not $git) { throw 'Git was not found after installation.' }
    }
    return $git
}
function Ensure-LLVM {
    $llvm = if ($env:LLVM_ROOT) { $env:LLVM_ROOT } else { "$env:ProgramFiles/LLVM" }
    $clang = Join-Path $llvm 'bin/clang-cl.exe'
    $valid = $false
    if (Test-Path -LiteralPath $clang) {
        $version = & $clang --version | Select-Object -First 1
        $valid = $version -match 'clang version (\d+)' -and [int]$Matches[1] -ge 23
    }
    if (-not $valid) {
        $asset = Get-ReleaseAsset 'llvm/llvm-project' '^LLVM-.*-win64.msi$' 'llvmorg-23.1.5'
        $installer = Get-Download $asset.browser_download_url $asset.name $asset.digest ''
        Install-Elevated "$env:WINDIR/System32/msiexec.exe" "/i `"$installer`" /passive /norestart"
        $llvm = "$env:ProgramFiles/LLVM"
    }
    foreach ($name in @('clang-cl.exe','lld-link.exe','llvm-lib.exe','llvm-rc.exe','llvm-mt.exe','llvm-ml.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $llvm "bin/$name"))) { throw "LLVM is missing $name." }
    }
    $env:LLVM_ROOT = $llvm
}
function Ensure-DirectX {
    $system = if ([Environment]::Is64BitProcess) { "$env:WINDIR/System32" } else { "$env:WINDIR/Sysnative" }
    if ((Test-Path -LiteralPath "$system/d3dx9_43.dll") -and (Test-Path -LiteralPath "$system/X3DAudio1_7.dll")) { return }
    $installer = Get-Download 'https://download.microsoft.com/download/8/4/a/84a35bf1-dafe-4ae8-82af-ad2ae20b6b14/directx_Jun2010_redist.exe' 'directx_Jun2010_redist.exe' '' 'Microsoft Corporation'
    $extracted = Join-Path $Workspace 'downloads/directx'
    New-Item -ItemType Directory -Force $extracted | Out-Null
    $process = Start-Process -FilePath $installer -ArgumentList "/Q /T:`"$extracted`"" -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw 'DirectX extraction failed.' }
    $setup = Join-Path $extracted 'DXSETUP.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $setup
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'DirectX setup signature failed.' }
    Install-Elevated $setup '/silent'
    if (-not (Test-Path -LiteralPath "$system/d3dx9_43.dll") -or -not (Test-Path -LiteralPath "$system/X3DAudio1_7.dll")) { throw 'DirectX runtime verification failed.' }
}
function Build-Source([string]$Git, [string]$VS) {
    $source = Join-Path $Workspace "source-$($SourceRevision.Substring(0,12))"
    if (-not (Test-Path -LiteralPath $source)) {
        Write-Host 'Downloading the faf-re source...'
        Invoke-Native $Git @('clone', '--filter=blob:none', '--no-checkout', 'https://github.com/Draiget/faf-re.git', $source)
        Invoke-Native $Git @('-C', $source, 'checkout', '--detach', $SourceRevision)
    }
    $origin = & $Git -C $source remote get-url origin
    $head = & $Git -C $source rev-parse HEAD
    if ($origin -ne 'https://github.com/Draiget/faf-re.git' -or $head -ne $SourceRevision) { throw 'The cached source does not match the expected repository/revision. Choose a fresh build folder.' }
    $changes = & $Git -C $source status --porcelain --untracked-files=no
    if ($changes) { throw 'The cached source has local changes. Preserve them and choose a fresh build folder.' }
    Invoke-Native $Git @('-C', $source, 'submodule', 'update', '--init', '--recursive')
    $pinnedUcrt = (Get-Content (Join-Path $source 'src/CMakeLists.txt') -Raw).Contains('FAF_UCRT_LIB_VERSION')
    if ($pinnedUcrt) { Ensure-UCRT }
    # Prefetch the checksum-pinned archives with retries before CMake's single-attempt
    # downloader runs. Read the selected version's manifest rather than hardcoding deps.
    $manifest = Get-Content (Join-Path $source 'cmake/FafDependencies.cmake') -Raw
    foreach ($match in [regex]::Matches($manifest, '(?s)set\(_faf_download_[^\s]+\s+(.*?)\)')) {
        $values = @([regex]::Matches($match.Groups[1].Value, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
        if ($values.Count -lt 2 -or $values[0] -notmatch '^https://' -or $values[1] -notmatch '^[a-fA-F0-9]{64}$') { continue }
        $name = if ($values.Count -ge 4) { $values[3] } else { [IO.Path]::GetFileName(([uri]$values[0]).AbsolutePath) }
        if ($name -ne [IO.Path]::GetFileName($name)) { throw 'Invalid dependency archive name.' }
        $download = Get-Download $values[0] $name $values[1] ''
        $cache = Join-Path $source 'dependencies/.downloads'
        New-Item -ItemType Directory -Force $cache | Out-Null
        Copy-Item -LiteralPath $download -Destination (Join-Path $cache $name) -Force
    }
    $sdkCandidates = @($env:DXSDK_DIR, "${env:ProgramFiles(x86)}/Microsoft DirectX SDK (June 2010)", (Join-Path $source 'dependencies/dxsdk'))
    $hasLegacySdk = $false
    foreach ($candidate in $sdkCandidates) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'Include/d3dx9core.h')) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'Lib/x64/d3dx9.lib'))) { $hasLegacySdk = $true }
    }
    if (-not $hasLegacySdk) {
        $sdkUrl = [regex]::Match($manifest, 'set\(_faf_dxsdk_url\s+"([^"]+)"')
        $sdkHash = [regex]::Match($manifest, 'set\(_faf_dxsdk_sha256\s+"([a-fA-F0-9]{64})"')
        if ($sdkUrl.Success -and $sdkHash.Success) {
            $download = Get-Download $sdkUrl.Groups[1].Value 'DXSDK_Jun10.exe' $sdkHash.Groups[1].Value ''
            $cache = Join-Path $source 'dependencies/.downloads'
            New-Item -ItemType Directory -Force $cache | Out-Null
            Copy-Item -LiteralPath $download -Destination (Join-Path $cache 'DXSDK_Jun10.exe') -Force
        }
    }
    $tools = Join-Path $VS 'Common7/IDE/CommonExtensions/Microsoft/CMake'
    $env:PATH = "$tools/CMake/bin;$tools/Ninja;$(Split-Path $Git);$env:PATH"
    # Keep the toolchain's own VS discovery on the validated 2022 instance.
    $version = (Get-Content (Join-Path $VS 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt') -Raw).Trim()
    $env:VCToolsInstallDir = Join-Path $VS "VC/Tools/MSVC/$version"
    $jobs = [Math]::Max(1, [Math]::Min(4, [Environment]::ProcessorCount))
    Write-Host "Building x64 Release ($jobs parallel jobs). Dependencies download automatically; this may take a while."
    # A failed configure leaves CMakeCache.txt behind; explicitly reconfigure on retry.
    Push-Location $source
    try {
        $configure = @('--preset', 'clang-x64-release')
        if ($pinnedUcrt) { $configure += '-DFAF_UCRT_LIB_VERSION=10.0.22000.0' }
        Invoke-Native (Join-Path $tools 'CMake/bin/cmake.exe') $configure
    }
    finally { Pop-Location }
    & (Join-Path $source 'build.ps1') -NoCopy -Jobs $jobs
    $output = Join-Path $source 'build/clang-x64-release/src'
    foreach ($name in @('main_x64.exe','dxcompiler.dll','dxil.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $output $name))) { throw "Build output missing: $name" }
    }
    return $output
}
if ($Library) { return }
try {
    if (-not [Environment]::Is64BitOperatingSystem) { throw '64-bit Windows is required.' }
    $Workspace = [IO.Path]::GetFullPath($Workspace)
    New-Item -ItemType Directory -Force $Workspace | Out-Null
    Ensure-DirectX
    $output = $null
    if ($Mode -eq 'Build') {
        Write-Host 'Checking Visual Studio 2022, Git and LLVM...'
        $vs = Ensure-VS
        $git = Ensure-Git
        Ensure-LLVM
        # Capture only the returned directory; keep build output visible in the log.
        $result = @(Build-Source $git $vs | ForEach-Object { Write-Host $_; $_ })
        $output = [string]$result[-1]
    }
    @{output=$output; revision=$SourceRevision; success=$true} | ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding UTF8
    Write-Host 'Prerequisites and build steps completed.'
    exit 0
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    @{success=$false; error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding UTF8
    exit 1
}
