param(
  [string]$Original = '',
  [string]$Changed = '',
  [string]$Work = ''
)
# Checks a mesh.fx made by make_bonetex_meshfx.py against the one it came from,
# compiling both the way the engine does (effects/d3d9states.compat + the .fx,
# the legacy d3dx9_31 compiler that D3DXSHADER_USE_LEGACY_D3DX9_31_DLL selects):
#
#  1. Without FAF_BONE_TEXTURE it must compile to exactly the same shaders.
#     Compare the listings, not the .fxo: fxc writes a few bytes differently
#     on every run, even for the same source.
#  2. With it, it must compile, every pass as shader model 3 and no null pixel
#     shader left (Direct3D 9 pairs a 3.0 vertex shader only with a 3.0 pixel
#     shader).
#  3. Through the D3D10 prelude it must give the same messages as before.
#
# Needs the DirectX SDK (June 2010) for its fxc, which still has /LD. Run it
# from PowerShell: Git Bash turns fxc's /switches into paths.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$effects = Join-Path $repo 'gamedata\effects'
if ($Original -eq '') { $Original = Join-Path $effects 'mesh.fx' }
if ($Changed -eq '') { $Changed = Join-Path $repo 'gamedata\effects-bonetex\effects\mesh.fx' }
if ($Work -eq '') { $Work = Join-Path $env:TEMP 'bonetex-check' }
New-Item -ItemType Directory -Force $Work | Out-Null

$sdk = if ($env:DXSDK_DIR) { $env:DXSDK_DIR } else { 'C:\Program Files (x86)\Microsoft DirectX SDK (June 2010)\' }
$fxc = Join-Path $sdk 'Utilities\bin\x86\fxc.exe'

function Compile([string]$fx, [string]$compat, [string]$prelude, [string]$target, [string]$tag, [string[]]$extra) {
  # Every compile goes through the same file name: fxc records it.
  $merged = Join-Path $Work 'merged.fx'
  $text = [IO.File]::ReadAllText((Join-Path $effects $compat)) + "`n" + $prelude + "`n" + [IO.File]::ReadAllText($fx)
  [IO.File]::WriteAllText($merged, $text)
  $argList = @('/nologo', "/T$target", '/Fo', (Join-Path $Work "$tag.fxo"), '/Fc', (Join-Path $Work "$tag.asm")) + $extra + @($merged)
  $p = Start-Process -FilePath $fxc -ArgumentList $argList -RedirectStandardError (Join-Path $Work "$tag.err") `
    -RedirectStandardOutput (Join-Path $Work "$tag.out") -NoNewWindow -Wait -PassThru
  return $p.ExitCode
}

function SameBytes([string]$a, [string]$b) {
  if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
  $x = [IO.File]::ReadAllBytes($a); $y = [IO.File]::ReadAllBytes($b)
  return ($x.Length -eq $y.Length) -and ([Convert]::ToBase64String($x) -eq [Convert]::ToBase64String($y))
}

$e1 = Compile $Original 'd3d9states.compat' '' 'fx_2_0' 'original' @('/LD')
$e2 = Compile $Changed 'd3d9states.compat' '' 'fx_2_0' 'changed' @('/LD')
"1. without FAF_BONE_TEXTURE: exit original={0} changed={1}, same shaders={2}" -f $e1, $e2, `
  (SameBytes (Join-Path $Work 'original.asm') (Join-Path $Work 'changed.asm'))

# /Gfa as the engine does for this variant (D3DXSHADER_AVOID_FLOW_CONTROL):
# without it the legacy compiler spends about ten times longer on ps_3_0.
$started = Get-Date
$e3 = Compile $Changed 'd3d9states.compat' "#define FAF_BONE_TEXTURE 1`n" 'fx_2_0' 'bonetex' @('/LD', '/Gfa')
$seconds = ((Get-Date) - $started).TotalSeconds
$asmPath = Join-Path $Work 'bonetex.asm'
$asm = if (Test-Path $asmPath) { [IO.File]::ReadAllText($asmPath) } else { '' }
$errors = @(Get-Content (Join-Path $Work 'bonetex.err') | Where-Object { $_ -match 'error' })
"2. with FAF_BONE_TEXTURE: exit={0} errors={1} vs_3_0={2} ps_3_0={3} older profiles={4} vertex texture reads={5} ({6:N1} s)" -f `
  $e3, $errors.Count, ([regex]::Matches($asm, '(?m)^\s*vs_3_0\b').Count), ([regex]::Matches($asm, '(?m)^\s*ps_3_0\b').Count), `
  ([regex]::Matches($asm, '(?m)^\s*(vs_1_1|vs_2_0|ps_2_0|ps_2_x)\b').Count), ([regex]::Matches($asm, '\btexldl\b').Count), $seconds
$errors | Select-Object -First 10

$e4 = Compile $Original 'd3d10states.compat' '' 'fx_4_0' 'd3d10_original' @('/Gec')
$e5 = Compile $Changed 'd3d10states.compat' "#define FAF_BONE_TEXTURE 1`n" 'fx_4_0' 'd3d10_changed' @('/Gec')
$strip = { param($file) (Get-Content $file | ForEach-Object { $_ -replace '^.*?\(\d+(,\d+(-\d+)?)?\):\s*', '' }) -join "`n" }
"3. D3D10 prelude: exit original={0} changed={1}, same messages={2}" -f $e4, $e5, `
  ((& $strip (Join-Path $Work 'd3d10_original.err')) -eq (& $strip (Join-Path $Work 'd3d10_changed.err')))
