# stage.ps1 -Name pr02 -Tree C:\...\faf-re-pr02 [-Exe main_x64.exe]: copies a build and its data folder into C:\ProgramData\FAForever\bin_x64_ev\<Name>\ and appends the UI test hook
param([string]$Name, [string]$Tree, [string]$Exe = 'main_x64.exe', [string]$BuildDir = 'build\clang-x64-release')
$root = 'C:\ProgramData\FAForever\bin_x64_ev'
$dst = "$root\$Name"
New-Item -ItemType Directory $dst -Force | Out-Null
foreach ($f in 'dxcompiler.dll', 'dxil.dll') { Copy-Item "C:\ProgramData\FAForever\bin_x64_perf\$f" $dst -Force }
Copy-Item "$Tree\$BuildDir\src\$Exe" "$dst\ev.exe" -Force
if (Test-Path "$dst\fafengine") { Remove-Item "$dst\fafengine" -Recurse -Force }
Copy-Item "$Tree\data\fafengine" "$dst\fafengine" -Recurse
$gm = "$dst\fafengine\lua\ui\game\gamemain.lua"
$hook = @'


-- Test hook (not part of the engine): runs /fafengine/lua/test/ev_camera.lua in the UI after CreateUI when it exists.
do
    local oldCreateUI = CreateUI

    function CreateUI(isReplay)
        oldCreateUI(isReplay)

        local script = '/fafengine/lua/test/ev_camera.lua'
        if DiskGetFileInfo(script) then
            doscript(script)
        end
    end
end
'@
if (-not (Select-String -Path $gm -Pattern 'ev_camera.lua' -Quiet)) { Add-Content $gm $hook -Encoding ascii }
$si = "$dst\fafengine\lua\simInit.lua"
if (-not (Test-Path $si)) { Copy-Item "$PSScriptRoot\simhook.lua" $si } elseif (-not (Select-String -Path $si -Pattern 'ev_sim.lua' -Quiet)) { Add-Content $si (Get-Content "$PSScriptRoot\simhook.lua" -Raw) -Encoding ascii }
New-Item -ItemType Directory "$dst\fafengine\lua\test" -Force | Out-Null
"staged $Name from $Tree"

