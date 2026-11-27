# noise.ps1: every PR build once more on its own (tags pr0N_b), D3D11 and D3D12, the default scenes only: the repeat of a build against itself, which is the noise floor of the water
$here = $PSScriptRoot
foreach ($pr in 'pr02','pr03','pr04','pr05','pr06','pr07') {
  & "$here\matrix.ps1" -Name $pr -Tag "${pr}_b" -Groups sr,astro -Apis d3d11,d3d12 -NoOff
}
"NOISE DONE" | Add-Content "$here\all_after.txt"
