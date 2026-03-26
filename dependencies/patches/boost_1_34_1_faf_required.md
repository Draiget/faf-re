# FAF Boost 1.34.1 Patch + Bootstrap

This repo uses an external Boost tree and only needs:
- `boost_thread`
- `boost_filesystem`

The patch file `boost_1_34_1_faf_required.patch` captures local fixes needed for modern MSVC/UCRT compatibility.

## One-shot bootstrap

Run from a Visual Studio developer shell:

```bat
%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_boost_1_34_1_required.ps1 -BoostRoot "<your external boost path>"
```

Patch-only (no build):

```bat
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_boost_1_34_1_required.ps1 -BoostRoot "<your external boost path>" -PatchOnly
```

Or set an env var once:

```bat
set BOOST_ROOT=<your external boost path>
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_boost_1_34_1_required.ps1
```

## Manual steps

1. Apply patch:

```bat
git -C "<your external boost path>" apply "<path to this repo>\\dependencies\\patches\\boost_1_34_1_faf_required.patch"
```

2. Build required libraries:

```bat
cd /d "<your external boost path>"
tools\jam\src\bin.ntx86\bjam.exe --v2 --layout=tagged toolset=msvc threading=multi link=static runtime-link=shared --with-thread --with-filesystem stage --stagedir=stage/faf-required-md
```

3. Verify output libs exist:

- `<your external boost path>\stage\faf-required-md\lib\libboost_thread-vc-mt-gd.lib`
- `<your external boost path>\stage\faf-required-md\lib\libboost_thread-vc-mt.lib`
- `<your external boost path>\stage\faf-required-md\lib\libboost_filesystem-vc-mt-gd.lib`
- `<your external boost path>\stage\faf-required-md\lib\libboost_filesystem-vc-mt.lib`
