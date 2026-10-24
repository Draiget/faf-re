# SFD diagnostics

Standalone diagnostics and tests for the independent SFD movie backend and its compatibility API. Setup, format details and validation results are in [FAF SFD movies](../../docs/FAF_SFD_COMPATIBILITY.md).

## Build and test

Build with clang-cl and Ninja from the repository root, using the engine's toolchain files (an absolute path: CMake resolves a relative one against the build directory); FFmpeg is compiled from the `dependencies/ffmpeg` submodule (see [the compatibility profile](../../docs/FAF_SFD_COMPATIBILITY.md#ffmpeg-dependency-and-build)):

```bat
cmake -S tools/sfd-inspect -B .tmp/sfd-tests -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=%CD%/cmake/toolchains/clang-cl-x86.cmake -DFAF_SFD_ASSET_DIR="path/to/game/movies"
cmake --build .tmp/sfd-tests
ctest --test-dir .tmp/sfd-tests --output-on-failure
```

- **x64**: use a separate build directory with `cmake/toolchains/clang-cl-x64.cmake`. Release is supported too.
- **ASan**: add `-DFAF_SFD_ASAN=ON` to instrument backend and test code; run from the developer shell so the ASan runtime DLL is found.
- **Assets**: the asset directory is optional. Without it, CTest runs only the synthetic parser tests. No game assets are copied or redistributed.
- **Sound**: the DirectSound test needs an available audio device. `--play-sound` audibly plays part of the selected movie; `--play` exercises the same player with no sound device.

## Examples

```bat
sfd-inspect --metadata main_menu.sfd FMV_loading02.sfd
sfd-inspect --decode e3_demo_cut.sfd
sfd-inspect --play Abasi.sfd
sfd-inspect --play-sound e3_demo_cut.sfd
```

## Limits

- These tests do not exercise FAF's D3D reset events, VFS resolution, Lua callbacks or XACT playback; those need the complete engine.
- Under ASan, the DirectSound test crashes inside Windows `DSOUND.dll` (standalone reproducer in the [validation results](../../docs/FAF_SFD_COMPATIBILITY.md#backend-tests)). Normal Win32/x64 audio tests pass; a no-sound sanitizer run is not validation of the Windows audio implementation.
