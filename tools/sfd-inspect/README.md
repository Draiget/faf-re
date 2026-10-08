# Independent SFD diagnostics

Run from an initialized Visual Studio developer shell, with the FFmpeg development
package described in [the compatibility profile](../../docs/FAF_SFD_COMPATIBILITY.md):

```bat
cmake -S tools/sfd-inspect -B .tmp/sfd-tests -A Win32 -DFAF_SFD_ASSET_DIR="path/to/game/movies"
cmake --build .tmp/sfd-tests --config Debug
ctest --test-dir .tmp/sfd-tests -C Debug --output-on-failure
```

Use a separate build directory with `-A x64` for 64-bit diagnostics. Add
`-DFAF_SFD_ASAN=ON` to instrument backend and test code; run from the developer
shell so the ASan runtime DLL can be found. Release is supported too.

The asset directory is optional. Without it, CTest runs only synthetic parser
tests. The DirectSound test requires an available audio device. No game assets
are copied or redistributed. `--play-sound` audibly plays part of the selected
movie; `--play` exercises the same player with no sound device.

Examples:

```bat
sfd-inspect --metadata main_menu.sfd FMV_loading02.sfd
sfd-inspect --decode e3_demo_cut.sfd
sfd-inspect --play Abasi.sfd
sfd-inspect --play-sound e3_demo_cut.sfd
```

These tests validate the independent backend and compatibility API. They do not
claim to exercise FAF's D3D reset events, VFS resolution, Lua callbacks or XACT
playback; those require the complete engine.

The observed Windows DirectSound/ASan incompatibility and its standalone
reproducer are described in the [validation report](../../docs/FAF_SFD_VALIDATION.md).
Normal Win32/x64 audio tests pass; do not interpret a no-sound sanitizer run as
validation of the Windows audio implementation.
