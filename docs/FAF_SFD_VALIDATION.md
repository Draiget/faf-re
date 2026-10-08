# Independent SFD migration validation

Validation dates: 2026-10-07 through 2026-10-08. This report separates standalone/backend evidence
from full-engine and visual integration evidence.

## Archive and source changes

The external archive is `../faf-sofdec-archive/`, outside the active repository.
Its ARCHIVE_README.md records original HEAD, branch and clean working-tree status.
It contains 39 SHA-256-verified source/project/README copies preserving relative
paths, working-tree and staged binary diffs, status.txt, SHA256.json, and a
verified complete-history Git bundle. Copies were verified again before deletion.
No build path references the archive.

Removed 30 archived files: the entire 21-file `src/sdk/cri/sofdec/` tree, seven
`moho/audio/Sofdec{Adx,M2a,Mpa}*Runtime.cpp` implementations, and
`moho/movie/MPVDecoder.{h,cpp}`. Git retains history; the active source does not
contain these implementations.

Added the five independent header/implementation pairs under
`src/sdk/moho/movie/sfd/`: IndependentSfdBackend, SfdHeaderParser, SfdMetadata,
FfmpegSfdDecoder and DirectSoundMovieSink. Added this report, the compatibility
profile, and the `tools/sfd-inspect` CMake diagnostic/test project.

Modified existing files intentionally:

- SofdecRuntime.h/.cpp: small legacy-name compatibility declarations/adapters.
- CMovie.cpp: remove duplicate legacy declarations and update compatibility
  comments; movie control flow is retained.
- StartupHelpers.cpp: send movie volume to sinks; detach/shut down players before
  releasing the DirectSound device.
- main.vcxproj/.filters: replace middleware inputs with the five independent
  units; configurable FFmpeg headers/libraries and explicit DLL staging. x64 run-directory
  staging is opt-in to avoid mixing its DLLs with the shared Win32 run directory.
- README.md and .gitignore: independent-backend documentation and ignored local
  FFmpeg development packages.

`CMovie.h` is byte-for-byte unchanged from HEAD. IMovie and CMovie virtual
interfaces, field order and Win32 layout assertions are unchanged. Lua/XACT movie
code is unchanged. New code has no fabricated original-address annotations.

The complete legacy-call forwarding table, required five FFmpeg libraries,
format details, setup instructions and supported/unsupported features are in
[FAF_SFD_COMPATIBILITY.md](FAF_SFD_COMPATIBILITY.md).

## Builds

Full engine builds use the VS 2022 developer shell, installed dependencies and
locally built LGPL FFmpeg 7.1.3 shared libraries. No third-party binaries are
included in the change.

| Configuration | Full engine result |
|---|---|
| Debug / Win32 | Passed; CMovie layout assertions compiled |
| Debug / x64 | Passed with the branch's existing x64 layout-assert policy |
| Release / Win32 | Passed |
| Release / x64 | Passed |

The existing project enables `/FORCE`, which emits LNK4088; its existing
EDITANDCONTINUE/CRT-section warnings and missing optional `pwsh.exe` post-build
message are not newly introduced SFD problems. The migration does not disable
additional project warnings. FFmpeg headers are treated as external headers.

## Backend tests

The normal CMake/CTest suites passed 7/7 in Debug/Win32 and Release/x64, including:

- Exact signature, relocated headers, truncated descriptors, invalid counts,
  malformed fields, effect mapping and 20,000 deterministic fuzz cases.
- Complete MPEG video decoding and opaque BGRA validation.
- Complete embedded ADX decode and resampler drain.
- Texture copying with padded destination pitch and canaries.
- First frame while paused, timed playback, pause freeze, resume and volume.
- Ring-buffer wrap, restart, EOF (including embedded audio drain), repeated
  reopen/dispose, missing-file rejection, and idempotent shutdown.
- Embedded-audio file with no sound device (steady-clock playback).
- Explicit graceful rejection of the observed special-composition file.

The final timed playback checks bound clock drift to 250 ms at the sampled point
and freeze video PTS during pause. Consumed DirectSound ring slots are cleared to
silence so underruns cannot expose previously consumed PCM from an earlier wrap.

Standalone Win32 and x64 diagnostics both compiled and passed normal embedded
DirectSound playback. Parser ASan tests passed. The x64 Debug ASan suite passed
parser, full video/audio decode and no-sound playback, but its DirectSound test
crashed inside Windows DSOUND.dll. A separate minimal program using only
DirectSound creation, a silent secondary buffer and Play reproduced the same
null read at DSOUND.dll+0x69362 without FAF or FFmpeg. Disabling the optional
RTL heap hook did not resolve it. This is an environment/sanitizer limitation,
not a passing sanitized audio test; ordinary x64 DirectSound tests pass.
The final ASan rerun passed 6/6 with only that known physical DirectSound test
explicitly excluded. FFmpeg DLLs themselves were not sanitizer-instrumented.

## Asset results

Installed assets remained outside the repository. Full decode results:

| File | Dimensions | Frames decoded | End PTS (seconds) |
|---|---:|---:|---:|
| main_menu.sfd | 1824x1024 | 2336 | 77.8667 |
| UEF_load.sfd | 1280x1024 | 179 | 5.96667 |
| fmv_scx_intro.sfd | 1600x672 | 6211 | 207.033 |
| credits_generic.sfd | 1824x1024 | 7192 | 239.733 |
| FMV_SCX_Outro.sfd | 1600x672 | 1770 | 59.0 |
| Abasi.sfd | 192x192 | 150 | 5.00598 |
| e3_demo_cut.sfd | 1280x720 | 362 | 12.0797 video / 12.0847 audio |

Decoded counts match SFD metadata. e3_demo_cut supplies 579,808 stereo samples at
48 kHz. Abasi and e3_demo_cut passed timed player/compatibility tests. All videos
in this table are MPEG-1; a synthetic 2-second MPEG-2/MP2 Program Stream with a
metadata pack also decoded successfully: 50 frames and 96,549 resampled stereo
samples from 44.1 kHz mono, with video/audio ends 2.01091/2.01145 seconds.

The Debug/Win32 engine smoke test with `/nosound` reached these real call sites:
`OpenMovie /movies/thqlogo.sfd`, `Preparing movie`, and `Playing movie` with the
resolved installed path. It was stopped by the test after observation. This
proves startup and movie API integration, not a complete interactive visual test.
The final Release/Win32 sound-enabled startup also initialized XACT wavebanks
and reached the same movie preparation/play calls; it was stopped after observation.

The installed corpus census covered 1004 headers: 1002 ordinary video-only,
one ordinary ADX-audio movie, and FMV_loading02.sfd with effect 1 / mode 33.
That file fails gracefully with filename, composition mode, dimensions, colour,
picture and flags in the diagnostic. Modes 81/97 were not observed.

## Remaining unverified behavior

Special composition/alpha rendering is unsupported, including FMV_loading02.sfd;
metadata and CMovie's existing height branch are preserved. Embedded subtitles,
CRITAGS/AINF semantics and other private/user data remain unconfirmed. No guessed
subtitle or effect implementation is present. Multiple video streams and TS are
outside the supported FAF profile.

A complete interactive campaign sequence, visible pixel comparison, D3D device
reset, external XACT sound/voice cue combinations and extended audible drift
assessment were not verified. Their existing callers are unchanged. Repeated
open tests demonstrate successful cleanup paths but are not a dedicated leak
profiler result.

## Dependency audit

The active source/project search for `cri/sofdec`, `SofdecMpvRuntime`,
`SofdecSfdRuntime`, `SofdecAdxRuntime`, `SofdecSfxRuntime`, and `MPVDecoder` returns
no source/build dependencies. Documentation mentions are historical only.
All four final linker command logs contain the five FFmpeg libraries and no
old decoder/middleware object inputs. All four build logs have no unresolved
symbol diagnostics. There is one active backend, no fallback,
compile-time selector, hardcoded-address call or archive include/link path.
