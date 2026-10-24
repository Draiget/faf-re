# FAF SFD movies

The engine plays Forged Alliance's SFD movies with its own independent player built on FFmpeg. All four full-engine configurations build, the backend test suites pass, and real movies decode and play; special-composition (alpha) movies, subtitles and a full interactive visual check are not done yet.

*Snapshot: 24/10/2026. Validation ran on 07–08/10/2026.*

- **Independent**: the player is not CRI Sofdec, contains no CRI SDK code and does not reproduce the middleware's internal architecture. This is not a formal clean-room claim.
- **Legacy names**: the `mwPly*`/`ADXM_*` names kept elsewhere in the engine are compatibility entry points only, not the original CRI implementation.

## Supported profile

- **Container**: MPEG Program Stream style SFD. Stream IDs: `BD` private_stream_1, `BE` padding, `BF` private_stream_2 metadata, `C0..DF` audio, `E0..EF` video.
- **Streams**: one MPEG-1/2 video stream, with optional ADX or MPEG audio. Multiple video streams and transport streams are not supported.
- **Movie types**: `CMovie`/`MOV_GetDuration` use 1 for video+audio and 3 for video-only. These are FAF compatibility constants, not middleware objects.

## Implementation

- **Decoding**: FFmpeg libavformat demuxes MPEG-PS; libavcodec decodes MPEG-1/2 and ADX/MP1/MP2/MP3; libswscale produces BGRA (opaque alpha); libswresample converts audio to interleaved S16 stereo at 48 kHz. FFmpeg objects and ownership never cross the decoder implementation boundary.
- **Threading and clock**: a player worker fills bounded queues independently of rendering. The audio device's playback position is the master clock while embedded audio plays; otherwise a steady clock is used. Pausing freezes both; reopening rebuilds decoder, queues, sink and PTS origin.
- **End of file**: EOF drains both codecs and the resampler, then waits for the final displayed frame's duration and the submitted audio before reporting ended.
- **Audio output**: `CMovieManager` owns the DirectSound device. Each audio movie has its own secondary buffer with wrap tracking and volume control. Manager volume updates reach active sinks. `/nosound` skips audio decode and uses the steady clock.
- **Unchanged**: XACT movie sound/voice cues and Lua movie semantics are independent of the player and unchanged.
- **Shutdown**: players close before the device is released; shutdown is idempotent.

Sources: `src/moho/movie/sfd/` (IndependentSfdBackend, SfdHeaderParser, SfdMetadata, FfmpegSfdDecoder, DirectSoundMovieSink), with small legacy-name adapters in `src/moho/audio/SofdecRuntime.h/.cpp`.

## Header fields

The parser scans at most the first 64 KiB (including, but not limited to, bases 0x800 and 0x1000) for the exact 24-byte `SofdecStream            ` identifier at base+0x20. It reads only bounded byte spans and never casts input to structures. The legacy engine supplies a 5000-byte probe, so only descriptors inside that probe can be accepted; the file-open path probes 64 KiB.

| Header offset | Representation | Meaning |
|---|---|---|
| 0x80 | LE32 | metadata size |
| 0x84 | U8 | pack type (observed supported value 0) |
| 0x88 | LE16 | packet-size-field length (2) |
| 0x8C | LE32 | pack size |
| 0xB0..0xB3 | U8 each | total/audio/video/private element counts |
| 0xB4 | LE32 | byte rate |
| 0xB8, 0xBC | LE32 | maximum audio/video playback lengths |
| 0xC0 | LE32 | maximum frame count |

- **Descriptor table**: starts at 0x180, up to 26 entries of 0x40 bytes. Counts must agree, all used descriptors must fit the probe, and declared sizes must bound the table. Stream ID is at descriptor+24.
- **Video descriptor**: codec +25, LE16 bitrate +26, packed dimensions +28..30, frame-rate code +31, feature-info +32, colour +33, picture +34, flags +35, expand +36, GOP N/M +37/+38, effect +39. Width = `(e[28] << 4) | (e[29] >> 4)`; height = `((e[29] & 15) << 8) | e[30]`.
- **Frame rate**: codes 1..8 mean 24000/1001, 24, 25, 30000/1001, 30, 50, 60000/1001, 60. The compatibility `fps` field is integer FPS times 1000 (fraction truncated).
- **ADX descriptor**: in e3_demo_cut.sfd it has codec 0 at +25, channel count at +27 and LE32 rate at +28 (2 channels, 48000 Hz). Other audio descriptor forms leave these optional fields unknown; FFmpeg discovers the actual stream.

## Composition and private metadata

- **Effects**: 1, 3 and 6 map to compatibility modes 33 (0x21), 81 (0x51) and 97 (0x61). CMovie's existing mode-33 height handling is intact.
- **Rejected at open**: special composition, nonstandard colour and picture types fail at player open with filename, mode, dimensions and descriptor details, instead of rendering guessed alpha. Header parsing keeps their metadata for diagnostics.
- **Private metadata**: the scanner records bounded private_stream_2 packet candidates in the probe as diagnostics, not as an extra MPEG demuxer. Debug builds log candidate lengths. CRITAGS, AINF and timed subtitle/user-data semantics are unconfirmed and no parser is invented. Subtitle compatibility clears output and returns zero.

## Legacy facade mapping

| Retained calls | Independent operation |
|---|---|
| mwPlyGetHdrInf | bounded HeaderParser, compatibility field conversion |
| mwPlyCalcWorkCprmSfd | 64-byte compatibility allocation; arena unused |
| mwPlyCreateSofdec / mwPlyDestroy | create/delete opaque RAII Player handle |
| mwPlyStartFname | Player::Open, including complete restart |
| mwPlyGetStat | Player status: 1 preparing, 2 ready/playing, 3 ended, 4 failed |
| mwPlyPause / mwPlyIsPause | freeze/resume/query player and audio clocks |
| mwPlyGetCurFrm / mwPlyRelCurFrm | borrow/release retained independent BGRA frame |
| mwPlyFxGetCompoMode | parsed composition mode |
| mwPlyFxSetOutBufSize / mwPlyFxCnvFrmARGB8888 | checked pitch/height and row copy |
| mwPlyGetSubtitle | empty output until a timed format is verified |
| mwPlyGetPlyInf | zero five debug statistics words |
| mwPlySetFrmSync | no-op; independent PTS scheduling |
| ADXM_WaitVsync / ADXM_ExecMain | lightweight success; workers handle cadence |
| ADXPC_SetupSoundDirectSound8 | configure non-owning sound device |
| ADXM_SetCbErr | independent error callback |
| ADXPC_SetupFileSystem / ADXM_SetupThrd / mwPlyInitSfdFx | no global setup required |
| mwPlyFinishSfdFx / ADXM_Finish | idempotent independent shutdown |
| ADXPC_NoOpShutdownCallback | no-op |

## FFmpeg dependency and build

- **Source**: `dependencies/ffmpeg` is a Git submodule of [Draiget/ffmpeg-mirror](https://github.com/Draiget/ffmpeg-mirror): the official FFmpeg 7.1.3 release tarball, unmodified, plus a `faf/` folder with a CMake build. `cmake/FafDependencies.cmake` initialises it with the other submodules.
- **Build**: `src/CMakeLists.txt` adds `dependencies/ffmpeg/faf` and links `FFmpeg::FFmpeg`. avutil, swresample, swscale, avcodec and avformat are compiled with clang-cl for the target architecture as static libraries, with FFmpeg's own flags, the engine's `faf_codegen` rules and the static C runtime, and linked into `main_x64.exe` / `main.exe`.
- **No binaries**: there are no FFmpeg DLLs, import libraries or prebuilt packages; nothing is downloaded or staged next to the executable, and the executables import no FFmpeg DLL.
- **Generated configuration**: `faf/x64/` and `faf/x86/` hold what FFmpeg's `configure` generated for the configuration below (`config.h`, `config_components.h`, `libavutil/avconfig.h`, the component lists) and `sources.cmake`, the per-library source lists evaluated from FFmpeg's own Makefiles. `faf/generate.sh` in the submodule regenerates them; the mirror's README explains how.
- **License**: LGPL v2.1 or later; nothing from `--enable-gpl` or `--enable-nonfree` is enabled. The engine links FFmpeg statically, which LGPL v2.1 section 6 allows because faf-re's complete source and the FFmpeg source in the submodule let anyone relink the engine against a modified FFmpeg. Distributing a build requires FFmpeg's notices; see [FFmpeg's license checklist](https://ffmpeg.org/legal.html).
- **MSVC project**: `src/main.vcxproj` (and `build.ps1`, which builds it) still links a prebuilt shared FFmpeg from `FafFfmpegRoot` and stages its DLLs. Its default, `dependencies/ffmpeg/$(Platform)`, no longer exists, so that project needs `/p:FafFfmpegRoot=...` pointing at such a package; the CMake build needs none.

The configuration (`faf/generate.sh` adds the clang-cl toolchain options, `--target-os=win32`, the architecture and `--disable-debug`):

```sh
--disable-x86asm --disable-everything --disable-programs --disable-doc --disable-network
--enable-static --disable-shared
--enable-avcodec --enable-avformat --enable-avutil --enable-swscale --enable-swresample
--enable-decoder=mpeg1video,mpeg2video,adpcm_adx,mp1,mp2,mp3
--enable-parser=mpegvideo,mpegaudio,adx
--enable-demuxer=mpegps,mpegvideo,adx,mp3
--enable-protocol=file
```

The elementary video/audio demuxers are needed for FFmpeg's stream probing even though the player opens the MPEG-PS demuxer. The component set is the one the former shared build had, with `--enable-static --disable-shared` in place of `--enable-shared --disable-static`.

Build the engine as described in the [README](../README.md#build):

```bat
cmake --preset clang-x64-release && cmake --build --preset clang-x64-release
```

The diagnostic and test project is [tools/sfd-inspect](../tools/sfd-inspect/README.md): `main.cpp` supports `--metadata`, `--decode`, `--play` and `--play-sound` on one or more files, and `parser-tests.cpp` is a separate executable for malformed-input and fuzz tests. No commercial assets are copied into the repository.

## Validation

### Builds

Full engine builds with the VS 2022 developer shell and locally built LGPL FFmpeg 7.1.3 shared libraries:

| Configuration | Result |
|---|---|
| Debug / Win32 | Passed; CMovie layout assertions compiled |
| Debug / x64 | Passed with the branch's existing x64 layout-assert policy |
| Release / Win32 | Passed |
| Release / x64 | Passed |

- **Warnings**: the project links with `/FORCE` (LNK4088); its EDITANDCONTINUE/CRT-section warnings and the missing optional `pwsh.exe` post-build message predate the SFD work. No extra warnings were disabled; FFmpeg headers are treated as external headers.
- **Linker**: all four linker command logs contain the five FFmpeg libraries and no old decoder/middleware objects; no build log has unresolved-symbol diagnostics. There is one active backend, with no fallback, compile-time selector, hardcoded-address call or archive include/link path.

### Backend tests

The CMake/CTest suites passed 7/7 in Debug/Win32 and Release/x64, covering:

- Exact signature, relocated headers, truncated descriptors, invalid counts, malformed fields, effect mapping and 20,000 deterministic fuzz cases.
- Complete MPEG video decoding and opaque BGRA validation; complete embedded ADX decode and resampler drain.
- Texture copying with padded destination pitch and canaries.
- First frame while paused, timed playback, pause freeze, resume and volume.
- Ring-buffer wrap, restart, EOF (including embedded audio drain), repeated reopen/dispose, missing-file rejection and idempotent shutdown.
- Embedded-audio file with no sound device (steady-clock playback).
- Graceful rejection of the observed special-composition file.

Timed playback checks bound clock drift to 250 ms at the sampled point and freeze video PTS during pause. Consumed DirectSound ring slots are cleared to silence, so an underrun cannot replay PCM from an earlier wrap. Standalone Win32 and x64 diagnostics both passed normal embedded DirectSound playback.

**ASan**: parser ASan tests passed. The x64 Debug ASan suite passed parser, full video/audio decode and no-sound playback, and the final rerun passed 6/6 with the physical DirectSound test excluded. That test crashes inside Windows `DSOUND.dll` under ASan: a minimal program using only DirectSound creation, a silent secondary buffer and Play hits the same null read at `DSOUND.dll+0x69362` without FAF or FFmpeg, and disabling the optional RTL heap hook did not help. This is an environment/sanitizer limitation, not a passing sanitized audio test; ordinary x64 DirectSound tests pass. FFmpeg DLLs were not sanitizer-instrumented.

### Game movies

Full decode of installed game movies (kept outside the repository):

| File | Dimensions | Frames decoded | End PTS (seconds) |
|---|---:|---:|---:|
| main_menu.sfd | 1824x1024 | 2336 | 77.8667 |
| UEF_load.sfd | 1280x1024 | 179 | 5.96667 |
| fmv_scx_intro.sfd | 1600x672 | 6211 | 207.033 |
| credits_generic.sfd | 1824x1024 | 7192 | 239.733 |
| FMV_SCX_Outro.sfd | 1600x672 | 1770 | 59.0 |
| Abasi.sfd | 192x192 | 150 | 5.00598 |
| e3_demo_cut.sfd | 1280x720 | 362 | 12.0797 video / 12.0847 audio |

- **Counts**: decoded frame counts match the SFD metadata. e3_demo_cut supplies 579,808 stereo samples at 48 kHz. Abasi and e3_demo_cut passed the timed player/compatibility tests.
- **MPEG-2**: all movies above are MPEG-1; a synthetic 2-second MPEG-2/MP2 Program Stream with a metadata pack also decoded: 50 frames and 96,549 resampled stereo samples from 44.1 kHz mono, video/audio ending at 2.01091/2.01145 s.
- **Census**: of the 1004 installed SFD files, 1002 are ordinary video-only, one is ordinary with embedded ADX audio (e3_demo_cut.sfd), and one is effect 1 / mode 33 (FMV_loading02.sfd), which fails gracefully with filename, composition mode, dimensions, colour, picture and flags in the diagnostic. Modes 81/97 were not observed; their synthetic parser mappings are tested, not their rendering.
- **Engine smoke test**: Debug/Win32 with `/nosound` reached `OpenMovie /movies/thqlogo.sfd`, `Preparing movie` and `Playing movie` with the resolved installed path. Release/Win32 with sound also initialized the XACT wavebanks and reached the same calls. Both were stopped after observation, so this proves startup and movie API integration, not a full interactive visual test.

## Known limitations

- **Special composition/alpha rendering is unsupported**, including mode 33 (FMV_loading02.sfd); its metadata and CMovie's existing height branch are kept.
- **Subtitles and private data**: embedded subtitles, CRITAGS/AINF semantics and other private/user data are unconfirmed; there is no guessed subtitle or effect implementation.
- **Out of profile**: multiple video streams and transport streams.
- **Not verified**: a complete interactive campaign sequence, visible pixel comparison, D3D device reset, external XACT sound/voice cue combinations and extended audible drift. Their existing callers are unchanged. Repeated-open tests show working cleanup paths but are not a leak-profiler result.

## Migration record

- **Archive**: the removed middleware code is archived in `../faf-sofdec-archive/`, outside the repository and referenced by no build path. Its ARCHIVE_README.md records the original HEAD, branch and clean working-tree status; it holds 39 SHA-256-verified source/project/README copies with relative paths, working-tree and staged binary diffs, status.txt, SHA256.json and a verified complete-history Git bundle.
- **Removed** (30 files, history kept in Git): the 21-file `cri/sofdec/` tree, seven `moho/audio/Sofdec{Adx,M2a,Mpa}*Runtime.cpp` implementations and `moho/movie/MPVDecoder.{h,cpp}`. A source/project search for `cri/sofdec`, `SofdecMpvRuntime`, `SofdecSfdRuntime`, `SofdecAdxRuntime`, `SofdecSfxRuntime` and `MPVDecoder` finds no remaining dependencies.
- **Added**: the five `src/moho/movie/sfd/` units, this document and the `tools/sfd-inspect` CMake project.
- **Changed**: `SofdecRuntime.h/.cpp` (legacy-name adapters); `CMovie.cpp` (duplicate legacy declarations removed, comments updated, control flow kept); `StartupHelpers.cpp` (movie volume sent to sinks, players shut down before the DirectSound device is released); `main.vcxproj/.filters` (middleware inputs replaced, configurable FFmpeg paths, explicit DLL staging); `README.md` and `.gitignore`.
- **Untouched**: `CMovie.h` is byte-for-byte unchanged, as are the IMovie/CMovie virtual interfaces, field order, Win32 layout assertions and the Lua/XACT movie code. New code carries no fabricated original-address annotations.

References: [FFmpeg send/receive API](https://ffmpeg.org/doxygen/7.1/group__lavc__encdec.html), [libswresample API](https://ffmpeg.org/doxygen/7.0/group__lswr.html), [upstream MPEG-PS demuxer](https://github.com/FFmpeg/FFmpeg/blob/n7.1.3/libavformat/mpeg.c).
