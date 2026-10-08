# FAF SFD compatibility profile

This document describes the SFD compatibility profile required by
Supreme Commander: Forged Alliance.

The active SFD player is an independent implementation. It is not CRI
Sofdec, does not contain CRI SDK code, and does not attempt to reproduce
the internal architecture of the original middleware.

Legacy mwPly*/ADXM_* names retained elsewhere in the engine are
compatibility entry points only. Each is a legacy compatibility name,
not the original CRI implementation. This is not a formal clean-room claim.

## Container and implementation

FAF uses MPEG Program Stream style SFD. Stream IDs are `BD` private_stream_1,
`BE` padding, `BF` private_stream_2 metadata, `C0..DF` audio and `E0..EF` video.
The supported profile contains one MPEG-1/2 video stream, with optional ADX or
MPEG audio. Multiple video streams and transport streams are not supported.
`CMovie`/`MOV_GetDuration` compatibility types use 1 for video+audio and 3 for
video-only. These are FAF compatibility constants, not middleware objects.

FFmpeg libavformat performs MPEG-PS demuxing; libavcodec decodes MPEG-1/2 and
ADX/MP1/MP2/MP3. libswscale produces BGRA (opaque alpha), and libswresample
converts audio to interleaved S16 stereo at 48 kHz. FFmpeg objects and ownership
never cross the decoder implementation boundary. A player worker fills bounded
queues independently of rendering. Audio device playback position is the master
clock when embedded audio is playing; otherwise a steady clock is used.
Pausing freezes both; reopening reconstructs decoder, queues, sink and PTS origin.
EOF drains both codecs and the resampler, and waits for the final displayed
frame duration and submitted audio before reporting ended.

The DirectSound device is owned by CMovieManager. Each audio movie uses its own
secondary buffer, with wrap tracking and volume control. `/nosound` skips audio
decode and uses the steady clock. XACT movie sound/voice cues and Lua movie
semantics are independent and unchanged. Manager volume updates reach active
sinks. Shutdown closes players before the device is released and is idempotent.

## Header fields

The parser scans at most the initial 64 KiB, including but not limited to bases
0x800 and 0x1000, for the exact 24-byte `SofdecStream            ` identifier
at base+0x20. It reads only bounded byte spans, never casts input to structures.
The legacy engine supplies a 5000-byte probe; only descriptors present in that
probe can be accepted. The file-open path probes 64 KiB.

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

The table starts at 0x180 with up to 26 entries of 0x40 bytes. Counts must agree,
all used descriptors must fit the probe, and declared sizes must bound the table.
Stream ID is at descriptor+24. Video fields are codec +25, LE16 bitrate +26,
packed dimensions +28..30, frame-rate code +31, feature-info +32, colour +33,
picture +34, flags +35, expand +36, GOP N/M +37/+38, effect +39.
Width = `(e[28] << 4) | (e[29] >> 4)`; height = `((e[29] & 15) << 8) | e[30]`.
Frame-rate codes 1..8 mean 24000/1001, 24, 25, 30000/1001, 30, 50, 60000/1001,
60. The compatibility `fps` field is integer FPS times 1000 (fraction truncated).

The inspected ADX descriptor in e3_demo_cut.sfd has codec 0 at +25, channel count
at +27 and LE32 rate at +28 (2 channels, 48000 Hz). Other audio descriptor forms
leave those optional header fields unknown; FFmpeg discovers the actual stream.

## Composition and private metadata

Effects 1, 3 and 6 map to compatibility modes 33 (0x21), 81 (0x51) and 97 (0x61).
CMovie's existing mode-33 height handling remains intact. Special composition,
nonstandard colour and picture types are currently rejected at player open with
filename, mode, dimensions and descriptor details, rather than rendering guessed
alpha. Header parsing preserves their metadata for diagnostics.

A census of the installed 1004 SFD assets found 1002 ordinary video-only files,
one ordinary file with embedded audio (e3_demo_cut.sfd), and one mode-33 file
(FMV_loading02.sfd). Mode 33 rendering remains unsupported. No modes 81/97 were
observed. Their synthetic parser mappings are tested, not their rendering.

The metadata scanner records bounded private_stream_2 packet candidates in the
probe; these are diagnostics, not an additional MPEG demuxer. Debug builds log
candidate lengths. CRITAGS, AINF and timed subtitle/user-data semantics remain
unconfirmed; no parser is invented. Subtitle compatibility clears output and
returns zero. The inspection tool prints private candidates and stream IDs.

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

Supply FFmpeg 7.1-compatible development headers, MSVC import libraries and DLLs
for **each** target architecture. Tested dependency version: FFmpeg 7.1.3.
`FafFfmpegRoot` defaults to `dependencies/ffmpeg/$(Platform)` and may be overridden
with `/p:FafFfmpegRoot=...`. The directory must contain `include/libav*`,
`include/libsw*`, and `lib/{avformat,avcodec,avutil,swscale,swresample}.lib`.
Place corresponding DLLs in `bin`; the `StageFafFfmpeg` MSBuild target copies them
to `$(OutDir)` after successful build, and to the existing Win32 `$(FafRunDir)`
used by the engine post-build staging step. x64 DLLs remain in the x64 output
directory so they cannot overwrite the Win32 run-directory dependencies.
`FafStageToRunDir` defaults to true on Win32 and false on x64. To stage an
x64 executable and DLLs, set `/p:FafStageToRunDir=true` and
`/p:FafRunDir=...` to a separate, existing x64 run directory configured with
the game bootstrap/data paths. Never stage both architectures into one directory.
When running from a different directory,
copy the same DLL set next to that executable. Never mix x86 and x64 DLLs.
Third-party binaries are ignored by Git and are not distributed in this change.

Use an LGPL-compatible shared build, without `--enable-gpl` or `--enable-nonfree`.
One minimal upstream configure feature set is:

```sh
--disable-everything --disable-programs --disable-doc --disable-network \
--enable-shared --disable-static \
--enable-avformat --enable-avcodec --enable-avutil --enable-swscale --enable-swresample \
--enable-decoder=mpeg1video,mpeg2video,adpcm_adx,mp1,mp2,mp3 \
--enable-parser=mpegvideo,mpegaudio,adx \
--enable-demuxer=mpegps,mpegvideo,adx,mp3 --enable-protocol=file
```

The elementary-video/audio demuxers are needed for FFmpeg's stream probing even
though the player opens the MPEG-PS demuxer. Add the compiler, architecture,
Windows target and installation prefix options for your toolchain. A Windows
resource compiler must target the same architecture. If using a MinGW build,
MSVC import libraries can be generated from the installed .def files using
`lib /def:avcodec-61.def /name:avcodec-61.dll /machine:X86 /out:avcodec.lib`
(and corresponding library/version names; use X64 for x64). Shared-library
redistribution must include the applicable FFmpeg notices and corresponding
source/build information; consult [FFmpeg's license checklist](https://ffmpeg.org/legal.html).

Initialize the Visual Studio developer shell and run:

```bat
msbuild src/sdk/main.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32
```

Repeat for Release and x64 as supported by the rest of the engine. See
[validation report](FAF_SFD_VALIDATION.md) for actual results and limitations.

The diagnostic sources in `tools/sfd-inspect` use the new parser and backend.
`main.cpp` supports `--metadata`, `--decode`, `--play`, and `--play-sound` with
one or more files. Playback mode checks pitch padding, frozen frames, resume,
restart, repeated opens, missing-file handling and EOF for short fixtures.
`parser-tests.cpp` is a separate executable for malformed-input and fuzz tests.
No commercial assets are copied into the repository.

References: [FFmpeg send/receive API](https://ffmpeg.org/doxygen/7.1/group__lavc__encdec.html),
[libswresample API](https://ffmpeg.org/doxygen/7.0/group__lswr.html),
[upstream MPEG-PS demuxer](https://github.com/FFmpeg/FFmpeg/blob/n7.1.3/libavformat/mpeg.c).
