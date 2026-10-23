// IMPORTANT:
//
// This file does NOT contain or expose the original CRI Sofdec runtime.
//
// The mwPly*, ADXM_*, ADXPC_* and related names below are legacy
// compatibility entry points retained so that recovered Forged Alliance
// engine code does not need an unnecessary large-scale rewrite.
//
// Their implementation is independent and lives under
// moho/movie/sfd/. It uses FFmpeg and FAF-specific SFD parsing.
//
// No CRI SDK source or reconstructed CRI implementation is compiled or
// linked by this project.
// Each retained symbol is a legacy compatibility name, not the original CRI implementation.
#include "SofdecRuntime.h"
#include "moho/movie/sfd/IndependentSfdBackend.h"
#include "moho/movie/sfd/SfdHeaderParser.h"
#include <algorithm>
#include <cstring>
#include <exception>
#include <memory>
#include <span>

namespace moho
{
  struct MwsfdPlaybackStateSubobj
  {
    sfd::Player player;
    int outputPitch{}, outputHeight{};
    std::shared_ptr<sfd::DecodedVideoFrame> borrowedFrame;
  };
} // namespace moho
void mwPlyGetHdrInf(
  const char* bytes,
  std::int32_t size,
  moho::MwsfdHdrInf* out
)
{
  if (!out)
    return;
  *out = {};
  if (!bytes || size <= 0)
    return;
  moho::sfd::HeaderInfo header;
  if (!moho::sfd::ParseSfdHeader(std::as_bytes(std::span(bytes, static_cast<std::size_t>(size))), header))
    return;
  out->playable = 1;
  out->ftype = header.audioStreams ? moho::kMwsfcreStreamMps : moho::kMwsfcreStreamVideoOnly;
  out->width = header.width;
  out->height = header.height;
  out->fps = header.fpsMilli;
  out->frameCount = static_cast<std::int32_t>(header.frameCount);
  out->compoMode = header.compositionMode;
  out->videoStreamCount = header.videoStreams;
  out->audioStreamCount = header.audioStreams;
  out->audioSampleRate = header.audioSampleRate;
  out->audioChannelCount = header.audioChannels;
}
std::int32_t mwPlyCalcWorkCprmSfd(
  const moho::MwsfcreCreateParams*
)
{
  // Positive compatibility allocation preserves CMovie's existing work-buffer
  // lifetime and layout. The independent backend never uses the supplied arena.
  return 64;
}
moho::MwsfdPlaybackStateSubobj* mwPlyCreateSofdec(
  const moho::MwsfcreCreateParams* params
)
{
  if (!params)
    return nullptr;
  try {
    return new moho::MwsfdPlaybackStateSubobj;
  } catch (const std::exception& error) {
    moho::sfd::ReportError(error.what());
    return nullptr;
  }
}
void mwPlyDestroy(
  moho::MwsfdPlaybackStateSubobj* p
)
{
  delete p;
}
void mwPlySetFrmSync(
  moho::MwsfdPlaybackStateSubobj*,
  std::int32_t
)
{ /* Player owns PTS scheduling. */
}
std::int32_t mwPlyPause(
  moho::MwsfdPlaybackStateSubobj* p,
  std::int32_t pause
)
{
  return p && p->player.Pause(pause != 0);
}
std::int32_t mwPlyIsPause(
  moho::MwsfdPlaybackStateSubobj* p
)
{
  return !p || p->player.IsPaused();
}
void mwPlyStartFname(
  moho::MwsfdPlaybackStateSubobj* p,
  const char* path
)
{
  if (p) {
    p->borrowedFrame.reset();
    p->player.Open(path);
  }
}
std::int32_t mwPlyGetStat(
  moho::MwsfdPlaybackStateSubobj* p
)
{
  return p ? p->player.Status() : 4;
}
moho::MwsfdFrameInfo* mwPlyGetCurFrm(
  moho::MwsfdPlaybackStateSubobj* p,
  moho::MwsfdFrameInfo* out
)
{
  if (!out)
    return nullptr;
  out->bufferAddress = nullptr;
  if (p) {
    p->borrowedFrame = p->player.CurrentFrame();
    out->bufferAddress = p->borrowedFrame.get();
  }
  return out;
}
void mwPlyRelCurFrm(
  moho::MwsfdPlaybackStateSubobj* p
)
{
  if (p)
    p->borrowedFrame.reset();
}
std::int32_t mwPlyFxGetCompoMode(
  moho::MwsfdPlaybackStateSubobj* p
)
{
  return p ? p->player.CompositionMode() : 0;
}
void mwPlyFxSetOutBufSize(
  moho::MwsfdPlaybackStateSubobj* p,
  std::int32_t pitch,
  std::int32_t height
)
{
  if (p) {
    p->outputPitch = pitch;
    p->outputHeight = height;
  }
}
void mwPlyFxCnvFrmARGB8888(
  moho::MwsfdPlaybackStateSubobj* p,
  const moho::MwsfdFrameInfo* info,
  void* destination
)
{
  if (!p || !info || !destination || !p->borrowedFrame || info->bufferAddress != p->borrowedFrame.get())
    return;
  const auto& frame = *p->borrowedFrame;
  if (p->outputPitch < frame.pitch || p->outputHeight < frame.height) {
    moho::sfd::ReportError("FAF SFD texture destination is smaller than decoded frame");
    return;
  }
  auto* bytes = static_cast<std::byte*>(destination);
  for (int y = 0; y < frame.height; ++y)
    std::memcpy(
      bytes + static_cast<std::size_t>(y) * p->outputPitch,
      frame.bgra.data() + static_cast<std::size_t>(y) * frame.pitch,
      frame.pitch
    );
}
std::int32_t mwPlyGetSubtitle(
  moho::MwsfdPlaybackStateSubobj*,
  char* text,
  std::int32_t size,
  std::int32_t* stats
)
{
  if (text && size > 0)
    text[0] = 0;
  if (stats)
    std::fill_n(stats, 5, 0);
  // TODO: identify timed subtitle/user-data framing and encoding from a FAF
  // asset that uses it. No confirmed example exists in the inspected corpus.
  return 0;
}
std::int32_t mwPlyGetPlyInf(
  moho::MwsfdPlaybackStateSubobj*,
  std::int32_t* out
)
{
  if (out)
    std::fill_n(out, 5, 0);
  return 1;
}
std::int32_t ADXM_WaitVsync()
{
  return 1;
} // Independent workers supply cadence; never sleep the render thread.
std::int32_t ADXM_ExecMain()
{
  return 1;
}
void ADXPC_SetupSoundDirectSound8(
  IDirectSound* device
)
{
  moho::sfd::SetSoundDevice(device);
}
void ADXPC_SetupFileSystem(
  void*
)
{} // CMovie resolves paths before opening.
void ADXM_SetupThrd(
  void*
)
{} // Each player owns its worker lifetime.
void ADXM_SetCbErr(
  moho::AdxmErrorCallback callback,
  std::int32_t parameter
)
{
  moho::sfd::SetErrorCallback(callback, static_cast<std::uint32_t>(parameter));
}
void mwPlyInitSfdFx(
  moho::MwsfdInitPrm*
)
{} // No global decoder resources.
void mwPlyFinishSfdFx()
{
  moho::sfd::Shutdown();
}
void ADXM_Finish()
{
  moho::sfd::Shutdown();
}
void ADXPC_NoOpShutdownCallback() {}
