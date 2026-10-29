// Engine addition (dedicated-server plan WPL.4): mwPlyGetHdrInf, moved unchanged
// out of moho/audio/SofdecRuntime.cpp (see the notice there: a compatibility
// name over moho/movie/sfd, not CRI code). It only parses an SFD header, which
// MOV_GetDuration (the core Lua set's GetMovieDuration, so the sim Lua state's
// too) needs on a headless build as well; the player stays with the client.
#include "moho/audio/SofdecRuntime.h"
#include "moho/movie/sfd/SfdHeaderParser.h"

#include <span>

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
