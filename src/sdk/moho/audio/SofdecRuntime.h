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
#pragma once
#include <cstdint>
struct IDirectSound;
namespace moho
{
  struct MwsfdPlaybackStateSubobj;
  // Compatibility structures used only by FAF source, not CRI object layouts.
  struct MwsfdHdrInf
  {
    std::int32_t playable{}, ftype{}, width{}, height{}, fps{}, frameCount{}, compoMode{};
    std::int32_t videoStreamCount{}, audioStreamCount{}, audioSampleRate{}, audioChannelCount{};
  };
  struct MwsfcreCreateParams
  {
    std::int32_t ftype{}, maxBitsPerSecond{}, maxWidth{}, maxHeight{}, framePoolWork{}, maxStreams{};
    void* work{};
    std::int32_t workSize{}, bufferFormat{}, outerFramePoolNum{};
  };
  struct MwsfdFrameInfo
  {
    const void* bufferAddress{};
  };
  enum MwsfdDecSvr : std::int32_t
  {
    MWSFD_DEC_SVR_MAIN = 1
  };
  struct MwsfdInitPrm
  {
    float vhz{};
    std::int32_t disp_cycle{}, disp_latency{};
    MwsfdDecSvr dec_svr{MWSFD_DEC_SVR_MAIN};
  };
  inline constexpr int kMwsfcreStreamMps = 1, kMwsfcreStreamVideoOnly = 3;
  using AdxmErrorCallback = int(__cdecl*)(std::uint32_t, const char*);
} // namespace moho
void mwPlyGetHdrInf(const char*, std::int32_t, moho::MwsfdHdrInf*);
std::int32_t mwPlyCalcWorkCprmSfd(const moho::MwsfcreCreateParams*);
moho::MwsfdPlaybackStateSubobj* mwPlyCreateSofdec(const moho::MwsfcreCreateParams*);
void mwPlyDestroy(moho::MwsfdPlaybackStateSubobj*);
void mwPlySetFrmSync(moho::MwsfdPlaybackStateSubobj*, std::int32_t);
std::int32_t mwPlyPause(moho::MwsfdPlaybackStateSubobj*, std::int32_t);
std::int32_t mwPlyIsPause(moho::MwsfdPlaybackStateSubobj*);
void mwPlyStartFname(moho::MwsfdPlaybackStateSubobj*, const char*);
std::int32_t mwPlyGetStat(moho::MwsfdPlaybackStateSubobj*);
moho::MwsfdFrameInfo* mwPlyGetCurFrm(moho::MwsfdPlaybackStateSubobj*, moho::MwsfdFrameInfo*);
void mwPlyRelCurFrm(moho::MwsfdPlaybackStateSubobj*);
std::int32_t mwPlyFxGetCompoMode(moho::MwsfdPlaybackStateSubobj*);
void mwPlyFxSetOutBufSize(moho::MwsfdPlaybackStateSubobj*, std::int32_t, std::int32_t);
void mwPlyFxCnvFrmARGB8888(moho::MwsfdPlaybackStateSubobj*, const moho::MwsfdFrameInfo*, void*);
std::int32_t mwPlyGetSubtitle(moho::MwsfdPlaybackStateSubobj*, char*, std::int32_t, std::int32_t*);
std::int32_t mwPlyGetPlyInf(moho::MwsfdPlaybackStateSubobj*, std::int32_t*);
std::int32_t ADXM_WaitVsync();
std::int32_t ADXM_ExecMain();
void ADXPC_SetupSoundDirectSound8(IDirectSound*);
void ADXPC_SetupFileSystem(void*);
void ADXM_SetupThrd(void*);
void ADXM_SetCbErr(moho::AdxmErrorCallback, std::int32_t);
void mwPlyInitSfdFx(moho::MwsfdInitPrm*);
void mwPlyFinishSfdFx();
void ADXM_Finish();
void ADXPC_NoOpShutdownCallback();
