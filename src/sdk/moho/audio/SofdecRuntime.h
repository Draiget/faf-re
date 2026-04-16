#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

struct IDirectSound;
struct IDirectSoundBuffer;

#ifndef FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_ENFORCE_STRICT_LAYOUT_ASSERTS 0
#endif

#ifndef FAF_RUNTIME_LAYOUT_ASSERT
#if FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_RUNTIME_LAYOUT_ASSERT(...) static_assert(__VA_ARGS__)
#else
#define FAF_RUNTIME_LAYOUT_ASSERT(...)
#endif
#endif
namespace moho
{
  enum MwsfdDecSvr : std::int32_t
  {
    MWSFD_DEC_SVR_MAIN = 1
  };

  struct MwsfdInitPrm
  {
    float vhz = 0.0f;
    std::int32_t disp_cycle = 0;
    std::int32_t disp_latency = 0;
    MwsfdDecSvr dec_svr = MWSFD_DEC_SVR_MAIN;
    std::int32_t rsv[4]{};
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdInitPrm, vhz) == 0x0, "MwsfdInitPrm::vhz offset must be 0x0");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdInitPrm, disp_cycle) == 0x4, "MwsfdInitPrm::disp_cycle offset must be 0x4");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdInitPrm, disp_latency) == 0x8,
    "MwsfdInitPrm::disp_latency offset must be 0x8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdInitPrm, dec_svr) == 0xC, "MwsfdInitPrm::dec_svr offset must be 0xC");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdInitPrm, rsv) == 0x10, "MwsfdInitPrm::rsv offset must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfdInitPrm) == 0x20, "MwsfdInitPrm size must be 0x20");

  /**
   * Runtime SFD init parameter lane used by `mwPlySfdInit`.
   */
  struct MwsfdInitSfdParams
  {
    std::uintptr_t callbacks = 0; // +0x00
    std::int32_t version = 0;     // +0x04
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdInitSfdParams, callbacks) == 0x00,
    "MwsfdInitSfdParams::callbacks offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdInitSfdParams, version) == 0x04,
    "MwsfdInitSfdParams::version offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfdInitSfdParams) == 0x08, "MwsfdInitSfdParams size must be 0x08");

  /**
   * Decode-server callback signature lane stored in `MwsfdLibWork`.
   */
  using MwsfdDecodeServerCallback = std::int32_t(__cdecl*)(std::int32_t callbackContext);

  constexpr std::int32_t kMwsfdDecodeServerSlotCount = 32;

  /**
   * Partial runtime owner for global MWSFD library work lane.
   *
   * Evidence:
   * - `FUN_00AC92D0/00AC9380/00AC9470/00AC96A0/00AC96B0` initialize and read
   *   startup/seek/error lanes in the `+0x04..+0x68` region.
   * - `FUN_00AD93D0/00AD93F0/00AD9410` read callback/context lanes at
   *   `+0x40..+0x54`.
   * - `FUN_00AD9340` gates decode-server execution via signal lane `+0x58` and
   *   iterates 32 playback lanes from `+0x6C` with 0x2A8 stride.
   */
  struct MwsfdLibWork
  {
    std::int32_t mUnknown00 = 0;            // +0x00
    float displayRefreshHz = 0.0f;          // +0x04
    std::int32_t displayCycle = 0;          // +0x08
    std::int32_t displayLatency = 0;        // +0x0C
    std::int32_t decodeServerSelection = 0; // +0x10
    std::uint8_t mUnknown14[0x10]{};
    std::int32_t requestServerBridgeFlag = 0; // +0x24
    std::uint8_t mUnknown28[0x0C]{};
    std::int32_t seekFlag = 0;                                    // +0x34
    std::int32_t defaultConditionInitialized = 0;                 // +0x38
    std::int32_t defaultConditionReserved = 0;                    // +0x3C
    MwsfdDecodeServerCallback decodeServerTopCallback = nullptr;  // +0x40
    std::int32_t decodeServerTopContext = 0;                      // +0x44
    MwsfdDecodeServerCallback decodeServerEndCallback = nullptr;  // +0x48
    std::int32_t decodeServerEndContext = 0;                      // +0x4C
    MwsfdDecodeServerCallback decodeServerRestCallback = nullptr; // +0x50
    std::int32_t decodeServerRestContext = 0;                     // +0x54
    std::int32_t decodeServerSignal = 0;                          // +0x58
    std::int32_t initLatch = 0;                                   // +0x5C
    std::uint8_t mUnknown60[0x08]{};
    std::int32_t lastErrorCode = 0; // +0x68
    std::uint8_t playbackSlotsRaw[kMwsfdDecodeServerSlotCount * 0x2A8]{};
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, displayRefreshHz) == 0x04,
    "MwsfdLibWork::displayRefreshHz offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, displayCycle) == 0x08,
    "MwsfdLibWork::displayCycle offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, displayLatency) == 0x0C,
    "MwsfdLibWork::displayLatency offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerSelection) == 0x10,
    "MwsfdLibWork::decodeServerSelection offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, requestServerBridgeFlag) == 0x24,
    "MwsfdLibWork::requestServerBridgeFlag offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdLibWork, seekFlag) == 0x34, "MwsfdLibWork::seekFlag offset must be 0x34");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, defaultConditionInitialized) == 0x38,
    "MwsfdLibWork::defaultConditionInitialized offset must be 0x38"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, defaultConditionReserved) == 0x3C,
    "MwsfdLibWork::defaultConditionReserved offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerTopCallback) == 0x40,
    "MwsfdLibWork::decodeServerTopCallback offset must be 0x40"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerTopContext) == 0x44,
    "MwsfdLibWork::decodeServerTopContext offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerEndCallback) == 0x48,
    "MwsfdLibWork::decodeServerEndCallback offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerEndContext) == 0x4C,
    "MwsfdLibWork::decodeServerEndContext offset must be 0x4C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerRestCallback) == 0x50,
    "MwsfdLibWork::decodeServerRestCallback offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerRestContext) == 0x54,
    "MwsfdLibWork::decodeServerRestContext offset must be 0x54"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, decodeServerSignal) == 0x58,
    "MwsfdLibWork::decodeServerSignal offset must be 0x58"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdLibWork, initLatch) == 0x5C, "MwsfdLibWork::initLatch offset must be 0x5C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, lastErrorCode) == 0x68,
    "MwsfdLibWork::lastErrorCode offset must be 0x68"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdLibWork, playbackSlotsRaw) == 0x6C,
    "MwsfdLibWork::playbackSlotsRaw offset must be 0x6C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfdLibWork) == 0x556C, "MwsfdLibWork size must be 0x556C");

  /**
   * SFX callback conversion state lane.
   */
  struct SfxCallbackFrameContext
  {
    std::int32_t reserved00 = 0;      // +0x00
    std::int32_t compositionCode = 0; // +0x04
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfxCallbackFrameContext, compositionCode) == 0x04,
    "SfxCallbackFrameContext::compositionCode offset must be 0x04"
  );

  /**
   * SFX stream info lane touched by callback frame conversion helpers.
   */
  struct SfxStreamState
  {
    std::uint8_t mUnknown00[0x90]{};
    std::int32_t fieldTransformMode = 0; // +0x90
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfxStreamState, fieldTransformMode) == 0x90,
    "SfxStreamState::fieldTransformMode offset must be 0x90"
  );

  using AdxmErrorCallback = int(__cdecl*)(std::uint32_t errorCode, const char* errorText);
  using AdxmMwIdleSleepCallback = std::int32_t(__cdecl*)(std::int32_t callbackParam);

  /**
   * Startup parameter block consumed by `adxm_setup_thrd`.
   *
   * Evidence:
   * - `FUN_00B06C10` copies `0x18` bytes when non-null.
   */
  struct AdxmThreadStartupParams
  {
    std::int32_t nPriority = 0;
    std::int32_t fsPriority = 0;
    std::int32_t vsyncPriority = 0;
    std::int32_t mwidlePriority = 0;
    std::int32_t threadCount = 0;
    std::int32_t reserved = 0;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(AdxmThreadStartupParams) == 0x18, "AdxmThreadStartupParams size must be 0x18");

  /**
   * Sofdec tag-window pair used by `mwsftag_*` search helpers.
   * Layout is one pointer + one byte-count lane.
   */
  struct MwsfTagWindow
  {
    std::int8_t* data = nullptr;
    std::int32_t size = 0;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfTagWindow, data) == 0x0, "MwsfTagWindow::data offset must be 0x0");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfTagWindow, size) == 0x4, "MwsfTagWindow::size offset must be 0x4");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfTagWindow) == 0x8, "MwsfTagWindow size must be 0x8");

  /**
   * Partial runtime view for Sofdec SFD work-control subobject used by handle
   * validation helper lanes.
   *
   * Evidence:
   * - `FUN_00AD8E90` tests non-zero state at offset `+0x48`.
   */
  struct SofdecSfdWorkctrlSubobj
  {
    std::uint8_t mUnknown00[0x48]{};
    std::int32_t handleState = 0;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSfdWorkctrlSubobj, handleState) == 0x48,
    "SofdecSfdWorkctrlSubobj::handleState offset must be 0x48"
  );

  /**
   * Partial create-parameter view consumed by SFPLY create/validation lanes.
   */
  struct SfplyCreateParams
  {
    std::uint8_t mUnknown00[0x04]{};
    void* workControlBuffer = nullptr; // +0x04
    std::uint8_t mUnknown08[0x38]{};
    std::uint32_t workControlSizeBytes = 0; // +0x40
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyCreateParams, workControlBuffer) == 0x04,
    "SfplyCreateParams::workControlBuffer offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyCreateParams, workControlSizeBytes) == 0x40,
    "SfplyCreateParams::workControlSizeBytes offset must be 0x40"
  );

  /**
   * SFPLY flow-counter lane used by playback-info snapshots.
   */
  struct SfplyFlowCount
  {
    std::int32_t producedBytes = 0;   // +0x00
    std::int32_t consumedBytes = 0;   // +0x04
    std::int32_t producedPackets = 0; // +0x08
    std::int32_t consumedPackets = 0; // +0x0C
    std::int32_t producedFrames = 0;  // +0x10
    std::int32_t consumedFrames = 0;  // +0x14
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, producedBytes) == 0x00,
    "SfplyFlowCount::producedBytes offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, consumedBytes) == 0x04,
    "SfplyFlowCount::consumedBytes offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, producedPackets) == 0x08,
    "SfplyFlowCount::producedPackets offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, consumedPackets) == 0x0C,
    "SfplyFlowCount::consumedPackets offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, producedFrames) == 0x10,
    "SfplyFlowCount::producedFrames offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyFlowCount, consumedFrames) == 0x14,
    "SfplyFlowCount::consumedFrames offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SfplyFlowCount) == 0x18, "SfplyFlowCount size must be 0x18");

  /**
   * SFPLY movie-info lane initialized by `_sfply_InitMvInf`.
   */
  struct SfplyMovieInfo
  {
    std::array<std::int32_t, 7> mUnknown00{}; // +0x00
    std::int32_t decodeDirection = 0;         // +0x1C
    std::int32_t mUnknown20 = 0;              // +0x20
    std::int32_t firstFrameIndex = -1;        // +0x24
    std::int32_t lastFrameIndex = -1;         // +0x28
    std::int32_t activeFrameIndex = -1;       // +0x2C
    std::array<std::int32_t, 4> mUnknown30{}; // +0x30
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyMovieInfo, decodeDirection) == 0x1C,
    "SfplyMovieInfo::decodeDirection offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyMovieInfo, firstFrameIndex) == 0x24,
    "SfplyMovieInfo::firstFrameIndex offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyMovieInfo, lastFrameIndex) == 0x28,
    "SfplyMovieInfo::lastFrameIndex offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyMovieInfo, activeFrameIndex) == 0x2C,
    "SfplyMovieInfo::activeFrameIndex offset must be 0x2C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SfplyMovieInfo) == 0x40, "SfplyMovieInfo size must be 0x40");

  /**
   * SFPLY playback-info lane initialized by `_sfply_InitPlyInf`.
   */
  struct SfplyPlaybackInfo
  {
    std::array<std::int32_t, 13> mUnknown00{}; // +0x00
    std::int32_t mUnknown34 = 0;               // +0x34
    SfplyFlowCount flowCounter0{};             // +0x38
    SfplyFlowCount flowCounter1{};             // +0x50
    SfplyFlowCount flowCounter2{};             // +0x68
    SfplyFlowCount flowCounter3{};             // +0x80
    std::array<std::int32_t, 4> mUnknown98{};  // +0x98
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyPlaybackInfo, flowCounter0) == 0x38,
    "SfplyPlaybackInfo::flowCounter0 offset must be 0x38"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyPlaybackInfo, flowCounter1) == 0x50,
    "SfplyPlaybackInfo::flowCounter1 offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyPlaybackInfo, flowCounter2) == 0x68,
    "SfplyPlaybackInfo::flowCounter2 offset must be 0x68"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyPlaybackInfo, flowCounter3) == 0x80,
    "SfplyPlaybackInfo::flowCounter3 offset must be 0x80"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SfplyPlaybackInfo) == 0xA8, "SfplyPlaybackInfo size must be 0xA8");

  /**
   * SFPLY timer-summary lane initialized by `SFTMR_InitTsum`.
   */
  struct SfplyTimerSummary
  {
    std::int32_t accumulatedTicksLow = 0;  // +0x00
    std::int32_t accumulatedTicksHigh = 0; // +0x04
    std::int32_t minTicksLow = -1;         // +0x08
    std::int32_t minTicksHigh = 0x7FFFFFFF; // +0x0C
    std::int32_t maxTicksLow = 0;          // +0x10
    std::int32_t maxTicksHigh = 0;         // +0x14
    std::int32_t sampleCount = 0;          // +0x18
    std::int32_t mUnknown1C = 0;           // +0x1C
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, accumulatedTicksLow) == 0x00,
    "SfplyTimerSummary::accumulatedTicksLow offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, accumulatedTicksHigh) == 0x04,
    "SfplyTimerSummary::accumulatedTicksHigh offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, minTicksLow) == 0x08,
    "SfplyTimerSummary::minTicksLow offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, minTicksHigh) == 0x0C,
    "SfplyTimerSummary::minTicksHigh offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, maxTicksLow) == 0x10,
    "SfplyTimerSummary::maxTicksLow offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, maxTicksHigh) == 0x14,
    "SfplyTimerSummary::maxTicksHigh offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, sampleCount) == 0x18,
    "SfplyTimerSummary::sampleCount offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerSummary, mUnknown1C) == 0x1C,
    "SfplyTimerSummary::mUnknown1C offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SfplyTimerSummary) == 0x20, "SfplyTimerSummary size must be 0x20");

  /**
   * SFPLY timer-info lane initialized by `_sfply_InitTmrInf`.
   */
  struct SfplyTimerInfo
  {
    std::array<SfplyTimerSummary, 6> summaries{}; // +0x00
    std::array<std::int32_t, 8> mUnknownC0{};     // +0xC0
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerInfo, summaries) == 0x00,
    "SfplyTimerInfo::summaries offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SfplyTimerInfo, mUnknownC0) == 0xC0,
    "SfplyTimerInfo::mUnknownC0 offset must be 0xC0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SfplyTimerInfo) == 0xE0, "SfplyTimerInfo size must be 0xE0");

  struct MwsstPauseGate;
  struct SofdecSjRingBufferHandle;
  struct SofdecSjMemoryHandle;
  struct SjChunkRange;
  using MwsstPauseGateQueryStartFn = std::int32_t(__stdcall*)(moho::MwsstPauseGate* gate, std::int32_t mode);

  /**
   * Runtime dispatch table lane used by one MWSST pause-gate owner.
   */
  struct MwsstPauseGateVtable
  {
    std::uint8_t mUnknown00[0x24]{};
    MwsstPauseGateQueryStartFn queryStart = nullptr; // +0x24
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsstPauseGateVtable, queryStart) == 0x24,
    "MwsstPauseGateVtable::queryStart offset must be 0x24"
  );

  /**
   * Runtime pause-gate owner touched by `mwsfsvr_StartPlayback`.
   */
  struct MwsstPauseGate
  {
    MwsstPauseGateVtable* dispatchTable = nullptr;
  };

  /**
   * Partial runtime view for one middleware stream-state lane used by
   * `_mw_sfd_start_ex` (`FUN_00ACAF40`).
   *
   * Evidence:
   * - `FUN_00ACAF40` passes `ply + 0x280` to `_MWSST_Pause` and `_MWSST_StartSj`.
   * - `FUN_00ACAF40` writes `apiType` at `+0x2A4`, bounding this subobject to `0x24` bytes.
   */
  struct MwsstStreamStateSubobj
  {
    std::int32_t state = 0; // +0x00
    std::uint8_t mUnknown04[0x8]{};
    MwsstPauseGate* pauseGate = nullptr; // +0x0C
    std::uint8_t mUnknown10[0x10]{};
    std::int32_t decodeServerSleepState = 0; // +0x20
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsstStreamStateSubobj, state) == 0x00,
    "MwsstStreamStateSubobj::state offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsstStreamStateSubobj, pauseGate) == 0x0C,
    "MwsstStreamStateSubobj::pauseGate offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsstStreamStateSubobj, decodeServerSleepState) == 0x20,
    "MwsstStreamStateSubobj::decodeServerSleepState offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsstStreamStateSubobj) == 0x24, "MwsstStreamStateSubobj size must be 0x24");

  struct SofdecSjSupplyHandle;
  using SofdecSjSupplyDestroyFn = void(__cdecl*)(SofdecSjSupplyHandle* handle);
  using SofdecSjSupplyOnStartFn = void(__cdecl*)(SofdecSjSupplyHandle* handle);
  using SofdecSjSupplyGetChunkFn = void(__cdecl*)(
    SofdecSjSupplyHandle* handle,
    std::int32_t lane,
    std::int32_t minBytes,
    moho::SjChunkRange* chunkRange
  );
  using SofdecSjSupplyPutChunkFn =
    void(__cdecl*)(SofdecSjSupplyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);
  using SofdecSjSupplySubmitChunkFn =
    void(__cdecl*)(SofdecSjSupplyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);
  using SofdecSjSupplyQueryAvailableFn = std::int32_t(__cdecl*)(SofdecSjSupplyHandle* handle, std::int32_t lane);

  /**
   * Runtime dispatch table lane used by SJ supply handles.
   *
   * Evidence:
   * - `FUN_00ACB020` calls `dispatchTable + 0x0C` to destroy old supply handle.
   * - `FUN_00ADDBC0` calls `dispatchTable + 0x14` before seamless start completes.
   */
  struct SofdecSjSupplyVtable
  {
    std::uint8_t mUnknown00[0x0C]{};
    SofdecSjSupplyDestroyFn destroy = nullptr; // +0x0C
    std::uint8_t mUnknown10[0x04]{};
    SofdecSjSupplyOnStartFn onStart = nullptr;                    // +0x14
    SofdecSjSupplyGetChunkFn getChunk = nullptr;                  // +0x18
    SofdecSjSupplyPutChunkFn putChunk = nullptr;                  // +0x1C
    SofdecSjSupplySubmitChunkFn submitChunk = nullptr;            // +0x20
    SofdecSjSupplyQueryAvailableFn queryAvailableBytes = nullptr; // +0x24
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, destroy) == 0x0C,
    "SofdecSjSupplyVtable::destroy offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, onStart) == 0x14,
    "SofdecSjSupplyVtable::onStart offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, getChunk) == 0x18,
    "SofdecSjSupplyVtable::getChunk offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, putChunk) == 0x1C,
    "SofdecSjSupplyVtable::putChunk offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, submitChunk) == 0x20,
    "SofdecSjSupplyVtable::submitChunk offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyVtable, queryAvailableBytes) == 0x24,
    "SofdecSjSupplyVtable::queryAvailableBytes offset must be 0x24"
  );

  struct SofdecSjSupplyHandle
  {
    SofdecSjSupplyVtable* dispatchTable = nullptr; // +0x00
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjSupplyHandle, dispatchTable) == 0x00,
    "SofdecSjSupplyHandle::dispatchTable offset must be 0x00"
  );

  /**
   * Partial runtime view for Sofdec playback object lanes touched directly by
   * `_mw_sfd_start_ex`.
   */
  struct MwsfdPlaybackStateSubobj
  {
    std::int32_t used = 0; // +0x00
    std::int32_t compoMode = 0;
    std::int32_t fileType = 0; // +0x08
    std::uint8_t mUnknown0C[0x0C]{};
    std::int32_t framePoolSize = 0; // +0x18 (nfrm_pool_wk)
    std::uint8_t mUnknown1C[0x20]{};
    void* handle = nullptr;          // +0x3C
    void* adxStreamHandle = nullptr; // +0x40
    std::int32_t mUnknown44 = 0;     // +0x44
    void* lscHandle = nullptr;       // +0x48
    /// Non-zero when the SFX composition mode has been pinned by the per-file
    /// MWSFD `_FxType` table and `mwsfsfx_DecideCompoMode` should not refresh
    /// the override slot from `MWSFD_GetFxType`. Read-only outside of
    /// `mwsfsfx_DecideCompoMode` itself.
    std::int32_t sfxCompoModeLocked = 0; // +0x4C
    /// Cached SFX composition-mode override pushed into `SFX_SetCompoMode`.
    /// Holds either an `MWSFD_GetFxType` lookup result or the
    /// `kSfxCompoModeOverrideDefault` (`0x11`) sentinel that selects the
    /// SFX runtime's default static composition mode.
    std::int32_t sfxCompoModeOverride = 0;         // +0x50
    std::int32_t disableIntermediateFrameDrop = 0; // +0x54
    std::uint8_t mUnknown58[0x8]{};
    std::int32_t mwplyServerFlag = 0;          // +0x60
    std::int32_t sfdServerFlag = 0;            // +0x64
    std::int32_t decodeServerDispatchFlag = 0; // +0x68
    std::uint8_t mUnknown6C[0x4]{};
    std::uint8_t concatPlayArmed = 0; // +0x70
    std::uint8_t isPrepared = 0;
    std::int8_t paused = 0;
    std::uint8_t mUnknown73 = 0;
    std::int32_t seamlessEntryCount = 0;  // +0x74
    void* lastSfdFrame = nullptr;         // +0x78
    std::int32_t retrievedFrameCount = 0; // +0x7C
    std::int32_t mUnknown80 = 0;          // +0x80
    std::int32_t releasedFrameCount = 0;  // +0x84
    std::uint8_t mUnknown88[0x20]{};
    void* sfxHandle = nullptr; // +0xA8
    std::uint8_t mUnknownAC[0xC]{};
    std::int32_t lastFrameConcatCount = 0; // +0xB8
    std::uint8_t mUnknownBC[0xD4]{};
    std::int32_t additionalInfoStamp = 0; // +0x190
    std::uint8_t mUnknown194[0x10]{};
    char* fname = nullptr;                                  // +0x1A4
    std::int32_t fnameCapacity = 0;                         // +0x1A8
    std::int32_t pendingStartRequestType = 0;               // +0x1AC
    std::int32_t pendingStartRequestReserved = 0;           // +0x1B0
    std::int32_t pendingStartRangeStart = 0;                // +0x1B4
    std::int32_t pendingStartRangeEnd = 0;                  // +0x1B8
    SofdecSjSupplyHandle* sjSupplyHandle = nullptr;         // +0x1BC
    SofdecSjRingBufferHandle* sjRingBufferHandle = nullptr; // +0x1C0
    std::uint8_t mUnknown1C4[0xC]{};
    std::int32_t sjSupplyMode = 0;                  // +0x1D0
    std::int32_t sjSupplyArg0 = 0;                  // +0x1D4
    std::int32_t sjSupplyArg1 = 0;                  // +0x1D8
    std::int32_t sjSupplyArg2 = 0;                  // +0x1DC
    SofdecSjMemoryHandle* sjMemoryHandle = nullptr; // +0x1E0
    std::int32_t sjMemoryBufferAddress = 0;         // +0x1E4
    std::int32_t sjMemoryBufferSize = 0;            // +0x1E8
    std::int32_t mwsfcreWorkSizeBytes = 0;          // +0x1EC
    std::uint8_t mUnknown1F0[0x0C]{};
    std::int32_t mwsfcreAllocationCount = 0;    // +0x1FC
    std::array<void*, 32> mwsfcreAllocations{}; // +0x200
    MwsstStreamStateSubobj streamState{};
    std::int32_t apiType = 0;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, used) == 0x00,
    "MwsfdPlaybackStateSubobj::used offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, fileType) == 0x08,
    "MwsfdPlaybackStateSubobj::fileType offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, framePoolSize) == 0x18,
    "MwsfdPlaybackStateSubobj::framePoolSize offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, handle) == 0x3C,
    "MwsfdPlaybackStateSubobj::handle offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, adxStreamHandle) == 0x40,
    "MwsfdPlaybackStateSubobj::adxStreamHandle offset must be 0x40"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, lscHandle) == 0x48,
    "MwsfdPlaybackStateSubobj::lscHandle offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, concatPlayArmed) == 0x70,
    "MwsfdPlaybackStateSubobj::concatPlayArmed offset must be 0x70"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, isPrepared) == 0x71,
    "MwsfdPlaybackStateSubobj::isPrepared offset must be 0x71"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, paused) == 0x72,
    "MwsfdPlaybackStateSubobj::paused offset must be 0x72"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, seamlessEntryCount) == 0x74,
    "MwsfdPlaybackStateSubobj::seamlessEntryCount offset must be 0x74"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sfxCompoModeLocked) == 0x4C,
    "MwsfdPlaybackStateSubobj::sfxCompoModeLocked offset must be 0x4C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sfxCompoModeOverride) == 0x50,
    "MwsfdPlaybackStateSubobj::sfxCompoModeOverride offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, disableIntermediateFrameDrop) == 0x54,
    "MwsfdPlaybackStateSubobj::disableIntermediateFrameDrop offset must be 0x54"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, mwplyServerFlag) == 0x60,
    "MwsfdPlaybackStateSubobj::mwplyServerFlag offset must be 0x60"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sfdServerFlag) == 0x64,
    "MwsfdPlaybackStateSubobj::sfdServerFlag offset must be 0x64"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, decodeServerDispatchFlag) == 0x68,
    "MwsfdPlaybackStateSubobj::decodeServerDispatchFlag offset must be 0x68"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, lastSfdFrame) == 0x78,
    "MwsfdPlaybackStateSubobj::lastSfdFrame offset must be 0x78"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, retrievedFrameCount) == 0x7C,
    "MwsfdPlaybackStateSubobj::retrievedFrameCount offset must be 0x7C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, releasedFrameCount) == 0x84,
    "MwsfdPlaybackStateSubobj::releasedFrameCount offset must be 0x84"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sfxHandle) == 0xA8,
    "MwsfdPlaybackStateSubobj::sfxHandle offset must be 0xA8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, lastFrameConcatCount) == 0xB8,
    "MwsfdPlaybackStateSubobj::lastFrameConcatCount offset must be 0xB8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, additionalInfoStamp) == 0x190,
    "MwsfdPlaybackStateSubobj::additionalInfoStamp offset must be 0x190"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, fname) == 0x1A4,
    "MwsfdPlaybackStateSubobj::fname offset must be 0x1A4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, fnameCapacity) == 0x1A8,
    "MwsfdPlaybackStateSubobj::fnameCapacity offset must be 0x1A8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, pendingStartRequestType) == 0x1AC,
    "MwsfdPlaybackStateSubobj::pendingStartRequestType offset must be 0x1AC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, pendingStartRequestReserved) == 0x1B0,
    "MwsfdPlaybackStateSubobj::pendingStartRequestReserved offset must be 0x1B0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, pendingStartRangeStart) == 0x1B4,
    "MwsfdPlaybackStateSubobj::pendingStartRangeStart offset must be 0x1B4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, pendingStartRangeEnd) == 0x1B8,
    "MwsfdPlaybackStateSubobj::pendingStartRangeEnd offset must be 0x1B8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjSupplyHandle) == 0x1BC,
    "MwsfdPlaybackStateSubobj::sjSupplyHandle offset must be 0x1BC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjRingBufferHandle) == 0x1C0,
    "MwsfdPlaybackStateSubobj::sjRingBufferHandle offset must be 0x1C0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjSupplyMode) == 0x1D0,
    "MwsfdPlaybackStateSubobj::sjSupplyMode offset must be 0x1D0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjSupplyArg0) == 0x1D4,
    "MwsfdPlaybackStateSubobj::sjSupplyArg0 offset must be 0x1D4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjSupplyArg1) == 0x1D8,
    "MwsfdPlaybackStateSubobj::sjSupplyArg1 offset must be 0x1D8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjSupplyArg2) == 0x1DC,
    "MwsfdPlaybackStateSubobj::sjSupplyArg2 offset must be 0x1DC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjMemoryHandle) == 0x1E0,
    "MwsfdPlaybackStateSubobj::sjMemoryHandle offset must be 0x1E0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjMemoryBufferAddress) == 0x1E4,
    "MwsfdPlaybackStateSubobj::sjMemoryBufferAddress offset must be 0x1E4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, sjMemoryBufferSize) == 0x1E8,
    "MwsfdPlaybackStateSubobj::sjMemoryBufferSize offset must be 0x1E8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, mwsfcreWorkSizeBytes) == 0x1EC,
    "MwsfdPlaybackStateSubobj::mwsfcreWorkSizeBytes offset must be 0x1EC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, mwsfcreAllocationCount) == 0x1FC,
    "MwsfdPlaybackStateSubobj::mwsfcreAllocationCount offset must be 0x1FC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, mwsfcreAllocations) == 0x200,
    "MwsfdPlaybackStateSubobj::mwsfcreAllocations offset must be 0x200"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, streamState) == 0x280,
    "MwsfdPlaybackStateSubobj::streamState offset must be 0x280"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdPlaybackStateSubobj, apiType) == 0x2A4,
    "MwsfdPlaybackStateSubobj::apiType offset must be 0x2A4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfdPlaybackStateSubobj) == 0x2A8, "MwsfdPlaybackStateSubobj size must be 0x2A8");

  struct MwsfdFrameInfo
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t frameId = 0;       // +0x04
    std::uint8_t mUnknown08[0x1C]{};
    std::int32_t concatCount = 0; // +0x24
    std::uint8_t mUnknown28[0x8]{};
    std::int32_t frameNumber = 0; // +0x30
    std::uint8_t mUnknown34[0x5C]{};
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdFrameInfo, bufferAddress) == 0x00,
    "MwsfdFrameInfo::bufferAddress offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(MwsfdFrameInfo, frameId) == 0x04, "MwsfdFrameInfo::frameId offset must be 0x04");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdFrameInfo, concatCount) == 0x24,
    "MwsfdFrameInfo::concatCount offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(MwsfdFrameInfo, frameNumber) == 0x30,
    "MwsfdFrameInfo::frameNumber offset must be 0x30"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(MwsfdFrameInfo) == 0x90, "MwsfdFrameInfo size must be 0x90");

  /**
   * Minimal runtime view for `SofDecVirt` object lane touched by virtual slot 25.
   *
   * Evidence:
   * - `FUN_00B20AD0` writes `1` to offset `+0x08`.
   */
  struct SofDecVirtualStateSubobj
  {
    std::uint8_t mUnknown00[0x8]{};
    std::int32_t readyFlag = 0;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofDecVirtualStateSubobj, readyFlag) == 0x8,
    "SofDecVirtualStateSubobj::readyFlag offset must be 0x8"
  );

  /**
   * Runtime view for one RNA timing node lane used by `SofDecVirt*` vtable slots.
   */
  struct AdxrnaTimingState
  {
    void* dispatchTable = nullptr;   // +0x00
    std::int32_t activeFlag = 0;     // +0x04
    std::int32_t mode = 0;           // +0x08
    std::int32_t sampleRate = 0;     // +0x0C
    std::uint32_t phaseModulo = 0;   // +0x10
    std::int32_t playheadSample = 0; // +0x14
    std::int32_t latchedSample = 0;  // +0x18
    std::uint32_t wrapPosition = 0;  // +0x1C
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, dispatchTable) == 0x00,
    "AdxrnaTimingState::dispatchTable offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, activeFlag) == 0x04,
    "AdxrnaTimingState::activeFlag offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(AdxrnaTimingState, mode) == 0x08, "AdxrnaTimingState::mode offset must be 0x08");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, sampleRate) == 0x0C,
    "AdxrnaTimingState::sampleRate offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, phaseModulo) == 0x10,
    "AdxrnaTimingState::phaseModulo offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, playheadSample) == 0x14,
    "AdxrnaTimingState::playheadSample offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, latchedSample) == 0x18,
    "AdxrnaTimingState::latchedSample offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxrnaTimingState, wrapPosition) == 0x1C,
    "AdxrnaTimingState::wrapPosition offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(AdxrnaTimingState) == 0x20, "AdxrnaTimingState size must be 0x20");

  /**
   * PCM wave-format layout used by Sofdec DirectSound port helpers.
   */
  struct SofdecPcmWaveFormat
  {
    std::uint16_t formatTag = 0;             // +0x00
    std::uint16_t channelCount = 0;          // +0x02
    std::uint32_t samplesPerSecond = 0;      // +0x04
    std::uint32_t averageBytesPerSecond = 0; // +0x08
    std::uint16_t blockAlignBytes = 0;       // +0x0C
    std::uint16_t bitsPerSample = 0;         // +0x0E
    std::uint16_t extraBytes = 0;            // +0x10
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, formatTag) == 0x00,
    "SofdecPcmWaveFormat::formatTag offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, channelCount) == 0x02,
    "SofdecPcmWaveFormat::channelCount offset must be 0x02"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, samplesPerSecond) == 0x04,
    "SofdecPcmWaveFormat::samplesPerSecond offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, averageBytesPerSecond) == 0x08,
    "SofdecPcmWaveFormat::averageBytesPerSecond offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, blockAlignBytes) == 0x0C,
    "SofdecPcmWaveFormat::blockAlignBytes offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, bitsPerSample) == 0x0E,
    "SofdecPcmWaveFormat::bitsPerSample offset must be 0x0E"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecPcmWaveFormat, extraBytes) == 0x10,
    "SofdecPcmWaveFormat::extraBytes offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecPcmWaveFormat) == 0x12, "SofdecPcmWaveFormat size must be 0x12");

  /**
   * Runtime view for one Sofdec sound-port handle (`MWSND`) lane.
   *
   * Evidence:
   * - `FUN_00B16610` clears `0x6C` bytes per handle.
   * - `FUN_00B16750` stamps vtable/primary buffer and wave-format fields.
   * - `FUN_00B16870/00B168D0/00B16990` consume primary/secondary buffers and
   *   playback flags from this layout.
   */
  struct SofdecSoundPort
  {
    void* dispatchTable = nullptr;                 // +0x00
    std::int32_t used = 0;                         // +0x04
    IDirectSoundBuffer* primaryBuffer = nullptr;   // +0x08
    std::int32_t monoRoutingMode = 0;              // +0x0C
    IDirectSoundBuffer* secondaryBuffer = nullptr; // +0x10
    std::int32_t bufferPlacementMode = 0;          // +0x14
    std::int32_t auxMaintenanceMode = 0;           // +0x18
    std::int32_t auxSwapPending = 0;               // +0x1C
    std::int32_t auxDrainPending = 0;              // +0x20
    std::int32_t auxDrainWriteCursorBytes = 0;     // +0x24
    std::int32_t auxDrainReadCursorBytes = 0;      // +0x28
    std::int32_t auxDrainAccumulatedBytes = 0;     // +0x2C
    SofdecPcmWaveFormat format = {};               // +0x30
    std::uint8_t mUnknown42[0x2]{};                // +0x42
    std::int32_t playbackCursorByteOffset = 0;     // +0x44
    std::int32_t channelCountPrimary = 0;          // +0x48
    std::int32_t channelModeFlag = 0;              // +0x4C
    std::int32_t playbackCursorResetPending = 0;   // +0x50
    std::int32_t balanceIndex = 0;                 // +0x54
    std::int32_t baseVolumeMilliBel = 0;           // +0x58
    std::int32_t spatialPresetEnabled = 0;         // +0x5C
    std::int32_t spatialPresetPrimaryIndex = 0;    // +0x60
    std::int32_t spatialPresetSecondaryIndex = 0;  // +0x64
    std::int32_t spatialPresetVolumeOffset = 0;    // +0x68
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, dispatchTable) == 0x00,
    "SofdecSoundPort::dispatchTable offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SofdecSoundPort, used) == 0x04, "SofdecSoundPort::used offset must be 0x04");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, primaryBuffer) == 0x08,
    "SofdecSoundPort::primaryBuffer offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, monoRoutingMode) == 0x0C,
    "SofdecSoundPort::monoRoutingMode offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, secondaryBuffer) == 0x10,
    "SofdecSoundPort::secondaryBuffer offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, bufferPlacementMode) == 0x14,
    "SofdecSoundPort::bufferPlacementMode offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxMaintenanceMode) == 0x18,
    "SofdecSoundPort::auxMaintenanceMode offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxSwapPending) == 0x1C,
    "SofdecSoundPort::auxSwapPending offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxDrainPending) == 0x20,
    "SofdecSoundPort::auxDrainPending offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxDrainWriteCursorBytes) == 0x24,
    "SofdecSoundPort::auxDrainWriteCursorBytes offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxDrainReadCursorBytes) == 0x28,
    "SofdecSoundPort::auxDrainReadCursorBytes offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, auxDrainAccumulatedBytes) == 0x2C,
    "SofdecSoundPort::auxDrainAccumulatedBytes offset must be 0x2C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SofdecSoundPort, format) == 0x30, "SofdecSoundPort::format offset must be 0x30");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, channelCountPrimary) == 0x48,
    "SofdecSoundPort::channelCountPrimary offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, playbackCursorByteOffset) == 0x44,
    "SofdecSoundPort::playbackCursorByteOffset offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, channelModeFlag) == 0x4C,
    "SofdecSoundPort::channelModeFlag offset must be 0x4C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, playbackCursorResetPending) == 0x50,
    "SofdecSoundPort::playbackCursorResetPending offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, balanceIndex) == 0x54,
    "SofdecSoundPort::balanceIndex offset must be 0x54"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, baseVolumeMilliBel) == 0x58,
    "SofdecSoundPort::baseVolumeMilliBel offset must be 0x58"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, spatialPresetEnabled) == 0x5C,
    "SofdecSoundPort::spatialPresetEnabled offset must be 0x5C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, spatialPresetPrimaryIndex) == 0x60,
    "SofdecSoundPort::spatialPresetPrimaryIndex offset must be 0x60"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, spatialPresetSecondaryIndex) == 0x64,
    "SofdecSoundPort::spatialPresetSecondaryIndex offset must be 0x64"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSoundPort, spatialPresetVolumeOffset) == 0x68,
    "SofdecSoundPort::spatialPresetVolumeOffset offset must be 0x68"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecSoundPort) == 0x6C, "SofdecSoundPort size must be 0x6C");

  /**
   * Partial runtime view for ADX bitstream decoder state lanes used by
   * ADXB accessors and snapshot/start-stop helpers.
   */
  struct AdxBitstreamDecoderState
  {
    std::int16_t slotState = 0;             // +0x00
    std::int16_t initState = 0;             // +0x02
    std::int32_t status = 0;                // +0x04
    void* adxPacketDecoder = nullptr;       // +0x08
    std::int8_t headerType = 0;             // +0x0C
    std::int8_t sourceSampleBits = 0;       // +0x0D
    std::int8_t sourceChannels = 0;         // +0x0E
    std::int8_t sourceBlockBytes = 0;       // +0x0F
    std::int32_t sourceBlockSamples = 0;    // +0x10
    std::int32_t sampleRate = 0;            // +0x14
    std::int32_t totalSampleCount = 0;      // +0x18
    std::int16_t adpcmCoefficientIndex = 0; // +0x1C
    std::uint8_t mUnknown1E[0x2]{};
    std::int32_t loopInsertedSamples = 0; // +0x20
    std::int16_t loopCount = 0;           // +0x24
    std::uint16_t loopType = 0;           // +0x26
    std::int32_t loopStartSample = 0;     // +0x28
    std::int32_t loopStartOffset = 0;     // +0x2C
    std::int32_t loopEndSample = 0;       // +0x30
    std::int32_t loopEndOffset = 0;       // +0x34
    void* pcmBufferTag = nullptr;         // +0x38
    void* pcmBuffer0 = nullptr;           // +0x3C
    void* pcmBuffer1 = nullptr;           // +0x40
    void* pcmBuffer2 = nullptr;           // +0x44
    std::int32_t streamDataOffset = 0;    // +0x48
    std::int32_t streamBlockCount = 0;    // +0x4C
    std::int32_t outputChannels = 0;      // +0x50
    std::int32_t outputBlockBytes = 0;    // +0x54
    std::int32_t outputBlockSamples = 0;  // +0x58
    void* outputPcmBuffer0 = nullptr;     // +0x5C
    void* outputPcmBuffer1 = nullptr;     // +0x60
    void* outputPcmBuffer2 = nullptr;     // +0x64
    std::uint8_t mUnknown68[0xC]{};
    std::int32_t decodeCursor = 0;         // +0x74
    void* entryGetWriteFunc = nullptr;     // +0x78
    std::int32_t entryGetWriteContext = 0; // +0x7C
    void* entryAddWriteFunc = nullptr;     // +0x80
    std::int32_t entryAddWriteContext = 0; // +0x84
    std::int32_t entrySubmittedBytes = 0;  // +0x88
    std::int32_t entryCommittedBytes = 0;  // +0x8C
    std::int32_t decodeProgress0 = 0;      // +0x90
    std::int32_t decodeProgress1 = 0;      // +0x94
    std::int16_t format = 0;               // +0x98
    std::int16_t preferredFormat = 0;      // +0x9A
    std::int16_t outputSamplePacking = 0;  // +0x9C
    std::uint8_t mUnknown9E[0x2]{};
    std::int16_t extKey0 = 0;                  // +0xA0
    std::int16_t extKeyMultiplier = 0;         // +0xA2
    std::int16_t extKeyAdder = 0;              // +0xA4
    std::int16_t snapshotExtKey0 = 0;          // +0xA6
    std::int16_t snapshotExtKeyMultiplier = 0; // +0xA8
    std::int16_t snapshotExtKeyAdder = 0;      // +0xAA
    std::int16_t snapshotDelay0 = 0;           // +0xAC
    std::uint8_t mUnknownAE[0x2]{};
    std::int16_t snapshotDelay1 = 0; // +0xB0
    std::uint8_t mUnknownB2[0x2]{};
    void* ahxDecoderHandle = nullptr; // +0xB4
    std::uint8_t mUnknownB8[0x8]{};
    void* mpegAudioDecoder = nullptr; // +0xC0
    std::uint8_t mUnknownC4[0x8]{};
    void* mpeg2AacDecoder = nullptr;       // +0xCC
    std::int32_t m2aDecodeSampleLimit = 0; // +0xD0
    std::int32_t m2aDecodeBlockLimit = 0;  // +0xD4
    std::int32_t ainfLength = 0;           // +0xD8
    std::uint8_t dataIdBytes[0x10]{};      // +0xDC
    std::int16_t defaultOutputVolume = 0;  // +0xEC
    std::int16_t defaultPanByChannel[3]{}; // +0xEE
    std::int32_t channelExpandHandle = 0;  // +0xF4
    std::uint8_t mUnknownF8[0x8]{};
    std::int32_t pendingSubmitBytes = 0;  // +0x100
    std::int32_t pendingConsumeBytes = 0; // +0x104
    std::uint8_t mUnknown108[0x8]{};
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, slotState) == 0x00,
    "AdxBitstreamDecoderState::slotState offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, initState) == 0x02,
    "AdxBitstreamDecoderState::initState offset must be 0x02"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, status) == 0x04,
    "AdxBitstreamDecoderState::status offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, adxPacketDecoder) == 0x08,
    "AdxBitstreamDecoderState::adxPacketDecoder offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, headerType) == 0x0C,
    "AdxBitstreamDecoderState::headerType offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, sourceSampleBits) == 0x0D,
    "AdxBitstreamDecoderState::sourceSampleBits offset must be 0x0D"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, sourceChannels) == 0x0E,
    "AdxBitstreamDecoderState::sourceChannels offset must be 0x0E"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, sourceBlockBytes) == 0x0F,
    "AdxBitstreamDecoderState::sourceBlockBytes offset must be 0x0F"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, sourceBlockSamples) == 0x10,
    "AdxBitstreamDecoderState::sourceBlockSamples offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, sampleRate) == 0x14,
    "AdxBitstreamDecoderState::sampleRate offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, totalSampleCount) == 0x18,
    "AdxBitstreamDecoderState::totalSampleCount offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, adpcmCoefficientIndex) == 0x1C,
    "AdxBitstreamDecoderState::adpcmCoefficientIndex offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopInsertedSamples) == 0x20,
    "AdxBitstreamDecoderState::loopInsertedSamples offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopCount) == 0x24,
    "AdxBitstreamDecoderState::loopCount offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopType) == 0x26,
    "AdxBitstreamDecoderState::loopType offset must be 0x26"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pcmBuffer0) == 0x3C,
    "AdxBitstreamDecoderState::pcmBuffer0 offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pcmBuffer1) == 0x40,
    "AdxBitstreamDecoderState::pcmBuffer1 offset must be 0x40"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pcmBuffer2) == 0x44,
    "AdxBitstreamDecoderState::pcmBuffer2 offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputChannels) == 0x50,
    "AdxBitstreamDecoderState::outputChannels offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputBlockBytes) == 0x54,
    "AdxBitstreamDecoderState::outputBlockBytes offset must be 0x54"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputBlockSamples) == 0x58,
    "AdxBitstreamDecoderState::outputBlockSamples offset must be 0x58"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputPcmBuffer0) == 0x5C,
    "AdxBitstreamDecoderState::outputPcmBuffer0 offset must be 0x5C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputPcmBuffer1) == 0x60,
    "AdxBitstreamDecoderState::outputPcmBuffer1 offset must be 0x60"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputPcmBuffer2) == 0x64,
    "AdxBitstreamDecoderState::outputPcmBuffer2 offset must be 0x64"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopStartSample) == 0x28,
    "AdxBitstreamDecoderState::loopStartSample offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopStartOffset) == 0x2C,
    "AdxBitstreamDecoderState::loopStartOffset offset must be 0x2C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopEndSample) == 0x30,
    "AdxBitstreamDecoderState::loopEndSample offset must be 0x30"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, loopEndOffset) == 0x34,
    "AdxBitstreamDecoderState::loopEndOffset offset must be 0x34"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pcmBufferTag) == 0x38,
    "AdxBitstreamDecoderState::pcmBufferTag offset must be 0x38"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, streamDataOffset) == 0x48,
    "AdxBitstreamDecoderState::streamDataOffset offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, streamBlockCount) == 0x4C,
    "AdxBitstreamDecoderState::streamBlockCount offset must be 0x4C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, decodeCursor) == 0x74,
    "AdxBitstreamDecoderState::decodeCursor offset must be 0x74"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entryGetWriteFunc) == 0x78,
    "AdxBitstreamDecoderState::entryGetWriteFunc offset must be 0x78"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entryGetWriteContext) == 0x7C,
    "AdxBitstreamDecoderState::entryGetWriteContext offset must be 0x7C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entryAddWriteFunc) == 0x80,
    "AdxBitstreamDecoderState::entryAddWriteFunc offset must be 0x80"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entryAddWriteContext) == 0x84,
    "AdxBitstreamDecoderState::entryAddWriteContext offset must be 0x84"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entrySubmittedBytes) == 0x88,
    "AdxBitstreamDecoderState::entrySubmittedBytes offset must be 0x88"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, entryCommittedBytes) == 0x8C,
    "AdxBitstreamDecoderState::entryCommittedBytes offset must be 0x8C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, decodeProgress0) == 0x90,
    "AdxBitstreamDecoderState::decodeProgress0 offset must be 0x90"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, decodeProgress1) == 0x94,
    "AdxBitstreamDecoderState::decodeProgress1 offset must be 0x94"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, format) == 0x98,
    "AdxBitstreamDecoderState::format offset must be 0x98"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, preferredFormat) == 0x9A,
    "AdxBitstreamDecoderState::preferredFormat offset must be 0x9A"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, outputSamplePacking) == 0x9C,
    "AdxBitstreamDecoderState::outputSamplePacking offset must be 0x9C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, extKey0) == 0xA0,
    "AdxBitstreamDecoderState::extKey0 offset must be 0xA0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, extKeyMultiplier) == 0xA2,
    "AdxBitstreamDecoderState::extKeyMultiplier offset must be 0xA2"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, extKeyAdder) == 0xA4,
    "AdxBitstreamDecoderState::extKeyAdder offset must be 0xA4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, snapshotExtKey0) == 0xA6,
    "AdxBitstreamDecoderState::snapshotExtKey0 offset must be 0xA6"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, snapshotExtKeyMultiplier) == 0xA8,
    "AdxBitstreamDecoderState::snapshotExtKeyMultiplier offset must be 0xA8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, snapshotExtKeyAdder) == 0xAA,
    "AdxBitstreamDecoderState::snapshotExtKeyAdder offset must be 0xAA"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, snapshotDelay0) == 0xAC,
    "AdxBitstreamDecoderState::snapshotDelay0 offset must be 0xAC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, snapshotDelay1) == 0xB0,
    "AdxBitstreamDecoderState::snapshotDelay1 offset must be 0xB0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, ahxDecoderHandle) == 0xB4,
    "AdxBitstreamDecoderState::ahxDecoderHandle offset must be 0xB4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, mpegAudioDecoder) == 0xC0,
    "AdxBitstreamDecoderState::mpegAudioDecoder offset must be 0xC0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, mpeg2AacDecoder) == 0xCC,
    "AdxBitstreamDecoderState::mpeg2AacDecoder offset must be 0xCC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, m2aDecodeSampleLimit) == 0xD0,
    "AdxBitstreamDecoderState::m2aDecodeSampleLimit offset must be 0xD0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, m2aDecodeBlockLimit) == 0xD4,
    "AdxBitstreamDecoderState::m2aDecodeBlockLimit offset must be 0xD4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, ainfLength) == 0xD8,
    "AdxBitstreamDecoderState::ainfLength offset must be 0xD8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, dataIdBytes) == 0xDC,
    "AdxBitstreamDecoderState::dataIdBytes offset must be 0xDC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, defaultOutputVolume) == 0xEC,
    "AdxBitstreamDecoderState::defaultOutputVolume offset must be 0xEC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, defaultPanByChannel) == 0xEE,
    "AdxBitstreamDecoderState::defaultPanByChannel offset must be 0xEE"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, channelExpandHandle) == 0xF4,
    "AdxBitstreamDecoderState::channelExpandHandle offset must be 0xF4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pendingSubmitBytes) == 0x100,
    "AdxBitstreamDecoderState::pendingSubmitBytes offset must be 0x100"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(AdxBitstreamDecoderState, pendingConsumeBytes) == 0x104,
    "AdxBitstreamDecoderState::pendingConsumeBytes offset must be 0x104"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(AdxBitstreamDecoderState) == 0x110, "AdxBitstreamDecoderState size must be 0x110");

  using SofdecErrorHandler = void(__cdecl*)(std::int32_t callbackObject, std::int32_t errorCode);

  struct SjChunkRange
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t byteCount = 0;     // +0x04
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SjChunkRange, bufferAddress) == 0x00,
    "SjChunkRange::bufferAddress offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SjChunkRange, byteCount) == 0x04, "SjChunkRange::byteCount offset must be 0x04");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SjChunkRange) == 0x08, "SjChunkRange size must be 0x08");

  struct SofdecSjUnifyChunkNode
  {
    SofdecSjUnifyChunkNode* next = nullptr; // +0x00
    std::int32_t reserved = 0;              // +0x04
    std::int32_t bufferAddress = 0;         // +0x08
    std::int32_t byteCount = 0;             // +0x0C
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyChunkNode, next) == 0x00,
    "SofdecSjUnifyChunkNode::next offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyChunkNode, bufferAddress) == 0x08,
    "SofdecSjUnifyChunkNode::bufferAddress offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyChunkNode, byteCount) == 0x0C,
    "SofdecSjUnifyChunkNode::byteCount offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecSjUnifyChunkNode) == 0x10, "SofdecSjUnifyChunkNode size must be 0x10");

  struct SofdecSjUnifyHandle
  {
    std::int32_t runtimeSlot = 0;         // +0x00
    std::uint8_t used = 0;                // +0x04
    std::uint8_t mergeAdjacentChunks = 0; // +0x05
    std::uint8_t mUnknown06[0x2]{};
    std::int32_t uuid = 0;                               // +0x08
    SofdecSjUnifyChunkNode* chainPoolBase = nullptr;     // +0x0C
    std::int32_t chainPoolCount = 0;                     // +0x10
    SofdecSjUnifyChunkNode* chainPoolFreeList = nullptr; // +0x14
    SofdecSjUnifyChunkNode* laneHeads[4]{};              // +0x18
    SofdecErrorHandler errFunc = nullptr;                // +0x28
    std::int32_t errObj = 0;                             // +0x2C
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, used) == 0x04,
    "SofdecSjUnifyHandle::used offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, mergeAdjacentChunks) == 0x05,
    "SofdecSjUnifyHandle::mergeAdjacentChunks offset must be 0x05"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, uuid) == 0x08,
    "SofdecSjUnifyHandle::uuid offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, chainPoolBase) == 0x0C,
    "SofdecSjUnifyHandle::chainPoolBase offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, chainPoolCount) == 0x10,
    "SofdecSjUnifyHandle::chainPoolCount offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, chainPoolFreeList) == 0x14,
    "SofdecSjUnifyHandle::chainPoolFreeList offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, laneHeads) == 0x18,
    "SofdecSjUnifyHandle::laneHeads offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, errFunc) == 0x28,
    "SofdecSjUnifyHandle::errFunc offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjUnifyHandle, errObj) == 0x2C,
    "SofdecSjUnifyHandle::errObj offset must be 0x2C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecSjUnifyHandle) == 0x30, "SofdecSjUnifyHandle size must be 0x30");

  struct SofdecSjRingBufferHandle
  {
    std::int32_t runtimeSlot = 0;         // +0x00
    std::int32_t used = 0;                // +0x04
    std::int32_t uuid = 0;                // +0x08
    std::int32_t pendingLane1Bytes = 0;   // +0x0C
    std::int32_t pendingLane0Bytes = 0;   // +0x10
    std::int32_t lane0Cursor = 0;         // +0x14
    std::int32_t lane1Cursor = 0;         // +0x18
    std::int8_t* bufferBase = nullptr;    // +0x1C
    std::int32_t bufferSize = 0;          // +0x20
    std::int32_t extraSize = 0;           // +0x24
    std::int32_t flowCounters[4]{};       // +0x28
    SofdecErrorHandler errFunc = nullptr; // +0x38
    std::int32_t errObj = 0;              // +0x3C
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, used) == 0x04,
    "SofdecSjRingBufferHandle::used offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, uuid) == 0x08,
    "SofdecSjRingBufferHandle::uuid offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, pendingLane1Bytes) == 0x0C,
    "SofdecSjRingBufferHandle::pendingLane1Bytes offset must be 0x0C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, pendingLane0Bytes) == 0x10,
    "SofdecSjRingBufferHandle::pendingLane0Bytes offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, lane0Cursor) == 0x14,
    "SofdecSjRingBufferHandle::lane0Cursor offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, lane1Cursor) == 0x18,
    "SofdecSjRingBufferHandle::lane1Cursor offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, bufferBase) == 0x1C,
    "SofdecSjRingBufferHandle::bufferBase offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, bufferSize) == 0x20,
    "SofdecSjRingBufferHandle::bufferSize offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, extraSize) == 0x24,
    "SofdecSjRingBufferHandle::extraSize offset must be 0x24"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, flowCounters) == 0x28,
    "SofdecSjRingBufferHandle::flowCounters offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, errFunc) == 0x38,
    "SofdecSjRingBufferHandle::errFunc offset must be 0x38"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjRingBufferHandle, errObj) == 0x3C,
    "SofdecSjRingBufferHandle::errObj offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecSjRingBufferHandle) == 0x40, "SofdecSjRingBufferHandle size must be 0x40");

  struct SofdecSjMemoryHandle
  {
    std::int32_t runtimeSlot = 0;         // +0x00
    std::int32_t used = 0;                // +0x04
    std::int32_t uuid = 0;                // +0x08
    std::int32_t pendingBytes = 0;        // +0x0C
    std::int32_t consumeOffset = 0;       // +0x10
    std::int32_t produceOffset = 0;       // +0x14
    std::int32_t bufferSize = 0;          // +0x18
    SofdecErrorHandler errFunc = nullptr; // +0x1C
    std::int32_t errObj = 0;              // +0x20
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjMemoryHandle, used) == 0x04,
    "SofdecSjMemoryHandle::used offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjMemoryHandle, uuid) == 0x08,
    "SofdecSjMemoryHandle::uuid offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjMemoryHandle, errFunc) == 0x1C,
    "SofdecSjMemoryHandle::errFunc offset must be 0x1C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(SofdecSjMemoryHandle, errObj) == 0x20,
    "SofdecSjMemoryHandle::errObj offset must be 0x20"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SofdecSjMemoryHandle) == 0x24, "SofdecSjMemoryHandle size must be 0x24");
} // namespace moho

namespace moho::cri
{
  // Compatibility aliases while Sofdec ownership is migrated from moho::* to moho::cri::*.
  using MwsfdInitPrm = ::moho::MwsfdInitPrm;
  using MwsfdLibWork = ::moho::MwsfdLibWork;
  using MwsfdPlaybackStateSubobj = ::moho::MwsfdPlaybackStateSubobj;
  using SofdecSfdWorkctrlSubobj = ::moho::SofdecSfdWorkctrlSubobj;
  using MwsfdFrameInfo = ::moho::MwsfdFrameInfo;
  using SofdecSjSupplyHandle = ::moho::SofdecSjSupplyHandle;
  using SofdecSjRingBufferHandle = ::moho::SofdecSjRingBufferHandle;
  using SofdecSjMemoryHandle = ::moho::SofdecSjMemoryHandle;
  using SofdecSoundPort = ::moho::SofdecSoundPort;
  using AdxBitstreamDecoderState = ::moho::AdxBitstreamDecoderState;
} // namespace moho::cri

namespace moho::cri::adx
{
  using BitstreamDecoderState = ::moho::AdxBitstreamDecoderState;
  using SoundPort = ::moho::SofdecSoundPort;
} // namespace moho::cri::adx

namespace moho::cri::cvfs
{
  using SjSupplyHandle = ::moho::SofdecSjSupplyHandle;
  using SjRingBufferHandle = ::moho::SofdecSjRingBufferHandle;
  using SjMemoryHandle = ::moho::SofdecSjMemoryHandle;
} // namespace moho::cri::cvfs

namespace moho::cri::sfd
{
  using InitPrm = ::moho::MwsfdInitPrm;
  using LibWork = ::moho::MwsfdLibWork;
  using PlaybackStateSubobj = ::moho::MwsfdPlaybackStateSubobj;
  using WorkctrlSubobj = ::moho::SofdecSfdWorkctrlSubobj;
  using FrameInfo = ::moho::MwsfdFrameInfo;
} // namespace moho::cri::sfd

namespace moho::cri::m2a
{
  // Runtime/state type aliases will be added here as public M2A types are lifted into the header.
}

namespace moho::cri::mpa
{
  // Runtime/state type aliases will be added here as public MPA types are lifted into the header.
}

extern "C" {
/**
 * Address: 0x00B07C40 (ADXPC_SetupSoundDirectSound8)
 *
 * IDA signature:
 * void __cdecl ADXPC_SetupSoundDirectSound8(LPDIRECTSOUND directSound);
 *
 * What it does:
 * Routes the DirectSound runtime pointer into ADX RNA sound handlers.
 */
void ADXPC_SetupSoundDirectSound8(IDirectSound* directSound);

/**
 * Address: 0x00B07C00 (ADXPC_SetupFileSystem thunk)
 * Body: 0x00B07B90 (_ADXPC_SetupFileSystem)
 *
 * IDA signature:
 * int __cdecl ADXPC_SetupFileSystem(char const** rootDirArgv);
 *
 * What it does:
 * Initializes ADX file-device wiring and applies optional root-directory
 * override from `rootDirArgv[0]`.
 */
int ADXPC_SetupFileSystem(const char** rootDirArgv);

/**
 * Address: 0x00B13FE0 (FUN_00B13FE0, _ADXPC_GetVersion)
 *
 * What it does:
 * Validates the ADXPC library signature lane and returns the static build
 * version string.
 */
char* ADXPC_GetVersion();

/**
 * Address: 0x00B07B80 (_adxpc_err_dvd)
 *
 * What it does:
 * Forwards one DVD/file-system error string to ADX error reporting lane.
 */
std::int32_t ADXPC_ReportDvdError(std::int32_t errorCode, char* errorText);

/**
 * Address: 0x00B07C10 (_ADXPC_ShutdownFileSystem)
 *
 * What it does:
 * Tears down ADXPC file-system/runtime state and returns shutdown result.
 */
char* ADXPC_ShutdownFileSystem();

/**
 * Address: 0x00B07C30 (j__ADXPC_ShutdownFileSystem)
 *
 * What it does:
 * Thunk alias to `ADXPC_ShutdownFileSystem`.
 */
char* ADXPC_ShutdownFileSystemThunk();

/**
 * Address: 0x00B07C50 (nullsub_31)
 *
 * What it does:
 * No-op ADXPC callback lane.
 */
void ADXPC_NoOpShutdownCallback();

/**
 * Address: 0x00B07C60 (sub_B07C60)
 *
 * What it does:
 * Enables ADXPC DVD-error reporting flag lane.
 */
std::int32_t ADXPC_EnableDvdErrorReporting();

/**
 * Address: 0x00B07C70 (sub_B07C70)
 *
 * What it does:
 * Disables ADXPC DVD-error reporting flag lane.
 */
std::int32_t ADXPC_DisableDvdErrorReporting();

/**
 * Address: 0x00B165D0 (sub_B165D0)
 *
 * What it does:
 * Writes ADXPC DVD-error reporting mode flag and returns the written value.
 */
std::int32_t ADXPC_SetDvdErrorReportingEnabled(std::int32_t enabled);

/**
 * Address: 0x00B15FB0 (FUN_00B15FB0, func_SofDec_DefaultWaveFormat)
 *
 * What it does:
 * Writes one default 44.1kHz/16-bit PCM stereo-or-mono wave-format block.
 */
moho::SofdecPcmWaveFormat*
SofdecBuildDefaultPcmWaveFormat(std::uint16_t channels, moho::SofdecPcmWaveFormat* outWaveFormat);

/**
 * Address: 0x00B16010 (FUN_00B16010, sub_B16010)
 *
 * What it does:
 * Starts one DirectSound buffer and polls status until playback bit sets
 * or timeout/error path triggers.
 */
std::int32_t SofdecStartBufferAndWaitForPlaying(IDirectSoundBuffer* soundBuffer);

/**
 * Address: 0x00B160F0 (FUN_00B160F0, _mwSndStop)
 *
 * What it does:
 * Stops one DirectSound buffer and polls until playback bit clears.
 */
void SofdecStopBufferAndWaitForIdle(IDirectSoundBuffer* soundBuffer);

/**
 * Address: 0x00B161C0 (FUN_00B161C0, func_SofDec_RestoreSoundBuffer)
 *
 * What it does:
 * Creates and zero-fills the global restore-probe DirectSound buffer.
 */
std::int32_t SofdecCreateRestoreProbeBuffer();

/**
 * Address: 0x00B162B0 (FUN_00B162B0, func_SofDec_Stop)
 *
 * What it does:
 * Stops/releases the global restore-probe DirectSound buffer.
 */
void SofdecShutdownRestoreProbeBuffer();

/**
 * Address: 0x00B164A0 (FUN_00B164A0, sub_B164A0)
 *
 * What it does:
 * Mirrors current play cursor from primary to secondary port buffer.
 */
std::int32_t SofdecMirrorPrimaryCursorToSecondaryBuffer(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B164E0 (FUN_00B164E0, func_DirectSoundBuffer_Restore)
 *
 * What it does:
 * Returns success for no-error or `DSERR_BUFFERLOST` after calling `Restore`.
 */
std::int32_t SofdecRestoreBufferIfLost(IDirectSoundBuffer* soundBuffer, std::int32_t operationResult);

/**
 * Address: 0x00B16510 (FUN_00B16510, SofDecVirt::Init)
 *
 * What it does:
 * Captures DirectSound runtime lane and clears sound-port slot activity.
 */
IDirectSoundBuffer** SofdecInitSoundPortRuntime(IDirectSound* directSound);

/**
 * Address: 0x00B16580 (FUN_00B16580, SofDecVirt::Func2)
 *
 * What it does:
 * Stops sound-port runtime and clears global mode/slot lanes.
 */
std::uint32_t* SofdecShutdownSoundPortRuntime();

/**
 * Address: 0x00B165E0 (FUN_00B165E0, func_SofDec_NextUnk3)
 *
 * What it does:
 * Finds first free sound-port slot in the fixed 32-entry pool.
 */
moho::SofdecSoundPort* SofdecAcquireFreeSoundPort();

/**
 * Address: 0x00B16610 (FUN_00B16610, sub_B16610)
 *
 * What it does:
 * Resets one sound-port slot to zeroed state.
 */
std::int32_t SofdecResetSoundPort(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16630 (FUN_00B16630, func_SofDec_CreateSoundBuffer)
 *
 * What it does:
 * Creates one DirectSound playback buffer using current Sofdec mode flags.
 */
IDirectSoundBuffer* SofdecCreatePlaybackBuffer(std::int32_t channels, std::uint32_t bufferBytes);

/**
 * Address: 0x00B16750 (FUN_00B16750, mwSndOpenPort)
 *
 * What it does:
 * Opens/configures one Sofdec sound-port handle from the slot pool.
 */
moho::SofdecSoundPort* SofdecOpenSoundPort(std::int32_t channels);

/**
 * Address: 0x00B16870 (FUN_00B16870, SofDecVirt2_Func1)
 *
 * What it does:
 * Closes one sound-port handle, releasing buffers and pool slot state.
 */
std::int32_t SofdecCloseSoundPort(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B168D0 (FUN_00B168D0, SofDecVirt2_Func2)
 *
 * What it does:
 * Stops/drains active sound-port buffers and re-synchronizes dual-buffer
 * cursor state when secondary buffer exists.
 */
std::int32_t SofdecDrainAndSyncSoundPort(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16990 (FUN_00B16990, SofDecVirt2_Func3)
 *
 * What it does:
 * Stops one sound-port's primary/secondary buffers and validates the global
 * restore-probe lane when present.
 */
void SofdecStopSoundPortBuffers(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B162E0 (FUN_00B162E0, sub_B162E0)
 *
 * What it does:
 * Recreates the global restore-probe buffer and starts one looped warmup play.
 */
std::int32_t SofdecWarmRestoreProbePlayback();

/**
 * Address: 0x00B163D0 (FUN_00B163D0, sub_B163D0)
 *
 * What it does:
 * Stops active restore-probe playback lane and then shuts probe state down.
 */
void SofdecStopWarmRestoreProbeAndShutdown();

/**
 * Address: 0x00B16A20 (FUN_00B16A20, SofDecVirt2_Func4)
 *
 * What it does:
 * Locks/unlocks one 8-byte probe window and returns one computed frame-span lane.
 */
std::int32_t SofdecLockProbeWindowAndGetFrameSpan(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16AD0 (FUN_00B16AD0, SofDecVirt2_Func5)
 *
 * What it does:
 * Updates one channel-mode lane and reapplies spatial preset state when needed.
 */
std::int32_t SofdecSetChannelMode(moho::SofdecSoundPort* soundPort, std::int32_t channelMode);

/**
 * Address: 0x00B16B10 (FUN_00B16B10, SofDecVirt2_Func6)
 *
 * What it does:
 * Returns current primary-buffer play cursor in decoded frame units.
 */
std::int32_t SofdecGetPlaybackFrameCursor(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16B80 (FUN_00B16B80, SofDecVirt2_Func7)
 *
 * What it does:
 * Sets one target playback frequency lane with [100,100000] clamp.
 */
std::int32_t SofdecSetPlaybackFrequencyHz(moho::SofdecSoundPort* soundPort, std::int32_t frequencyHz);

/**
 * Address: 0x00B16BD0 (FUN_00B16BD0, SofDecVirt2_Func8)
 *
 * What it does:
 * Returns target playback frequency lane.
 */
std::int32_t SofdecGetPlaybackFrequencyHz(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16C00 (FUN_00B16C00, SofDecVirt2_Func9)
 *
 * What it does:
 * Sets output bit-depth lane used by cursor/sample conversions.
 */
std::int32_t SofdecSetOutputBitsPerSample(moho::SofdecSoundPort* soundPort, std::int16_t bitsPerSample);

/**
 * Address: 0x00B16C30 (FUN_00B16C30, SofDecVirt2_Func10)
 *
 * What it does:
 * Returns current output bit-depth lane.
 */
std::int32_t SofdecGetOutputBitsPerSample(const moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16C60 (FUN_00B16C60, SofDecVirt2_Func11)
 *
 * What it does:
 * Applies base volume lane and commits effective gain to DirectSound.
 */
std::int32_t SofdecSetBaseVolumeLevel(moho::SofdecSoundPort* soundPort, std::int32_t volumeLane);

/**
 * Address: 0x00B16CE0 (FUN_00B16CE0, SofDecVirt2_Func12)
 *
 * What it does:
 * Validates the primary-buffer lane for volume paths and returns zero.
 */
std::int32_t SofdecValidatePrimaryBufferForVolumeOps(const moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16D60 (FUN_00B16D60, SofDecVirt2_Func13)
 *
 * What it does:
 * Configures one spatial preset lane and applies live pan/volume when eligible.
 */
moho::SofdecSoundPort*
SofdecConfigureSpatialPreset(moho::SofdecSoundPort* soundPort, std::int32_t channelLane, std::int32_t presetIndex);

/**
 * Address: 0x00B16DE0 (FUN_00B16DE0, sub_B16DE0)
 *
 * What it does:
 * Internal spatial-preset application lane (pan curve + volume offset).
 */
std::int32_t
SofdecApplySpatialPresetInternal(moho::SofdecSoundPort* soundPort, std::int32_t channelLane, std::int32_t presetIndex);

/**
 * Address: 0x00B16E60 (FUN_00B16E60, sub_B16E60)
 *
 * What it does:
 * Clears spatial preset offset and reapplies base pan/volume lanes.
 */
std::int32_t SofdecResetSpatialPreset(moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16E90 (FUN_00B16E90, SofDecVirt2_Func14)
 *
 * What it does:
 * Validates the primary-buffer lane for balance paths and returns zero.
 */
std::int32_t SofdecValidatePrimaryBufferForBalanceOps(const moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16EC0 (FUN_00B16EC0, SofDecVirt2_Func15)
 *
 * What it does:
 * Sets balance index lane and commits mapped pan to DirectSound.
 */
void SofdecSetBalanceIndex(moho::SofdecSoundPort* soundPort, std::int32_t balanceIndex);

/**
 * Address: 0x00B16F30 (FUN_00B16F30, SofDecVirt2_Func16)
 *
 * What it does:
 * Returns current balance index lane.
 */
std::int32_t SofdecGetBalanceIndex(const moho::SofdecSoundPort* soundPort);

/**
 * Address: 0x00B16F60 (FUN_00B16F60, sub_B16F60)
 *
 * What it does:
 * Internal control lane that pushes target frequency into DirectSound.
 */
std::int32_t SofdecApplyControlFrequencyInternal(moho::SofdecSoundPort* soundPort, std::int32_t frequencyHz);

/**
 * Address: 0x00B16FC0 (FUN_00B16FC0, SofDecVirt2_Func17)
 *
 * What it does:
 * Dispatches one control-code lane to frequency-control helper.
 */
std::int32_t
SofdecControlSetValue(moho::SofdecSoundPort* soundPort, std::int32_t controlCode, std::int32_t controlValue);

/**
 * Address: 0x00B16FE0 (FUN_00B16FE0, SofDecVirt2_Func18)
 *
 * What it does:
 * Clears two output counters and returns first output pointer.
 */
std::int32_t* SofdecQueryPendingWindow(
  std::int32_t contextLane,
  std::int32_t queryLane,
  std::int32_t* outPrimary,
  std::int32_t* outSecondary
);

/**
 * Address: 0x00B07C80 (_ADXM_SetupThrd)
 * Body: 0x00B06C10 (_adxm_setup_thrd)
 *
 * IDA signature:
 * void __cdecl ADXM_SetupThrd(moho::AdxmThreadStartupParams const* startupParams);
 *
 * What it does:
 * Initializes ADXM synchronization/timer/thread runtime.
 */
void ADXM_SetupThrd(const moho::AdxmThreadStartupParams* startupParams);

/**
 * Address: 0x00B06C00 (_ADXM_SetCbErr thunk)
 * Body: 0x00B0C760 (_SVM_SetCbErr)
 *
 * IDA signature:
 * void __cdecl ADXM_SetCbErr(moho::AdxmErrorCallback callback, int callbackParam);
 *
 * What it does:
 * Publishes the process-global Sofdec/ADXM error callback.
 */
void ADXM_SetCbErr(moho::AdxmErrorCallback callback, std::int32_t callbackParam);

/**
 * Address: 0x00B06FC0 (FUN_00B06FC0, _ADXM_SetCbSleepMwIdle)
 *
 * What it does:
 * Publishes ADXM mw-idle sleep callback/context lanes and returns callback.
 */
moho::AdxmMwIdleSleepCallback ADXM_SetCbSleepMwIdle(moho::AdxmMwIdleSleepCallback callback, std::int32_t callbackParam);

/**
 * Address: 0x00B06E40 (FUN_00B06E40, _ADXM_GetLockLevel)
 *
 * What it does:
 * Returns current ADXM lock nesting level lane.
 */
std::int32_t ADXM_GetLockLevel();

/**
 * Address: 0x00B07420 (sub_B07420)
 *
 * What it does:
 * Returns current ADXM interval lane #1.
 */
std::int32_t ADXM_GetInterval1();

/**
 * Address: 0x00B074B0 (func_SofdecSetFunc1)
 *
 * What it does:
 * Publishes Sofdec frame-read callback after signal acquisition.
 */
std::int32_t SofdecSetFrameReadCallback(std::uint32_t(__cdecl* callback)());

/**
 * Address: 0x00B074F0 (sub_B074F0)
 *
 * What it does:
 * Sets ADXM interval lane #2 and returns the written value.
 */
std::int32_t ADXM_SetInterval2(std::int32_t interval);

/**
 * Address: 0x00B07500 (func_SofdecSetScreenHeight2)
 *
 * What it does:
 * Sets Sofdec secondary screen-height lane and returns the written value.
 */
std::int32_t SofdecSetScreenHeight2(std::int32_t screenHeight);

/**
 * Address: 0x00B07870 (func_SofdecWaitForSignal2)
 *
 * What it does:
 * Repeatedly tries `_SVM_TestAndSet` on one local signal lane for up to
 * 1000 one-millisecond retries.
 */
std::int32_t SofdecWaitForSignal2(std::int32_t signalLaneValue);

/**
 * Address: 0x00B078B0 (nullsub_30)
 *
 * What it does:
 * No-op signal-release callback lane.
 */
void SofdecSignalReleaseNoOp(std::int32_t signalLaneValue);

/**
 * Address: 0x00B078C0 (sub_B078C0)
 *
 * What it does:
 * Applies global scanline offset to one in/out value with clamp/underflow
 * behavior used by Sofdec wait timing logic.
 */
std::uint32_t SofdecApplyScanlineOffset(std::uint32_t* valueInOut, std::uint32_t clampMax);

/**
 * Address: 0x00B07900 (sub_B07900)
 *
 * What it does:
 * Sets global Sofdec scanline offset lane and returns the written value.
 */
std::int32_t SofdecSetScanlineOffset(std::int32_t offset);

/**
 * Address: 0x00B07430 (sub_B07430)
 *
 * What it does:
 * Arms ADXM multimedia-timer switch lanes and returns previous arm state.
 */
std::int32_t ADXM_ArmMultimediaTimerSwitch();

/**
 * Address: 0x00B07450 (sub_B07450)
 *
 * What it does:
 * Disarms ADXM multimedia-timer switch lanes and starts 1ms multimedia timer.
 */
void ADXM_StartMultimediaTimer();

/**
 * Address: 0x00B07490 (sub_B07490)
 *
 * What it does:
 * Pulses ADXM sync event lane when present and returns event handle/result.
 */
void* ADXM_PulseSyncEvent();

/**
 * Address: 0x00B07750 (sub_B07750)
 *
 * What it does:
 * Waits until current scanline reaches target window for one interval.
 */
std::int32_t ADXM_WaitForScanlineTarget(std::uint32_t interval, std::uint32_t screenHeight);

/**
 * Address: 0x00B07910 (sub_B07910)
 *
 * What it does:
 * Updates ADXM scanline synchronization for the active callback lane.
 */
std::int32_t ADXM_UpdateScanlineSync();

/**
 * Address: 0x00B07A70 (sub_B07A70)
 *
 * What it does:
 * Waits until scanline drops to lower-half window for current interval.
 */
std::uint32_t ADXM_WaitForScanlineHalfWindow(std::uint32_t interval, std::uint32_t screenHeight);

/**
 * Address: 0x00B06E50 (_ADXM_ExecMain)
 *
 * IDA signature:
 * void __cdecl ADXM_ExecMain(void);
 *
 * What it does:
 * Pumps one ADXM middleware frame.
 */
void ADXM_ExecMain();

/**
 * Address: 0x00B0A390 (_ADXT_Init)
 *
 * What it does:
 * Initializes ADXT middleware runtime subsystems on first-use and bumps
 * ADXT init reference count.
 */
void ADXT_Init();

/**
 * Address: 0x00B0D9C0 (_ADXT_SetOutPan)
 *
 * What it does:
 * Runs one ADXT output-pan update inside legacy ADX enter/leave wrappers and forwards to
 * `adxt_SetOutPan`.
 */
void ADXT_SetOutPan(void* adxtRuntime, std::int32_t laneIndex, std::int32_t panLevel);

/**
 * Address: 0x00B0D9F0 (_adxt_SetOutPan)
 *
 * What it does:
 * Resolves one effective channel pan (default/override/mono rules), stores
 * the caller pan lane, and applies output pan to ADX RNA.
 */
std::int32_t adxt_SetOutPan(void* adxtRuntime, std::int32_t laneIndex, std::int32_t panLevel);

/**
 * Address: 0x00AC9130 (_mwPlyInitSfdFx)
 *
 * IDA signature:
 * void __cdecl mwPlyInitSfdFx(moho::MwsfdInitPrm* initParams);
 *
 * What it does:
 * Initializes movie Sofdec playback runtime and first-use middleware state.
 */
void mwPlyInitSfdFx(moho::MwsfdInitPrm* initParams);

/**
 * Address: 0x00AC93D0 (_mwPlyFinishSfdFx)
 *
 * What it does:
 * Shuts down movie Sofdec playback runtime when init reference count reaches 0.
 */
void mwPlyFinishSfdFx();

/**
 * Address: 0x00AC9120 (_MWSFLIB_GetLibWorkPtr)
 *
 * What it does:
 * Returns one pointer to global MWSFD library work lane.
 */
moho::MwsfdLibWork* MWSFLIB_GetLibWorkPtr();

/**
 * Address: 0x00AC9490 (_mwPlySfdInit)
 *
 * What it does:
 * Initializes SFD runtime for one requested middleware version and installs
 * the global SFD error callback lane.
 */
std::int32_t mwPlySfdInit(std::int32_t requestedVersion);

/**
 * Address: 0x00AC9530 (_mwPlySfdFinish)
 *
 * What it does:
 * Runs one global SFD shutdown pass and returns success.
 */
std::int32_t mwPlySfdFinish();

/**
 * Address: 0x00AC9280 (_mwsflib_LscErrFunc)
 *
 * What it does:
 * Bridges one LSC error callback message into `MWSFSVM_Error`.
 */
void mwsflib_LscErrFunc(std::int32_t callbackObject, const char* message);

/**
 * Address: 0x00AC92D0 (_mwsflib_InitLibWork)
 *
 * What it does:
 * Resets global MWSFD lib-work storage and applies runtime startup defaults.
 */
void mwsflib_InitLibWork(moho::MwsfdInitPrm* initParams);

/**
 * Address: 0x00AC9380 (_mwsflib_SetDefCond)
 *
 * What it does:
 * Applies two startup condition lanes for default movie playback timing.
 */
std::int32_t mwsflib_SetDefCond(const float* startupConditionValue);

/**
 * Address: 0x00AC9470 (_MWSFLIB_SetErrCode)
 *
 * What it does:
 * Stores one global MWSFD error code lane and returns the same value.
 */
std::int32_t MWSFLIB_SetErrCode(std::int32_t errorCode);

/**
 * Address: 0x00AC96A0 (_MWSFLIB_SetSeekFlg)
 *
 * What it does:
 * Sets global MWSFD seek-flag lane.
 */
void MWSFLIB_SetSeekFlg(std::int32_t enabled);

/**
 * Address: 0x00AC96B0 (_MWSFLIB_GetSeekFlg)
 *
 * What it does:
 * Returns global MWSFD seek-flag lane.
 */
std::int32_t MWSFLIB_GetSeekFlg();

/**
 * Address: 0x00AC9290 (_mwsflib_SetSvrFunc)
 *
 * What it does:
 * Registers MWSFSVR thread-entry callbacks in MWSFSVM runtime lanes.
 */
void mwsflib_SetSvrFunc();

/**
 * Address: 0x00AC8D10 (FUN_00AC8D10, _mwply_Destroy)
 *
 * What it does:
 * Stops active decode lanes, tears down all linked playback resources,
 * checks allocation leak counters, and clears the playback object.
 */
void mwply_Destroy(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC8D00 (FUN_00AC8D00, _mwPlyDestroy)
 *
 * What it does:
 * Public teardown wrapper that forwards one playback handle to
 * `mwply_Destroy`.
 */
void mwPlyDestroy(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC8F60 (FUN_00AC8F60, _MWSFD_Malloc)
 *
 * What it does:
 * Allocates one playback-owned Sofdec work block and tracks it in the
 * per-playback allocation table.
 */
void* MWSFD_Malloc(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t size);

/**
 * Address: 0x00ACA090 (FUN_00ACA090, _mwPlyGetCurFrm)
 *
 * What it does:
 * Fetches the current SFD frame into one runtime frame-info object and
 * updates playback frame counters/concat tracking lanes.
 */
moho::MwsfdFrameInfo* mwPlyGetCurFrm(moho::MwsfdPlaybackStateSubobj* ply, moho::MwsfdFrameInfo* outFrameInfo);

/**
 * Address: 0x00ACA760 (FUN_00ACA760, _mwPlyRelCurFrm)
 *
 * What it does:
 * Releases one current SFD frame lane and advances release/retrieve cursors
 * when a frame is still pending in playback state.
 */
void mwPlyRelCurFrm(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACA8A0 (_mwPlyGetNumSkipDisp)
 *
 * What it does:
 * Returns display-skip counter lane tracked by one playback object.
 */
std::int32_t mwPlyGetNumSkipDisp(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB5C0 (_mwPlyGetSfdHn)
 *
 * What it does:
 * Returns active SFD handle-address lane when playback handle is valid.
 */
std::int32_t mwPlyGetSfdHn(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB620 (_mwPlyGetNumDropFrm)
 *
 * What it does:
 * Returns aggregate dropped-frame count (decode-skip + display-skip).
 */
std::int32_t mwPlyGetNumDropFrm(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB660 (_mwPlyGetNumSkipDec)
 *
 * What it does:
 * Returns decode-skip counter lane from SFD playback-info snapshot.
 */
std::int32_t mwPlyGetNumSkipDec(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB8E0 (_MWSFD_GetPlyInf)
 *
 * What it does:
 * Copies current SFD playback-info snapshot into caller output buffer.
 */
std::int32_t MWSFD_GetPlyInf(moho::MwsfdPlaybackStateSubobj* ply, void* outPlyInfo);

/**
 * Address: 0x00ACB950 (FUN_00ACB950, _MWSFD_GetCond)
 *
 * What it does:
 * Reads one condition lane from the active playback SFD handle, or from
 * process-global defaults when playback handle is null.
 */
std::int32_t
MWSFD_GetCond(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t conditionId, std::int32_t* outConditionValue);

namespace moho
{
  /**
   * Runtime ADXT parameter block mirrored into global `sfadxt_para`.
   */
  struct SofdecAdxtParams
  {
    std::int32_t value0 = 0; // +0x00
    std::int32_t value1 = 0; // +0x04
    std::int32_t adxWorkBytes = 0; // +0x08
    std::int32_t value3 = 0; // +0x0C
    std::int32_t value4 = 0; // +0x10
    std::int32_t value5 = 0; // +0x14
    std::int32_t adxInputBufferBytes = 0; // +0x18
  };

  static_assert(offsetof(SofdecAdxtParams, value0) == 0x00, "SofdecAdxtParams::value0 offset must be 0x00");
  static_assert(offsetof(SofdecAdxtParams, value1) == 0x04, "SofdecAdxtParams::value1 offset must be 0x04");
  static_assert(
    offsetof(SofdecAdxtParams, adxWorkBytes) == 0x08,
    "SofdecAdxtParams::adxWorkBytes offset must be 0x08"
  );
  static_assert(offsetof(SofdecAdxtParams, value3) == 0x0C, "SofdecAdxtParams::value3 offset must be 0x0C");
  static_assert(offsetof(SofdecAdxtParams, value4) == 0x10, "SofdecAdxtParams::value4 offset must be 0x10");
  static_assert(offsetof(SofdecAdxtParams, value5) == 0x14, "SofdecAdxtParams::value5 offset must be 0x14");
  static_assert(
    offsetof(SofdecAdxtParams, adxInputBufferBytes) == 0x18,
    "SofdecAdxtParams::adxInputBufferBytes offset must be 0x18"
  );
  static_assert(sizeof(SofdecAdxtParams) == 0x1C, "SofdecAdxtParams size must be 0x1C");
} // namespace moho

/**
 * Address: 0x00AD88E0 (FUN_00AD88E0, _SFD_GetCond)
 *
 * What it does:
 * Reads one condition value from work-control condition storage, validating
 * handle state for non-null work-control objects.
 */
std::int32_t
SFD_GetCond(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId, std::int32_t* outConditionValue);

/**
 * Address: 0x00AD0270 (FUN_00AD0270, _SFD_SetAdxtPara)
 *
 * What it does:
 * Copies one ADXT parameter block into global `sfadxt_para`, applying the
 * binary alignment rules for ADXT work/input buffer lanes.
 */
std::int32_t SFD_SetAdxtPara(const moho::SofdecAdxtParams* params);

/**
 * Address: 0x00AD1900 (FUN_00AD1900, _SFD_SetMpvCond)
 *
 * What it does:
 * Applies one MPV condition callback lane for a specific SFD work-control
 * handle (or global lane when handle is null).
 */
std::int32_t SFD_SetMpvCond(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t conditionId,
  std::int32_t (*conditionCallback)()
);

/**
 * Address: 0x00AD16A0 (FUN_00AD16A0, _SFD_SetMpvPara)
 *
 * What it does:
 * Copies one MPV parameter snapshot into global runtime lanes and resets
 * ring-buffer/tab tables.
 */
std::int32_t SFD_SetMpvPara(const void* parameterSnapshot);

/**
 * Address: 0x00AD1A50 (FUN_00AD1A50, _SFD_SetVideoUsrSj)
 *
 * What it does:
 * Validates one SFD handle and forwards one video user-stream lane into MPV.
 */
std::int32_t SFD_SetVideoUsrSj(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t streamIndex,
  std::int32_t streamObjectAddress,
  std::int32_t streamCallbackAddress,
  std::int32_t streamContextAddress
);

  /**
   * Address: 0x00AD6DE0 (FUN_00AD6DE0, _SFPLY_Init)
   *
   * What it does:
   * Initializes SFPLY runtime defaults and clears record-get-frame counter.
   */
  std::int32_t SFPLY_Init();

  /**
   * Address: 0x00AD1B70 (FUN_00AD1B70, _SFMPV_Init)
   *
   * What it does:
   * Initializes the global Sofdec MPV lane, validates fatal-startup state,
   * and clears the MPV parameter/table storage on success.
   */
  std::int32_t SFMPV_Init();

  /**
   * Address: 0x00AD9290 (FUN_00AD9290, _mwSfdVsync)
   *
   * What it does:
 * Advances MWSFD vsync counters, enters SFD vertical-blank lane under
 * `MWSFSVM_TestAndSet(initLatch)` guard, then releases the latch.
 */
std::int32_t mwSfdVsync();

/**
 * Address: 0x00AD6E00 (FUN_00AD6E00, _SFD_VbIn)
 *
 * What it does:
 * Forwards one SFD vertical-blank enter lane to timer runtime.
 */
std::int32_t SFD_VbIn();

/**
 * Address: 0x00AD6E10 (FUN_00AD6E10, _SFD_VbOut)
 *
 * What it does:
 * Reserved vertical-blank leave lane (no-op in this build).
 */
void SFD_VbOut();

/**
 * Address: 0x00AD6E20 (FUN_00AD6E20, _SFD_IsHnSvrWait)
 *
 * What it does:
 * Returns whether one SFD handle can proceed outside server-wait states.
 */
std::int32_t SFD_IsHnSvrWait(std::int32_t sfdHandleAddress);

/**
 * Address: 0x00AD6EC0 (FUN_00AD6EC0, _SFD_ExecServer)
 *
 * What it does:
 * Runs one decode-server tick for all valid SFD handles and returns aggregate
 * server status.
 */
std::int32_t SFD_ExecServer();

/**
 * Address: 0x00AD6E90 (FUN_00AD6E90, _SFD_ExecOne)
 *
 * What it does:
 * Executes one SFD per-handle server step after handle validation.
 */
std::int32_t SFD_ExecOne(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AECEF0 (FUN_00AECEF0, _SFD_SetSeekPosTbl)
 *
 * What it does:
 * Validates one SFD handle and writes one seek-position table lane value into
 * attached SFSEE runtime state.
 */
std::int32_t SFD_SetSeekPosTbl(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t seekTableAddress);

/**
 * Address: 0x00AECF30 (FUN_00AECF30, _SFD_StartHeadAnaly)
 *
 * What it does:
 * Validates one SFD handle, enables condition lane `47`, and transitions
 * playback into standby for header analysis.
 */
std::int32_t SFD_StartHeadAnaly(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AECF70 (FUN_00AECF70, _SFD_IsHeadAnalyEnd)
 *
 * What it does:
 * Validates one SFD handle and mirrors SFSEE header-analysis completion flag
 * into caller output storage.
 */
std::int32_t SFD_IsHeadAnalyEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outHeadAnalyzed);

/**
 * Address: 0x00ADBA60 (FUN_00ADBA60, _SFD_GetPlayFps)
 *
 * What it does:
 * Returns effective playback FPS for one handle from timer frame-rate and
 * time-base scale lanes.
 */
std::int32_t SFD_GetPlayFps(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outPlayFramesPerSecond);

/**
 * Address: 0x00AE60E0 (FUN_00AE60E0, _SFD_GetTimePerFile)
 *
 * What it does:
 * Returns per-file adjusted playback time lanes and file-history ordinal from
 * timer and queued sample-total history state.
 */
std::int32_t SFD_GetTimePerFile(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t* outTimeMajor,
  std::int32_t* outTimeMinor,
  std::int32_t* outFileHistoryOrdinal
);

/**
 * Address: 0x00ADB350 (FUN_00ADB350, _SFD_OutUsrFrmSync)
 *
 * What it does:
 * Validates one SFD handle, increments user-frame sync sequence lane, and
 * marks output-sync state as dirty.
 */
std::int32_t SFD_OutUsrFrmSync(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00ADBB30 (FUN_00ADBB30, _SFD_OutDispSync)
 *
 * What it does:
 * Validates one SFD handle, stores display-sync time lanes, increments
 * display-sync sequence lane, and marks output-sync state as dirty.
 */
std::int32_t
SFD_OutDispSync(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t displayTimeMajor, std::int32_t displayTimeMinor);

/**
 * Address: 0x00ADBF60 (FUN_00ADBF60, _SFD_LockFrm)
 *
 * What it does:
 * Locks one frame-object lane resolved from a frame-search slot and increments
 * per-handle lock depth.
 */
std::int32_t SFD_LockFrm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t frameSearchLaneAddress);

/**
 * Address: 0x00ADBFD0 (FUN_00ADBFD0, _SFD_UnlockFrm)
 *
 * What it does:
 * Unlocks one frame-object lane resolved from a frame-search slot and
 * decrements per-handle lock depth.
 */
std::int32_t SFD_UnlockFrm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t frameSearchLaneAddress);

/**
 * Address: 0x00AE0C70 (FUN_00AE0C70, _M2PES_GetVersionStr)
 *
 * What it does:
 * Returns the static CRI M2PES runtime version banner string.
 */
extern "C" const char* M2PES_GetVersionStr();

/**
 * Address: 0x00AE3230 (FUN_00AE3230, _M2T_GetVersionStr)
 *
 * What it does:
 * Returns the static CRI M2T runtime version banner string.
 */
extern "C" const char* M2T_GetVersionStr();

/**
 * Address: 0x00ADFD80 (FUN_00ADFD80, _M2TSD_GetVersionStr)
 *
 * What it does:
 * Returns the static CRI M2TSD runtime version banner string.
 */
extern "C" const char* M2TSD_GetVersionStr();

/**
 * Address: 0x00AD6FD0 (FUN_00AD6FD0, _sfply_ExecOneSub)
 *
 * What it does:
 * Executes transfer-server and SFSEE server lanes for one SFD handle.
 */
std::int32_t sfply_ExecOneSub(std::int32_t workctrlAddress);

/**
 * Address: 0x00AD6FF0 (FUN_00AD6FF0, _sfply_TrExecServer)
 *
 * What it does:
 * Dispatches transfer setup callback lane `2` for one SFD handle.
 */
std::int32_t sfply_TrExecServer(std::int32_t workctrlAddress);

/**
 * Address: 0x00AD7000 (FUN_00AD7000, _sfply_StatStop)
 *
 * What it does:
 * Resolves STOP state lane for one playback handle from current phase flags.
 */
std::int32_t sfply_StatStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7020 (FUN_00AD7020, _sfply_StatPrep)
 *
 * What it does:
 * Resolves PREP state lane and dispatches transfer start when sync gate opens.
 */
std::int32_t sfply_StatPrep(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD70A0 (FUN_00AD70A0, _sfply_IsPrepEnd)
 *
 * What it does:
 * Checks whether audio/video transfer preparation lanes are completed.
 */
std::int32_t sfply_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7120 (FUN_00AD7120, _sfply_AdjustPrepEnd)
 *
 * What it does:
 * Finalizes PREP completion by fixing AV flags, sync mode, and ETRG lane.
 */
std::int32_t sfply_AdjustPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7140 (FUN_00AD7140, _sfply_FixAvPlay)
 *
 * What it does:
 * Clears stale AV condition lanes when ring-buffer totals are empty.
 */
std::int32_t sfply_FixAvPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD71C0 (FUN_00AD71C0, _sfply_AdjustSyncMode)
 *
 * What it does:
 * Normalizes sync-mode condition lane against current AV-enable conditions.
 */
std::int32_t sfply_AdjustSyncMode(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7210 (FUN_00AD7210, _sfply_AdjustEtrg)
 *
 * What it does:
 * Reconciles ETRG condition lane (`25`) from AV-enable lanes and timer policy.
 */
std::int32_t sfply_AdjustEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD72A0 (FUN_00AD72A0, _sfply_StatStby)
 *
 * What it does:
 * Resolves STANDBY state lane and starts transfers once sync preconditions hold.
 */
std::int32_t sfply_StatStby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7310 (FUN_00AD7310, _sfply_StatPlay)
 *
 * What it does:
 * Resolves PLAY state lane with finish and BPA transition checks.
 */
std::int32_t sfply_StatPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7350 (FUN_00AD7350, _sfply_StatFin)
 *
 * What it does:
 * Returns current FIN state lane from one playback work-control object.
 */
std::int32_t sfply_StatFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7360 (FUN_00AD7360, _sfply_IsStartSync)
 *
 * What it does:
 * Evaluates whether transfer start is sync-safe for one playback handle.
 */
std::int32_t sfply_IsStartSync(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD73C0 (FUN_00AD73C0, _sfply_ChkBpa)
 *
 * What it does:
 * Toggles BPA pause state under SFLIB critical section and dispatches pause op.
 */
std::int32_t sfply_ChkBpa(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7440 (FUN_00AD7440, _sfply_IsBpaOn)
 *
 * What it does:
 * Decides whether BPA pause should be enabled from playback/data/timer lanes.
 */
std::int32_t sfply_IsBpaOn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7580 (FUN_00AD7580, _sfply_IsBpaOff)
 *
 * What it does:
 * Decides whether BPA pause should be released from playback/data/timer lanes.
 */
std::int32_t sfply_IsBpaOff(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7640 (FUN_00AD7640, _sfply_IsAnyoneTerm)
 *
 * What it does:
 * Checks transfer and buffer termination flags across active playback lanes.
 */
std::int32_t sfply_IsAnyoneTerm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD76B0 (FUN_00AD76B0, _sfply_EnoughViData)
 *
 * What it does:
 * Checks whether the active video lane has enough buffered data for playback.
 */
std::int32_t sfply_EnoughViData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7720 (FUN_00AD7720, _sfply_EnoughAiData)
 *
 * What it does:
 * Checks whether the active audio lane has enough buffered data for playback.
 */
std::int32_t sfply_EnoughAiData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7780 (FUN_00AD7780, _sfply_ChkFin)
 *
 * What it does:
 * Evaluates all playback finish triggers and transitions to FIN when hit.
 */
std::int32_t sfply_ChkFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD77D0 (FUN_00AD77D0, _sfply_IsEtime)
 *
 * What it does:
 * Checks whether current playback time reached configured end time.
 */
std::int32_t sfply_IsEtime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7830 (FUN_00AD7830, _sfply_IsEtrg)
 *
 * What it does:
 * Evaluates end-trigger condition policy from transfer termination flags.
 */
std::int32_t sfply_IsEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD78B0 (FUN_00AD78B0, _sfply_IsStagnant)
 *
 * What it does:
 * Checks playback stagnation under active-playing and non-paused conditions.
 */
std::int32_t sfply_IsStagnant(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD78F0 (FUN_00AD78F0, _sfply_IsPlayTimeAutoStop)
 *
 * What it does:
 * Checks whether configured play-time auto-stop condition has been reached.
 */
std::int32_t sfply_IsPlayTimeAutoStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7960 (FUN_00AD7960, _sfply_Fin)
 *
 * What it does:
 * Stops transfer lanes and transitions one playback handle to FIN phase.
 */
std::int32_t sfply_Fin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7990 (FUN_00AD7990, _SFPLY_DecideSvrStat)
 *
 * What it does:
 * Collapses all active SFD handle states into one global decode-server status
 * lane (`0`: idle, `1`: running, `2`: fault/terminal).
 */
std::int32_t sfply_DecideSvrStat();

/**
 * Address: 0x00AD7A30 (FUN_00AD7A30, _sfply_Create)
 *
 * What it does:
 * Validates create parameters, allocates a free SFLIB slot, and initializes one SFPLY handle.
 */
moho::SofdecSfdWorkctrlSubobj* sfply_Create(const moho::SfplyCreateParams* createParams, std::int32_t createContext);

/**
 * Address: 0x00AD7A80 (FUN_00AD7A80, _sfply_ChkCrePara)
 *
 * What it does:
 * Validates SFPLY create parameters and reports SFLIB error lanes on invalid input.
 */
std::int32_t sfply_ChkCrePara(const moho::SfplyCreateParams* createParams);

/**
 * Address: 0x00AD7AC0 (FUN_00AD7AC0, _sfply_SearchFreeHn)
 *
 * What it does:
 * Scans SFLIB object slots and returns first free handle index, or `-1`.
 */
std::int32_t sfply_SearchFreeHn();

/**
 * Address: 0x00AD7C30 (FUN_00AD7C30, _sfply_InitMvInf)
 *
 * What it does:
 * Resets one SFPLY movie-info lane to default sentinel values.
 */
std::int32_t sfply_InitMvInf(moho::SfplyMovieInfo* movieInfo);

/**
 * Address: 0x00AD7C80 (FUN_00AD7C80, _sfply_InitPlyInf)
 *
 * What it does:
 * Clears one SFPLY playback-info lane and initializes embedded flow counters.
 */
std::int32_t sfply_InitPlyInf(moho::SfplyPlaybackInfo* playbackInfo);

/**
 * Address: 0x00AD7CF0 (FUN_00AD7CF0, _sfply_InitFlowCnt)
 *
 * What it does:
 * Clears one SFPLY flow-counter lane.
 */
moho::SfplyFlowCount* sfply_InitFlowCnt(moho::SfplyFlowCount* flowCount);

/**
 * Address: 0x00AD7D10 (FUN_00AD7D10, _sfply_InitTmrInf)
 *
 * What it does:
 * Clears one SFPLY timer-info lane and initializes timer summaries.
 */
std::int32_t sfply_InitTmrInf(moho::SfplyTimerInfo* timerInfo);

/**
 * Address: 0x00AD7D80 (FUN_00AD7D80, _SFPLY_AddDecPic)
 *
 * What it does:
 * Accumulates decoded-picture count and dispatches optional condition callback.
 */
std::int32_t SFPLY_AddDecPic(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t decodedPictureDelta,
  std::int32_t callbackContext
);

/**
 * Address: 0x00AD7DC0 (FUN_00AD7DC0, _SFPLY_AddSkipPic)
 *
 * What it does:
 * Accumulates skipped-picture count and dispatches optional condition callback.
 */
std::int32_t SFPLY_AddSkipPic(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t skippedPictureDelta,
  std::int32_t callbackContext
);

/**
 * Address: 0x00AD7E00 (FUN_00AD7E00, _sfply_TrCreate)
 *
 * What it does:
 * Creates transfer lane setup for one SFPLY handle.
 */
std::int32_t sfply_TrCreate(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7E10 (FUN_00AD7E10, _SFD_Destroy)
 *
 * What it does:
 * Stops and destroys one SFD handle, then removes it from the global slot table.
 */
std::int32_t SFD_Destroy(void* sfdHandle);

/**
 * Address: 0x00AD7E70 (FUN_00AD7E70, _sfply_TrDestroy)
 *
 * What it does:
 * Clears SFPLY transfer state lanes and runs transfer destroy setup.
 */
std::int32_t sfply_TrDestroy(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7E90 (FUN_00AD7E90, _SFD_Start)
 *
 * What it does:
 * Starts one SFD handle in standby or immediate-play mode based on condition `47`.
 */
std::int32_t SFD_Start(void* sfdHandle);

/**
 * Address: 0x00AD7EF0 (FUN_00AD7EF0, _sfply_Start)
 *
 * What it does:
 * Transitions one SFPLY handle into PLAY phase.
 */
std::int32_t sfply_Start(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7F00 (FUN_00AD7F00, _sfply_TrStart)
 *
 * What it does:
 * Dispatches transfer start transition (`7 -> 6`) for one SFPLY handle.
 */
std::int32_t sfply_TrStart(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7F20 (FUN_00AD7F20, _SFD_Stop)
 *
 * What it does:
 * Stops one SFD handle and sets the server-wait/start gate lane.
 */
std::int32_t SFD_Stop(void* sfdHandle);

/**
 * Address: 0x00AD7F60 (FUN_00AD7F60, _SFPLY_Stop)
 *
 * What it does:
 * Stops transfer lanes and rebuilds/reset one SFPLY handle when needed.
 */
std::int32_t SFPLY_Stop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD7FA0 (FUN_00AD7FA0, _SFPLY_SetResetFlg)
 *
 * What it does:
 * Writes SFPLY global reset-guard flag and returns written value.
 */
std::int32_t SFPLY_SetResetFlg(std::int32_t enabled);

/**
 * Address: 0x00AD7FB0 (FUN_00AD7FB0, _SFPLY_GetResetFlg)
 *
 * What it does:
 * Reads SFPLY global reset-guard flag.
 */
std::int32_t SFPLY_GetResetFlg();

/**
 * Address: 0x00AD7FC0 (FUN_00AD7FC0, _sfply_TrStop)
 *
 * What it does:
 * Dispatches transfer stop transition and updates local stop-state lanes.
 */
std::int32_t sfply_TrStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00ACBA90 (FUN_00ACBA90, _mwPlyGetStat)
 *
 * What it does:
 * Returns one playback status lane, deriving stream-active/error states from
 * current SFD handle status when composition mode is streaming.
 */
std::int32_t mwPlyGetStat(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACBBC0 (FUN_00ACBBC0, _mwPlyGetSyncMode)
 *
 * What it does:
 * Reads playback sync-mode condition lane (`15`) and returns normalized mode
 * (`0`, `1`, `2`) with diagnostics on invalid state.
 */
std::int32_t mwPlyGetSyncMode(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACBFC0 (_mwPlyGetNumSkipEmptyB)
 *
 * What it does:
 * Returns empty-B skip counter lane from playback-info snapshot.
 */
std::int32_t mwPlyGetNumSkipEmptyB(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACC080 (_mwPlyGetPlyInf)
 *
 * What it does:
 * Writes six playback-debug counters into caller-provided output words.
 */
std::int32_t mwPlyGetPlyInf(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t* outInfoWords);

/**
 * Address: 0x00ACC6C0 (FUN_00ACC6C0, _mwPlyGetTimerCh)
 *
 * What it does:
 * Returns timer-channel lane from default condition slot `61`.
 */
void* mwPlyGetTimerCh(void* timerChannelFallback);

/**
 * Address: 0x00ACE9A0 (_SFX_CnvFrmByCbFunc)
 *
 * What it does:
 * Dispatches one SFX callback-frame conversion path based on composition mode.
 */
void SFX_CnvFrmByCbFunc(
  moho::SfxCallbackFrameContext* conversionState,
  moho::SfxStreamState* streamState,
  std::int32_t callbackArg
);

/**
 * Address: 0x00AD9340 (_mwsfsvr_DecodeServer)
 *
 * What it does:
 * Executes one decode-server tick over all playback lanes after lock/callback
 * gating.
 */
std::int32_t mwsfsvr_DecodeServer();

/**
 * Address: 0x00AD95C0 (_mwsfsvr_StartPlayback)
 *
 * What it does:
 * Starts/restarts one Sofdec playback lane under decode-server state checks.
 */
void mwsfsvr_StartPlayback(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB020 (_mwPlyStartMem)
 *
 * What it does:
 * Replaces active SJ supply with memory-backed source and restarts playback.
 */
std::int32_t mwPlyStartMem(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t bufferAddress, std::int32_t bufferSize);

/**
 * Address: 0x00ACB0C0 (_mwPlyStartSj)
 *
 * What it does:
 * Binds one SJ supply handle as active source and restarts playback.
 */
std::int32_t mwPlyStartSj(moho::MwsfdPlaybackStateSubobj* ply, moho::SofdecSjSupplyHandle* supplyHandle);

/**
 * Address: 0x00ACB1D0 (FUN_00ACB1D0, _mwply_Stop)
 *
 * What it does:
 * Stops decode + seamless link lanes for one playback handle and halts the
 * linked LSC stream lane.
 */
void mwply_Stop(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB1C0 (FUN_00ACB1C0, _mwPlyStop)
 *
 * What it does:
 * Thunk wrapper to `mwply_Stop`.
 */
void mwPlyStop(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACB390 (_MWSFPLY_RecordFname)
 *
 * What it does:
 * Copies one filename into playback-owned filename lane with bounded fallback.
 */
void MWSFPLY_RecordFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);

/**
 * Address: 0x00ADDB50 (_mwPlyEntryFname)
 *
 * What it does:
 * Enters one filename into LSC queue and updates seamless-entry counters.
 */
void mwPlyEntryFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);

/**
 * Address: 0x00ADDBC0 (_mwPlyStartSeamless)
 *
 * What it does:
 * Starts seamless playback lane and clears API mode latch.
 */
void mwPlyStartSeamless(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADDC30 (_mwPlySetSeamlessLp)
 *
 * What it does:
 * Sets seamless loop flag in linked LSC runtime lane.
 */
void mwPlySetSeamlessLp(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t enabled);

/**
 * Address: 0x00ADDCE0 (_mwPlyReleaseLp)
 *
 * What it does:
 * Clears seamless loop mode and releases current seamless link state.
 */
void mwPlyReleaseLp(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADDD20 (_mwPlyReleaseSeamless)
 *
 * What it does:
 * Unlinks seamless stream lane from active playback path.
 */
void mwPlyReleaseSeamless(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADDE00 (_mwPlyStartAfsLp)
 *
 * What it does:
 * Starts seamless-loop playback from AFS source range.
 */
void mwPlyStartAfsLp(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t afsHandle, std::int32_t fileIndex);

/**
 * Address: 0x00ADDD60 (_mwPlyEntryAfs)
 *
 * What it does:
 * Resolves one AFS file range and queues it into the playback LSC lane.
 */
void mwPlyEntryAfs(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t afsHandle, std::int32_t fileIndex);

/**
 * Address: 0x00ADDE50 (_mwPlyEntryFnameRange)
 *
 * What it does:
 * Queues one filename + range into LSC lane for seamless playlist startup.
 */
void mwPlyEntryFnameRange(
  moho::MwsfdPlaybackStateSubobj* ply,
  const char* fname,
  std::int32_t rangeStart,
  std::int32_t rangeEnd
);

/**
 * Address: 0x00ADDEA0 (_mwPlyStartFnameRangeLp)
 *
 * What it does:
 * Starts seamless-loop playback from queued filename range.
 */
void mwPlyStartFnameRangeLp(
  moho::MwsfdPlaybackStateSubobj* ply,
  const char* fname,
  std::int32_t rangeStart,
  std::int32_t rangeEnd
);

/**
 * Address: 0x00ACB410 (_MWSFPLY_ReqStartFnameRange)
 *
 * What it does:
 * Records filename and arms pending range-start request lanes.
 */
void MWSFPLY_ReqStartFnameRange(
  moho::MwsfdPlaybackStateSubobj* ply,
  const char* fname,
  std::int32_t rangeStart,
  std::int32_t rangeEnd
);

/**
 * Address: 0x00ADDD50 (_mwPlyGetNumSlFiles)
 *
 * What it does:
 * Returns number of seamless-link streams currently queued in LSC lane.
 */
std::int32_t mwPlyGetNumSlFiles(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADDF00 (_mwPlyGetSlFname)
 *
 * What it does:
 * Returns queued seamless-link filename by stream index when valid.
 */
const char* mwPlyGetSlFname(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t streamIndex);

/**
 * Address: 0x00ADDF70 (_MWSFLSC_GetStat)
 *
 * What it does:
 * Returns current LSC global status lane for one playback object.
 */
std::int32_t MWSFLSC_GetStat(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADDF80 (_MWSFLSC_GetStmId)
 *
 * What it does:
 * Returns LSC stream id mapped from one queued stream index.
 */
std::int32_t MWSFLSC_GetStmId(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t streamIndex);

/**
 * Address: 0x00ADDF90 (_MWSFLSC_GetStmFname)
 *
 * What it does:
 * Returns LSC stream filename pointer by stream id.
 */
const char* MWSFLSC_GetStmFname(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t streamId);

/**
 * Address: 0x00ADDFA0 (_MWSFLSC_GetStmStat)
 *
 * What it does:
 * Returns LSC per-stream status lane by stream id.
 */
std::int32_t MWSFLSC_GetStmStat(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t streamId);

/**
 * Address: 0x00ADDFB0 (_MWSFLSC_GetStmRdSct)
 *
 * What it does:
 * Returns LSC per-stream read-sector lane by stream id.
 */
std::int32_t MWSFLSC_GetStmRdSct(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t streamId);

/**
 * Address: 0x00ADDFC0 (_MWSFLSC_IsFsStatErr)
 *
 * What it does:
 * Returns true when one LSC handle reports file-system error status.
 */
bool MWSFLSC_IsFsStatErr(void* lscHandle);

/**
 * Address: 0x00ADDFE0 (_MWSFLSC_SetFlowLimit)
 *
 * What it does:
 * Applies one flow-limit value to playback LSC lane when linked.
 */
std::int32_t MWSFLSC_SetFlowLimit(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t flowLimit);

/**
 * Address: 0x00AD8F30 (_MWSTM_Init)
 *
 * What it does:
 * Initializes MWSTM runtime lane for this build (no-op, success).
 */
std::int32_t MWSTM_Init();

/**
 * Address: 0x00AD8F40 (_MWSTM_InitStatic)
 *
 * What it does:
 * Initializes MWSTM static lane for this build (no-op, success).
 */
std::int32_t MWSTM_InitStatic();

/**
 * Address: 0x00AD8F50 (_MWSTM_Finish)
 *
 * What it does:
 * Finalizes MWSTM runtime lane for this build (no-op, success).
 */
std::int32_t MWSTM_Finish();

/**
 * Address: 0x00AD8F60 (_MWSTM_FinishStatic)
 *
 * What it does:
 * Finalizes MWSTM static lane for this build (no-op, success).
 */
std::int32_t MWSTM_FinishStatic();

/**
 * Address: 0x00AD8F70 (_MWSTM_SetRdSct)
 *
 * What it does:
 * Updates ADX stream requested read-sector window when stream handle exists.
 */
std::int32_t MWSTM_SetRdSct(std::int32_t streamHandleAddress, std::int32_t requestedSectorCount);

/**
 * Address: 0x00AD8F90 (_MWSTM_SetTrSct)
 *
 * What it does:
 * Placeholder transfer-sector setter lane for this build (no-op, success).
 */
std::int32_t MWSTM_SetTrSct(std::int32_t streamHandleAddress, std::int32_t transferSectorCount);

/**
 * Address: 0x00AD9020 (_MWSTM_Start)
 *
 * What it does:
 * Starts one ADX stream handle and returns success code lane.
 */
std::int32_t MWSTM_Start(std::int32_t streamHandleAddress);

/**
 * Address: 0x00AD9030 (_MWSTM_IsFsStatErr)
 *
 * What it does:
 * Returns true when one ADX stream reports filesystem-error status class.
 */
bool MWSTM_IsFsStatErr(std::int32_t streamHandleAddress);

/**
 * Address: 0x00AED7D0 (FUN_00AED7D0, _mwPlySwitchToIdle)
 *
 * What it does:
 * Forwards to ADXM vertical-sync wait lane.
 */
extern "C" std::int32_t mwPlySwitchToIdle();

/**
 * Address: 0x00AED7E0 (FUN_00AED7E0, _mwPlySaveRsc)
 *
 * What it does:
 * Dispatches playback-resource save hook lane.
 */
extern "C" void mwPlySaveRsc();

/**
 * Address: 0x00AED7F0 (FUN_00AED7F0, _mwPlyRestoreRsc)
 *
 * What it does:
 * Dispatches playback-resource restore hook lane.
 */
extern "C" void mwPlyRestoreRsc();

/**
 * Address: 0x00AED220 (FUN_00AED220, _SFD_IsSeekAble)
 *
 * What it does:
 * Validates one SFD handle and reports whether SFSEE seek conversion lanes
 * are available.
 */
std::int32_t SFD_IsSeekAble(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t* outSeekable);

/**
 * Address: 0x00AED2C0 (FUN_00AED2C0, _SFD_CnvTimeToPos)
 *
 * What it does:
 * Converts one playback time pair to seek position when the attached SFSEE
 * runtime is seek-capable.
 */
std::int32_t
SFD_CnvTimeToPos(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t timeMajor, std::int32_t timeMinor, std::int32_t* outSeekPosition);

/**
 * Address: 0x00AED380 (FUN_00AED380, _SFD_CnvPosToTime)
 *
 * What it does:
 * Converts one seek position to playback time pair when the attached SFSEE
 * runtime is seek-capable.
 */
std::int32_t
SFD_CnvPosToTime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t seekPosition, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);

/**
 * Address: 0x00AED480 (FUN_00AED480, _SFD_Seek)
 *
 * What it does:
 * Stops playback, stores seek request words, and dispatches transfer setup
 * lane `13`.
 */
std::int32_t SFD_Seek(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* seekRequestWords);

/**
 * Address: 0x00AED620 (FUN_00AED620, _SFD_SetSeekPos)
 *
 * What it does:
 * Stores SFSEE seek-base position lane for one SFD handle.
 */
std::int32_t SFD_SetSeekPos(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t seekPositionBytes);

/**
 * Address: 0x00AED530 (FUN_00AED530, _SFD_SetFileSize)
 *
 * What it does:
 * Stores total file-size lane into active sfsee runtime handle and refreshes
 * effective byte-rate tracking.
 */
std::int32_t SFD_SetFileSize(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t fileSizeBytes);

/**
 * Address: 0x00AED580 (FUN_00AED580, _SFD_SetTotTime)
 *
 * What it does:
 * Stores configured total-time numerator/denominator lanes into active sfsee
 * runtime state and refreshes effective byte-rate tracking.
 */
std::int32_t
SFD_SetTotTime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t totalTimeMajor, std::int32_t totalTimeMinor);

/**
 * Address: 0x00AED5D0 (FUN_00AED5D0, _SFD_SetByteRate)
 *
 * What it does:
 * Stores configured byte-rate lane into active sfsee runtime state and
 * refreshes effective byte-rate tracking.
 */
std::int32_t SFD_SetByteRate(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t byteRate);

/**
 * Address: 0x00AE5AB0 (FUN_00AE5AB0, _SFD_SetVideoPts)
 *
 * What it does:
 * Seeds the SFD video PTS queue lane from caller-provided source buffer/count
 * after handle validation.
 */
std::int32_t
SFD_SetVideoPts(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t ptsQueueSourceAddress, std::int32_t ptsEntryCount);

/**
 * Address: 0x00AE5E90 (FUN_00AE5E90, _SFD_SetConcatPlay)
 *
 * What it does:
 * Enables concat-play condition lane for one SFD handle after handle
 * validation.
 */
std::int32_t SFD_SetConcatPlay(void* sfdHandle);

/**
 * Address: 0x00ACF050 (FUN_00ACF050, _SFD_SetVideoPid)
 *
 * What it does:
 * Forwards one video PID handle lane into SFD condition `81` for a non-null
 * work-control handle.
 */
std::int32_t SFD_SetVideoPid(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, void* videoPidHandle);

/**
 * Address: 0x00ACF070 (FUN_00ACF070, _SFD_SetAudioPid)
 *
 * What it does:
 * Forwards one audio PID handle lane into SFD condition `82` for a non-null
 * work-control handle.
 */
std::int32_t SFD_SetAudioPid(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, void* audioPidHandle);

/**
 * Address: 0x00ACFB00 (FUN_00ACFB00, _SFD_SetOutVol)
 *
 * What it does:
 * Updates one SFD handle output-volume lane when audio-output condition lane
 * is enabled.
 */
std::int32_t SFD_SetOutVol(void* sfdHandle, std::int32_t volumeLevel);

/**
 * Address: 0x00ACFB50 (FUN_00ACFB50, _SFD_GetOutVol)
 *
 * What it does:
 * Reads one SFD handle output-volume lane when audio-output condition lane is
 * enabled.
 */
std::int32_t SFD_GetOutVol(void* sfdHandle);

/**
 * Address: 0x00ACFA60 (FUN_00ACFA60, _SFD_SetOutPan)
 *
 * What it does:
 * Updates one SFD handle output-pan lane when audio-output condition lane is
 * enabled.
 */
std::int32_t SFD_SetOutPan(void* sfdHandle, std::int32_t laneIndex, std::int32_t panLevel);

/**
 * Address: 0x00ACFAB0 (FUN_00ACFAB0, _SFD_GetOutPan)
 *
 * What it does:
 * Reads one SFD handle output-pan lane when audio-output condition lane is
 * enabled.
 */
std::int32_t SFD_GetOutPan(void* sfdHandle, std::int32_t laneIndex);

/**
 * Address: 0x00ADE0D0 (_MWSFRNA_SetOutVol)
 *
 * What it does:
 * Forwards output-volume lane to the active playback SFD handle.
 */
std::int32_t MWSFRNA_SetOutVol(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t volumeLevel);

/**
 * Address: 0x00ADE0E0 (_MWSFRNA_GetOutVol)
 *
 * What it does:
 * Returns output-volume lane from the active playback SFD handle.
 */
std::int32_t MWSFRNA_GetOutVol(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ADE0F0 (_MWSFRNA_SetOutPan)
 *
 * What it does:
 * Forwards one output-pan lane update to the active playback SFD handle.
 */
std::int32_t MWSFRNA_SetOutPan(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t laneIndex, std::int32_t panLevel);

/**
 * Address: 0x00ADE100 (_MWSFRNA_GetOutPan)
 *
 * What it does:
 * Returns one output-pan lane value from the active playback SFD handle.
 */
std::int32_t MWSFRNA_GetOutPan(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t laneIndex);

/**
 * Address: 0x00ADE430 (_CFT_Finish)
 *
 * What it does:
 * No-op cleanup lane for CFT subsystem shutdown.
 */
void CFT_Finish();

/**
 * Address: 0x00ADE400 (_CFT_Init)
 *
 * What it does:
 * Initializes CFT conversion backends and records runtime version-string
 * pointer lane.
 */
void CFT_Init();

/**
 * Address: 0x00AEDF40 (FUN_00AEDF40, _CFT_MakeYcc422ColAdjTbl)
 *
 * What it does:
 * Builds one YCC422 color-adjust table pack for Sofdec conversion lanes.
 */
std::int32_t CFT_MakeYcc422ColAdjTbl(std::int32_t tableAddress);

/**
 * Address: 0x00AEE090 (FUN_00AEE090, _CFT_MakeArgb8888ColAdjTbl)
 *
 * What it does:
 * Initializes ARGB8888 Y/Cb/Cr conversion table lane pointers and rebuilds
 * conversion tables.
 */
std::int32_t CFT_MakeArgb8888ColAdjTbl(std::int32_t tableAddress);

/**
 * Address: 0x00AED830 (FUN_00AED830, _CFT_Ycc420plnToA256V)
 *
 * What it does:
 * Converts one YCC420 source lane into destination alpha-channel lane, with
 * optional user remap table.
 */
std::uint8_t*
CFT_Ycc420plnToA256V(std::uint8_t** sourcePlanes, const std::int32_t* conversionWords, const std::int32_t* userTableAddress);

/**
 * Address: 0x00AED990 (FUN_00AED990, _CFT_MakeArgb8888AlpLumiTbl)
 *
 * What it does:
 * Builds one ARGB8888 alpha/luminance table pack with a luminance-window
 * ramp and shared chroma side tables.
 */
std::int32_t
CFT_MakeArgb8888AlpLumiTbl(std::int32_t luminancePivot, std::int32_t luminanceMin, std::int32_t luminanceMax, std::int32_t tableAddress);

/**
  * Alias of FUN_00AEDB70 (non-canonical helper lane).
 *
 * What it does:
 * Builds one ARGB8888 alpha table pack for 3110 blend mode.
 */
std::int32_t
CFT_MakeArgb8888Alp3110Tbl(std::int32_t tableAddress, std::int32_t alpha0, std::int32_t alpha1, std::int32_t alpha2);

/**
  * Alias of FUN_00AEDD50 (non-canonical helper lane).
 *
 * What it does:
 * Builds one ARGB8888 alpha table pack for 3211 blend mode.
 */
std::int32_t
CFT_MakeArgb8888Alp3211Tbl(std::int32_t tableAddress, std::int32_t alpha0, std::int32_t alpha1, std::int32_t alpha2);

/**
 * Address: 0x00B03CE0 (FUN_00B03CE0, _UTY_SupportSse)
 *
 * What it does:
 * Initializes and returns process-global SSE support availability lane.
 */
std::int32_t UTY_SupportSse();

/**
 * Address: 0x00ADE440 (_CFTCOM_SetCftFunctionName)
 *
 * What it does:
 * Stores process-global CFT function-name pointer lane.
 */
const char* CFTCOM_SetCftFunctionName(const char* functionName);

/**
 * Address: 0x00ADE450 (_CFTCOM_GetCftFunctionName)
 *
 * What it does:
 * Returns process-global CFT function-name pointer lane.
 */
const char* CFTCOM_GetCftFunctionName();

/**
 * Address: 0x00ADE460 (_CFT_OptimizeSpeed)
 *
 * What it does:
 * Stores process-global CFT optimize-speed mode lane.
 */
std::int32_t CFT_OptimizeSpeed(std::int32_t optimizeSpeedMode);

/**
 * Address: 0x00ADE470 (_CFTCOM_GetOptimizeSpeed)
 *
 * What it does:
 * Returns process-global CFT optimize-speed mode lane.
 */
std::int32_t CFTCOM_GetOptimizeSpeed();

/**
 * Address: 0x00ADE480 (_SFXINF_GetStmInf)
 *
 * What it does:
 * Returns default SFX composition tag value.
 */
std::int32_t SFXINF_GetStmInf(moho::SfxStreamState* streamState, const char* tagName);

/**
 * Address: 0x00ADE490 (_SFBUF_Init)
 *
 * What it does:
 * Initializes SFBUF UUID/runtime lane.
 */
std::int32_t SFBUF_Init();

/**
 * Address: 0x00ADE4A0 (_SFBUF_Finish)
 *
 * What it does:
 * No-op cleanup lane for SFBUF subsystem shutdown.
 */
void SFBUF_Finish();

/**
 * Address: 0x00ADE1F0 (_SFXA_Finish)
 *
 * What it does:
 * No-op teardown lane for SFX alpha-conversion runtime.
 */
void SFXA_Finish();

/**
 * Address: 0x00ADE1D0 (_sfxalp_InitLibWork)
 *
 * What it does:
 * Clears SFXA global work lanes and restores free-handle upper bound.
 */
std::int32_t sfxalp_InitLibWork();

/**
 * Address: 0x00ADE230 (_sfxamv_SearchFreeHn)
 *
 * What it does:
 * Returns first unused SFXA runtime-handle slot address.
 */
std::int32_t sfxamv_SearchFreeHn();

/**
 * Address: 0x00ADE200 (_SFXA_Create)
 *
 * What it does:
 * Acquires one free SFXA handle, initializes it, and marks it active.
 */
std::int32_t SFXA_Create();

/**
 * Address: 0x00ADE260 (_sfxamv_InitHn)
 *
 * What it does:
 * Initializes one SFXA handle with default luminance and alpha lanes.
 */
std::int32_t sfxamv_InitHn(std::int32_t sfxaHandleAddress);

/**
 * Address: 0x00ADE290 (_SFXA_Destroy)
 *
 * What it does:
 * Releases one SFXA handle slot and decrements active-handle count.
 */
void SFXA_Destroy(std::int32_t sfxaHandleAddress);

/**
 * Address: 0x00ADE2B0 (_SFXA_MakeAlpLumiTbl)
 *
 * What it does:
 * Builds luminance table through optional per-handle callback and clears the
 * pending-update flag.
 */
std::int32_t SFXA_MakeAlpLumiTbl(std::int32_t sfxaHandleAddress, std::int32_t reservedMode, std::int32_t tableAddress);

/**
 * Address: 0x00ADE2E0 (_SFXA_MakeAlp3110Tbl)
 *
 * What it does:
 * Builds alpha table in 3110 mode through optional per-handle callback.
 */
std::int32_t SFXA_MakeAlp3110Tbl(std::int32_t sfxaHandleAddress, std::int32_t reservedMode, std::int32_t tableAddress);

/**
 * Address: 0x00ADE310 (_SFXA_MakeAlp3211Tbl)
 *
 * What it does:
 * Builds alpha table in 3211 mode through optional per-handle callback.
 */
std::int32_t SFXA_MakeAlp3211Tbl(std::int32_t sfxaHandleAddress, std::int32_t reservedMode, std::int32_t tableAddress);

/**
 * Address: 0x00ADE350 (_SFXA_SetLumiPrm)
 *
 * What it does:
 * Stores one SFXA luminance-parameter triplet and marks table-update needed.
 */
std::int32_t SFXA_SetLumiPrm(
  std::int32_t sfxaHandleAddress,
  std::int32_t luminanceMin,
  std::int32_t luminanceMax,
  std::int32_t luminancePivot
);

/**
 * Address: 0x00ADE380 (_SFXA_GetLumiPrm)
 *
 * What it does:
 * Returns one SFXA luminance-parameter triplet.
 */
std::int32_t SFXA_GetLumiPrm(
  std::int32_t sfxaHandleAddress,
  std::int32_t* outLuminanceMin,
  std::int32_t* outLuminanceMax,
  std::int32_t* outLuminancePivot
);

/**
 * Address: 0x00ADE3A0 (_SFXA_SetAlp3Prm)
 *
 * What it does:
 * Stores one SFXA alpha triplet lane.
 */
std::int32_t
SFXA_SetAlp3Prm(std::int32_t sfxaHandleAddress, std::int8_t alpha0, std::int8_t alpha1, std::int8_t alpha2);

/**
 * Address: 0x00ADE3C0 (_SFXA_GetAlp3Prm)
 *
 * What it does:
 * Returns one SFXA alpha triplet lane.
 */
std::int32_t
SFXA_GetAlp3Prm(std::int32_t sfxaHandleAddress, std::int8_t* outAlpha0, std::int8_t* outAlpha1, std::int8_t* outAlpha2);

/**
 * Address: 0x00ADE340 (_SFXA_IsNeedUpdateLumiTbl)
 *
 * What it does:
 * Returns the pending "update luminance table" flag lane from one SFXA
 * runtime handle.
 */
std::int32_t SFXA_IsNeedUpdateLumiTbl(std::int32_t sfxaHandleAddress);

/**
 * Address: 0x00ADE3E0 (_SFXSUD_Init)
 *
 * What it does:
 * Initializes the Sofdec SUD backend lane.
 */
void SFXSUD_Init();

/**
 * Address: 0x00ADE3F0 (_SFXSUD_Finish)
 *
 * What it does:
 * Finalizes the Sofdec SUD backend lane.
 */
std::int32_t SFXSUD_Finish();

/**
 * Address: 0x00ADE580 (_sfbuf_MakeBufPtr)
 *
 * What it does:
 * Expands contiguous SFBUF lane sizes into per-lane base-address pointers.
 */
std::int32_t
sfbuf_MakeBufPtr(std::int32_t* outBufferPointers, const std::int32_t* ringBufferSizes, std::int32_t baseBufferAddress);

/**
 * Address: 0x00ADE8E0 (_sfbuf_InitBufData)
 *
 * What it does:
 * Initializes one SFBUF lane header with type/setup flags and default state
 * lanes.
 */
std::int32_t* sfbuf_InitBufData(std::int32_t* sfbufLaneWords, std::int32_t laneType, std::int32_t setupState);

/**
 * Address: 0x00ADE910 (_sfbuf_InitUoSj)
 *
 * What it does:
 * Clears three four-word SFBUF UO/SJ state blocks.
 */
std::int32_t* sfbuf_InitUoSj(std::int32_t* uoSjStateWords);

/**
 * Address: 0x00ADE8B0 (_sfbuf_InitUoSjBuf)
 *
 * What it does:
 * Initializes one SFBUF UO/SJ lane and clears its UO/SJ state block.
 */
std::int32_t* sfbuf_InitUoSjBuf(
  std::int32_t sfbufHandleAddress,
  const std::int32_t* bufferAddressTable,
  const std::int32_t* bufferSizeTable,
  std::int32_t laneIndex
);

/**
 * Address: 0x00ADE7D0 (_sfbuf_InitAringBuf)
 *
 * What it does:
 * Initializes one SFBUF audio-ring lane from base-address/size tables.
 */
std::int32_t sfbuf_InitAringBuf(
  std::int32_t sfbufHandleAddress,
  const std::int32_t* bufferAddressTable,
  const std::int32_t* bufferSizeTable,
  std::int32_t laneIndex
);

/**
 * Address: 0x00ADE740 (_sfbuf_InitVfrmBuf)
 *
 * What it does:
 * Initializes one SFBUF video-frame lane and clears its frame-state words.
 */
std::int32_t sfbuf_InitVfrmBuf(
  std::int32_t vfrmOwnerAddress,
  std::int32_t sfbufHandleAddress,
  const std::int32_t* bufferAddressTable,
  const std::int32_t* bufferSizeTable,
  std::int32_t laneIndex
);

/**
 * Address: 0x00ADE650 (_sfbuf_CreateSj)
 *
 * What it does:
 * Builds one SJ ring-buffer create-state pack from source and extra-size
 * inputs.
 */
std::int32_t sfbuf_CreateSj(
  std::int32_t* outSjCreateStateWords,
  std::int32_t sourceBufferAddress,
  std::int32_t sourceBufferBytes,
  std::int32_t extraBufferBytes
);

/**
 * Address: 0x00ADE5B0 (_sfbuf_InitRingSj)
 *
 * What it does:
 * Initializes one SFBUF SJ-ring lane, either inactive or active with a newly
 * created SJ ring handle.
 */
std::int32_t sfbuf_InitRingSj(
  std::int32_t sfbufHandleAddress,
  const std::int32_t* bufferAddressTable,
  const std::int32_t* bufferSizeTable,
  std::int32_t laneIndex,
  std::int32_t extraBufferBytes
);

/**
 * Address: 0x00ADE4B0 (_SFBUF_InitHn)
 *
 * What it does:
 * Initializes SFBUF ring/audio/video/UO lanes from one layout-config block.
 */
std::int32_t
SFBUF_InitHn(std::int32_t vfrmOwnerAddress, std::int32_t sfbufHandleAddress, const std::int32_t* sfbufInitConfigWords);

/**
 * Address: 0x00ADE9C0 (_sfbuf_ChkSupSj)
 *
 * What it does:
 * Validates one SFBUF supply-state descriptor lane.
 */
std::int32_t sfbuf_ChkSupSj(const std::int32_t* supplyDescriptorWords);

/**
 * Address: 0x00ADEA60 (_sfbuf_SetSupSj)
 *
 * What it does:
 * Installs one SFBUF supply-state descriptor into target lane under SFLIB
 * lock.
 */
void sfbuf_SetSupSj(
  std::int32_t* supplyLaneWords,
  const std::int32_t* supplyDescriptorWords,
  std::int32_t ownerLaneAddress,
  std::int32_t setupState
);

/**
 * Address: 0x00ADEA00 (_sfbuf_SetSupplySjSub)
 *
 * What it does:
 * Routes one validated supply descriptor into selected SFBUF transfer lane.
 */
std::int32_t sfbuf_SetSupplySjSub(
  std::int32_t sfbufHandleAddress,
  const std::int32_t* supplyDescriptorWords,
  std::int32_t transferLaneIndex
);

/**
 * Address: 0x00ADE930 (_SFBUF_SetSupplySj)
 *
 * What it does:
 * Binds one supply descriptor to active SFTRN lane routing.
 */
std::int32_t
SFBUF_SetSupplySj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* supplyDescriptorWords);

/**
 * Address: 0x00ADEAC0 (_sfbuf_InitConti)
 *
 * What it does:
 * Clears one SFBUF continuity state pair.
 */
std::int32_t* sfbuf_InitConti(std::int32_t* continuityStateWords);

/**
 * Address: 0x00ADEAE0 (_SFBUF_SetUoch)
 *
 * What it does:
 * Stores one user-output chunk descriptor into an SFBUF lane slot.
 */
std::int32_t* SFBUF_SetUoch(
  std::int32_t sfbufHandleAddress,
  std::int32_t laneIndex,
  std::int32_t uochSlotIndex,
  const std::int32_t* chunkDescriptorWords
);

/**
 * Address: 0x00ADEB30 (_SFBUF_GetUoch)
 *
 * What it does:
 * Reads one user-output chunk descriptor from an SFBUF lane slot.
 */
std::int32_t SFBUF_GetUoch(
  std::int32_t sfbufHandleAddress,
  std::int32_t laneIndex,
  std::int32_t uochSlotIndex,
  std::int32_t* outChunkDescriptorWords
);

/**
 * Address: 0x00ADEB80 (_SFBUF_GetRingSj)
 *
 * What it does:
 * Returns one SFBUF lane SJ ring handle pointer word.
 */
std::int32_t
SFBUF_GetRingSj(std::int32_t sfbufHandleAddress, std::int32_t laneIndex, std::int32_t* outRingHandleAddress);

/**
 * Address: 0x00ADEBF0 (_sfbuf_RingGetSub)
 *
 * What it does:
 * Peeks one SFBUF ring lane into contiguous two-chunk cursor output.
 */
std::int32_t sfbuf_RingGetSub(
  std::int32_t sfbufHandleAddress,
  std::int32_t ringIndex,
  std::int32_t* outCursor,
  std::int32_t laneMode
);

/**
 * Address: 0x00ADECB0 (_sfbuf_RingAddSub)
 *
 * What it does:
 * Advances one SFBUF ring lane and updates accumulated write/read totals.
 */
std::int32_t sfbuf_RingAddSub(
  std::int32_t sfbufHandleAddress,
  std::int32_t ringIndex,
  std::int32_t advanceCount,
  std::int32_t laneMode
);

/**
 * Address: 0x00ADEDA0 (_sfbuf_ResetConti)
 *
 * What it does:
 * Clears delimiter continuity markers when they are outside current read
 * chunks.
 */
std::uint32_t sfbuf_ResetConti(std::int32_t* supplyStateWords);

/**
 * Address: 0x00ADEE00 (_sfbuf_PeekChunk)
 *
 * What it does:
 * Reads current readable chunk windows without consuming ring bytes.
 */
std::int32_t sfbuf_PeekChunk(
  std::int32_t ringHandleAddress,
  std::int32_t laneMode,
  moho::SjChunkRange* outFirstChunk,
  moho::SjChunkRange* outSecondChunk
);

/**
 * Address: 0x00ADEE90 (_sfbuf_MoveChunk)
 *
 * What it does:
 * Moves one chunk span from input lane to output lane in SJ ring.
 */
std::int32_t sfbuf_MoveChunk(std::int32_t ringHandleAddress, std::int32_t laneMode, std::int32_t requestedBytes);

/**
 * Address: 0x00ADEBB0 (_SFBUF_RingGetWrite)
 *
 * What it does:
 * Reads one SFBUF ring write cursor lane through shared ring-get helper.
 */
std::int32_t SFBUF_RingGetWrite(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outCursor);

/**
 * Address: 0x00ADEBD0 (_SFBUF_RingGetRead)
 *
 * What it does:
 * Reads one SFBUF ring read cursor lane through shared ring-get helper.
 */
std::int32_t SFBUF_RingGetRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outCursor);

/**
 * Address: 0x00ADEC80 (_SFBUF_RingAddWrite)
 *
 * What it does:
 * Advances one SFBUF ring write cursor by a requested count.
 */
std::int32_t SFBUF_RingAddWrite(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t advanceCount);

/**
 * Address: 0x00ADEC90 (_SFBUF_RingAddRead)
 *
 * What it does:
 * Advances one SFBUF ring read cursor by a requested count.
 */
std::int32_t SFBUF_RingAddRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t advanceCount);

/**
 * Address: 0x00ADEED0 (_SFBUF_RingGetDlm)
 *
 * What it does:
 * Returns current delimiter marker pair for one SFBUF ring lane.
 */
void SFBUF_RingGetDlm(
  std::int32_t sfbufHandleAddress,
  std::int32_t ringIndex,
  std::int32_t* outPrimaryDelimiterAddress,
  std::int32_t* outSecondaryDelimiterAddress
);

/**
 * Address: 0x00ADEF20 (_SFBUF_RingSetDlm)
 *
 * What it does:
 * Stores delimiter marker pair for one SFBUF ring lane.
 */
void SFBUF_RingSetDlm(
  std::int32_t sfbufHandleAddress,
  std::int32_t ringIndex,
  std::int32_t primaryDelimiterAddress,
  std::int32_t secondaryDelimiterAddress
);

/**
 * Address: 0x00ADEFB0 (_SFBUF_GetWTot)
 *
 * What it does:
 * Returns cumulative write total for one SFBUF ring lane.
 */
std::int32_t SFBUF_GetWTot(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);

/**
 * Address: 0x00ADF020 (_SFBUF_RingGetSj)
 *
 * What it does:
 * Validates one SFBUF ring lane setup state and returns its SJ handle.
 */
std::int32_t
SFBUF_RingGetSj(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outRingHandleAddress);

/**
 * Address: 0x00ADF070 (_SFBUF_AddRtotSj)
 *
 * What it does:
 * Adds one byte-count increment to ring read-total lane when nonnegative.
 */
std::int32_t* SFBUF_AddRtotSj(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t addBytes);

/**
 * Address: 0x00ADF0A0 (_SFBUF_AringGetWrite)
 *
 * What it does:
 * Builds one audio-ring write snapshot window from SFBUF aring lane state.
 */
std::int32_t
SFBUF_AringGetWrite(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outAringSnapshotWords);

/**
 * Address: 0x00ADF220 (_SFBUF_AringAddWrite)
 *
 * What it does:
 * Advances one aring write cursor and updates aring write-total counter.
 */
std::int32_t SFBUF_AringAddWrite(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t addSamples);

/**
 * Address: 0x00ADF2D0 (_SFBUF_AringGetRead)
 *
 * What it does:
 * Builds one audio-ring read snapshot window from SFBUF aring lane state.
 */
std::int32_t
SFBUF_AringGetRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outAringSnapshotWords);

/**
 * Address: 0x00ADF450 (_SFBUF_AringAddRead)
 *
 * What it does:
 * Advances one aring read cursor and updates aring read-total counter.
 */
std::int32_t SFBUF_AringAddRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t addSamples);

/**
 * Address: 0x00ADF500 (_SFBUF_VfrmGetWrite)
 *
 * What it does:
 * Returns default success for vfrm write snapshot lane.
 */
std::int32_t SFBUF_VfrmGetWrite();

/**
 * Address: 0x00ADF510 (_SFBUF_VfrmAddWrite)
 *
 * What it does:
 * Marks SFBUF runtime dirty after vfrm write-lane update.
 */
std::int32_t SFBUF_VfrmAddWrite(std::int32_t sfbufHandleAddress);

/**
 * Address: 0x00ADF520 (_SFBUF_VfrmGetRead)
 *
 * What it does:
 * Reads vfrm transfer state via SFTRN bridge when lane is not setup.
 */
std::int32_t
SFBUF_VfrmGetRead(std::int32_t sfbufHandleAddress, std::int32_t laneIndex, std::int32_t arg0, std::int32_t arg1);

/**
 * Address: 0x00ADF570 (_SFBUF_VfrmAddRead)
 *
 * What it does:
 * Commits vfrm read lane via SFTRN bridge when lane is not setup.
 */
std::int32_t
SFBUF_VfrmAddRead(std::int32_t sfbufHandleAddress, std::int32_t laneIndex, std::int32_t arg0, std::int32_t arg1);

/**
 * Address: 0x00ADF5C0 (_SFBUF_SetPrepFlg)
 *
 * What it does:
 * Writes one per-lane prep flag in SFBUF lane state.
 */
std::int32_t SFBUF_SetPrepFlg(std::int32_t sfbufHandleAddress, std::int32_t laneIndex, std::int32_t prepFlag);

/**
 * Address: 0x00ADF5E0 (_SFBUF_GetPrepFlg)
 *
 * What it does:
 * Reads one per-lane prep flag from SFBUF lane state.
 */
std::int32_t SFBUF_GetPrepFlg(std::int32_t sfbufHandleAddress, std::int32_t laneIndex);

/**
 * Address: 0x00ADF600 (_SFBUF_SetTermFlg)
 *
 * What it does:
 * Writes one per-lane term flag in SFBUF lane state.
 */
std::int32_t SFBUF_SetTermFlg(std::int32_t sfbufHandleAddress, std::int32_t laneIndex, std::int32_t termFlag);

/**
 * Address: 0x00ADF620 (_SFBUF_GetTermFlg)
 *
 * What it does:
 * Reads one per-lane term flag from SFBUF lane state.
 */
std::int32_t SFBUF_GetTermFlg(std::int32_t sfbufHandleAddress, std::int32_t laneIndex);

/**
 * Address: 0x00ADF640 (_SFBUF_GetRingBufSiz)
 *
 * What it does:
 * Returns sum of current read-side chunk spans for one SFBUF ring lane.
 */
std::int32_t SFBUF_GetRingBufSiz(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);

/**
 * Address: 0x00ADF670 (_SFBUF_RingGetFreeSiz)
 *
 * What it does:
 * Returns sum of current write-side chunk spans for one SFBUF ring lane.
 */
std::int32_t SFBUF_RingGetFreeSiz(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);

/**
 * Address: 0x00ADF720 (_sfbuf_InitSjUuid)
 *
 * What it does:
 * Captures ring/memory SJ UUID tags used by SFBUF supply-type probes.
 */
std::int32_t sfbuf_InitSjUuid();

/**
 * Address: 0x00ADF770 (_sfbuf_IsSjRbf)
 *
 * What it does:
 * Checks whether one SJ handle resolves to ring-buffer supply UUID.
 */
std::int32_t sfbuf_IsSjRbf(std::int32_t sjHandleAddress);

/**
 * Address: 0x00ADF790 (_sfbuf_IsSjMem)
 *
 * What it does:
 * Checks whether one SJ handle resolves to memory supply UUID.
 */
std::int32_t sfbuf_IsSjMem(std::int32_t sjHandleAddress);

/**
 * Address: 0x00ADF6A0 (_SFBUF_GetFlowCnt)
 *
 * What it does:
 * Extracts lane flow counters from ring or memory SJ supply owners.
 */
std::int32_t
SFBUF_GetFlowCnt(std::int32_t sjHandleAddress, std::int32_t* outLane1FlowCount, std::int32_t* outLane0FlowCount);

/**
 * Address: 0x00ADF7B0 (_SFBUF_UpdateFlowCnt)
 *
 * What it does:
 * Merges low 32-bit flow count with carry into high 32-bit lane.
 */
std::int64_t SFBUF_UpdateFlowCnt(std::int32_t previousFlowLow, std::int32_t previousFlowHigh, std::int32_t nextFlowLow);

/**
 * Address: 0x00ADF7F0 (_SFTRN_Init)
 *
 * What it does:
 * Copies one transfer-entry dispatch list and invokes init callbacks.
 */
std::int32_t SFTRN_Init(void* outTransferEntryTable, void* transferEntryTable);

/**
 * Address: 0x00ADF820 (_SFTRN_Finish)
 *
 * What it does:
 * Invokes finish callbacks for one transfer-entry dispatch list.
 */
std::int32_t SFTRN_Finish(void* transferEntryTable);

/**
 * Address: 0x00ADF830 (_sftrn_CallTrEntry)
 *
 * What it does:
 * Iterates transfer-entry callbacks for init/finish lanes until stop/error.
 */
std::int32_t sftrn_CallTrEntry(void* transferEntryTable, std::int32_t entrySelector);

/**
 * Address: 0x00ADF870 (_SFTRN_InitHn)
 *
 * What it does:
 * Initializes transfer lane runtime data and builds route graph for one
 * playback workctrl owner.
 */
std::int32_t SFTRN_InitHn(
  std::int32_t workctrlAddress,
  std::int32_t transferDataArrayAddress,
  const std::int32_t* transferBuildConfigAddressPtr
);

/**
 * Address: 0x00ADF8D0 (_sftrn_InitTrData)
 *
 * What it does:
 * Resets one transfer lane runtime header and seeds stage defaults.
 */
std::int32_t* sftrn_InitTrData(std::int32_t* transferDataWords, std::int32_t transferDescriptorAddress);

/**
 * Address: 0x00ADF910 (_sftrn_BuildAll)
 *
 * What it does:
 * Selects system/audio/video/user transfer route graph for one workctrl.
 */
std::int32_t
sftrn_BuildAll(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* transferBuildConfigWords);

/**
 * Address: 0x00ADF9F0 (_sftrn_BuildSystem)
 *
 * What it does:
 * Builds system-root transfer route and optional downstream lanes.
 */
std::int32_t
sftrn_BuildSystem(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* transferBuildConfigWords);

/**
 * Address: 0x00ADFA90 (_sftrn_BuildAudio)
 *
 * What it does:
 * Builds audio transfer route graph with optional extended branch.
 */
std::int32_t
sftrn_BuildAudio(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* transferBuildConfigWords);

/**
 * Address: 0x00ADFAF0 (_sftrn_BuildVideo)
 *
 * What it does:
 * Builds video transfer route graph with optional extended branch.
 */
std::int32_t
sftrn_BuildVideo(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, const std::int32_t* transferBuildConfigWords);

/**
 * Address: 0x00ADFB50 (_sftrn_BuildUsr)
 *
 * What it does:
 * Builds user transfer route graph lanes.
 */
std::int32_t sftrn_BuildUsr(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00ADFB70 (_sftrn_ConnTrnBuf0)
 *
 * What it does:
 * Connects transfer lane output slot 0 to one SFBUF lane.
 */
std::int32_t
sftrn_ConnTrnBuf0(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);

/**
 * Address: 0x00ADFB90 (_sftrn_ConnTrnBufV)
 *
 * What it does:
 * Connects transfer video output lane to one SFBUF lane.
 */
std::int32_t
sftrn_ConnTrnBufV(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);

/**
 * Address: 0x00ADFBB0 (_sftrn_ConnTrnBufA)
 *
 * What it does:
 * Connects transfer audio output lane to one SFBUF lane.
 */
std::int32_t
sftrn_ConnTrnBufA(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);

/**
 * Address: 0x00ADFBD0 (_sftrn_ConnTrnBufU)
 *
 * What it does:
 * Connects transfer user output lane to one SFBUF lane.
 */
std::int32_t
sftrn_ConnTrnBufU(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);

/**
 * Address: 0x00ADFBF0 (_sftrn_ConnTrnBuf)
 *
 * What it does:
 * Binds one transfer output slot to one target SFBUF lane.
 */
std::int32_t sftrn_ConnTrnBuf(
  moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
  std::int32_t sourceLane,
  std::int32_t transferSlot,
  std::int32_t targetLane
);

/**
 * Address: 0x00ADFC30 (_sftrn_ConnBufTrn)
 *
 * What it does:
 * Binds one SFBUF source lane to one transfer input lane.
 */
std::int32_t
sftrn_ConnBufTrn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);

/**
 * Address: 0x00ADFC60 (_SFTRN_CallTrSetup)
 *
 * What it does:
 * Calls one setup callback slot across transfer descriptor lanes.
 */
std::int32_t SFTRN_CallTrSetup(std::int32_t workctrlAddress, std::int32_t callbackIndex);

/**
 * Address: 0x00ADFCA0 (_SFTRN_CallTrtTrif)
 *
 * What it does:
 * Calls one transfer descriptor callback for one transfer lane.
 */
std::int32_t SFTRN_CallTrtTrif(
  std::int32_t workctrlAddress,
  std::int32_t transferLaneIndex,
  std::int32_t callbackIndex,
  std::int32_t arg0,
  std::int32_t arg1
);

/**
 * Address: 0x00ADFCE0 (_SFTRN_SetPrepFlg)
 *
 * What it does:
 * Sets one transfer-lane prep flag.
 */
std::int32_t SFTRN_SetPrepFlg(std::int32_t workctrlAddress, std::int32_t transferLaneIndex, std::int32_t prepFlag);

/**
 * Address: 0x00ADFD00 (_SFTRN_GetPrepFlg)
 *
 * What it does:
 * Returns one transfer-lane prep flag.
 */
std::int32_t SFTRN_GetPrepFlg(std::int32_t workctrlAddress, std::int32_t transferLaneIndex);

/**
 * Address: 0x00ADFD20 (_SFTRN_SetTermFlg)
 *
 * What it does:
 * Sets one transfer-lane terminate flag.
 */
std::int32_t SFTRN_SetTermFlg(std::int32_t workctrlAddress, std::int32_t transferLaneIndex, std::int32_t termFlag);

/**
 * Address: 0x00ADFD40 (_SFTRN_GetTermFlg)
 *
 * What it does:
 * Returns one transfer-lane terminate flag.
 */
std::int32_t SFTRN_GetTermFlg(std::int32_t workctrlAddress, std::int32_t transferLaneIndex);

/**
 * Address: 0x00ADFD60 (_SFTRN_IsSetup)
 *
 * What it does:
 * Returns whether one transfer lane is marked prepared.
 */
std::int32_t SFTRN_IsSetup(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t transferLaneType);

/**
 * Address: 0x00ADEF70 (_SFBUF_RingGetDataSiz)
 *
 * What it does:
 * Returns queued byte-count lane for one SFBUF ring.
 */
std::int32_t SFBUF_RingGetDataSiz(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);

/**
 * Address: 0x00ADEF90 (_SFBUF_GetRTot)
 *
 * What it does:
 * Returns cumulative-read total lane for one SFBUF ring.
 */
std::int32_t SFBUF_GetRTot(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);

/**
 * Address: 0x00ACAE90 (_mwPlyStartFname)
 *
 * What it does:
 * Starts one filename playback lane by validating handle/name and
 * forwarding into the internal start-by-name setup path.
 */
void mwPlyStartFname(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);

/**
 * Address: 0x00ADDC70 (_mwPlyStartFnameLp)
 *
 * What it does:
 * Starts one seamless loop playback lane from a recorded filename.
 */
void mwPlyStartFnameLp(moho::MwsfdPlaybackStateSubobj* ply, const char* fname);

/**
 * Address: 0x00ACB130 (_mwSfdStopDec)
 *
 * What it does:
 * Stops active SFD decode lanes for one playback handle and tears down
 * attached stream/link runtime handles.
 */
void mwSfdStopDec(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00ACAF40 (_mw_sfd_start_ex)
 *
 * IDA signature:
 * void __cdecl mw_sfd_start_ex(moho::MwsfdPlaybackStateSubobj* ply);
 *
 * What it does:
 * Reinitializes one Sofdec playback object for start/seek lanes, including
 * SFD-handle reset, tag/frame setup, pause-state replay, and stream-state
 * restart.
 */
void mw_sfd_start_ex(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC9540 (_MWSFLIB_SfdErrFunc)
 *
 * IDA signature:
 * int __cdecl MWSFLIB_SfdErrFunc(int mwsfdHandle, int errorCode);
 *
 * What it does:
 * Updates process-global Sofdec SFD error state (latest handle lanes plus
 * bounded error-code history) and forwards formatted diagnostics into
 * `MWSFSVM_Error`.
 */
std::int32_t MWSFLIB_SfdErrFunc(std::int32_t mwsfdHandle, std::int32_t errorCode);

/**
 * Address: 0x00AD8E90 (_SFLIB_CheckHn)
 *
 * IDA signature:
 * int __cdecl SFLIB_CheckHn(struct_sofdec_sfd_workctrl_subobj* workctrlSubobj);
 *
 * What it does:
 * Verifies that one Sofdec SFD work-control object has a non-zero runtime
 * handle-state lane; returns `0` on success and `-1` on invalid input.
 */
std::int32_t SFLIB_CheckHn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

/**
 * Address: 0x00AD8F10 (_SFLIB_LockCs)
 *
 * What it does:
 * Enters SFLIB critical section by forwarding into global Sofdec lock lane.
 */
void SFLIB_LockCs();

/**
 * Address: 0x00AD8F20 (_SFLIB_UnlockCs)
 *
 * What it does:
 * Leaves SFLIB critical section by forwarding into global Sofdec unlock lane.
 */
void SFLIB_UnlockCs();

/**
 * Address: 0x00AC66E0 (FUN_00AC66E0, _MWSFSFX_GetSfxHn)
 *
 * What it does:
 * Returns one playback object's bound SFX handle lane.
 */
void* MWSFSFX_GetSfxHn(const moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC6CF0 (FUN_00AC6CF0, _mwPlyFxGetCompoMode)
 *
 * What it does:
 * Reads active SFX composition mode for one playback handle and normalizes
 * dynamic-B/C modes to dynamic-A.
 */
std::int32_t mwPlyFxGetCompoMode(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC6DD0 (FUN_00AC6DD0, _MWSFSFX_SetOutBufSize)
 *
 * What it does:
 * For valid playback handles, forwards output-buffer dimensions and unit
 * width into the bound SFX runtime handle.
 */
void MWSFSFX_SetOutBufSize(
  moho::MwsfdPlaybackStateSubobj* ply,
  std::int32_t outputPitch,
  std::int32_t outputHeight,
  std::int32_t unitWidth
);

/**
 * Address: 0x00AC6D40 (FUN_00AC6D40, _mwPlyFxSetOutBufSize)
 *
 * What it does:
 * Sets playback SFX output buffer dimensions with default unit-width lane.
 */
void mwPlyFxSetOutBufSize(moho::MwsfdPlaybackStateSubobj* ply, std::int32_t outputPitch, std::int32_t outputHeight);

/**
 * Address: 0x00AC6DA0 (FUN_00AC6DA0, _mwPlyFxSetOutBufPitchHeight)
 *
 * What it does:
 * Alias wrapper for output pitch/height lane setup with default unit width.
 */
void mwPlyFxSetOutBufPitchHeight(
  moho::MwsfdPlaybackStateSubobj* ply,
  std::int32_t outputPitch,
  std::int32_t outputHeight
);

/**
 * Address: 0x00AC6FF0 (_mwsftag_IsPlayVideoElementary)
 *
 * What it does:
 * Returns `1` when one playback handle is configured for elementary video
 * stream mode (`fileType == 2`), otherwise `0`.
 */
std::int32_t mwsftag_IsPlayVideoElementary(const moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC7050 (_MWSFTAG_SetTagInf)
 *
 * What it does:
 * Ensures AINF/SFX tag lanes are populated once for one playback object when
 * SJ ring input is available.
 */
std::int32_t MWSFTAG_SetTagInf(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC7080 (_MWSFTAG_UpdateTagInf)
 *
 * What it does:
 * Re-reads AINF/SFX tag lanes from SJ input and refreshes active SFX tag
 * binding for one playback object.
 */
std::int32_t MWSFTAG_UpdateTagInf(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC70A0 (_mwsftag_GetAinfFromSj)
 *
 * What it does:
 * Pulls current `CRITAGS` AINF payload from SJ lane-1 data, updates cached
 * playback tag-info lanes, and advances SJ ownership windows.
 */
const char* mwsftag_GetAinfFromSj(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC7210 (_mwsftag_GetSFXinfFromAinf)
 *
 * What it does:
 * Resolves one `SFXINFS`/`SFXINFE` span from cached AINF data and forwards it
 * into SFX runtime tag state.
 */
std::int32_t mwsftag_GetSFXinfFromAinf(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00AC7290 (_MWSFTAG_ClearUsrSj)
 *
 * What it does:
 * Clears SFD user-SJ lane for non-elementary playback objects when SJ ring
 * input is active.
 */
std::int32_t MWSFTAG_ClearUsrSj(moho::MwsfdPlaybackStateSubobj* ply);

/**
 * Address: 0x00B088E0 (_sj_hexstr_to_val)
 *
 * What it does:
 * Converts one 7-character hex-length field into byte count.
 */
std::int32_t sj_hexstr_to_val(const char* hexString);

/**
 * Address: 0x00B089B0 (_SJ_GetTagContent)
 *
 * What it does:
 * Writes one tag payload window (`data,size`) from a tag-header pointer.
 */
std::int32_t SJ_GetTagContent(std::int8_t* tagHeader, moho::MwsfTagWindow* outWindow);

/**
 * Address: 0x00B089D0 (_SJ_SearchTag)
 *
 * What it does:
 * Scans one tag stream for a begin-tag token (optionally bounded by end-tag)
 * and returns the matched tag header address when found.
 */
const char* SJ_SearchTag(
  const moho::MwsfTagWindow* inputWindow,
  const char* beginTagName,
  const char* endTagName,
  moho::MwsfTagWindow* outWindow
);

/**
 * Address: 0x00AC9A70 (_mwsftag_GetTag)
 *
 * What it does:
 * Finds one named tag within one source tag window and writes the matched
 * child window (`data,size`) to `outWindow`.
 */
moho::MwsfTagWindow* mwsftag_GetTag(
  moho::MwsfTagWindow* sourceWindow,
  const char* tagName,
  const char* userInfoTag,
  moho::MwsfTagWindow* outWindow
);

/**
 * Address: 0x00AC9AD0 (_mwsftag_GetIntVal)
 *
 * What it does:
 * Reads one integer tag value from one tag window.
 */
std::int32_t mwsftag_GetIntVal(
  moho::MwsfTagWindow* sourceWindow,
  const char* tagName,
  const char* userInfoTag,
  std::int32_t* outValue
);

/**
 * Address: 0x00AC9C20 (_mwsftag_MoveNextTag)
 *
 * What it does:
 * Advances one source window past the current child tag and emits the
 * remaining window span.
 */
std::int32_t mwsftag_MoveNextTag(
  const moho::MwsfTagWindow* sourceWindow,
  const moho::MwsfTagWindow* currentTagWindow,
  moho::MwsfTagWindow* outRemainingWindow
);

/**
 * Address: 0x00AC9ED0 (_MWSFD_CmpTime)
 *
 * What it does:
 * Clamps negative time lanes to zero and forwards comparison to
 * Sofdec runtime time-compare helper (`UTY_CmpTime`).
 */
std::int32_t
MWSFD_CmpTime(std::int32_t leftTime, std::int32_t timeUnit, std::int32_t rightTime, std::int32_t currentTime);

/**
 * Address: 0x00AC9D00 (_MWSFTAG_SearchTimedatFromChdat)
 *
 * What it does:
 * Scans one chapter-data tag window for the active `TIMEDAT` span that
 * contains the current playback time and returns that selected window.
 */
std::int8_t* MWSFTAG_SearchTimedatFromChdat(
  moho::MwsfTagWindow* chapterDataWindow,
  std::int32_t compareArg0,
  std::int32_t compareArg1,
  std::int32_t baseTime,
  moho::MwsfTagWindow* outTimedatWindow
);

/**
 * Address: 0x00B06DC0 (_ADXM_Finish)
 *
 * What it does:
 * Tears down ADXM threads/locks/event state when init reference count reaches 0.
 */
void ADXM_Finish();

/**
 * Address: 0x00B17BD0 (FUN_00B17BD0, _ADXRNA_Init)
 *
 * What it does:
 * Initializes ADXRNA global runtime state and increments init reference count.
 */
std::int32_t ADXRNA_Init();

/**
 * Address: 0x00B17BE0 (FUN_00B17BE0, _ADXRNA_Finish)
 *
 * What it does:
 * Decrements ADXRNA init reference count and tears down global runtime state
 * when count reaches zero.
 */
std::int32_t ADXRNA_Finish();

/**
 * Address: 0x00B17B50 (FUN_00B17B50, _ADXCRS_Init)
 *
 * What it does:
 * Increments ADX critical-section init count.
 */
std::int32_t ADXCRS_Init();

/**
 * Address: 0x00B17B70 (FUN_00B17B70, _ADXCRS_Finish)
 *
 * What it does:
 * Decrements ADX critical-section init count.
 */
std::int32_t ADXCRS_Finish();

/**
 * Address: 0x00B17A70 (FUN_00B17A70, _ADXT_ExecFsSvr)
 *
 * What it does:
 * Executes one guarded ADXT filesystem-server tick.
 */
void ADXT_ExecFsSvr();

/**
 * Address: 0x00B17B00 (FUN_00B17B00, _ADXT_ExecFsServer)
 *
 * What it does:
 * Executes one guarded ADXT filesystem-server wrapper tick.
 */
void ADXT_ExecFsServer();

/**
 * Address: 0x00B17B20 (FUN_00B17B20, _ADXT_IsActiveFsSvr)
 *
 * What it does:
 * Returns whether ADXT filesystem-server dispatch is currently active.
 */
std::int32_t ADXT_IsActiveFsSvr();

/**
 * Address: 0x00B17B90 (_ADXCRS_Lock)
 *
 * What it does:
 * Enters ADX critical section lane via global Sofdec lock.
 */
void ADXCRS_Lock();

/**
 * Address: 0x00B17BA0 (_ADXCRS_Unlock)
 *
 * What it does:
 * Leaves ADX critical section lane via global Sofdec unlock.
 */
void ADXCRS_Unlock();

/**
 * Address: 0x00B177A0 (_SJERR_CallErr)
 */
void SJERR_CallErr(const char* message);

/**
 * Address: 0x00B177F0 (_SJCRS_Lock)
 */
void SJCRS_Lock();

/**
 * Address: 0x00B17800 (_SJCRS_Unlock)
 */
void SJCRS_Unlock();

/**
 * Address: 0x00B07CA0 (_SJRBF_Error)
 */
void SJRBF_Error(std::int32_t errorObject, std::int32_t errorCode);

/**
 * Address: 0x00B07CB0 (_SJRBF_Init)
 */
void SJRBF_Init();

/**
 * Address: 0x00B07CD0 (_sjrbf_Init)
 */
std::int32_t sjrbf_Init();

/**
 * Address: 0x00B07CF0 (_SJRBF_Finish)
 */
std::int32_t SJRBF_Finish();

/**
 * Address: 0x00B07D10 (_sjrbf_Finish)
 */
std::int32_t sjrbf_Finish();

/**
 * Address: 0x00B07D30 (_SJRBF_Create)
 */
moho::SofdecSjRingBufferHandle*
SJRBF_Create(std::int32_t bufferAddress, std::int32_t bufferSize, std::int32_t extraSize);

/**
 * Address: 0x00B07D60 (_sjrbf_Create)
 */
moho::SofdecSjRingBufferHandle*
sjrbf_Create(std::int32_t bufferAddress, std::int32_t bufferSize, std::int32_t extraSize);

/**
 * Address: 0x00B07DD0 (_SJRBF_Destroy)
 */
void SJRBF_Destroy(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B07E40 (_SJRBF_CallErr_)
 */
void SJRBF_CallErr_(const char* errorCode, const char* errorText);

/**
 * Address: 0x00B07DF0 (_sjrbf_Destroy)
 */
void sjrbf_Destroy(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B07EC0 (_sjrbf_GetUuid)
 */
std::int32_t sjrbf_GetUuid(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B07EA0 (_SJRBF_GetUuid)
 */
std::int32_t SJRBF_GetUuid(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B07F30 (_sjrbf_EntryErrFunc)
 */
void sjrbf_EntryErrFunc(
  moho::SofdecSjRingBufferHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B07F00 (_SJRBF_EntryErrFunc)
 */
void SJRBF_EntryErrFunc(
  moho::SofdecSjRingBufferHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B07F80 (_SJRBF_Reset)
 */
void SJRBF_Reset(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B07FA0 (_sjrbf_Reset)
 */
moho::SofdecSjRingBufferHandle* sjrbf_Reset(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B08000 (_SJRBF_GetNumData)
 */
std::int32_t SJRBF_GetNumData(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B08030 (_sjrbf_GetNumData)
 */
std::int32_t sjrbf_GetNumData(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B080A0 (_SJRBF_GetChunk)
 */
void SJRBF_GetChunk(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B080D0 (_sjrbf_GetChunk)
 */
void sjrbf_GetChunk(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B08210 (_SJRBF_PutChunk)
 */
void SJRBF_PutChunk(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B08240 (_sjrbf_PutChunk)
 */
void sjrbf_PutChunk(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B08360 (_SJRBF_UngetChunk)
 */
void SJRBF_UngetChunk(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B08390 (_sjrbf_UngetChunk)
 */
void sjrbf_UngetChunk(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B084F0 (_SJRBF_IsGetChunk)
 */
std::int32_t SJRBF_IsGetChunk(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B08520 (_sjrbf_IsGetChunk)
 */
std::int32_t sjrbf_IsGetChunk(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B085F0 (_SJRBF_GetBufPtr)
 */
std::int32_t SJRBF_GetBufPtr(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B08610 (_sjrbf_GetBufPtr)
 */
std::int32_t sjrbf_GetBufPtr(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B08650 (_SJRBF_GetBufSize)
 */
std::int32_t SJRBF_GetBufSize(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B08670 (_sjrbf_GetBufSize)
 */
std::int32_t sjrbf_GetBufSize(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B086B0 (_SJRBF_GetXtrSize)
 */
std::int32_t SJRBF_GetXtrSize(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B086D0 (_sjrbf_GetXtrSize)
 */
std::int32_t sjrbf_GetXtrSize(moho::SofdecSjRingBufferHandle* handle);

/**
 * Address: 0x00B08710 (_SJRBF_SetFlowCnt)
 */
void SJRBF_SetFlowCnt(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t counterIndex,
  std::int32_t value
);

/**
 * Address: 0x00B08740 (_sjrbf_SetFlowCnt)
 */
void sjrbf_SetFlowCnt(
  moho::SofdecSjRingBufferHandle* handle,
  std::int32_t lane,
  std::int32_t counterIndex,
  std::int32_t value
);

/**
 * Address: 0x00B08790 (_SJRBF_GetFlowCnt)
 */
std::int32_t SJRBF_GetFlowCnt(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, std::int32_t counterIndex);

/**
 * Address: 0x00B087C0 (_sjrbf_GetFlowCnt)
 */
std::int32_t sjrbf_GetFlowCnt(moho::SofdecSjRingBufferHandle* handle, std::int32_t lane, std::int32_t counterIndex);

/**
 * Address: 0x00B09030 (_SJMEM_Error)
 */
void SJMEM_Error(std::int32_t errorObject, std::int32_t errorCode);

/**
 * Address: 0x00B09040 (_SJMEM_Init)
 */
void SJMEM_Init();

/**
 * Address: 0x00B09060 (_sjmem_Init)
 */
std::int32_t sjmem_Init();

/**
 * Address: 0x00B09080 (_SJMEM_Finish)
 */
std::int32_t SJMEM_Finish();

/**
 * Address: 0x00B090A0 (_sjmem_Finish)
 */
std::int32_t sjmem_Finish();

/**
 * Address: 0x00B090C0 (_SJMEM_Create)
 */
moho::SofdecSjMemoryHandle* SJMEM_Create(std::int32_t bufferAddress, std::int32_t bufferSize);

/**
 * Address: 0x00B090F0 (_sjmem_Create)
 */
moho::SofdecSjMemoryHandle* sjmem_Create(std::int32_t bufferAddress, std::int32_t bufferSize);

/**
 * Address: 0x00B091D0 (_SJMEM_CallErr_)
 */
void SJMEM_CallErr_(const char* errorCode, const char* errorText);

/**
 * Address: 0x00B09180 (_sjmem_Destroy)
 */
std::int32_t sjmem_Destroy(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09160 (_SJMEM_Destroy)
 */
void SJMEM_Destroy(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09250 (_sjmem_GetUuid)
 */
std::int32_t sjmem_GetUuid(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09230 (_SJMEM_GetUuid)
 */
std::int32_t SJMEM_GetUuid(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B092C0 (_sjmem_EntryErrFunc)
 */
void sjmem_EntryErrFunc(
  moho::SofdecSjMemoryHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B09290 (_SJMEM_EntryErrFunc)
 */
void SJMEM_EntryErrFunc(
  moho::SofdecSjMemoryHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B09310 (_SJMEM_Reset)
 */
void SJMEM_Reset(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09330 (_sjmem_Reset)
 */
moho::SofdecSjMemoryHandle* sjmem_Reset(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09380 (_SJMEM_GetNumData)
 *
 * What it does:
 * Returns readable-byte count for one SJMEM lane under lock.
 */
std::int32_t SJMEM_GetNumData(moho::SofdecSjMemoryHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B093B0 (_sjmem_GetNumData)
 *
 * What it does:
 * Returns readable-byte count for lane `1`; lane `0` returns `0`.
 */
std::int32_t sjmem_GetNumData(moho::SofdecSjMemoryHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B09410 (_SJMEM_GetChunk)
 *
 * What it does:
 * Lock-wrapper that fetches one readable chunk descriptor from SJMEM.
 */
void SJMEM_GetChunk(
  moho::SofdecSjMemoryHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B09440 (_sjmem_GetChunk)
 *
 * What it does:
 * Emits one chunk-range (`bufferAddress`, `byteCount`) for lane `1`.
 */
void sjmem_GetChunk(
  moho::SofdecSjMemoryHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B094E0 (_SJMEM_PutChunk)
 *
 * What it does:
 * Lock-wrapper for SJMEM put-chunk validation lane.
 */
void SJMEM_PutChunk(moho::SofdecSjMemoryHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B09510 (_sjmem_PutChunk)
 *
 * What it does:
 * Validates put-chunk lane selection and reports invalid-lane requests.
 */
void sjmem_PutChunk(moho::SofdecSjMemoryHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B09590 (_SJMEM_UngetChunk)
 *
 * What it does:
 * Lock-wrapper that rewinds one previously granted SJMEM chunk.
 */
void SJMEM_UngetChunk(moho::SofdecSjMemoryHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B095C0 (_sjmem_UngetChunk)
 *
 * What it does:
 * Rewinds lane `1` read state when chunk address/size match expected cursor.
 */
void sjmem_UngetChunk(moho::SofdecSjMemoryHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B09680 (_SJMEM_IsGetChunk)
 *
 * What it does:
 * Lock-wrapper that reports whether requested SJMEM bytes are available.
 */
std::int32_t SJMEM_IsGetChunk(
  moho::SofdecSjMemoryHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B096B0 (_sjmem_IsGetChunk)
 *
 * What it does:
 * Writes granted-byte count and returns whether it equals request size.
 */
std::int32_t sjmem_IsGetChunk(
  moho::SofdecSjMemoryHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B09760 (_SJMEM_GetBufPtr)
 *
 * What it does:
 * Lock-wrapper returning SJMEM base buffer address lane.
 */
std::int32_t SJMEM_GetBufPtr(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09780 (_sjmem_GetBufPtr)
 *
 * What it does:
 * Returns SJMEM base buffer address lane for a valid handle.
 */
std::int32_t sjmem_GetBufPtr(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B097C0 (_SJMEM_GetBufSize)
 *
 * What it does:
 * Lock-wrapper returning SJMEM configured buffer size.
 */
std::int32_t SJMEM_GetBufSize(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B097E0 (_sjmem_GetBufSize)
 *
 * What it does:
 * Returns SJMEM configured buffer size for a valid handle.
 */
std::int32_t sjmem_GetBufSize(moho::SofdecSjMemoryHandle* handle);

/**
 * Address: 0x00B09960 (_SJUNI_Error)
 */
void SJUNI_Error(std::int32_t errorObject, std::int32_t errorCode);

/**
 * Address: 0x00B09970 (_SJUNI_Init)
 */
void SJUNI_Init();

/**
 * Address: 0x00B09990 (_sjuni_Init)
 */
std::int32_t sjuni_Init();

/**
 * Address: 0x00B099B0 (_SJUNI_Finish)
 */
std::int32_t SJUNI_Finish();

/**
 * Address: 0x00B099D0 (_sjuni_Finish)
 */
std::int32_t sjuni_Finish();

/**
 * Address: 0x00B099F0 (_SJUNI_Create)
 */
moho::SofdecSjUnifyHandle*
SJUNI_Create(std::uint8_t mergeAdjacentChunks, std::int32_t chainPoolAddress, std::int32_t chainPoolBytes);

/**
 * Address: 0x00B09A20 (_sjuni_Create)
 */
moho::SofdecSjUnifyHandle*
sjuni_Create(std::uint8_t mergeAdjacentChunks, std::int32_t chainPoolAddress, std::int32_t chainPoolBytes);

/**
 * Address: 0x00B09AA0 (_SJUNI_Destroy)
 */
void SJUNI_Destroy(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09AC0 (_sjuni_Destroy)
 */
void sjuni_Destroy(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09B10 (_SJUNI_CallErr_)
 */
void SJUNI_CallErr_(const char* errorCode, const char* errorText);

/**
 * Address: 0x00B09B70 (_SJUNI_GetUuid)
 */
std::int32_t SJUNI_GetUuid(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09B90 (_sjuni_GetUuid)
 */
std::int32_t sjuni_GetUuid(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09BD0 (_SJUNI_EntryErrFunc)
 */
void SJUNI_EntryErrFunc(
  moho::SofdecSjUnifyHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B09C00 (_sjuni_EntryErrFunc)
 */
void sjuni_EntryErrFunc(
  moho::SofdecSjUnifyHandle* handle,
  moho::SofdecErrorHandler errorHandler,
  std::int32_t errorObject
);

/**
 * Address: 0x00B09C50 (_SJUNI_Reset)
 */
void SJUNI_Reset(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09C70 (_sjuni_Reset)
 */
void sjuni_Reset(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B09D00 (_SJUNI_GetNumData)
 */
std::int32_t SJUNI_GetNumData(moho::SofdecSjUnifyHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B09D30 (_sjuni_GetNumData)
 */
std::int32_t sjuni_GetNumData(moho::SofdecSjUnifyHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B09DB0 (_SJUNI_GetChunk)
 */
void SJUNI_GetChunk(
  moho::SofdecSjUnifyHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B09DE0 (_sjuni_GetChunk)
 */
void sjuni_GetChunk(
  moho::SofdecSjUnifyHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  moho::SjChunkRange* outChunkRange
);

/**
 * Address: 0x00B09EF0 (_SJUNI_PutChunk)
 */
void SJUNI_PutChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B09F20 (_sjuni_PutChunk)
 */
void sjuni_PutChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B0A020 (_SJUNI_UngetChunk)
 */
void SJUNI_UngetChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B0A050 (_sjuni_UngetChunk)
 */
void sjuni_UngetChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane, moho::SjChunkRange* chunkRange);

/**
 * Address: 0x00B0A140 (_SJUNI_IsGetChunk)
 */
std::int32_t SJUNI_IsGetChunk(
  moho::SofdecSjUnifyHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B0A170 (_sjuni_IsGetChunk)
 */
std::int32_t sjuni_IsGetChunk(
  moho::SofdecSjUnifyHandle* handle,
  std::int32_t lane,
  std::int32_t requestedBytes,
  std::int32_t* outGrantedBytes
);

/**
 * Address: 0x00B0A230 (_SJUNI_GetNumChunk)
 */
std::int32_t SJUNI_GetNumChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B0A260 (_sjuni_GetNumChunk)
 */
std::int32_t sjuni_GetNumChunk(moho::SofdecSjUnifyHandle* handle, std::int32_t lane);

/**
 * Address: 0x00B0A2B0 (_SJUNI_GetNumChainPool)
 */
std::int32_t SJUNI_GetNumChainPool(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B0A2D0 (_sjuni_GetNumChainPool)
 */
std::int32_t sjuni_GetNumChainPool(moho::SofdecSjUnifyHandle* handle);

/**
 * Address: 0x00B207D0 (_CRICRS_Enter)
 *
 * What it does:
 * Enters Sofdec RNA global critical section.
 */
void CRICRS_Enter();

/**
 * Address: 0x00B207E0 (_CRICRS_Leave)
 *
 * What it does:
 * Leaves Sofdec RNA global critical section.
 */
void CRICRS_Leave();

/**
 * Address: 0x00B15860 (FUN_00B15860, sub_B15860)
 *
 * What it does:
 * Returns ADXRNA play-flag bit (`stateFlags bit1`) for one RNA handle.
 */
std::int32_t ADXRNA_IsPlaySwEnabled(std::int32_t rnaHandle);

/**
 * Address: 0x00B14E40 (FUN_00B14E40, _ADXRNA_SetPlaySw)
 *
 * What it does:
 * Updates ADXRNA play-switch lane and transition flags under RNA lock.
 */
void ADXRNA_SetPlaySw(std::int32_t rnaHandle, std::int32_t enabled);

/**
 * Address: 0x00B207F0 (adxrna_Init)
 *
 * What it does:
 * Clears active lanes for the fixed RNA timing node pool.
 */
moho::AdxrnaTimingState* adxrna_Init();

/**
 * Address: 0x00B20B30 (ADXB_SetDecErrMode)
 *
 * What it does:
 * Sets process-global ADXB decode-error mode lane.
 */
std::int32_t ADXB_SetDecErrMode(std::int32_t decodeErrorMode);

/**
 * Address: 0x00B20B40 (ADXB_GetDecErrMode)
 *
 * What it does:
 * Returns process-global ADXB decode-error mode lane.
 */
std::int32_t ADXB_GetDecErrMode();

/**
 * Address: 0x00B20B50 (ADXB_Init)
 *
 * What it does:
 * Initializes ADXB runtime globals and resets decoder object pool.
 */
std::int32_t ADXB_Init();

/**
 * Address: 0x00B20B80 (ADXB_Finish)
 *
 * What it does:
 * Shuts down ADXB runtime globals and clears decoder object pool.
 */
std::int32_t ADXB_Finish();

/**
 * Address: 0x00B20C50 (ADXB_Create)
 *
 * What it does:
 * Allocates and initializes one ADXB decoder object from fixed runtime pool.
 */
moho::AdxBitstreamDecoderState* ADXB_Create(void* pcmBufferTag, void* pcmBuffer0, void* pcmBuffer1, void* pcmBuffer2);

/**
 * Address: 0x00B20CF0 (ADXB_Destroy)
 *
 * What it does:
 * Tears down one ADXB decoder object and clears its runtime slot.
 */
std::int32_t ADXB_Destroy(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B20AF0 (func_SofDecGetTime)
 *
 * What it does:
 * Returns monotonic performance-counter time in microseconds.
 */
std::int32_t SofDecGetTimeMicroseconds();

/**
 * Address: 0x00B20D20 (SKG_Init)
 *
 * What it does:
 * Increments global SKG init reference count.
 */
std::int32_t SKG_Init();

/**
 * Address: 0x00B20D30 (SKG_Finish)
 *
 * What it does:
 * Decrements global SKG init reference count.
 */
std::int32_t SKG_Finish();

/**
 * Address: 0x00B20D40 (ADXB_DecodeHeaderAdx)
 *
 * What it does:
 * Decodes one ADX/AHX header and seeds the ADXB decoder state lanes.
 */
std::int32_t
ADXB_DecodeHeaderAdx(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);

/**
 * Address: 0x00B20FE0 (ADXB_SetDefFmt)
 *
 * What it does:
 * Selects default ADXB output format based on requested codec family.
 */
void ADXB_SetDefFmt(moho::AdxBitstreamDecoderState* decoder, std::int32_t requestedFormat);

/**
 * Address: 0x00B21050 (ADXB_SetDefPrm)
 *
 * What it does:
 * Resets ADXB runtime parameters to default decode lanes.
 */
moho::AdxBitstreamDecoderState* ADXB_SetDefPrm(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B210E0 (ADXB_DecodeHeader)
 *
 * What it does:
 * Dispatches one input header to the matching ADXB decoder path.
 */
std::int32_t
ADXB_DecodeHeader(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);

/**
 * Address: 0x00B211E0 (ADXB_EntryGetWrFunc)
 *
 * What it does:
 * Registers entry-get write callback lane and context.
 */
moho::AdxBitstreamDecoderState* ADXB_EntryGetWrFunc(
  moho::AdxBitstreamDecoderState* decoder,
  void* entryGetWriteFunc,
  std::int32_t entryGetWriteContext
);

/**
 * Address: 0x00B21200 (ADXB_EntryAddWrFunc)
 *
 * What it does:
 * Registers entry-add write callback lane and context.
 */
moho::AdxBitstreamDecoderState* ADXB_EntryAddWrFunc(
  moho::AdxBitstreamDecoderState* decoder,
  void* entryAddWriteFunc,
  std::int32_t entryAddWriteContext
);

/**
 * Address: 0x00B21220 (ADXB_GetPcmBuf)
 *
 * What it does:
 * Returns primary PCM output buffer pointer.
 */
void* ADXB_GetPcmBuf(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21230 (ADXB_GetFormat)
 *
 * What it does:
 * Returns active ADXB decode format lane.
 */
std::int32_t ADXB_GetFormat(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21240 (ADXB_GetSfreq)
 *
 * What it does:
 * Returns decoded stream sample-rate lane.
 */
std::int32_t ADXB_GetSfreq(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21250 (ADXB_GetNumChan)
 *
 * What it does:
 * Returns effective output channel count (including channel-expand override).
 */
std::int32_t ADXB_GetNumChan(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21270 (ADXB_GetFmtBps)
 *
 * What it does:
 * Returns source bit-depth lane.
 */
std::int32_t ADXB_GetFmtBps(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21280 (ADXB_GetOutBps)
 *
 * What it does:
 * Returns output sample packing bit-depth based on format/pacing lanes.
 */
std::int32_t ADXB_GetOutBps(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B212E0 (ADXB_GetBlkSmpl)
 *
 * What it does:
 * Returns source block sample-count lane.
 */
std::int32_t ADXB_GetBlkSmpl(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B212F0 (ADXB_GetBlkLen)
 *
 * What it does:
 * Returns source block byte-length lane.
 */
std::int32_t ADXB_GetBlkLen(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21300 (ADXB_GetTotalNumSmpl)
 *
 * What it does:
 * Returns decoded total sample-count lane.
 */
std::int32_t ADXB_GetTotalNumSmpl(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21310 (ADXB_GetCof)
 *
 * What it does:
 * Returns ADPCM coefficient index lane.
 */
std::int32_t ADXB_GetCof(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21320 (ADXB_GetLpInsNsmpl)
 *
 * What it does:
 * Returns loop inserted-sample count lane.
 */
std::int32_t ADXB_GetLpInsNsmpl(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21330 (ADXB_GetNumLoop)
 *
 * What it does:
 * Returns loop count lane.
 */
std::int32_t ADXB_GetNumLoop(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21340 (ADXB_GetLpStartPos)
 *
 * What it does:
 * Returns loop-start sample index from one ADXB decoder state object.
 */
std::int32_t ADXB_GetLpStartPos(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21350 (ADXB_GetLpStartOfst)
 *
 * What it does:
 * Returns loop-start byte offset from one ADXB decoder state object.
 */
std::int32_t ADXB_GetLpStartOfst(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21360 (ADXB_GetLpEndPos)
 *
 * What it does:
 * Returns loop-end sample index from one ADXB decoder state object.
 */
std::int32_t ADXB_GetLpEndPos(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21370 (ADXB_GetLpEndOfst)
 *
 * What it does:
 * Returns loop-end byte offset from one ADXB decoder state object.
 */
std::int32_t ADXB_GetLpEndOfst(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21380 (ADXB_GetAinfLen)
 *
 * What it does:
 * Returns AINF extension payload length cached in the decoder state.
 */
std::int32_t ADXB_GetAinfLen(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21390 (ADXB_GetDefOutVol)
 *
 * What it does:
 * Returns default output volume from AINF metadata.
 */
std::int16_t ADXB_GetDefOutVol(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B213A0 (ADXB_GetDefPan)
 *
 * What it does:
 * Returns one default pan lane from AINF metadata.
 */
std::int16_t ADXB_GetDefPan(const moho::AdxBitstreamDecoderState* decoder, std::int32_t channelIndex);

/**
 * Address: 0x00B213C0 (ADXB_GetDataId)
 *
 * What it does:
 * Returns pointer to cached AINF data-id bytes.
 */
std::uint8_t* ADXB_GetDataId(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B213D0 (ADXB_TakeSnapshot)
 *
 * What it does:
 * Captures ADX packet-decoder delay/ext-key lanes into ADXB snapshot fields.
 */
std::int32_t ADXB_TakeSnapshot(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21410 (ADXB_RestoreSnapshot)
 *
 * What it does:
 * Restores ADX packet-decoder delay/ext-key lanes from ADXB snapshot fields.
 */
std::int32_t ADXB_RestoreSnapshot(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21460 (ADXSJE_SetExtString)
 *
 * What it does:
 * Generates and stores per-stream ADX key triple from one extension string.
 */
moho::AdxBitstreamDecoderState* ADXSJE_SetExtString(moho::AdxBitstreamDecoderState* decoder, const char* extString);

/**
 * Address: 0x00B214C0 (SKG_GenerateKey)
 *
 * What it does:
 * Generates one ADX key triple (`k0, km, ka`) from input bytes.
 */
std::int32_t SKG_GenerateKey(
  const char* sourceBytes,
  std::int32_t sourceLength,
  std::int16_t* outKey0,
  std::int16_t* outKeyMultiplier,
  std::int16_t* outKeyAdder
);

/**
 * Address: 0x00B215D0 (ADXB_SetDefExtString)
 *
 * What it does:
 * Updates process-global default ADX extension key triple from one string.
 */
std::int32_t ADXB_SetDefExtString(const char* extString);

/**
 * Address: 0x00B21600 (ADXB_GetExtParams)
 *
 * What it does:
 * Returns decoder-local ADX extension key triple.
 */
std::int16_t ADXB_GetExtParams(
  const moho::AdxBitstreamDecoderState* decoder,
  std::int16_t* outKey0,
  std::int16_t* outKeyMultiplier,
  std::int16_t* outKeyAdder
);

/**
 * Address: 0x00B21630 (ADXB_SetExtParams)
 *
 * What it does:
 * Stores decoder-local ADX extension key triple.
 */
moho::AdxBitstreamDecoderState* ADXB_SetExtParams(
  moho::AdxBitstreamDecoderState* decoder,
  std::int16_t key0,
  std::int16_t keyMultiplier,
  std::int16_t keyAdder
);

/**
 * Address: 0x00B21660 (adxb_get_key)
 *
 * What it does:
 * Resolves runtime key triple based on ADX encryption mode/version lanes.
 */
std::int32_t adxb_get_key(
  moho::AdxBitstreamDecoderState* decoder,
  std::uint8_t encryptionMode,
  std::uint8_t headerVersion,
  std::int32_t streamId,
  std::int16_t* outKey0,
  std::int16_t* outKeyMultiplier,
  std::int16_t* outKeyAdder
);

/**
 * Address: 0x00B21770 (ADXB_GetStat)
 *
 * What it does:
 * Returns decoder status lane.
 */
std::int32_t ADXB_GetStat(const moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21780 (ADXB_EntryData)
 *
 * What it does:
 * Seeds one decode-entry run and returns number of decode blocks.
 */
std::int32_t
ADXB_EntryData(moho::AdxBitstreamDecoderState* decoder, std::int32_t streamDataOffset, std::int32_t inputBytes);

/**
 * Address: 0x00B217F0 (ADXB_Start)
 *
 * What it does:
 * Transitions one ADXB decoder to running state.
 */
moho::AdxBitstreamDecoderState* ADXB_Start(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x00B21810 (ADXB_Stop)
 *
 * What it does:
 * Runs optional post-process detach and stops one ADX packet decoder.
 */
std::int32_t ADXB_Stop(moho::AdxBitstreamDecoderState* decoder);

/**
 * Address: 0x0109BC6C data lane assigned by ADXT attach helpers.
 *
 * What it does:
 * Optional post-process detach callback consumed by `ADXB_Stop`.
 */
extern void(__cdecl* ADXB_OnStopPostProcess)(moho::AdxBitstreamDecoderState* decoder);
}
