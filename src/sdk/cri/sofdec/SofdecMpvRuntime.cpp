/**
 * CRI Sofdec MPV (Movie Player Video) subsystem runtime functions.
 *
 * This file contains recovered initialization and parameter-validation logic
 * for the statically linked CRI Sofdec MPV library as shipped in Forged Alliance.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

// ---------------------------------------------------------------------------
// Forward declarations for CRI library functions used by this module
// ---------------------------------------------------------------------------

extern "C" {
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  std::int32_t UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
  std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
  void SFTIM_UpdateItime(void* timerState, std::int32_t interpolationTime);
  std::int32_t SFTIM_GetNextItime(void* timerState, std::int32_t interpolationTime);
  void SFTIM_GetTime(std::int32_t workctrlAddress, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  std::int32_t SFTIM_GetSpeed(std::int32_t workctrlAddress);
  std::int32_t UTY_CmpTime(
    std::int32_t lhsMajor,
    std::int32_t lhsMinor,
    std::int32_t rhsMajor,
    std::int32_t rhsMinor
  );
  void sfmpv_GetDtime(
    std::int32_t workctrlAddress,
    std::int32_t mode,
    std::int32_t* outDeltaMajor,
    std::int32_t* outDeltaMinor
  );
  void sfmpv_SetSkipTtu(std::int32_t workctrlAddress);
  std::int32_t m2v_SkipFrm(std::int32_t decoderHandle, std::int32_t streamBufferAddress);
  std::int32_t SJRBF_GetFlowCnt(std::int32_t streamBufferAddress, std::int32_t lane0, std::int32_t lane1);
  std::int32_t sfmpv_ChkMpvErr(
    std::int32_t workctrlAddress,
    std::int32_t decodeResult,
    std::int32_t consumedBytes,
    std::int32_t errorCode
  );
  std::int32_t sfmpv_AddRtotSj(std::int32_t workctrlAddress, std::int32_t consumedBytes);
  std::int32_t SFPLY_AddSkipPic(
    std::int32_t workctrlAddress,
    std::int32_t skippedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t sfmpvf_GetVfrmDataFromFrmInf(std::int32_t workctrlAddress, std::int32_t frameInfoIndex);
  std::int32_t SFMPVF_SearchFrmObj(std::int32_t workctrlAddress, std::int32_t frameInfoIndex);
  std::int32_t SFMPVF_SearchFrmObjFromId(std::int32_t workctrlAddress, std::int32_t frameObjectId);
  std::int32_t SFMPVF_SearchVfrmData(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  void SFMPVF_EndDrawFrm(std::int32_t frameObjectAddress);
}

// ---------------------------------------------------------------------------
// MPV parameter block -- CRI-internal global state
// ---------------------------------------------------------------------------

/**
 * CRI Sofdec MPV parameter structure, stored at a fixed BSS address.
 * 0x24 bytes (9 DWORDs) are bulk-copied into each MPV info block by
 * `sfmpv_InitInf`.
 */
struct SfmpvPara
{
  std::int32_t field_0x00;         // +0x00
  std::int32_t field_0x04;         // +0x04
  std::int32_t field_0x08;         // +0x08
  std::int32_t field_0x0C;         // +0x0C
  std::int32_t val4;               // +0x10  -- checked by sfmpvf_CheckMpvPara
  std::int32_t field_0x14;         // +0x14
  std::int32_t field_0x18;         // +0x18
  std::int32_t nfrm_pool_wk;      // +0x1C  -- max 16 frame pool entries
  std::int32_t val8;               // +0x20  -- checked by sfmpvf_CheckMpvPara
};

static_assert(sizeof(SfmpvPara) == 0x24, "SfmpvPara size must be 0x24");

// ---------------------------------------------------------------------------
// MPV complement-points sub-structure
// ---------------------------------------------------------------------------

/**
 * Complement (interpolation/prediction) point state, initialised by
 * `sfmpv_InitComplementPts`.  8 DWORDs = 0x20 bytes at known offsets.
 */
struct SfmpvComplementPts
{
  std::int32_t field_0x00; // +0x00
  std::int32_t field_0x04; // +0x04
  std::int32_t field_0x08; // +0x08
  std::int32_t reserved_0C; // +0x0C  (gap -- not written by init)
  std::int32_t field_0x10; // +0x10
  std::int32_t field_0x14; // +0x14
  std::int32_t field_0x18; // +0x18
  std::int32_t field_0x1C; // +0x1C
};

static_assert(sizeof(SfmpvComplementPts) == 0x20, "SfmpvComplementPts size must be 0x20");

// ---------------------------------------------------------------------------
// MPV picture-user sub-structure
// ---------------------------------------------------------------------------

/**
 * Picture-user state block.  `SFMPVF_InitPicUsr` zeroes 5 header DWORDs
 * followed by 16 pairs of DWORDs (32 entries), totalling 37 DWORDs.
 */
struct SfmpvPicUsr
{
  std::int32_t header[5]; // +0x00  -- zeroed by init
  struct PicUsrEntry
  {
    std::int32_t value0; // +0x00
    std::int32_t value1; // +0x04
  };
  PicUsrEntry entries[16]; // +0x14  -- zeroed by init
};

/**
 * Per-handle timing lane consumed by MPV late/skip decision helpers.
 *
 * Evidence:
 * - `FUN_00AD4100` accesses this subobject at workctrl offset `+0x0D30`.
 */
struct SfmpvTimingLane
{
  using IsLateCallback =
    std::int32_t(__cdecl*)(std::int32_t workctrlAddress, std::int32_t mode, std::int32_t interpolationTime, std::int32_t baseFraction);

  std::uint8_t mUnknown00To17[0x18]{}; // +0x00
  IsLateCallback isLateCallback = nullptr; // +0x18
  std::uint8_t mUnknown1CToE3[0xC8]{}; // +0x1C
  std::int32_t baseInterpolationTime = 0; // +0xE4
  std::int32_t baseFraction = 0; // +0xE8
  std::uint8_t mUnknownECTo117[0x2C]{}; // +0xEC
  std::int32_t interpolationEnabled = 0; // +0x118
  std::uint8_t mUnknown11CTo13B[0x20]{}; // +0x11C
  std::int32_t frameInterpolationTime = 0; // +0x13C
  std::uint8_t mUnknown140To163[0x24]{}; // +0x140
  std::int32_t decodeProgressTime = 0; // +0x164
};

static_assert(offsetof(SfmpvTimingLane, isLateCallback) == 0x18, "SfmpvTimingLane::isLateCallback offset must be 0x18");
static_assert(
  offsetof(SfmpvTimingLane, baseInterpolationTime) == 0xE4,
  "SfmpvTimingLane::baseInterpolationTime offset must be 0xE4"
);
static_assert(offsetof(SfmpvTimingLane, baseFraction) == 0xE8, "SfmpvTimingLane::baseFraction offset must be 0xE8");
static_assert(
  offsetof(SfmpvTimingLane, interpolationEnabled) == 0x118,
  "SfmpvTimingLane::interpolationEnabled offset must be 0x118"
);
static_assert(
  offsetof(SfmpvTimingLane, frameInterpolationTime) == 0x13C,
  "SfmpvTimingLane::frameInterpolationTime offset must be 0x13C"
);
static_assert(
  offsetof(SfmpvTimingLane, decodeProgressTime) == 0x164,
  "SfmpvTimingLane::decodeProgressTime offset must be 0x164"
);

/**
 * MPV info lane addressed from one workctrl via pointer at offset `+0x1FC0`.
 */
struct SfmpvInfoRuntimeView
{
  std::int32_t decoderHandle = 0; // +0x00
  std::uint8_t mUnknown04To6F[0x6C]{}; // +0x04
  std::int32_t activeFrameObjectAddress = 0; // +0x70
  std::uint8_t mUnknown74To83[0x10]{}; // +0x74
  std::int32_t lateFrameCounter = 0; // +0x84
  std::uint8_t mUnknown88ToA3[0x1C]{}; // +0x88
  std::int32_t skipPicCallbackContext = 0; // +0xA4
  std::uint8_t mUnknownA8ToE3[0x3C]{}; // +0xA8
  std::uint8_t disableSkipLatch = 0; // +0xE4
  std::uint8_t mUnknownE5To16B[0x87]{}; // +0xE5
  std::int32_t skipIssuedFlag = 0; // +0x16C
};

static_assert(offsetof(SfmpvInfoRuntimeView, decoderHandle) == 0x00, "SfmpvInfoRuntimeView::decoderHandle offset must be 0x00");
static_assert(
  offsetof(SfmpvInfoRuntimeView, activeFrameObjectAddress) == 0x70,
  "SfmpvInfoRuntimeView::activeFrameObjectAddress offset must be 0x70"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, lateFrameCounter) == 0x84,
  "SfmpvInfoRuntimeView::lateFrameCounter offset must be 0x84"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, skipPicCallbackContext) == 0xA4,
  "SfmpvInfoRuntimeView::skipPicCallbackContext offset must be 0xA4"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, disableSkipLatch) == 0xE4,
  "SfmpvInfoRuntimeView::disableSkipLatch offset must be 0xE4"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, skipIssuedFlag) == 0x16C,
  "SfmpvInfoRuntimeView::skipIssuedFlag offset must be 0x16C"
);

/**
 * Workctrl runtime view used by recovered MPV helper lanes.
 */
struct SfmpvHandleRuntimeView
{
  std::uint8_t mUnknown00To57[0x58]{}; // +0x00
  std::int32_t decodePathMode = 0; // +0x58
  std::uint8_t mUnknown5CToAA3[0xA48]{}; // +0x5C
  std::int32_t lateFrameGateThreshold = 0; // +0xAA4
  std::uint8_t mUnknownAA8ToD2F[0x288]{}; // +0xAA8
  SfmpvTimingLane timingLane{}; // +0xD30
  std::uint8_t mUnknownE98To1FBF[0x1128]{}; // +0xE98
  SfmpvInfoRuntimeView* mpvInfo = nullptr; // +0x1FC0
};

static_assert(offsetof(SfmpvHandleRuntimeView, decodePathMode) == 0x58, "SfmpvHandleRuntimeView::decodePathMode offset must be 0x58");
static_assert(
  offsetof(SfmpvHandleRuntimeView, lateFrameGateThreshold) == 0xAA4,
  "SfmpvHandleRuntimeView::lateFrameGateThreshold offset must be 0xAA4"
);
static_assert(offsetof(SfmpvHandleRuntimeView, timingLane) == 0xD30, "SfmpvHandleRuntimeView::timingLane offset must be 0xD30");
static_assert(offsetof(SfmpvHandleRuntimeView, mpvInfo) == 0x1FC0, "SfmpvHandleRuntimeView::mpvInfo offset must be 0x1FC0");

struct SfmpvfVfrmDataRuntime
{
  std::int32_t drawState = 0; // +0x00
};

static_assert(offsetof(SfmpvfVfrmDataRuntime, drawState) == 0x00, "SfmpvfVfrmDataRuntime::drawState offset must be 0x00");

// ---------------------------------------------------------------------------
// Global CRI MPV state variables (BSS)
// ---------------------------------------------------------------------------

extern "C" {
  extern SfmpvPara sfmpv_para;
  extern std::int32_t sfmpv_rfb_adr_tbl[2];
  extern std::int32_t sfmpv_work;
  extern std::int32_t sSofDec_tabs[16];
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

namespace
{
  /** MPV parameter validation failure code. */
  constexpr std::int32_t kSfmpvErrInvalidPara = -16773355; // 0xFF000F15
  constexpr std::int32_t kSfmpvErrSkipFrameFailed = -16773369; // 0xFF000F07
  constexpr std::int32_t kSfmpvErrFrameObjectMissingById = -16773345; // 0xFF000F1F
  constexpr std::int32_t kSfmpvErrInvalidVfrmDrawState = -16773362; // 0xFF000F0E
  constexpr std::int32_t kSfmpvErrFrameObjectMismatch = -16773361; // 0xFF000F0F

  template <typename T>
  [[nodiscard]] T* AddressToPointer(const std::int32_t address) noexcept
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }
}

// ---------------------------------------------------------------------------
// Recovered functions
// ---------------------------------------------------------------------------

extern "C" {

/**
 * Address: 0x00ADAC30 (FUN_00ADAC30, _SFTIM_InitTcode)
 *
 * What it does:
 * Zeroes a 32-byte timecode structure (7 DWORDs + 2 WORDs at end).
 */
std::int32_t SFTIM_InitTcode(void* timecodeState)
{
  auto* const state = static_cast<std::uint8_t*>(timecodeState);

  std::memset(state, 0, 28);             // 7 DWORDs
  *reinterpret_cast<std::uint16_t*>(state + 28) = 0;
  *reinterpret_cast<std::uint16_t*>(state + 30) = 0;

  return reinterpret_cast<std::int32_t>(timecodeState);
}

/**
 * Address: 0x00ADAC00 (FUN_00ADAC00, _SFTIM_InitTtu)
 *
 * What it does:
 * Initialises a time-tracking unit: zeroes the head DWORD, inits the
 * embedded timecode, then sets the mode and scale fields.
 */
std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue)
{
  timerState[0] = 0;
  const auto result = SFTIM_InitTcode(timerState + 1);
  timerState[9] = static_cast<std::uint32_t>(initialValue);
  timerState[10] = 1;
  return result;
}

/**
 * Address: 0x00AD4EA0 (FUN_00AD4EA0, _sfmpv_InitPicAtr)
 *
 * What it does:
 * Fills a 32-DWORD picture-attribute block with 0xFFFFFFFF (-1).
 */
void sfmpv_InitPicAtr(void* picAtrState)
{
  UTY_MemsetDword(picAtrState, 0xFFFFFFFF, 0x20);
}

/**
 * Address: 0x00AD4E30 (FUN_00AD4E30, _sfmpv_InitFrmObj)
 *
 * What it does:
 * Initialises an array of frame objects. Each frame object is 58 DWORDs
 * (0xE8 bytes). Clears control fields, initialises the embedded timer,
 * copies one tab entry per frame, and inits picture attributes.
 */
void sfmpv_InitFrmObj(std::uint32_t* frameObjects, const std::int32_t* tabEntries, std::int32_t count)
{
  for (std::int32_t i = 0; i < count; ++i, frameObjects += 58) {
    frameObjects[0] = 0;
    frameObjects[1] = 0;
    SFTIM_InitTtu(frameObjects + 3, 0);
    frameObjects[2] = static_cast<std::uint32_t>(tabEntries[i]);
    frameObjects[14] = 0;
    frameObjects[15] = 1;
    frameObjects[16] = 0;
    frameObjects[17] = 0;
    frameObjects[18] = 0;
    frameObjects[19] = 0;
    frameObjects[20] = 0;
    frameObjects[22] = 0xFFFFFFFF; // -1
    sfmpv_InitPicAtr(frameObjects + 23);
  }
}

/**
 * Address: 0x00AD4DB0 (FUN_00AD4DB0, _sfmpv_InitComplementPts)
 *
 * What it does:
 * Zeroes and sentinel-fills an 8-DWORD complement-points block.
 */
void sfmpv_InitComplementPts(std::uint32_t* complementPts)
{
  complementPts[0] = 0;
  complementPts[1] = 0;
  complementPts[2] = 0;
  complementPts[4] = 0xFFFFFFFF; // -1
  complementPts[5] = 0xFFFFFFFF; // -1
  complementPts[6] = 0;
  complementPts[7] = 0xFFFFFFFF; // -1
}

/**
 * Address: 0x00AD4EC0 (FUN_00AD4EC0, _SFMPVF_InitPicUsr)
 *
 * What it does:
 * Zeroes the picture-user state: 5 header DWORDs followed by 16 pairs
 * (32 DWORDs).
 */
void SFMPVF_InitPicUsr(std::uint32_t* picUsrState)
{
  picUsrState[0] = 0;
  picUsrState[1] = 0;
  picUsrState[2] = 0;
  picUsrState[3] = 0;
  picUsrState[4] = 0;

  std::uint32_t* cursor = picUsrState + 5;
  for (std::int32_t i = 0; i < 16; ++i) {
    cursor[0] = 0;
    cursor[1] = 0;
    cursor += 2;
  }
}

/**
 * Address: 0x00AD4DD0 (FUN_00AD4DD0, _sfmpvf_CheckMpvPara)
 *
 * What it does:
 * Validates global MPV parameters: frame pool count must be in [1..16],
 * and either (val4 && val8) hold, or all rfb address table entries and
 * SofDec tab entries must be non-zero.
 */
std::int32_t sfmpvf_CheckMpvPara()
{
  if (sfmpv_para.nfrm_pool_wk <= 0 || sfmpv_para.nfrm_pool_wk > 16) {
    return -1;
  }

  if (sfmpv_para.val4 != 0 && sfmpv_para.val8 != 0) {
    return 0;
  }

  // Check rfb address table -- all entries up to sfmpv_work boundary must be non-zero
  const auto* rfbEntry = &sfmpv_rfb_adr_tbl[0];
  while (*rfbEntry != 0) {
    ++rfbEntry;
    if (reinterpret_cast<std::uintptr_t>(rfbEntry) >= reinterpret_cast<std::uintptr_t>(&sfmpv_work)) {
      // All rfb entries non-zero; now check SofDec tabs
      for (std::int32_t idx = 0; idx < sfmpv_para.nfrm_pool_wk; ++idx) {
        if (sSofDec_tabs[idx] == 0) {
          return -1;
        }
      }
      return 0;
    }
  }

  return -1;
}

/**
 * Address: 0x00AD4C80 (FUN_00AD4C80, _sfmpv_InitInf)
 *
 * IDA signature:
 * int __cdecl sfmpv_InitInf(int a1, _DWORD *a2)
 *
 * What it does:
 * Initialises an MPV info block: validates global parameters, copies the
 * parameter block, rfb address table, and SofDec tabs into the info
 * structure, then initialises frame objects, picture attributes,
 * complement points, picture-user state, and links user-stream slots.
 */
std::int32_t sfmpv_InitInf(std::int32_t /*unused*/, std::uint32_t* infoBlock)
{
  if (sfmpvf_CheckMpvPara() != 0) {
    return SFLIB_SetErr(0, kSfmpvErrInvalidPara);
  }

  // Copy parameter block (9 DWORDs = 0x24 bytes) starting at infoBlock[1]
  std::memcpy(infoBlock + 1, &sfmpv_para, 0x24);

  // Copy rfb address table entries
  infoBlock[10] = static_cast<std::uint32_t>(sfmpv_rfb_adr_tbl[0]);
  infoBlock[11] = static_cast<std::uint32_t>(sfmpv_rfb_adr_tbl[1]);

  // Copy SofDec tabs (16 DWORDs = 0x40 bytes) starting at infoBlock[12]
  std::memcpy(infoBlock + 12, sSofDec_tabs, 0x40);

  // Zero/init header and control fields
  infoBlock[0] = 0;
  infoBlock[28] = 0;
  infoBlock[29] = 5;
  infoBlock[30] = 192;       // 0xC0
  infoBlock[78] = 0;
  infoBlock[79] = 1;
  infoBlock[31] = 0;
  infoBlock[32] = 0;
  infoBlock[88] = 0;
  infoBlock[89] = 0;
  infoBlock[90] = 0;
  infoBlock[91] = 0;
  infoBlock[92] = 0;
  infoBlock[93] = 0;

  // Initialise frame objects (16 entries starting at infoBlock[96], using tab entries from infoBlock[12])
  sfmpv_InitFrmObj(infoBlock + 96, reinterpret_cast<const std::int32_t*>(infoBlock + 12), 16);

  infoBlock[33] = 0;
  infoBlock[34] = 0;

  // Initialise picture attributes at infoBlock[35]
  sfmpv_InitPicAtr(infoBlock + 35);

  // Sentinel and control fields
  infoBlock[67] = 0xFFFFFFFF; // -1
  infoBlock[68] = 0;
  infoBlock[69] = 0x7FFFFFFF;

  // Initialise complement points at infoBlock[70]
  sfmpv_InitComplementPts(infoBlock + 70);

  // Initialise picture-user state at infoBlock[1024]
  SFMPVF_InitPicUsr(infoBlock + 1024);

  // Link 16 user-stream slots: each frame object slot (stride 58 DWORDs)
  // gets a pointer to its corresponding picture-user entry pair (stride 2 DWORDs)
  auto* slotPtr = infoBlock + 117;       // first frame object's user-stream link field
  auto* picUsrEntry = infoBlock + 1029;   // first picture-user entry (after 5-DWORD header)
  for (std::int32_t i = 0; i < 16; ++i) {
    *slotPtr = reinterpret_cast<std::uint32_t>(picUsrEntry);
    picUsrEntry += 2;
    slotPtr += 58;
  }

  return 0;
}

/**
 * Address: 0x00AD4100 (FUN_00AD4100, _sfmpv_IsLate)
 *
 * What it does:
 * Computes one MPV late-frame condition using current interpolation/time lanes,
 * optional callback override, and per-handle late-frame gate counters.
 */
std::int32_t sfmpv_IsLate(const std::int32_t workctrlAddress, const std::int32_t updateMode)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t interpolationTime = 0;
  if (timingLane->interpolationEnabled != 0) {
    interpolationTime = timingLane->baseInterpolationTime + timingLane->decodeProgressTime - timingLane->frameInterpolationTime;
  }

  const auto lateCallback = timingLane->isLateCallback;
  const std::int32_t baseFraction = timingLane->baseFraction;
  if (lateCallback != nullptr) {
    return lateCallback(workctrlAddress, updateMode, interpolationTime, baseFraction);
  }

  if (updateMode == 1) {
    SFTIM_UpdateItime(timingLane, interpolationTime);
    interpolationTime = SFTIM_GetNextItime(timingLane, interpolationTime);
  } else if (updateMode == 2) {
    interpolationTime = SFTIM_GetNextItime(timingLane, interpolationTime);
  }

  if (SFTIM_GetSpeed(workctrlAddress) <= 1000 && mpvInfo->lateFrameCounter >= workctrl->lateFrameGateThreshold) {
    return 0;
  }

  std::int32_t currentTimeMajor = 0;
  std::int32_t currentTimeMinor = 0;
  SFTIM_GetTime(workctrlAddress, &currentTimeMajor, &currentTimeMinor);
  if (currentTimeMajor < 0) {
    return 0;
  }

  std::int32_t frameDeltaMajor = 0;
  std::int32_t frameDeltaMinor = 0;
  sfmpv_GetDtime(workctrlAddress, updateMode, &frameDeltaMajor, &frameDeltaMinor);
  if (
    UTY_CmpTime(
      currentTimeMajor,
      currentTimeMinor,
      interpolationTime - (baseFraction * frameDeltaMajor) / frameDeltaMinor,
      baseFraction
    ) != 0
  ) {
    return 0;
  }

  ++mpvInfo->lateFrameCounter;
  return 1;
}

/**
 * Address: 0x00AD4260 (FUN_00AD4260, _sfmpv_SkipFrm)
 *
 * What it does:
 * Runs one MPV frame-skip decode step, updates consumed-stream counters, and
 * records one skipped-picture callback when skip succeeds.
 */
std::int32_t sfmpv_SkipFrm(const std::int32_t workctrlAddress, const std::int32_t streamBufferAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  sfmpv_SetSkipTtu(workctrlAddress);
  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1);
  const std::int32_t skipDecodeResult = m2v_SkipFrm(mpvInfo->decoderHandle, streamBufferAddress);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1) - flowCountBefore;

  const std::int32_t checkedResult =
    sfmpv_ChkMpvErr(workctrlAddress, skipDecodeResult, consumedBytes, kSfmpvErrSkipFrameFailed);
  sfmpv_AddRtotSj(workctrlAddress, consumedBytes);
  if (checkedResult != 0) {
    return checkedResult;
  }

  if (mpvInfo->disableSkipLatch == 0) {
    mpvInfo->skipIssuedFlag = 1;
  }

  SFPLY_AddSkipPic(workctrlAddress, 1, mpvInfo->skipPicCallbackContext);
  return 0;
}

/**
 * Address: 0x00AD52E0 (FUN_00AD52E0, _sfmpvf_AddReadSub)
 *
 * What it does:
 * Validates one frame-read completion lane, clears the frame draw-state, and
 * finalizes the associated frame-object draw owner.
 */
std::int32_t sfmpvf_AddReadSub(
  const std::int32_t workctrlAddress,
  const std::int32_t frameInfoIndex,
  const std::int32_t frameObjectId
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t frameObjectAddress = 0;
  SfmpvfVfrmDataRuntime* vfrmData = nullptr;

  if (workctrl->decodePathMode == 2) {
    frameObjectAddress = SFMPVF_SearchFrmObjFromId(workctrlAddress, frameObjectId);
    if (frameObjectAddress == 0) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameObjectMissingById);
    }

    vfrmData = AddressToPointer<SfmpvfVfrmDataRuntime>(SFMPVF_SearchVfrmData(workctrlAddress, frameObjectAddress));
  } else {
    vfrmData = AddressToPointer<SfmpvfVfrmDataRuntime>(sfmpvf_GetVfrmDataFromFrmInf(workctrlAddress, frameInfoIndex));
    if (vfrmData->drawState != 1) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrInvalidVfrmDrawState);
    }

    frameObjectAddress = SFMPVF_SearchFrmObj(workctrlAddress, frameInfoIndex);
    if (mpvInfo->activeFrameObjectAddress != frameObjectAddress) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameObjectMismatch);
    }
  }

  vfrmData->drawState = 0;
  SFMPVF_EndDrawFrm(frameObjectAddress);
  return 0;
}

} // extern "C"
