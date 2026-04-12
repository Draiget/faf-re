/**
 * CRI Sofdec MPV (Movie Player Video) subsystem runtime functions.
 *
 * This file contains recovered initialization and parameter-validation logic
 * for the statically linked CRI Sofdec MPV library as shipped in Forged Alliance.
 */

#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// Forward declarations for CRI library functions used by this module
// ---------------------------------------------------------------------------

extern "C" {
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  std::int32_t UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
  std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
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

} // extern "C"
