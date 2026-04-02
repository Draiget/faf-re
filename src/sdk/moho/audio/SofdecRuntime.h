#pragma once

#include <cstddef>
#include <cstdint>

struct IDirectSound;

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

  static_assert(offsetof(MwsfdInitPrm, vhz) == 0x0, "MwsfdInitPrm::vhz offset must be 0x0");
  static_assert(offsetof(MwsfdInitPrm, disp_cycle) == 0x4, "MwsfdInitPrm::disp_cycle offset must be 0x4");
  static_assert(offsetof(MwsfdInitPrm, disp_latency) == 0x8, "MwsfdInitPrm::disp_latency offset must be 0x8");
  static_assert(offsetof(MwsfdInitPrm, dec_svr) == 0xC, "MwsfdInitPrm::dec_svr offset must be 0xC");
  static_assert(offsetof(MwsfdInitPrm, rsv) == 0x10, "MwsfdInitPrm::rsv offset must be 0x10");
  static_assert(sizeof(MwsfdInitPrm) == 0x20, "MwsfdInitPrm size must be 0x20");

  using AdxmErrorCallback = int(__cdecl*)(std::uint32_t errorCode, const char* errorText);

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

  static_assert(sizeof(AdxmThreadStartupParams) == 0x18, "AdxmThreadStartupParams size must be 0x18");

  /**
   * Sofdec tag-window pair used by `mwsftag_*` search helpers.
   * Layout is one pointer + one byte-count lane.
   */
  struct MwsfTagWindow
  {
    std::int8_t* data = nullptr;
    std::int32_t size = 0;
  };

  static_assert(offsetof(MwsfTagWindow, data) == 0x0, "MwsfTagWindow::data offset must be 0x0");
  static_assert(offsetof(MwsfTagWindow, size) == 0x4, "MwsfTagWindow::size offset must be 0x4");
  static_assert(sizeof(MwsfTagWindow) == 0x8, "MwsfTagWindow size must be 0x8");

  /**
   * Partial runtime view for Sofdec SFD work-control subobject used by handle
   * validation helper lanes.
   *
   * Evidence:
   * - `FUN_00AD8E90` tests pointer at offset `+0x48` (`flibHn`).
   */
  struct SofdecSfdWorkctrlSubobj
  {
    std::uint8_t mUnknown00[0x48]{};
    void* flibHn = nullptr;
  };

  static_assert(
    offsetof(SofdecSfdWorkctrlSubobj, flibHn) == 0x48, "SofdecSfdWorkctrlSubobj::flibHn offset must be 0x48"
  );
} // namespace moho

extern "C"
{
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
   * Verifies that one Sofdec SFD work-control object and its `flibHn` lane are
   * both non-null; returns `0` on success and `-1` on invalid input.
   */
  std::int32_t SFLIB_CheckHn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);

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
  std::int32_t MWSFD_CmpTime(
    std::int32_t leftTime,
    std::int32_t timeUnit,
    std::int32_t rightTime,
    std::int32_t currentTime
  );

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
}
