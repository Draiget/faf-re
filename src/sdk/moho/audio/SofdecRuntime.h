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
   * Address: 0x00B06DC0 (_ADXM_Finish)
   *
   * What it does:
   * Tears down ADXM threads/locks/event state when init reference count reaches 0.
   */
  void ADXM_Finish();
}
