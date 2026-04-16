#include "moho/audio/CSimSoundManagerSaveConstruct.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace
{
  moho::CSimSoundManagerSaveConstruct gCSimSoundManagerSaveConstruct{};

  [[nodiscard]] gpg::SerHelperBase* SaveConstructSelfNode(moho::CSimSoundManagerSaveConstruct& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSaveConstructNode(moho::CSimSoundManagerSaveConstruct& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = SaveConstructSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00761100 (FUN_00761100)
   *
   * What it does:
   * Unlinks startup `CSimSoundManagerSaveConstruct` helper links and rewires
   * the node into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCSimSoundManagerSaveConstructNodeVariantA() noexcept
  {
    return UnlinkSaveConstructNode(gCSimSoundManagerSaveConstruct);
  }

  /**
   * Address: 0x00761130 (FUN_00761130)
   *
   * What it does:
   * Duplicate unlink/reset lane for the startup
   * `CSimSoundManagerSaveConstruct` helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCSimSoundManagerSaveConstructNodeVariantB() noexcept
  {
    return UnlinkSaveConstructNode(gCSimSoundManagerSaveConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00761D90 (FUN_00761D90, gpg::SerSaveConstructHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs save-construct-args callback.
   */
  void CSimSoundManagerSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }
} // namespace moho
