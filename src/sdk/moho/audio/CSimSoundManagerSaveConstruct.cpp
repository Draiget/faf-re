#include "moho/audio/CSimSoundManagerSaveConstruct.h"

#include "moho/audio/AudioReflectionHelpers.h"

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

