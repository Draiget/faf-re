#include "moho/audio/CSimSoundManagerConstruct.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00761E10 (FUN_00761E10, gpg::SerConstructHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs construct/delete callbacks.
   */
  void CSimSoundManagerConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }
} // namespace moho

