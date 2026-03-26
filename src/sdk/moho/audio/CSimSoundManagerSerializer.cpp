#include "moho/audio/CSimSoundManagerSerializer.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00761E90 (FUN_00761E90, gpg::SerSaveLoadHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs load/save callbacks.
   */
  void CSimSoundManagerSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }
} // namespace moho

