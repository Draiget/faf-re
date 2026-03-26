#include "moho/audio/ISoundManagerSerializer.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00761BE0 (FUN_00761BE0, gpg::SerSaveLoadHelper_ISoundManager::Init)
   *
   * What it does:
   * Resolves `ISoundManager` RTTI and installs load/save callbacks.
   */
  void ISoundManagerSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveISoundManagerType();
    audio_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }
} // namespace moho

