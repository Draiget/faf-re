#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho::audio_reflection
{
  [[nodiscard]] gpg::RType* ResolveISoundManagerType();
  [[nodiscard]] gpg::RType* ResolveCSimSoundManagerType();
  [[nodiscard]] gpg::RType* ResolveCScriptEventType();

  void AddBase(gpg::RType* ownerType, gpg::RType* baseType);

  void RegisterSerializeCallbacks(
    gpg::RType* typeInfo, gpg::RType::load_func_t loadCallback, gpg::RType::save_func_t saveCallback
  );

} // namespace moho::audio_reflection

