#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho::audio_reflection
{
  [[nodiscard]] gpg::RType* ResolveISoundManagerType();
  [[nodiscard]] gpg::RType* ResolveCScriptEventType();

  void AddBase(gpg::RType* ownerType, gpg::RType* baseType);

} // namespace moho::audio_reflection
