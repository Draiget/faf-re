#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho::audio_reflection
{
  [[nodiscard]] gpg::RType* ResolveISoundManagerType();
  [[nodiscard]] gpg::RType* ResolveCSimSoundManagerType();
  [[nodiscard]] gpg::RType* ResolveCScriptEventType();

  void AddBase(gpg::RType* ownerType, gpg::RType* baseType);

  void RegisterConstructCallbacks(
    gpg::RType* typeInfo, gpg::RType::construct_func_t constructCallback, gpg::RType::delete_func_t deleteCallback
  );

  void RegisterSerializeCallbacks(
    gpg::RType* typeInfo, gpg::RType::load_func_t loadCallback, gpg::RType::save_func_t saveCallback
  );

  void RegisterSaveConstructArgsCallback(
    gpg::RType* typeInfo, gpg::RType::save_construct_args_func_t saveConstructArgsCallback
  );
} // namespace moho::audio_reflection

