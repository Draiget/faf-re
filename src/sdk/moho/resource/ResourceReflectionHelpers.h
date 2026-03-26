#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho::resource_reflection
{
  [[nodiscard]] gpg::RType* ResolveCAniSkelType();
  [[nodiscard]] gpg::RType* ResolveCAniResourceSkelType();
  [[nodiscard]] gpg::RType* ResolveCParticleTextureType();
  [[nodiscard]] gpg::RType* ResolveCSimResourcesType();
  [[nodiscard]] gpg::RType* ResolveISimResourcesType();
  [[nodiscard]] gpg::RType* ResolveIResourcesType();
  [[nodiscard]] gpg::RType* ResolveRD3DTextureResourceType();
  [[nodiscard]] gpg::RType* ResolveID3DTextureSheetType();

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
} // namespace moho::resource_reflection
