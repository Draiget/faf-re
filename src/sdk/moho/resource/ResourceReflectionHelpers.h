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
  /**
   * Address: 0x004441C0 (FUN_004441C0)
   *
   * What it does:
   * Returns cached `RD3DTextureResource` reflected type, resolving it lazily.
   */
  [[nodiscard]] gpg::RType* ResolveRD3DTextureResourceType();
  /**
   * Address: 0x00444200 (FUN_00444200)
   *
   * What it does:
   * Returns cached `ID3DTextureSheet` reflected type, resolving it lazily.
   */
  [[nodiscard]] gpg::RType* ResolveID3DTextureSheetType();
  /**
   * Address: 0x004441E0 (FUN_004441E0)
   *
   * What it does:
   * Returns cached `MemBuffer<const char>` reflected type, resolving it lazily.
   */
  [[nodiscard]] gpg::RType* ResolveMemBufferConstType();

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
