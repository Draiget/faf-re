#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class CEffectImplSerializer
  {
  public:
    /**
     * Address: 0x0065A2C0 (FUN_0065A2C0, gpg::SerSaveLoadHelper_CEffectImpl::Init)
     */
    virtual void RegisterSerializeFunctions();

  public:
    /**
     * Address: 0x006598A0 (FUN_006598A0, Moho::CEffectImplSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006598B0 (FUN_006598B0, Moho::CEffectImplSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CEffectImplSerializer, mHelperNext) == 0x04, "CEffectImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mHelperPrev) == 0x08, "CEffectImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mLoadCallback) == 0x0C, "CEffectImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEffectImplSerializer, mSaveCallback) == 0x10, "CEffectImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEffectImplSerializer) == 0x14, "CEffectImplSerializer size must be 0x14");

  /**
   * Address: 0x00BFBA20 (FUN_00BFBA20, cleanup_CEffectImplSerializer)
   *
   * What it does:
   * Unlinks startup CEffectImpl serializer helper node and restores self-links.
   */
  gpg::SerHelperBase* cleanup_CEffectImplSerializer();

  /**
   * Address: 0x00BD40E0 (FUN_00BD40E0, register_CEffectImplSerializer)
   *
   * What it does:
   * Initializes startup CEffectImpl serializer helper callbacks and installs
   * process-exit cleanup.
   */
  int register_CEffectImplSerializer();
} // namespace moho
