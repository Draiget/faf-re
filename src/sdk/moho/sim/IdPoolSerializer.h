#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class IdPoolSerializer
  {
  public:
    /**
     * Address: 0x00403DC0 (FUN_00403DC0, gpg::SerSaveLoadHelper<class Moho::IdPool>::Init)
     *
     * What it does:
     * Resolves `IdPool` RTTI and binds the load/save reflection callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(IdPoolSerializer, mHelperNext) == 0x04, "IdPoolSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(IdPoolSerializer, mHelperPrev) == 0x08, "IdPoolSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(IdPoolSerializer, mLoadCallback) == 0x0C, "IdPoolSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(IdPoolSerializer, mSaveCallback) == 0x10, "IdPoolSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(IdPoolSerializer) == 0x14, "IdPoolSerializer size must be 0x14");

  /**
   * Address: 0x00BC2DA0 (FUN_00BC2DA0, register_IdPoolSerializer)
   *
   * What it does:
   * Materializes startup `IdPoolSerializer` storage, installs serializer
   * callback lanes, and registers process-exit teardown.
   */
  void register_IdPoolSerializer();
} // namespace moho
