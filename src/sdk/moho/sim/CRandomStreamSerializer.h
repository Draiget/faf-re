#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class CRandomStreamSerializer
  {
  public:
    /**
     * Address: 0x0040F380 (FUN_0040F380, gpg::SerSaveLoadHelper<class Moho::CRandomStream>::Init)
     *
     * What it does:
     * Binds CRandomStream load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CRandomStreamSerializer, mHelperNext) == 0x04,
    "CRandomStreamSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CRandomStreamSerializer, mHelperPrev) == 0x08,
    "CRandomStreamSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CRandomStreamSerializer, mLoadCallback) == 0x0C,
    "CRandomStreamSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CRandomStreamSerializer, mSaveCallback) == 0x10,
    "CRandomStreamSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CRandomStreamSerializer) == 0x14, "CRandomStreamSerializer size must be 0x14");

  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes CRandomStream type-info storage and
   * registers its process-exit destructor.
   */
  void register_CRandomStreamTypeInfo();

  /**
   * Address: 0x00BC3380 (FUN_00BC3380, register_CRandomStreamSerializer)
   *
   * What it does:
   * Startup thunk that initializes CRandomStream serializer helper lanes and
   * registers process-exit teardown.
   */
  void register_CRandomStreamSerializer();
} // namespace moho
