#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CArmyImplSerializer
  {
  public:
    /**
     * Address: 0x00701000 (FUN_00701000, Moho::CArmyImplSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback that forwards to `CArmyImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00701010 (FUN_00701010, Moho::CArmyImplSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback that forwards to `CArmyImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00701DD0 (FUN_00701DD0, gpg::SerSaveLoadHelper_CArmyImpl::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CArmyImplSerializer, mHelperNext) == 0x04, "CArmyImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CArmyImplSerializer, mHelperPrev) == 0x08, "CArmyImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CArmyImplSerializer, mLoadCallback) == 0x0C, "CArmyImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyImplSerializer, mSaveCallback) == 0x10, "CArmyImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyImplSerializer) == 0x14, "CArmyImplSerializer size must be 0x14");

  /**
   * Address: 0x00BD9C20 (FUN_00BD9C20, register_CArmyImplSerializer)
   *
   * What it does:
   * Initializes serializer callback lanes for `CArmyImpl` and binds them into
   * reflected RTTI.
   */
  void register_CArmyImplSerializer();
} // namespace moho
