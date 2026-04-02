#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1B80C
   * COL:  0x00E70C9C
   */
  class CAiBuilderImplSerializer
  {
  public:
    /**
     * Address: 0x0059FE20 (FUN_0059FE20, Moho::CAiBuilderImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiBuilderImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059FE30 (FUN_0059FE30, Moho::CAiBuilderImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiBuilderImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A06D0 (FUN_005A06D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiBuilderImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiBuilderImplSerializer, mHelperNext) == 0x04,
    "CAiBuilderImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiBuilderImplSerializer, mHelperPrev) == 0x08,
    "CAiBuilderImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiBuilderImplSerializer, mLoadCallback) == 0x0C,
    "CAiBuilderImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiBuilderImplSerializer, mSaveCallback) == 0x10,
    "CAiBuilderImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiBuilderImplSerializer) == 0x14, "CAiBuilderImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCC320 (FUN_00BCC320, register_CAiBuilderImplSerializer)
   *
   * What it does:
   * Initializes the global builder serializer helper callbacks and installs
   * process-exit cleanup.
   */
  void register_CAiBuilderImplSerializer();
} // namespace moho
