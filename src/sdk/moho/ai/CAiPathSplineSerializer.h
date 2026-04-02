#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1C8DC
   * COL:  0x00E726A8
   */
  class CAiPathSplineSerializer
  {
  public:
    /**
     * Address: 0x005B24A0 (FUN_005B24A0, Moho::CAiPathSplineSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPathSpline::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B24B0 (FUN_005B24B0, Moho::CAiPathSplineSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPathSpline::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B48E0 (FUN_005B48E0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathSpline RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CAiPathSplineSerializer, mHelperNext) == 0x04, "CAiPathSplineSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CAiPathSplineSerializer, mHelperPrev) == 0x08, "CAiPathSplineSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CAiPathSplineSerializer, mLoadCallback) == 0x0C, "CAiPathSplineSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiPathSplineSerializer, mSaveCallback) == 0x10, "CAiPathSplineSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiPathSplineSerializer) == 0x14, "CAiPathSplineSerializer size must be 0x14");

  /**
   * Address: 0x00BCD350 (FUN_00BCD350, register_CAiPathSplineSerializer)
   *
   * What it does:
   * Initializes startup serializer callbacks for `CAiPathSpline` and installs
   * process-exit helper unlink cleanup.
   */
  int register_CAiPathSplineSerializer();
} // namespace moho
