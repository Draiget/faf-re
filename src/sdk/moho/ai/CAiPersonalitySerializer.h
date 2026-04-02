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
   * VFTABLE: 0x00E1CAA8
   * COL:  0x00E729EC
   */
  class CAiPersonalitySerializer
  {
  public:
    /**
     * Address: 0x005B6A80 (FUN_005B6A80, Moho::CAiPersonalitySerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPersonality::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B6A90 (FUN_005B6A90, Moho::CAiPersonalitySerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPersonality::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B9350 (FUN_005B9350)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPersonality RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiPersonalitySerializer, mHelperNext) == 0x04,
    "CAiPersonalitySerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mHelperPrev) == 0x08,
    "CAiPersonalitySerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mLoadCallback) == 0x0C,
    "CAiPersonalitySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mSaveCallback) == 0x10,
    "CAiPersonalitySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPersonalitySerializer) == 0x14, "CAiPersonalitySerializer size must be 0x14");

  /**
   * Address: 0x00BCD5A0 (FUN_00BCD5A0)
   *
   * What it does:
   * Preregisters startup RTTI for the legacy AI `SValuePair` lane and installs
   * process-exit cleanup.
   */
  int register_SValuePairTypeInfo();

  /**
   * Address: 0x00BCD5C0 (FUN_00BCD5C0, register_SValuePairSerializer)
   *
   * What it does:
   * Initializes startup serializer callbacks for `SValuePair` and installs
   * process-exit helper unlink cleanup.
   */
  int register_SValuePairSerializer();

  /**
   * Address: 0x00BCD660 (FUN_00BCD660, register_CAiPersonalitySerializer)
   *
   * What it does:
   * Initializes global CAiPersonality serializer helper callbacks and installs
   * process-exit cleanup.
   */
  int register_CAiPersonalitySerializer();
} // namespace moho
