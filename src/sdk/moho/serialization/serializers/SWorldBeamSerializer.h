#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * SWorldBeam serializer helper used by the recovered startup registration.
   */
  class SWorldBeamSerializer
  {
  public:
    /**
     * Address: 0x0048F480 (Moho::SWorldBeamSerializer::Deserialize)
     *
     * What it does:
     * Dispatches archive loading into `SWorldBeam::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0048F490 (Moho::SWorldBeamSerializer::Serialize)
     *
     * What it does:
     * Dispatches archive saving into `SWorldBeam::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0048FB50 (gpg::SerSaveLoadHelper_SWorldBeam::Init)
     *
     * What it does:
     * Binds `SWorldBeam` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(SWorldBeamSerializer, mHelperNext) == 0x04, "SWorldBeamSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SWorldBeamSerializer, mHelperPrev) == 0x08, "SWorldBeamSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SWorldBeamSerializer, mDeserialize) == 0x0C, "SWorldBeamSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SWorldBeamSerializer, mSerialize) == 0x10, "SWorldBeamSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SWorldBeamSerializer) == 0x14, "SWorldBeamSerializer size must be 0x14");

  /**
   * Helper that binds primitive `BlendMode` enum callbacks for `SWorldBeam`.
   */
  class SWorldBeamBlendModePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0048FAB0 (gpg::PrimitiveSerHelper<Moho::SWorldBeam::BlendMode, int>::Init)
     *
     * What it does:
     * Binds primitive `BlendMode` load/save callbacks onto the reflected enum type.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SWorldBeamBlendModePrimitiveSerializer, mHelperNext) == 0x04,
    "SWorldBeamBlendModePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SWorldBeamBlendModePrimitiveSerializer, mHelperPrev) == 0x08,
    "SWorldBeamBlendModePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SWorldBeamBlendModePrimitiveSerializer, mDeserialize) == 0x0C,
    "SWorldBeamBlendModePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SWorldBeamBlendModePrimitiveSerializer, mSerialize) == 0x10,
    "SWorldBeamBlendModePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SWorldBeamBlendModePrimitiveSerializer) == 0x14, "SWorldBeamBlendModePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BEFE40 (sub_BEFE40)
   *
   * What it does:
   * Unlinks the `SWorldBeamBlendModePrimitiveSerializer` helper node and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SWorldBeamBlendModePrimitiveSerializer();

  /**
   * Address: 0x00BC5300 (sub_BC5300)
   *
   * What it does:
   * Initializes `SWorldBeam::BlendMode` primitive serializer callbacks and schedules exit cleanup.
   */
  int register_SWorldBeamBlendModePrimitiveSerializer();

  /**
   * Address: 0x00BEFED0 (Moho::SWorldBeamSerializer::~SWorldBeamSerializer)
   *
   * What it does:
   * Unlinks the `SWorldBeamSerializer` helper node and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SWorldBeamSerializer();

  /**
   * Address: 0x00BC5360 (reigster_SWorldBeamSerializer)
   *
   * What it does:
   * Initializes `SWorldBeam` serializer callbacks and schedules exit cleanup.
   */
  int register_SWorldBeamSerializer();
} // namespace moho
