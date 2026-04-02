#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * SWorldParticle serializer helper used by the recovered startup registration.
   */
  class SWorldParticleSerializer
  {
  public:
    /**
     * Address: 0x0048F8D0 (Moho::SWorldParticleSerializer::Deserialize)
     *
     * What it does:
     * Dispatches archive loading into `SWorldParticle::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0048F8E0 (Moho::SWorldParticleSerializer::Serialize)
     *
     * What it does:
     * Dispatches archive saving into `SWorldParticle::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0048FD30 (Moho::SWorldParticleSerializer::Init)
     *
     * What it does:
     * Binds `SWorldParticle` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SWorldParticleSerializer, mHelperNext) == 0x04, "SWorldParticleSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SWorldParticleSerializer, mHelperPrev) == 0x08, "SWorldParticleSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SWorldParticleSerializer, mDeserialize) == 0x0C, "SWorldParticleSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SWorldParticleSerializer, mSerialize) == 0x10, "SWorldParticleSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SWorldParticleSerializer) == 0x14, "SWorldParticleSerializer size must be 0x14");

  /**
   * Helper that binds primitive `BlendMode` enum callbacks for `SWorldParticle`.
   */
  class SWorldParticleBlendModePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0048FBF0 (gpg::PrimitiveSerHelper<Moho::SWorldParticle::BlendMode, int>::Init)
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
    offsetof(SWorldParticleBlendModePrimitiveSerializer, mHelperNext) == 0x04,
    "SWorldParticleBlendModePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SWorldParticleBlendModePrimitiveSerializer, mHelperPrev) == 0x08,
    "SWorldParticleBlendModePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SWorldParticleBlendModePrimitiveSerializer, mDeserialize) == 0x0C,
    "SWorldParticleBlendModePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SWorldParticleBlendModePrimitiveSerializer, mSerialize) == 0x10,
    "SWorldParticleBlendModePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(SWorldParticleBlendModePrimitiveSerializer) == 0x14,
    "SWorldParticleBlendModePrimitiveSerializer size must be 0x14"
  );

  /**
   * Helper that binds primitive `ZMode` enum callbacks for `SWorldParticle`.
   */
  class SWorldParticleZModePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0048FC90 (gpg::PrimitiveSerHelper<Moho::SWorldParticle::ZMode, int>::Init)
     *
     * What it does:
     * Binds primitive `ZMode` load/save callbacks onto the reflected enum type.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SWorldParticleZModePrimitiveSerializer, mHelperNext) == 0x04,
    "SWorldParticleZModePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SWorldParticleZModePrimitiveSerializer, mHelperPrev) == 0x08,
    "SWorldParticleZModePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SWorldParticleZModePrimitiveSerializer, mDeserialize) == 0x0C,
    "SWorldParticleZModePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SWorldParticleZModePrimitiveSerializer, mSerialize) == 0x10,
    "SWorldParticleZModePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SWorldParticleZModePrimitiveSerializer) == 0x14, "SWorldParticleZModePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BEFF10 (sub_BEFF10)
   *
   * What it does:
   * Unlinks the `SWorldParticleBlendModePrimitiveSerializer` helper node and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SWorldParticleBlendModePrimitiveSerializer();

  /**
   * Address: 0x00BC53C0 (sub_BC53C0)
   *
   * What it does:
   * Initializes `SWorldParticle::BlendMode` primitive serializer callbacks and schedules exit cleanup.
   */
  int register_SWorldParticleBlendModePrimitiveSerializer();

  /**
   * Address: 0x00BEFF50 (sub_BEFF50)
   *
   * What it does:
   * Unlinks the `SWorldParticleZModePrimitiveSerializer` helper node and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SWorldParticleZModePrimitiveSerializer();

  /**
   * Address: 0x00BC5420 (sub_BC5420)
   *
   * What it does:
   * Initializes `SWorldParticle::ZMode` primitive serializer callbacks and schedules exit cleanup.
   */
  int register_SWorldParticleZModePrimitiveSerializer();

  /**
   * Address: 0x00BEFFE0 (Moho::SWorldParticleSerializer::~SWorldParticleSerializer)
   *
   * What it does:
   * Unlinks the `SWorldParticleSerializer` helper node and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SWorldParticleSerializer();

  /**
   * Address: 0x00BC5480 (register_SWorldParticleSerializer)
   *
   * What it does:
   * Initializes `SWorldParticle` serializer callbacks and schedules exit cleanup.
   */
  int register_SWorldParticleSerializer();
} // namespace moho
