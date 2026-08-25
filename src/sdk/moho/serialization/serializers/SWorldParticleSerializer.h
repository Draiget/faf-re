#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/particles/SWorldParticle.h"

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
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldParticle::BlendMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4BlendMode@SWorldParticle@Moho@@H@gpg'`,
   * i.e. `BlendMode` nested inside `SWorldParticle` -- a distinct
   * instantiation from `SWorldBeam::BlendMode`'s, converted separately):
   * `FUN_00BC53C0` (real, `__xc_a`-reachable). No dead low-address
   * duplicate found for this one.
   */
  using SWorldParticleBlendModePrimitiveSerializer = gpg::PrimitiveSerHelper<SWorldParticle::BlendMode, int>;

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldParticle::ZMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ZMode@SWorldParticle@Moho@@H@gpg'`):
   * `FUN_00BC5420` (real, `__xc_a`-reachable). No dead low-address
   * duplicate found for this one.
   */
  using SWorldParticleZModePrimitiveSerializer = gpg::PrimitiveSerHelper<SWorldParticle::ZMode, int>;

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
