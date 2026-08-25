#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/particles/SWorldParticle.h"

namespace moho
{
  /**
   * SWorldParticle serializer helper used by the recovered startup registration.
   */
  class SWorldParticleSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5480 (FUN_00BC5480, register_SWorldParticleSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SWorldParticleSerializer@Moho@@6B@` -- no eager
     * `RegisterSerializeFunctions`-style call exists here. The
     * `push offset ~SWorldParticleSerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it is not a call the 2007 source wrote), so it is not
     * reproduced explicitly here -- declaring a real destructor below is
     * sufficient for the compiler to emit the same registration.
     */
    SWorldParticleSerializer();

    /**
     * Address: 0x00BEFFE0 (FUN_00BEFFE0, Moho::SWorldParticleSerializer::~SWorldParticleSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SWorldParticleSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
} // namespace moho
