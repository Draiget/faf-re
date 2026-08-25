#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/particles/SWorldBeam.h"

namespace moho
{
  /**
   * SWorldBeam serializer helper used by the recovered startup registration.
   */
  class SWorldBeamSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5360 (FUN_00BC5360, reigster_SWorldBeamSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SWorldBeamSerializer@Moho@@6B@` -- no eager
     * `RegisterSerializeFunctions`-style call exists here. The
     * `push offset ~SWorldBeamSerializer; call _atexit` sequence visible in
     * the real ctor's tail is the compiler's own implicit static-destructor
     * registration for a global with a non-trivial destructor (it is not a
     * call the 2007 source wrote), so it is not reproduced explicitly here
     * -- declaring a real destructor below is sufficient for the compiler
     * to emit the same registration.
     */
    SWorldBeamSerializer();

    /**
     * Address: 0x00BEFED0 (FUN_00BEFED0, Moho::SWorldBeamSerializer::~SWorldBeamSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SWorldBeamSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(SWorldBeamSerializer, mDeserialize) == 0x0C, "SWorldBeamSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SWorldBeamSerializer, mSerialize) == 0x10, "SWorldBeamSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SWorldBeamSerializer) == 0x14, "SWorldBeamSerializer size must be 0x14");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::SWorldBeam::BlendMode,int>
   * VFTABLE: never constructed prior to this recovery -- see the ctor
   * Doxygen block on `gpg::PrimitiveSerHelper` in Reflection.h.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4BlendMode@SWorldBeam@Moho@@H@gpg'`,
   * i.e. `BlendMode` nested inside `SWorldBeam`, not the top-level enum
   * some sibling classes use): `FUN_00BC5300` (real, `__xc_a`-reachable).
   * No dead low-address duplicate found for this one.
   */
  using SWorldBeamBlendModePrimitiveSerializer = gpg::PrimitiveSerHelper<SWorldBeam::BlendMode, int>;
} // namespace moho
