#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1CAA8
   * COL:  0x00E729EC
   */
  class CAiPersonalitySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCD660 (FUN_00BCD660, dynamic initializer for the global
     * `CAiPersonalitySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiPersonalitySerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiPersonalitySerializer();

    /**
     * Address: 0x00BF7740 (FUN_00BF7740, Moho::CAiPersonalitySerializer::~CAiPersonalitySerializer)
     * Address: 0x005B6AE0 (FUN_005B6AE0), Address: 0x005B6B10 (FUN_005B6B10)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCD660) as the global's `atexit` teardown.
     */
    ~CAiPersonalitySerializer();

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
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

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
} // namespace moho
