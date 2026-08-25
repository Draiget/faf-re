#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F2F4
   */
  class SAttachPointSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005E42E0 (FUN_005E42E0, SAttachPointSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `SAttachPoint` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E42F0 (FUN_005E42F0, SAttachPointSerializer::Serialize)
     *
     * What it does:
     * Serializes one `SAttachPoint` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCEDF0 (FUN_00BCEDF0, dynamic initializer for the global
     * `SAttachPointSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SAttachPointSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here, and this class has no user-declared destructor (the real
     * binary explicitly registers `atexit(&sub_BF8A90)` instead). Note: the
     * previous recovery mis-attributed this class's `Init()` to 0x005E42D0
     * (`nullsub_1636`, a genuinely empty function elsewhere in the binary) --
     * the real dispatch address for this helper's `Init()` has not been
     * located and is left uncited below.
     */
    SAttachPointSerializer();

    /**
     * What it does:
     * Binds load/save serializer callbacks into `SAttachPoint` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SAttachPointSerializer, mLoadCallback) == 0x0C,
    "SAttachPointSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SAttachPointSerializer, mSaveCallback) == 0x10,
    "SAttachPointSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SAttachPointSerializer) == 0x14, "SAttachPointSerializer size must be 0x14");

  /**
   * Address: 0x00BCEDF0 caller lane (`IAiTransport.cpp`'s reflection
   * bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `SAttachPointSerializer` singleton from an explicit registration
   * sequence. `gSAttachPointSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
   * sequence does not need editing.
   */
  int register_SAttachPointSerializer();
} // namespace moho
