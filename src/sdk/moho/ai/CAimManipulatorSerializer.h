#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E21420
   * COL:  0x00E7AA9C
   */
  class CAimManipulatorSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00630030 (FUN_00630030, Moho::CAimManipulatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAimManipulator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00630040 (FUN_00630040, Moho::CAimManipulatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAimManipulator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BD2290 (FUN_00BD2290, dynamic initializer for the global
     * `CAimManipulatorSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAimManipulatorSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAimManipulatorSerializer();

    /**
     * Address: 0x00BFA960 (FUN_00BFA960, ??1CAimManipulatorSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CAimManipulatorSerializer();

    /**
     * Address: 0x00632D80 (FUN_00632D80)
     *
     * What it does:
     * Lazily resolves CAimManipulator RTTI and installs load/save callbacks
     * from this helper object into the type descriptor. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CAimManipulatorSerializer, mDeserialize) == 0x0C,
    "CAimManipulatorSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CAimManipulatorSerializer, mSerialize) == 0x10,
    "CAimManipulatorSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CAimManipulatorSerializer) == 0x14, "CAimManipulatorSerializer size must be 0x14");

  /**
   * Address: 0x00BD2290 caller lane (`ManipulatorStartupRegistrations.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAimManipulatorSerializer` singleton from an explicit registration
   * sequence. `gCAimManipulatorSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `ManipulatorStartupRegistrations.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  void register_CAimManipulatorSerializer();
} // namespace moho
