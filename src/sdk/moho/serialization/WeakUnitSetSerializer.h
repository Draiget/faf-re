#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2D82C
   * COL: 0x00E86F2C
   */
  class WeakUnitSetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD84E0 (FUN_00BD84E0, dynamic initializer for the global
     * `WeakUnitSetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target (0x00BFE4E0) is
     * a plain unlink thunk (IDA name `sub_BFE4E0`, no mangled destructor
     * symbol exists for this class), so it is modeled as the compiler's
     * implicit static-destructor registration rather than an explicit call.
     */
    WeakUnitSetSerializer();

    /**
     * Address: 0x00BFE4E0 (FUN_00BFE4E0, sub_BFE4E0)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_006D2D00`/
     * `FUN_006D2D30` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneAN` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~WeakUnitSetSerializer();

    /**
     * Address: 0x006D2C50 (FUN_006D2C50, sub_6D2C50)
     *
     * What it does:
     * Deserializes one weak unit-set payload through `EntitySetTemplate<Unit>` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2C90 (FUN_006D2C90, sub_6D2C90)
     *
     * What it does:
     * Serializes one weak unit-set payload through `EntitySetTemplate<Unit>` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2E30 (FUN_006D2E30, sub_6D2E30)
     *
     * What it does:
     * Binds `WeakEntitySetTemplate<Unit>` RTTI serializer callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(WeakUnitSetSerializer, mDeserialize) == 0x0C, "WeakUnitSetSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(WeakUnitSetSerializer, mSerialize) == 0x10, "WeakUnitSetSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(WeakUnitSetSerializer) == 0x14, "WeakUnitSetSerializer size must be 0x14");
} // namespace moho
