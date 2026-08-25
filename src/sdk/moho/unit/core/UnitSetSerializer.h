#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7EC
   * COL: 0x00E87028
   */
  class UnitSetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8480 (FUN_00BD8480, dynamic initializer for the global
     * `UnitSetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7UnitSetSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here.
     */
    UnitSetSerializer();

    /**
     * Address: 0x006D2A00 (FUN_006D2A00, sub_6D2A00)
     *
     * What it does:
     * Deserializes one `EntitySetTemplate<Unit>` payload using `EntitySetBase` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2A40 (FUN_006D2A40, sub_6D2A40)
     *
     * What it does:
     * Serializes one `EntitySetTemplate<Unit>` payload using `EntitySetBase` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2D90 (FUN_006D2D90, sub_6D2D90)
     *
     * What it does:
     * Binds `EntitySetTemplate<Unit>` RTTI serializer callbacks.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(UnitSetSerializer, mDeserialize) == 0x0C, "UnitSetSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(UnitSetSerializer, mSerialize) == 0x10, "UnitSetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UnitSetSerializer) == 0x14, "UnitSetSerializer size must be 0x14");
} // namespace moho
