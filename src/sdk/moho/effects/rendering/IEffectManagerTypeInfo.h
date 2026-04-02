#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E36B94
   * COL: 0x00E9018C
   */
  class IEffectManagerTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00770FE0 (FUN_00770FE0, Moho::IEffectManagerTypeInfo::dtr)
     * Slot: 2
     *
     * IDA signature:
     * void **__thiscall Moho::IEffectManagerTypeInfo::dtr(void **this, char a2);
     */
    ~IEffectManagerTypeInfo() override;

    /**
     * Address: 0x00770FD0 (FUN_00770FD0, Moho::IEffectManagerTypeInfo::GetName)
     * Slot: 3
     *
     * IDA signature:
     * const char *Moho::IEffectManagerTypeInfo::GetName();
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00770FB0 (FUN_00770FB0, Moho::IEffectManagerTypeInfo::Init)
     * Slot: 9
     *
     * IDA signature:
     * void __thiscall Moho::IEffectManagerTypeInfo::Register(gpg::RType *this);
     *
     * What it does:
     * Sets interface object size metadata and finalizes RTTI registration.
     */
    void Init() override;
  };

  static_assert(sizeof(IEffectManagerTypeInfo) == 0x64, "IEffectManagerTypeInfo size must be 0x64");
} // namespace moho
