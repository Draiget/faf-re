#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E25E30
   * COL: 0x00E7ED34
   */
  class CEffectManagerImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0066B330 (FUN_0066B330, Moho::CEffectManagerImplTypeInfo::dtr)
     * Slot: 2
     *
     * IDA signature:
     * void **__thiscall sub_66B330(void **this, char a2);
     */
    ~CEffectManagerImplTypeInfo() override;

    /**
     * Address: 0x0066B320 (FUN_0066B320, Moho::CEffectManagerImplTypeInfo::GetName)
     * Slot: 3
     *
     * IDA signature:
     * const char *sub_66B320();
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0066B300 (FUN_0066B300, Moho::CEffectManagerImplTypeInfo::Init)
     * Slot: 9
     *
     * IDA signature:
     * int __thiscall sub_66B300(gpg::RType *this);
     *
     * What it does:
     * Sets `CEffectManagerImpl` object size metadata, registers
     * `IEffectManager` as the base reflection field, and finalizes RTTI.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0066C220 (FUN_0066C220, Moho::CEffectManagerImplTypeInfo::AddBase_IEffectManager)
     *
     * IDA signature:
     * void __stdcall sub_66C220(gpg::RType *a1);
     *
     * What it does:
     * Adds base-type metadata for `IEffectManager` at subobject offset `0`.
     */
    static void AddBase_IEffectManager(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CEffectManagerImplTypeInfo) == 0x64, "CEffectManagerImplTypeInfo size must be 0x64");
} // namespace moho

