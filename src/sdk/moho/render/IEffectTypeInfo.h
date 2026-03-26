#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E36AA4
   * COL: 0x00E9032C
   */
  class IEffectTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00771130 (FUN_00771130, Moho::IEffectTypeInfo::dtr)
     * Slot: 2
     *
     * IDA signature:
     * void **__thiscall Moho::IEffectTypeInfo::dtr(void **this, char a2);
     */
    ~IEffectTypeInfo() override;

    /**
     * Address: 0x00771120 (FUN_00771120, Moho::IEffectTypeInfo::GetName)
     * Slot: 3
     *
     * IDA signature:
     * const char *Moho::IEffectTypeInfo::GetName();
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x007710F0 (FUN_007710F0, Moho::IEffectTypeInfo::Init)
     * Slot: 9
     *
     * IDA signature:
     * int __thiscall Moho::IEffectTypeInfo::Init(gpg::RType *this);
     *
     * What it does:
     * Sets `IEffect` object size metadata, registers `CScriptObject` as
     * reflection base at offset `0`, then finalizes type registration.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00771340 (FUN_00771340, Moho::IEffectTypeInfo::AddBase_CScriptObject)
     *
     * IDA signature:
     * void __stdcall sub_771340(gpg::RType *a1);
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);
  };

  static_assert(sizeof(IEffectTypeInfo) == 0x64, "IEffectTypeInfo size must be 0x64");
} // namespace moho

