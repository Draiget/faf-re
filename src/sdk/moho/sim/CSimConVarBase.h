#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarInstanceBase.h"

namespace moho
{
  class Sim;
  class CSimConVarInstanceBase;

  /**
   * VFTABLE: 0x00E198DC
   * COL:  0x00E6EB08
   */
  class CSimConVarBase : public CSimConCommand
  {
  public:
    CSimConVarBase(bool requiresCheat, const char* name);

    /**
     * Address: 0x00734820 (FUN_00734820, sub_734820)
     *
     * IDA signature:
     * int __thiscall sub_734820(Moho::CSimConVarBase *this, Moho::Sim *arg0, int a3, int a4, int a5, int a6);
     *
     * What it does:
     * Resolves the per-Sim convar instance and forwards command args to instance handler slot.
     */
    int Run(Sim* sim, ParsedCommandArgs* commandArgs, Wm3::Vector3f*, CArmyImpl*, SEntitySetTemplateUnit*) override;

    /**
     * Address: 0x00579790 (FUN_00579790, sub_579790)
     *
     * What it does:
     * Identity virtual used by base vtable; returns `this`.
     */
    CSimConVarBase* Identity() override;

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Allocates and initializes a typed `CSimConVarInstanceBase` for this convar definition.
     */
    virtual CSimConVarInstanceBase* CreateInstance() = 0; // slot 2

    [[nodiscard]] static std::uint32_t AllocateSimConVarIndex() noexcept;

  public:
    std::uint32_t mIndex; // +0x0C
  };

  static_assert(sizeof(CSimConVarBase) == 0x10, "CSimConVarBase size must be 0x10");
  static_assert(offsetof(CSimConVarBase, mName) == 0x04, "CSimConVarBase::mName offset must be 0x04");
  static_assert(offsetof(CSimConVarBase, mRequiresCheat) == 0x08, "CSimConVarBase::mRequiresCheat offset must be 0x08");
  static_assert(offsetof(CSimConVarBase, mIndex) == 0x0C, "CSimConVarBase::mIndex offset must be 0x0C");

  template <typename T>
  class TSimConVar : public CSimConVarBase
  {
  public:
    TSimConVar(bool requiresCheat, const char* name, const T& defaultValue)
      : CSimConVarBase(requiresCheat, name)
      , mDefaultValue(defaultValue)
    {
      mIndex = AllocateSimConVarIndex();
    }

    CSimConVarInstanceBase* CreateInstance() override
    {
      auto* const instance = new TSimConVarInstance<T>();
      if (!instance) {
        return nullptr;
      }

      instance->mName = mName;
      instance->mValue = mDefaultValue;
      return instance;
    }

  public:
    T mDefaultValue; // 0x10
  };

  /**
   * Address: 0x0057DED0 (FUN_0057DED0, Moho::TSimConVar_bool::NewInstance)
   *
   * What it does:
   * Allocates one bool convar-instance object and seeds its name/default value.
   */
  template <>
  CSimConVarInstanceBase* TSimConVar<bool>::CreateInstance();

  /**
   * Address: 0x005D3CE0 (FUN_005D3CE0, Moho::TSimConVar_float::NewInstance)
   *
   * What it does:
   * Allocates one float convar-instance object and seeds its name/default value.
   */
  template <>
  CSimConVarInstanceBase* TSimConVar<float>::CreateInstance();

  static_assert(
    offsetof(TSimConVar<bool>, mDefaultValue) == 0x10, "TSimConVar<bool>::mDefaultValue offset must be 0x10"
  );
  static_assert(offsetof(TSimConVar<int>, mDefaultValue) == 0x10, "TSimConVar<int>::mDefaultValue offset must be 0x10");
  static_assert(
    offsetof(TSimConVar<float>, mDefaultValue) == 0x10, "TSimConVar<float>::mDefaultValue offset must be 0x10"
  );
  static_assert(
    offsetof(TSimConVar<std::uint8_t>, mDefaultValue) == 0x10, "TSimConVar<uint8_t>::mDefaultValue offset must be 0x10"
  );
  static_assert(
    offsetof(TSimConVar<msvc8::string>, mDefaultValue) == 0x10, "TSimConVar<string>::mDefaultValue offset must be 0x10"
  );
} // namespace moho
