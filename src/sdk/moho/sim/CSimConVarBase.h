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
    /**
     * Address: 0x00579760 (FUN_00579760, Moho::CSimConVarBase::CSimConVarBase)
     *
     * What it does:
     * Initializes one convar definition lane, assigns a unique global convar
     * index, and binds the `CSimConVarBase` vftable.
     */
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
     * Address: 0x00A82547 (FUN_00A82547, _purecall in base)
     *
     * What it does:
     * Allocates and initializes a typed `CSimConVarInstanceBase` for this convar definition.
     */
    virtual CSimConVarInstanceBase* CreateInstance() = 0; // slot 2

    [[nodiscard]] static std::uint32_t AllocateSimConVarIndex() noexcept;

  public:
    std::uint32_t mIndex; // +0x0C
  };

  /**
   * Address: 0x00743210 (FUN_00743210, sub_743210)
   *
   * What it does:
   * Returns the current process-global sim-convar index counter (number of
   * distinct console variables registered so far). Used by the Sim load-
   * serializer to grow `mSimVars` to full convar count before indexing.
   */
  [[nodiscard]] std::uint32_t GetSimConVarIndexCounter() noexcept;

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
    }

    /**
     * Address: 0x0057DF30 (FUN_0057DF30) for the `TSimConVar<int>` instantiation -
     * not explicitly specialized like `<bool>`/`<float>` below, so this generic
     * body is what the compiler actually emits for `int`.
     * Address: 0x00735400 (FUN_00735400, `TSimConVar<std::uint8_t>::CreateInstance`
     * -- same generic shape: `operator new(0xC)`, copies `mName` (`this+4`) and
     * the byte `mDefaultValue` (`this+0x10`) into the new instance's `+0x08`
     * `mValue` lane. Real vtable-construction evidence via `??_7?$TSimConVar@E@
     * Moho@@6B@+0x8` (`E` is IDA's demangled shorthand for `unsigned char`
     * here, not a real enum).)
     *
     * `T = msvc8::string` does NOT use this generic body -- traced its raw
     * `.asm` and found the compiler splits it into two out-of-line symbols
     * instead of the single generic shape above: 0x007354E0
     * (`TSimConVar<msvc8::string>::CreateInstance` itself -- allocates
     * `sizeof(TSimConVarInstance<msvc8::string>)` and builds a stack copy of
     * `mDefaultValue`) and 0x00735A30 (the placement-construct step, taking
     * the raw memory, `mName`, and that copy by value -- see
     * `ConstructTSimConVarInstanceString`, CSimConVarInstanceBase.h/.cpp).
     * See the explicit specialization below instead of this generic body.
     */
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
   * Address: 0x0057DEA0 (FUN_0057DEA0, Moho::TSimConVar_bool::TSimConVar_bool)
   *
   * What it does:
   * Initializes one bool convar definition, assigning convar index and default
   * bool payload lane.
   */
  template <>
  TSimConVar<bool>::TSimConVar(bool requiresCheat, const char* name, const bool& defaultValue);

  /**
   * Address: 0x005D3CE0 (FUN_005D3CE0, Moho::TSimConVar_float::NewInstance)
   *
   * What it does:
   * Allocates one float convar-instance object and seeds its name/default value.
   */
  template <>
  CSimConVarInstanceBase* TSimConVar<float>::CreateInstance();

  /**
   * Address: 0x007354E0 (FUN_007354E0, Moho::TSimConVarInstance_string::NewInstance)
   *
   * What it does:
   * Allocates one string sim-convar instance and constructs it in place
   * from this convar's name and a copy of its default value. Unlike the
   * `bool`/`float` overrides above, the binary splits this into two
   * out-of-line symbols (this allocate-and-copy wrapper, plus the
   * placement-construct step at 0x00735A30 -- see
   * `ConstructTSimConVarInstanceString`), so it needs its own explicit
   * specialization rather than sharing the generic template body.
   */
  template <>
  CSimConVarInstanceBase* TSimConVar<msvc8::string>::CreateInstance();

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
