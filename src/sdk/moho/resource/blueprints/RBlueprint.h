#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

namespace gpg
{
  class RField;
  class RType;
}

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace moho
{
  class RRuleGameRules;
  struct RResId;

  /**
   * Address: 0x0050DC10 (FUN_0050DC10)
   *
   * What it does:
   * Reflection type init for the common blueprint base (`sizeof = 0x60`).
   */
  struct RBlueprint
  {
    static gpg::RType* sPointerType;

    void* mVTable;                  // +0x00
    RRuleGameRules* mOwner;         // +0x04
    msvc8::string mBlueprintId;     // +0x08
    msvc8::string mDescription;     // +0x24
    msvc8::string mSource;          // +0x40
    std::int32_t mBlueprintOrdinal; // +0x5C

    /**
     * Address: 0x0050DD60 (FUN_0050DD60)
     * Mangled: ??0RBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
     *
     * IDA signature:
     * Moho::RBlueprint *__thiscall Moho::RBlueprint::RBlueprint(
     *         Moho::RBlueprint *this@<ecx>,
     *         Moho::RRuleGameRules *rules,
     *         Moho::RResId const &resId);
     *
     * What it does:
     * Initializes a base `RBlueprint` from a (rules, resource id) pair: bumps the
     * shared instance counter, captures the owning `RRuleGameRules` pointer, copies
     * the resource id string into `mBlueprintId`, default-initializes the description
     * and source strings, and assigns a unique blueprint ordinal from the rules.
     */
    RBlueprint(RRuleGameRules* owner, const RResId& resId);

    /**
     * Address: 0x0050DE60 (FUN_0050DE60)
     * Mangled: ??1RBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Releases base blueprint string lanes, decrements the shared instance
     * counter stat slot, and restores the base `gpg::RObject` vtable lane.
     */
    ~RBlueprint();

    /**
     * Address: 0x0050DF10 (FUN_0050DF10, Moho::RBlueprint::InitBlueprint)
     *
     * What it does:
     * Applies one Lua blueprint table into this reflected object, runs the
     * polymorphic `OnInitBlueprint()` lane, then merges resolved fields back
     * into the Lua table.
     */
    void InitBlueprint(LuaPlus::LuaObject& luaBlueprint);

    /**
     * Address: 0x0050DBA0 (FUN_0050DBA0)
     * Mangled: ?OnInitBlueprint@RBlueprint@Moho@@MAEXXZ
     *
     * What it does:
     * Base blueprint post-load hook; default implementation is empty.
     */
    void OnInitBlueprint();

    /**
     * Address: 0x00556CE0 (FUN_00556CE0, Moho::RBlueprint::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for `RBlueprint*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x0050DF90 (FUN_0050DF90, Moho::RBlueprint::GetLuaBlueprint)
     *
     * What it does:
     * Returns `__blueprints[BlueprintOrdinal]` from the active Lua globals.
     */
    [[nodiscard]] LuaPlus::LuaObject GetLuaBlueprint(LuaPlus::LuaState* state) const;
  };

  /**
   * Address: 0x0050DBB0 (FUN_0050DBB0, Moho::RBlueprintTypeInfo::RBlueprintTypeInfo)
   *
   * What it does:
   * Materializes the runtime reflection descriptor for `RBlueprint`.
   */
  class RBlueprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050DBB0 (FUN_0050DBB0, Moho::RBlueprintTypeInfo::RBlueprintTypeInfo)
     *
     * What it does:
     * Preregisters the `RBlueprint` RTTI instance at startup.
     */
    RBlueprintTypeInfo();

    /**
     * Address: 0x0050DC50 (FUN_0050DC50, Moho::RBlueprintTypeInfo::dtr)
     * Address: 0x0050DCB0 (FUN_0050DCB0, core dtor body)
     *
     * What it does:
     * Releases the startup-owned reflection descriptor and restores the base
     * `gpg::RObject` vtable.
     */
    ~RBlueprintTypeInfo() override;

    /**
     * Address: 0x0050DC40 (FUN_0050DC40, Moho::RBlueprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the RTTI label for `RBlueprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050DC10 (FUN_0050DC10, Moho::RBlueprintTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size, registers the `gpg::RObject` base lane, and
     * publishes the `RBlueprint` field metadata.
     */
    void Init() override;

    /**
     * Address: 0x0050DCF0 (FUN_0050DCF0, Moho::RBlueprintTypeInfo::AddFields)
     *
     * What it does:
     * Registers reflected field lanes for the base `RBlueprint` layout.
     */
    static gpg::RField* AddFields(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC7FC0 (FUN_00BC7FC0, register_RBlueprintTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes `RBlueprintTypeInfo` and hooks process-exit
   * cleanup.
   */
  void register_RBlueprintTypeInfo();

  static_assert(offsetof(RBlueprint, mOwner) == 0x04, "RBlueprint::mOwner offset must be 0x04");
  static_assert(offsetof(RBlueprint, mBlueprintId) == 0x08, "RBlueprint::mBlueprintId offset must be 0x08");
  static_assert(offsetof(RBlueprint, mDescription) == 0x24, "RBlueprint::mDescription offset must be 0x24");
  static_assert(offsetof(RBlueprint, mSource) == 0x40, "RBlueprint::mSource offset must be 0x40");
  static_assert(offsetof(RBlueprint, mBlueprintOrdinal) == 0x5C, "RBlueprint::mBlueprintOrdinal offset must be 0x5C");
  static_assert(sizeof(RBlueprint) == 0x60, "RBlueprint size must be 0x60");
  static_assert(sizeof(RBlueprintTypeInfo) == 0x64, "RBlueprintTypeInfo size must be 0x64");
} // namespace moho
