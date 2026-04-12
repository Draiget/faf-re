#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"
#include "Wm3Vector3.h"

namespace moho
{
  class Sim;
  class Entity;

  enum CDamageMethod : std::int32_t
  {
    CDamage_SINGLE_TARGET = 0,
    CDamage_AREA_EFFECT = 1,
    CDamage_RING_EFFECT = 2,
  };

  class CDamage : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00736C00 (FUN_00736C00, Moho::CDamage::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `CDamage`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00736C20 (FUN_00736C20, Moho::CDamage::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00736C40 (FUN_00736C40, ??0CDamage@Moho@@QAE@CDamage@Z)
     *
     * What it does:
     * Copy-constructs one detached damage payload and re-links its weak
     * instigator/target nodes into owner intrusive weak chains.
     */
    CDamage(const CDamage& other);

    /**
     * Address: 0x007384C0 (FUN_007384C0, ??0CDamage@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs one script-backed damage payload for the owning Sim Lua state.
     */
    explicit CDamage(Sim* sim);

    /**
     * Address: 0x0064BAD0 (FUN_0064BAD0, ??1CDamage@Moho@@QAE@@Z)
     * Deleting destructor thunk: 0x00736D50 (FUN_00736D50, Moho::CDamage::dtr)
     * Slot: 2
     *
     * What it does:
     * Unlinks weak links, releases string storage, decrements instance counter,
     * then runs base `CScriptObject` teardown.
     */
    ~CDamage() override;

  public:
    CDamageMethod mMethod;        // +0x34
    WeakPtr<Entity> mInstigator;  // +0x38
    WeakPtr<Entity> mTarget;      // +0x40
    float mRadius;                // +0x48
    float mMaxRadius;             // +0x4C
    Wm3::Vec3f mOrigin;           // +0x50
    float mAmount;                // +0x5C
    msvc8::string mType;          // +0x60
    std::uint8_t mDamageFriendly; // +0x7C
    std::uint8_t mDamageNeutral;  // +0x7D
    std::uint8_t mDamageSelf;     // +0x7E
    std::uint8_t pad_7F;          // +0x7F
    Wm3::Vec3f mVector;           // +0x80
  };

  static_assert(sizeof(CDamage) == 0x8C, "CDamage size must be 0x8C");
  static_assert(offsetof(CDamage, mMethod) == 0x34, "CDamage::mMethod offset must be 0x34");
  static_assert(offsetof(CDamage, mInstigator) == 0x38, "CDamage::mInstigator offset must be 0x38");
  static_assert(offsetof(CDamage, mTarget) == 0x40, "CDamage::mTarget offset must be 0x40");
  static_assert(offsetof(CDamage, mRadius) == 0x48, "CDamage::mRadius offset must be 0x48");
  static_assert(offsetof(CDamage, mMaxRadius) == 0x4C, "CDamage::mMaxRadius offset must be 0x4C");
  static_assert(offsetof(CDamage, mOrigin) == 0x50, "CDamage::mOrigin offset must be 0x50");
  static_assert(offsetof(CDamage, mAmount) == 0x5C, "CDamage::mAmount offset must be 0x5C");
  static_assert(offsetof(CDamage, mType) == 0x60, "CDamage::mType offset must be 0x60");
  static_assert(offsetof(CDamage, mDamageFriendly) == 0x7C, "CDamage::mDamageFriendly offset must be 0x7C");
  static_assert(offsetof(CDamage, mDamageNeutral) == 0x7D, "CDamage::mDamageNeutral offset must be 0x7D");
  static_assert(offsetof(CDamage, mDamageSelf) == 0x7E, "CDamage::mDamageSelf offset must be 0x7E");
  static_assert(offsetof(CDamage, mVector) == 0x80, "CDamage::mVector offset must be 0x80");

  /**
   * VFTABLE: 0x00E33034
   * COL: 0x00E743A8
   */
  class CDamageTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007382A0 (FUN_007382A0, Moho::CDamageTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `CDamage` type metadata.
     */
    ~CDamageTypeInfo() override;

    /**
     * Address: 0x00738290 (FUN_00738290, Moho::CDamageTypeInfo::GetName)
     *
     * What it does:
     * Returns reflected type label `"CDamage"`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00738260 (FUN_00738260, Moho::CDamageTypeInfo::Init)
     *
     * What it does:
     * Sets reflected `CDamage` size, wires `CScriptObject` base metadata, and
     * publishes `CDamage` field descriptors.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0073A6B0 (FUN_0073A6B0, Moho::CDamageTypeInfo::AddBase_CScriptObject)
     *
     * What it does:
     * Adds reflected `CScriptObject` base lane at offset zero.
     */
    static void AddBaseScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00738340 (FUN_00738340, Moho::CDamageTypeInfo::AddFields)
     *
     * What it does:
     * Publishes `CDamage` reflected field lanes in binary order.
     */
    static void AddFields(gpg::RType* typeInfo);

    /**
     * Address: 0x0073A710 (FUN_0073A710, gpg::RType::AddField_CDamage_EMethod_0x34Method)
     *
     * What it does:
     * Appends reflected `Method` enum lane at `+0x34`.
     */
    static gpg::RField* AddFieldMethod(gpg::RType* typeInfo);

    /**
     * Address: 0x0073A790 (FUN_0073A790, gpg::RType::AddField_SMinMax_float_0x48MinMaxRadius)
     *
     * What it does:
     * Appends reflected `MinMaxRadius` lane (`SMinMax<float>`) at `+0x48`.
     */
    static gpg::RField* AddFieldMinMaxRadius(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CDamageTypeInfo) == 0x64, "CDamageTypeInfo size must be 0x64");

  /**
   * Address: 0x00738200 (FUN_00738200, preregister_CDamageTypeInfo)
   *
   * What it does:
   * Constructs/preregisters process-global `CDamageTypeInfo` descriptor.
   */
  [[nodiscard]] gpg::RType* preregister_CDamageTypeInfo();

  /**
   * Address: 0x00BDB6F0 (FUN_00BDB6F0, register_CDamageTypeInfo)
   *
   * What it does:
   * Runs preregistration and installs process-exit cleanup for
   * `CDamageTypeInfo`.
   */
  int register_CDamageTypeInfo();

  /**
   * Address: 0x00737E60 (FUN_00737E60, Moho::SIM_Damage)
   *
   * What it does:
   * Applies one typed `CDamage` payload through the core Sim damage pipeline.
   */
  void SIM_Damage(Sim* sim, const CDamage& damage);

  /**
   * Address: 0x00737ED0 (FUN_00737ED0, Moho::SIM_MetaImpactArea)
   * Mangled: ?SIM_MetaImpactArea@Moho@@YAXPAVSim@1@ABVCDamage@1@@Z
   *
   * What it does:
   * Applies one area-impact pulse against entities matching the category lane
   * encoded in `damage`.
   */
  void SIM_MetaImpactArea(Sim* sim, const CDamage& damage);

  /**
   * VFTABLE: 0x00E130BC
   * COL: 0x00E743C0
   */
  template <>
  class CScrLuaMetatableFactory<CDamage> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00739CF0 (FUN_00739CF0, Moho::CScrLuaMetatableFactory<Moho::CDamage>::Create)
     *
     * What it does:
     * Builds the metatable object used for `CDamage` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<CDamage>) == 0x8, "CScrLuaMetatableFactory<CDamage> size must be 0x8");
} // namespace moho
