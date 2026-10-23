#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Motor.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/script/CScriptObject.h"

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  class StatItem;

  /**
   * Address: 0x00694BD0 (FUN_00694BD0, Lua ctor lane)
   * Address: 0x00694CF0 (FUN_00694CF0, default ctor lane)
   *
   * What it does:
   * Motor implementation that integrates tree sway/fall state and applies
   * a pending entity transform each update.
   */
  class MotorFallDown final : public Motor, public CScriptObject, public InstanceCounter<MotorFallDown>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00694CF0 (FUN_00694CF0, default ctor lane)
     */
    MotorFallDown();

    /**
     * Address: 0x00694BD0 (FUN_00694BD0, Lua ctor lane)
     */
    explicit MotorFallDown(LuaPlus::LuaState* state);

    /**
     * Address: 0x00694D70 (FUN_00694D70, deleting-thunk chain)
     * Address: 0x00694DA0 (FUN_00694DA0, non-deleting body)
     */
    ~MotorFallDown() override;

    /**
     * Address: 0x00694B90 (FUN_00694B90, Moho::MotorFallDown::GetClass)
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00694BB0 (FUN_00694BB0, Moho::MotorFallDown::GetDerivedObjectRef)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00695180 (FUN_00695180, update lane)
     */
    void Update(Entity* entity) override;

  public:
    float mFallDirectionRadians; // +0x38
    float mFallAngleRadians;     // +0x3C
    float mFallDepth;            // +0x40 (angular velocity lane)
    bool mBreakOnWhack;          // +0x44

    /**
     * Address: 0x00694FF0 (FUN_00694FF0)
     *
     * What it does:
     * Builds a new `MotorFallDown` for an archive load and hands it back unowned; its
     * members are loaded over it afterwards.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x00696110 (FUN_00696110)
     *
     * What it does:
     * Loads the `Motor` and `CScriptObject` bases, then the fall direction,
     * angle and depth and the break-on-whack flag.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006961D0 (FUN_006961D0)
     *
     * What it does:
     * Saves what `MemberDeserialize` loads.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(
    offsetof(MotorFallDown, mFallDirectionRadians) == 0x38,
    "MotorFallDown::mFallDirectionRadians offset must be 0x38"
  );
  static_assert(offsetof(MotorFallDown, mFallAngleRadians) == 0x3C, "MotorFallDown::mFallAngleRadians offset must be 0x3C");
  static_assert(offsetof(MotorFallDown, mFallDepth) == 0x40, "MotorFallDown::mFallDepth offset must be 0x40");
  static_assert(offsetof(MotorFallDown, mBreakOnWhack) == 0x44, "MotorFallDown::mBreakOnWhack offset must be 0x44");
  static_assert(sizeof(MotorFallDown) == 0x48, "MotorFallDown size must be 0x48");

  template <>
  class CScrLuaMetatableFactory<MotorFallDown> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00695B90 (FUN_00695B90, Moho::CScrLuaMetatableFactory<Moho::MotorFallDown>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<MotorFallDown>) == 0x08,
    "CScrLuaMetatableFactory<MotorFallDown> size must be 0x08"
  );

  class MotorFallDownTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00694E00 (FUN_00694E00, Moho::MotorFallDownTypeInfo::MotorFallDownTypeInfo)
     */
    MotorFallDownTypeInfo();

    /**
     * Address: 0x00694EA0 (FUN_00694EA0, Moho::MotorFallDownTypeInfo::dtr)
     */
    ~MotorFallDownTypeInfo() override;

    /**
     * Address: 0x00694E90 (FUN_00694E90, Moho::MotorFallDownTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00694E60 (FUN_00694E60, Moho::MotorFallDownTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00695CC0 (FUN_00695CC0, Moho::MotorFallDownTypeInfo::AddBase_CScriptObject)
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00695D20 (FUN_00695D20, Moho::MotorFallDownTypeInfo::AddBase_Motor)
     */
    static void AddBase_Motor(gpg::RType* typeInfo);
  };

  static_assert(sizeof(MotorFallDownTypeInfo) == 0x64, "MotorFallDownTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD5BE0 (FUN_00BD5BE0, register_MotorFallDownTypeInfo)
   */
  void register_MotorFallDownTypeInfo();

  /**
   * Address: 0x00BD5CC0 (FUN_00BD5CC0, register_CScrLuaMetatableFactory_MotorFallDown_Index)
   */
  int register_CScrLuaMetatableFactory_MotorFallDown_Index();

  class CScrLuaInitForm;

  /**
   * Address: 0x00695720 (FUN_00695720, cfunc_MotorFallDownWhack)
   *
   * What it does:
   * Unwraps the raw `lua_State` callback context and forwards to
   * `cfunc_MotorFallDownWhackL`.
   */
  int cfunc_MotorFallDownWhack(struct lua_State* luaContext);

  /**
   * Address: 0x006957A0 (FUN_006957A0, cfunc_MotorFallDownWhackL)
   *
   * What it does:
   * Parses `MotorFallDown:Whack(nx, ny, nz, force, dobreak)`; on the first
   * whack captures the XZ-plane fall direction `atan2(nx, nz)` and latches
   * the `dobreak` flag into the motor's active-fall state. Every call adds
   * `force` to the motor's depth (angular velocity) accumulator.
   */
  int cfunc_MotorFallDownWhackL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00695740 (FUN_00695740, func_MotorFallDownWhack_LuaFuncDef)
   *
   * What it does:
   * Publishes the `MotorFallDown:Whack(nx, ny, nz, force, dobreak)` binder
   * into the sim Lua init set.
   */
  CScrLuaInitForm* func_MotorFallDownWhack_LuaFuncDef();
} // namespace moho
