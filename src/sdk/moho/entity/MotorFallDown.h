#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityMotor.h"
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
  class MotorFallDown final : public EntityMotor, public CScriptObject
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

  /**
   * Address: 0x00695BC0 (FUN_00695BC0, Moho::InstanceCounter<Moho::MotorFallDown>::GetStatItem)
   */
  template <>
  StatItem* InstanceCounter<MotorFallDown>::GetStatItem();

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

  class MotorFallDownSerializer
  {
  public:
    /**
     * Address: 0x00695080 (FUN_00695080, serializer load thunk)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00695090 (FUN_00695090, serializer save thunk)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006950B0 (FUN_006950B0, serializer registration lane)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(MotorFallDownSerializer, mHelperLinks) == 0x04,
    "MotorFallDownSerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(MotorFallDownSerializer, mDeserialize) == 0x0C,
    "MotorFallDownSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(MotorFallDownSerializer, mSerialize) == 0x10,
    "MotorFallDownSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(MotorFallDownSerializer) == 0x14, "MotorFallDownSerializer size must be 0x14");

  class MotorFallDownConstruct
  {
  public:
    /**
     * Address: 0x00694F50 (FUN_00694F50, construct registration lane)
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(MotorFallDownConstruct, mHelperLinks) == 0x04,
    "MotorFallDownConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(MotorFallDownConstruct, mConstructCallback) == 0x0C,
    "MotorFallDownConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(MotorFallDownConstruct, mDeleteCallback) == 0x10,
    "MotorFallDownConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(MotorFallDownConstruct) == 0x14, "MotorFallDownConstruct size must be 0x14");

  /**
   * Address: 0x00BFD130 (FUN_00BFD130, cleanup_MotorFallDownTypeInfo)
   */
  void cleanup_MotorFallDownTypeInfo();

  /**
   * Address: 0x00BFD190 (FUN_00BFD190, cleanup_MotorFallDownConstruct)
   */
  gpg::SerHelperBase* cleanup_MotorFallDownConstruct();

  /**
   * Address: 0x00BFD1C0 (FUN_00BFD1C0, cleanup_MotorFallDownSerializer)
   */
  gpg::SerHelperBase* cleanup_MotorFallDownSerializer();

  /**
   * Address: 0x00BD5BE0 (FUN_00BD5BE0, register_MotorFallDownTypeInfo)
   */
  void register_MotorFallDownTypeInfo();

  /**
   * Address: 0x00BD5C00 (FUN_00BD5C00, register_MotorFallDownConstruct)
   */
  int register_MotorFallDownConstruct();

  /**
   * Address: 0x00BD5C40 (FUN_00BD5C40, register_MotorFallDownSerializer)
   */
  int register_MotorFallDownSerializer();

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
