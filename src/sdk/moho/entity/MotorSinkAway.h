#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityMotor.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * Address: 0x00696500 (FUN_00696500, ctor lane)
   *
   * What it does:
   * Concrete entity motor that keeps one sink-speed lane and exposes script-object behavior.
   */
  class MotorSinkAway final : public EntityMotor, public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00696500 (FUN_00696500, default ctor)
     */
    MotorSinkAway();

    /**
     * Address: 0x006963F0 (FUN_006963F0, Lua ctor lane)
     */
    MotorSinkAway(LuaPlus::LuaState* state, float sinkDeltaY);

    /**
     * Address: 0x00696580 (FUN_00696580, deleting-thunk chain)
     * Address: 0x006965A0 (FUN_006965A0, non-deleting body)
     */
    ~MotorSinkAway() override;

    /**
     * Address: 0x006963B0 (FUN_006963B0, Moho::MotorSinkAway::GetClass)
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x006963D0 (FUN_006963D0, Moho::MotorSinkAway::GetDerivedObjectRef)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00696940 (FUN_00696940, update lane)
     */
    void Update(Entity* entity) override;

  public:
    float mSinkDeltaY; // +0x38
  };

  static_assert(offsetof(MotorSinkAway, mSinkDeltaY) == 0x38, "MotorSinkAway::mSinkDeltaY offset must be 0x38");
  static_assert(sizeof(MotorSinkAway) == 0x3C, "MotorSinkAway size must be 0x3C");

  template <>
  class CScrLuaMetatableFactory<MotorSinkAway> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00696FD0 (FUN_00696FD0, Moho::CScrLuaMetatableFactory<Moho::MotorSinkAway>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<MotorSinkAway>) == 0x08,
    "CScrLuaMetatableFactory<MotorSinkAway> size must be 0x8"
  );

  class MotorSinkAwayTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00696600 (FUN_00696600, Moho::MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo)
     */
    MotorSinkAwayTypeInfo();

    /**
     * Address: 0x006966A0 (FUN_006966A0, Moho::MotorSinkAwayTypeInfo::dtr)
     */
    ~MotorSinkAwayTypeInfo() override;

    /**
     * Address: 0x00696690 (FUN_00696690, Moho::MotorSinkAwayTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00696660 (FUN_00696660, Moho::MotorSinkAwayTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00696E90 (FUN_00696E90, Moho::MotorSinkAwayTypeInfo::AddBase_CScriptObject)
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00696EF0 (FUN_00696EF0, Moho::MotorSinkAwayTypeInfo::AddBase_Motor)
     */
    static void AddBase_Motor(gpg::RType* typeInfo);
  };

  static_assert(sizeof(MotorSinkAwayTypeInfo) == 0x64, "MotorSinkAwayTypeInfo size must be 0x64");

  class MotorSinkAwaySerializer
  {
  public:
    /**
     * Address: 0x00696880 (FUN_00696880, serializer load thunk)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00696890 (FUN_00696890, serializer save thunk)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006968B0 (FUN_006968B0, serializer registration lane)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(MotorSinkAwaySerializer, mHelperLinks) == 0x04,
    "MotorSinkAwaySerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(MotorSinkAwaySerializer, mDeserialize) == 0x0C,
    "MotorSinkAwaySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(MotorSinkAwaySerializer, mSerialize) == 0x10,
    "MotorSinkAwaySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(MotorSinkAwaySerializer) == 0x14, "MotorSinkAwaySerializer size must be 0x14");

  class MotorSinkAwayConstruct
  {
  public:
    /**
     * Address: 0x006967E0 (FUN_006967E0, construct registration lane)
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(MotorSinkAwayConstruct, mHelperLinks) == 0x04,
    "MotorSinkAwayConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(MotorSinkAwayConstruct, mConstructCallback) == 0x0C,
    "MotorSinkAwayConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(MotorSinkAwayConstruct, mDeleteCallback) == 0x10,
    "MotorSinkAwayConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(MotorSinkAwayConstruct) == 0x14, "MotorSinkAwayConstruct size must be 0x14");

  /**
   * Address: 0x00BFD210 (FUN_00BFD210, cleanup_MotorSinkAwayTypeInfo)
   */
  void cleanup_MotorSinkAwayTypeInfo();

  /**
   * Address: 0x00BFD270 (FUN_00BFD270, cleanup_MotorSinkAwayConstruct)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwayConstruct();

  /**
   * Address: 0x00BFD2A0 (FUN_00BFD2A0, cleanup_MotorSinkAwaySerializer)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwaySerializer();

  /**
   * Address: 0x00BD5D50 (FUN_00BD5D50, register_MotorSinkAwayTypeInfo)
   */
  void register_MotorSinkAwayTypeInfo();

  /**
   * Address: 0x00BD5D70 (FUN_00BD5D70, register_MotorSinkAwayConstruct)
   */
  int register_MotorSinkAwayConstruct();

  /**
   * Address: 0x00BD5DB0 (FUN_00BD5DB0, register_MotorSinkAwaySerializer)
   */
  int register_MotorSinkAwaySerializer();

  /**
   * Address: 0x00BD5E00 (FUN_00BD5E00, register_CScrLuaMetatableFactory_MotorSinkAway_Index)
   */
  int register_CScrLuaMetatableFactory_MotorSinkAway_Index();
} // namespace moho
