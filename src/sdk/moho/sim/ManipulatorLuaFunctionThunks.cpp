#include "moho/sim/ManipulatorLuaFunctionThunks.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "Wm3Vector3.h"
#include "moho/animation/IAniManipulator.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAimManipulator.h"
#include "moho/ai/CBuilderArmManipulator.h"
#include "moho/animation/CRotateManipulator.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"

struct lua_State;

namespace moho
{
  class CAimManipulator;
  class CBoneEntityManipulator;
  class CBuilderArmManipulator;
  class CFootPlantManipulator;
  class CRotateManipulator;
  class CThrustManipulator;
  class Entity;
  class Unit;

  int cfunc_CreateAimController(lua_State* luaContext);
  int cfunc_CreateBuilderArmController(lua_State* luaContext);
  int cfunc_CreateFootPlantController(lua_State* luaContext);
  int cfunc_CreateThrustController(lua_State* luaContext);
  int cfunc_CBoneEntityManipulatorSetPivot(lua_State* luaContext);
  int cfunc_EntityAttachBoneToEntityBone(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorSetAimingArc(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorSetAimingArcL(LuaPlus::LuaState* state);
  int cfunc_CBuilderArmManipulatorGetHeadingPitch(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorGetHeadingPitchL(LuaPlus::LuaState* state);
  int cfunc_CBuilderArmManipulatorSetHeadingPitch(lua_State* luaContext);
  int cfunc_CBuilderArmManipulatorSetHeadingPitchL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetSpinDown(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetGoal(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearGoal(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearGoalL(LuaPlus::LuaState* state);
  int cfunc_CRotateManipulatorSetSpeed(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetTargetSpeed(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetAccel(lua_State* luaContext);
  int cfunc_CRotateManipulatorClearFollowBone(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetFollowBone(lua_State* luaContext);
  int cfunc_CRotateManipulatorGetCurrentAngle(lua_State* luaContext);
  int cfunc_CRotateManipulatorSetCurrentAngle(lua_State* luaContext);
  int cfunc_CThrustManipulatorSetThrustingParam(lua_State* luaContext);
  int cfunc_CThrustManipulatorSetThrustingParamL(LuaPlus::LuaState* state);

  template <>
  class CScrLuaMetatableFactory<CBoneEntityManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CBuilderArmManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CFootPlantManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<Entity> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CRotateManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CThrustManipulator> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CBoneEntityManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CBoneEntityManipulator> size must be 0x8"
  );
  static_assert(
    sizeof(CScrLuaMetatableFactory<CBuilderArmManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CBuilderArmManipulator> size must be 0x8"
  );
  static_assert(
    sizeof(CScrLuaMetatableFactory<CFootPlantManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CFootPlantManipulator> size must be 0x8"
  );
  static_assert(sizeof(CScrLuaMetatableFactory<Entity>) == 0x08, "CScrLuaMetatableFactory<Entity> size must be 0x8");
  static_assert(
    sizeof(CScrLuaMetatableFactory<CRotateManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CRotateManipulator> size must be 0x8"
  );
  static_assert(
    sizeof(CScrLuaMetatableFactory<CThrustManipulator>) == 0x08,
    "CScrLuaMetatableFactory<CThrustManipulator> size must be 0x8"
  );

  CScrLuaMetatableFactory<CBoneEntityManipulator> CScrLuaMetatableFactory<CBoneEntityManipulator>::sInstance{};
  CScrLuaMetatableFactory<CBuilderArmManipulator> CScrLuaMetatableFactory<CBuilderArmManipulator>::sInstance{};
  CScrLuaMetatableFactory<CFootPlantManipulator> CScrLuaMetatableFactory<CFootPlantManipulator>::sInstance{};
  CScrLuaMetatableFactory<Entity> CScrLuaMetatableFactory<Entity>::sInstance{};
  CScrLuaMetatableFactory<CRotateManipulator> CScrLuaMetatableFactory<CRotateManipulator>::sInstance{};
  CScrLuaMetatableFactory<CThrustManipulator> CScrLuaMetatableFactory<CThrustManipulator>::sInstance{};

  struct CBoneEntityManipulatorSerializerStartupNode
  {
    void* mVtable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoad = nullptr;   // +0x0C
    gpg::RType::save_func_t mSave = nullptr;   // +0x10
  };

  static_assert(
    offsetof(CBoneEntityManipulatorSerializerStartupNode, mHelperNext) == 0x04,
    "CBoneEntityManipulatorSerializerStartupNode::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CBoneEntityManipulatorSerializerStartupNode, mHelperPrev) == 0x08,
    "CBoneEntityManipulatorSerializerStartupNode::mHelperPrev offset must be 0x08"
  );
  static_assert(
    sizeof(CBoneEntityManipulatorSerializerStartupNode) == 0x14,
    "CBoneEntityManipulatorSerializerStartupNode size must be 0x14"
  );

  CBoneEntityManipulatorSerializerStartupNode gCBoneEntityManipulatorSerializerStartupNode{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(CBoneEntityManipulatorSerializerStartupNode& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(CBoneEntityManipulatorSerializerStartupNode& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Entity>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
      moho::WeakPtr<moho::Entity>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  struct CBoneEntityManipulatorSerializerRuntimeView : moho::IAniManipulator
  {
    moho::WeakPtr<moho::Unit> mGoalUnit;        // +0x80
    moho::WeakPtr<moho::Entity> mTargetEntity; // +0x88
    std::int32_t mReferenceBoneIndex;           // +0x90
    Wm3::Vector3f mPivot;                       // +0x94
  };

  static_assert(
    offsetof(CBoneEntityManipulatorSerializerRuntimeView, mGoalUnit) == 0x80,
    "CBoneEntityManipulatorSerializerRuntimeView::mGoalUnit offset must be 0x80"
  );
  static_assert(
    offsetof(CBoneEntityManipulatorSerializerRuntimeView, mTargetEntity) == 0x88,
    "CBoneEntityManipulatorSerializerRuntimeView::mTargetEntity offset must be 0x88"
  );
  static_assert(
    offsetof(CBoneEntityManipulatorSerializerRuntimeView, mReferenceBoneIndex) == 0x90,
    "CBoneEntityManipulatorSerializerRuntimeView::mReferenceBoneIndex offset must be 0x90"
  );
  static_assert(
    offsetof(CBoneEntityManipulatorSerializerRuntimeView, mPivot) == 0x94,
    "CBoneEntityManipulatorSerializerRuntimeView::mPivot offset must be 0x94"
  );
  static_assert(
    sizeof(CBoneEntityManipulatorSerializerRuntimeView) == 0xA0,
    "CBoneEntityManipulatorSerializerRuntimeView size must be 0xA0"
  );

  /**
   * Address: 0x006356D0 (FUN_006356D0, CBoneEntityManipulator serializer load body)
   *
   * What it does:
   * Deserializes one `CBoneEntityManipulator` lane by loading
   * `IAniManipulator` base state, goal/target weak-pointer lanes,
   * reference-bone index, and pivot vector.
   */
  [[maybe_unused]] void DeserializeCBoneEntityManipulatorSerializerBody(
    CBoneEntityManipulatorSerializerRuntimeView* const manipulator,
    gpg::ReadArchive* const archive
  )
  {
    if (!archive || !manipulator) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedIAniManipulatorType(), static_cast<moho::IAniManipulator*>(manipulator), owner);
    archive->Read(CachedWeakPtrUnitType(), &manipulator->mGoalUnit, owner);
    archive->Read(CachedWeakPtrEntityType(), &manipulator->mTargetEntity, owner);
    archive->ReadInt(&manipulator->mReferenceBoneIndex);
    archive->Read(CachedVector3fType(), &manipulator->mPivot, owner);
  }

  /**
   * Address: 0x006357D0 (FUN_006357D0, CBoneEntityManipulator serializer save body)
   *
   * What it does:
   * Serializes one `CBoneEntityManipulator` lane by saving `IAniManipulator`
   * base state, goal/target weak-pointer lanes, reference-bone index,
   * and pivot vector.
   */
  [[maybe_unused]] void SerializeCBoneEntityManipulatorSerializerBody(
    const CBoneEntityManipulatorSerializerRuntimeView* const manipulator,
    gpg::WriteArchive* const archive
  )
  {
    if (!archive || !manipulator) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(CachedIAniManipulatorType(), static_cast<const moho::IAniManipulator*>(manipulator), owner);
    archive->Write(CachedWeakPtrUnitType(), &manipulator->mGoalUnit, owner);
    archive->Write(CachedWeakPtrEntityType(), &manipulator->mTargetEntity, owner);
    archive->WriteInt(manipulator->mReferenceBoneIndex);
    archive->Write(CachedVector3fType(), &manipulator->mPivot, owner);
  }

  /**
   * Address: 0x00634BC0 (FUN_00634BC0, Moho::CBoneEntityManipulatorSerializer::Deserialize)
   *
   * What it does:
   * Load-callback thunk that forwards one serializer lane into the canonical
   * CBone deserialization body (`FUN_006356D0`).
   */
  [[maybe_unused]] void DeserializeCBoneEntityManipulatorSerializerThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const manipulator =
      reinterpret_cast<CBoneEntityManipulatorSerializerRuntimeView*>(static_cast<std::uintptr_t>(objectPtr));
    DeserializeCBoneEntityManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x00634BD0 (FUN_00634BD0, Moho::CBoneEntityManipulatorSerializer::Serialize)
   *
   * What it does:
   * Save-callback thunk that forwards one serializer lane into the canonical
   * CBone serialization body (`FUN_006357D0`).
   */
  [[maybe_unused]] void SerializeCBoneEntityManipulatorSerializerThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto* const manipulator =
      reinterpret_cast<const CBoneEntityManipulatorSerializerRuntimeView*>(static_cast<std::uintptr_t>(objectPtr));
    SerializeCBoneEntityManipulatorSerializerBody(manipulator, archive);
  }

  /**
   * Address: 0x00635380 (FUN_00635380)
   *
   * What it does:
   * Tail-forward thunk that aliases the canonical CBoneEntityManipulator
   * serializer-save body (`FUN_006357D0`).
   */
  [[maybe_unused]] void SerializeCBoneEntityManipulatorSerializerBodyThunk(
    const CBoneEntityManipulatorSerializerRuntimeView* const manipulator,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCBoneEntityManipulatorSerializerBody(manipulator, archive);
  }

  CScrLuaMetatableFactory<CBoneEntityManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CBoneEntityManipulator>& CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00635490 (FUN_00635490)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<CBoneEntityManipulator>` and returns that
   * singleton.
   */
  [[maybe_unused]] CScrLuaMetatableFactory<CBoneEntityManipulator>*
  startup_CScrLuaMetatableFactory_CBoneEntityManipulator_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CBoneEntityManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CBuilderArmManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CBuilderArmManipulator>& CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CBuilderArmManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CFootPlantManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CFootPlantManipulator>& CScrLuaMetatableFactory<CFootPlantManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CFootPlantManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<Entity>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<Entity>& CScrLuaMetatableFactory<Entity>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<Entity>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CRotateManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CRotateManipulator>& CScrLuaMetatableFactory<CRotateManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CRotateManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<CThrustManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CThrustManipulator>& CScrLuaMetatableFactory<CThrustManipulator>::Instance()
  {
    return sInstance;
  }

  LuaPlus::LuaObject CScrLuaMetatableFactory<CThrustManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  LuaPlus::LuaObject CreateRotateManipulatorLuaMetatable(LuaPlus::LuaState* const state)
  {
    return CScrLuaMetatableFactory<CRotateManipulator>::Instance().Get(state);
  }

  /**
   * Address: 0x006371B0 (FUN_006371B0, func_CreateLuaBuilderArmObject)
   *
   * What it does:
   * Writes the `CBuilderArmManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject* func_CreateLuaBuilderArmObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00633050 (FUN_00633050, func_CreateLuaAimManipulatorObject)
   *
   * What it does:
   * Writes the `CAimManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject* func_CreateLuaAimManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CAimManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x006352F0 (FUN_006352F0, func_CreateLuaBoneEntityManipulatorObject)
   *
   * What it does:
   * Writes the `CBoneEntityManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject*
  func_CreateLuaBoneEntityManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x0063A1D0 (FUN_0063A1D0, func_CreateLuaFootPlantManipulatorObject)
   *
   * What it does:
   * Writes the `CFootPlantManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject*
  func_CreateLuaFootPlantManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CFootPlantManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00645540 (FUN_00645540, func_CreateCRotateManipulatorObject)
   *
   * What it does:
   * Writes the `CRotateManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject*
  func_CreateCRotateManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CRotateManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x0064B380 (FUN_0064B380, func_CreateLuaCThrustManipulator)
   *
   * What it does:
   * Writes the `CThrustManipulator` metatable Lua object into `object` and
   * returns the same destination pointer.
   */
  LuaPlus::LuaObject* func_CreateLuaCThrustManipulator(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<CThrustManipulator>::Instance().Get(state);
    return object;
  }
} // namespace moho

namespace
{
  constexpr const char* kGlobalLuaFactoryClassName = "<global>";
  constexpr const char* kCreateAimControllerName = "CreateAimController";
  constexpr const char* kCreateAimControllerHelpText =
    "CreateAimController(weapon, label, turretBone, [barrelBone], [muzzleBone])";
  constexpr const char* kCreateBuilderArmControllerName = "CreateBuilderArmController";
  constexpr const char* kCreateBuilderArmControllerHelpText =
    "CreateBuilderArmController(unit,turretBone, [barrelBone], [aimBone])";
  constexpr const char* kCreateFootPlantControllerName = "CreateFootPlantController";
  constexpr const char* kCreateFootPlantControllerHelpText =
    "CreateFootPlantController(unit, footBone, kneeBone, hipBone, [straightLegs], [maxFootFall])";
  constexpr const char* kCreateThrustControllerName = "CreateThrustController";
  constexpr const char* kCreateThrustControllerHelpText = "CreateThrustController(unit, label, thrustBone)";

  constexpr const char* kCBoneEntityManipulatorSetPivotName = "SetPivot";
  constexpr const char* kCBoneEntityManipulatorSetPivotClassName = "CBoneEntityManipulator";
  constexpr const char* kCBoneEntityManipulatorSetPivotHelpText =
    "manip:SetPivot(x,y,z) -- Set the pivot point of the attached bone";

  constexpr const char* kEntityAttachBoneToEntityBoneName = "AttachBoneToEntityBone";
  constexpr const char* kEntityAttachBoneToEntityBoneClassName = "Entity";
  constexpr const char* kEntityAttachBoneToEntityBoneHelpText =
    "Attach a unit bone position to an entity bone position";

  constexpr const char* kCBuilderArmManipulatorSetAimingArcName = "SetAimingArc";
  constexpr const char* kCBuilderArmManipulatorClassName = "CBuilderArmManipulator";
  constexpr const char* kCBuilderArmManipulatorSetAimingArcHelpText =
    "BuilderArmManipulator:SetAimingArc(minHeading, maxHeading, headingMaxSlew, minPitch, maxPitch, pitchMaxSlew)";

  constexpr const char* kCBuilderArmManipulatorGetHeadingPitchName = "GetHeadingPitch";
  constexpr const char* kCBuilderArmManipulatorGetHeadingPitchHelpText = "CBuilderArmManipulator:GetHeading()";
  constexpr const char* kCBuilderArmManipulatorSetHeadingPitchName = "SetHeadingPitch";
  constexpr const char* kCBuilderArmManipulatorSetHeadingPitchHelpText =
    "CBuilderArmManipulator:SetHeadingPitch( heading, pitch )";
  constexpr float kDegreesToRadians = 0.017453292f;

  constexpr const char* kCRotateManipulatorSetSpinDownName = "SetSpinDown";
  constexpr const char* kCRotateManipulatorSetGoalName = "SetGoal";
  constexpr const char* kCRotateManipulatorClearGoalName = "ClearGoal";
  constexpr const char* kCRotateManipulatorSetSpeedName = "SetSpeed";
  constexpr const char* kCRotateManipulatorSetTargetSpeedName = "SetTargetSpeed";
  constexpr const char* kCRotateManipulatorSetAccelName = "SetAccel";
  constexpr const char* kCRotateManipulatorClearFollowBoneName = "ClearFollowBone";
  constexpr const char* kCRotateManipulatorSetFollowBoneName = "SetFollowBone";
  constexpr const char* kCRotateManipulatorGetCurrentAngleName = "GetCurrentAngle";
  constexpr const char* kCRotateManipulatorSetCurrentAngleName = "SetCurrentAngle";
  constexpr const char* kCRotateManipulatorClassName = "CRotateManipulator";

  constexpr const char* kCRotateManipulatorSetSpinDownHelpText = "RotateManipulator:SetSpinDown(self, flag)";
  constexpr const char* kCRotateManipulatorSetGoalHelpText = "RotateManipulator:SetGoal(self, degrees)";
  constexpr const char* kCRotateManipulatorClearGoalHelpText = "RotateManipulator:ClearGoal()";
  constexpr const char* kCRotateManipulatorSetSpeedHelpText = "RotateManipulator:SetSpeed(self, degrees_per_second)";
  constexpr const char* kCRotateManipulatorSetTargetSpeedHelpText =
    "RotateManipulator:SetTargetSpeed(degrees_per_second)";
  constexpr const char* kCRotateManipulatorSetAccelHelpText =
    "RotateManipulator:SetAccel(degrees_per_second_squared)";
  constexpr const char* kCRotateManipulatorClearFollowBoneHelpText = "RotateManipulator:ClearFollowBone()";
  constexpr const char* kCRotateManipulatorSetFollowBoneHelpText = "RotateManipulator:SetFollowBone(bone)";
  constexpr const char* kCRotateManipulatorGetCurrentAngleHelpText = "RotateManipulator:GetCurrentAngle()";
  constexpr const char* kCRotateManipulatorSetCurrentAngleHelpText = "RotateManipulator:SetCurrentAngle(angle)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr const char* kInvalidRotatorError = "CSpinManipulator:SetGoal: invalid rotator";

  constexpr const char* kCThrustManipulatorSetThrustingParamName = "SetThrustingParam";
  constexpr const char* kCThrustManipulatorClassName = "CThrustManipulator";
  constexpr const char* kCThrustManipulatorSetThrustingParamHelpText =
    "ThrustManipulator:SetThrustingParam(xCapMin, xCapMax, yCapMin, yCapMax, zCapMin, zCapMax, turnForceMult, "
    "turnSpeed)";

  [[nodiscard]] gpg::RType* CachedCRotateManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CRotateManipulator");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CRotateManipulator");
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] moho::CScriptObject** ExtractScriptObjectSlot(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, moho::CScriptObject::GetPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] moho::CRotateManipulator*
  GetRotateManipulatorOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RType* const rotateType = CachedCRotateManipulatorType();
    const gpg::RRef upcast = rotateType ? gpg::REF_UpcastPtr(sourceRef, rotateType) : gpg::RRef{};
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CRotateManipulator*>(upcast.mObj);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] float ReadRequiredLuaNumber(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject stackObject{};
    stackObject.m_state = state;
    stackObject.m_stackIndex = stackIndex;
    if (lua_type(state->m_state, stackIndex) != 3) {
      LuaPlus::LuaObject valueObject(stackObject);
      valueObject.TypeError("number");
    }

    return lua_tonumber(stackObject.m_state->m_state, stackObject.m_stackIndex);
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardManipulatorLuaThunk() noexcept
  {
    return Target();
  }

  struct ThrustCapVector3f
  {
    float x;
    float y;
    float z;
  };

  struct CThrustManipulatorLuaRuntimeView
  {
    std::byte preCapStorage[0xAC];
    ThrustCapVector3f mCapMin;
    ThrustCapVector3f mCapMax;
    float mTurnForceMult;
    float mTurnSpeed;
  };

  static_assert(offsetof(CThrustManipulatorLuaRuntimeView, mCapMin) == 0xAC, "mCapMin offset must be 0xAC");
  static_assert(offsetof(CThrustManipulatorLuaRuntimeView, mCapMax) == 0xB8, "mCapMax offset must be 0xB8");
  static_assert(
    offsetof(CThrustManipulatorLuaRuntimeView, mTurnForceMult) == 0xC4,
    "mTurnForceMult offset must be 0xC4"
  );
  static_assert(offsetof(CThrustManipulatorLuaRuntimeView, mTurnSpeed) == 0xC8, "mTurnSpeed offset must be 0xC8");

  struct ManipulatorLuaFunctionThunksBootstrap
  {
    ManipulatorLuaFunctionThunksBootstrap()
    {
      (void)moho::j_func_CreateAimController_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetFiringArc_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef();
      (void)moho::register_CAimManipulatorOnTarget_LuaFuncDef();
      (void)moho::register_CAimManipulatorSetEnabled_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();
      (void)moho::j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef();
      (void)moho::register_EntityAttachBoneToEntityBone_LuaFuncDef();
      (void)moho::j_func_CreateBuilderArmController_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef();
      (void)moho::j_func_CreateCollisionDetector_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorEnable_LuaFuncDef();
      (void)moho::register_CCollisionManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_CCollisionManipulatorWatchBone_LuaFuncDef();
      (void)moho::register_CreateFootPlantController_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorSetPrecedence_LuaFuncDef();
      (void)moho::register_IAniManipulatorEnable_LuaFuncDef();
      (void)moho::register_IAniManipulatorDisable_LuaFuncDef();
      (void)moho::j_func_IAniManipulatorDestroy_LuaFuncDef();
      (void)moho::j_func_CreateAnimator_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorPlayAnim_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetRate_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetRate_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetAnimationTime_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef();
      (void)moho::j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef();
      (void)moho::register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef();
      (void)moho::j_func_CreateRotator_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetSpinDown_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorClearGoal_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetAccel_LuaFuncDef();
      (void)moho::register_CRotateManipulatorClearFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorSetFollowBone_LuaFuncDef();
      (void)moho::j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef();
      (void)moho::register_CRotateManipulatorSetCurrentAngle_LuaFuncDef();
      (void)moho::j_func_CreateSlaver_LuaFuncDef();
      (void)moho::register_CSlaveManipulatorSetMaxRate_LuaFuncDef();
      (void)moho::j_func_CreateSlider_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetWorldUnits_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetSpeed_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetAcceleration_LuaFuncDef();
      (void)moho::register_CSlideManipulatorSetDeceleration_LuaFuncDef();
      (void)moho::j_func_CSlideManipulatorSetGoal_LuaFuncDef();
      (void)moho::register_CSlideManipulatorBeenDestroyed_LuaFuncDef();
      (void)moho::j_func_CreateStorageManip_LuaFuncDef();
      (void)moho::j_func_CreateThrustController_LuaFuncDef();
      (void)moho::j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef();
    }
  };

  [[maybe_unused]] ManipulatorLuaFunctionThunksBootstrap gManipulatorLuaFunctionThunksBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006369D0 (FUN_006369D0, func_CBuilderArmManipulatorSetAimingArc)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_CBuilderArmManipulatorSetAimingArcL`.
   */
  int cfunc_CBuilderArmManipulatorSetAimingArc(lua_State* const luaContext)
  {
    return cfunc_CBuilderArmManipulatorSetAimingArcL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00636A50 (FUN_00636A50, cfunc_CBuilderArmManipulatorSetAimingArcL)
   *
   * What it does:
   * Reads six degree-domain arc parameters from Lua, converts to radians, and
   * updates builder-arm heading/pitch arc lanes.
   */
  int cfunc_CBuilderArmManipulatorSetAimingArcL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCBuilderArmManipulatorSetAimingArcHelpText, 7, argumentCount);
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CBuilderArmManipulator* const manipulator = moho::SCR_FromLua_CBuilderArmManipulator(manipulatorObject, state);

    float paramsRadians[6]{};
    for (int index = 0; index < 6; ++index) {
      paramsRadians[index] = ReadRequiredLuaNumber(state, index + 2) * kDegreesToRadians;
    }

    manipulator->SetAimingArc(
      paramsRadians[0],
      paramsRadians[1],
      paramsRadians[2] * 0.1f,
      paramsRadians[3],
      paramsRadians[4],
      paramsRadians[5] * 0.1f
    );
    return 0;
  }

  /**
   * Address: 0x00636BD0 (FUN_00636BD0, cfunc_CBuilderArmManipulatorGetHeadingPitch)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_CBuilderArmManipulatorGetHeadingPitchL`.
   */
  int cfunc_CBuilderArmManipulatorGetHeadingPitch(lua_State* const luaContext)
  {
    return cfunc_CBuilderArmManipulatorGetHeadingPitchL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00636C50 (FUN_00636C50, cfunc_CBuilderArmManipulatorGetHeadingPitchL)
   *
   * What it does:
   * Pushes current builder-arm heading/pitch values to Lua.
   */
  int cfunc_CBuilderArmManipulatorGetHeadingPitchL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCBuilderArmManipulatorGetHeadingPitchHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CBuilderArmManipulator* const manipulator = moho::SCR_FromLua_CBuilderArmManipulator(manipulatorObject, state);

    lua_pushnumber(state->m_state, manipulator->mHeading);
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, manipulator->mPitch);
    (void)lua_gettop(state->m_state);
    return 2;
  }

  /**
   * Address: 0x00636D30 (FUN_00636D30, cfunc_CBuilderArmManipulatorSetHeadingPitch)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_CBuilderArmManipulatorSetHeadingPitchL`.
   */
  int cfunc_CBuilderArmManipulatorSetHeadingPitch(lua_State* const luaContext)
  {
    return cfunc_CBuilderArmManipulatorSetHeadingPitchL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00636DB0 (FUN_00636DB0, cfunc_CBuilderArmManipulatorSetHeadingPitchL)
   *
   * What it does:
   * Reads heading/pitch scalar args from Lua and stores them on the builder-arm
   * manipulator runtime lane.
   */
  int cfunc_CBuilderArmManipulatorSetHeadingPitchL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCBuilderArmManipulatorSetHeadingPitchHelpText, 3, argumentCount);
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CBuilderArmManipulator* const manipulator = moho::SCR_FromLua_CBuilderArmManipulator(manipulatorObject, state);

    const float pitch = ReadRequiredLuaNumber(state, 3);
    const float heading = ReadRequiredLuaNumber(state, 2);
    manipulator->mHeading = heading;
    manipulator->mPitch = pitch;
    return 0;
  }

  /**
   * Address: 0x006445C0 (FUN_006445C0, cfunc_CRotateManipulatorClearGoal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CRotateManipulatorClearGoalL`.
   */
  int cfunc_CRotateManipulatorClearGoal(lua_State* const luaContext)
  {
    return cfunc_CRotateManipulatorClearGoalL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00644640 (FUN_00644640, cfunc_CRotateManipulatorClearGoalL)
   *
   * What it does:
   * Resolves one rotate manipulator from Lua, clears its goal-armed lane, and
   * raises Lua errors for invalid/mismatched game-object handles.
   */
  int cfunc_CRotateManipulatorClearGoalL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCRotateManipulatorClearGoalHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    moho::CRotateManipulator* const manipulator = GetRotateManipulatorOptional(manipulatorObject, state);
    if (!manipulator) {
      lua_pushstring(state->m_state, kInvalidRotatorError);
      (void)lua_gettop(state->m_state);
      lua_error(state->m_state);
      return 0;
    }

    manipulator->mHasGoal = 0u;
    return 0;
  }

  /**
   * Address: 0x0064AD10 (FUN_0064AD10, cfunc_CThrustManipulatorSetThrustingParam)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_CThrustManipulatorSetThrustingParamL`.
   */
  int cfunc_CThrustManipulatorSetThrustingParam(lua_State* const luaContext)
  {
    return cfunc_CThrustManipulatorSetThrustingParamL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0064AD90 (FUN_0064AD90, cfunc_CThrustManipulatorSetThrustingParamL)
   *
   * What it does:
   * Validates and reads `SetThrustingParam(...)` numeric arguments from Lua
   * then updates cap ranges plus turn force/speed on one thrust manipulator.
   */
  int cfunc_CThrustManipulatorSetThrustingParamL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(
        state,
        kLuaExpectedArgsWarning,
        kCThrustManipulatorSetThrustingParamHelpText,
        9,
        argumentCount
      );
    }

    const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CThrustManipulator* const manipulator = moho::SCR_FromLua_CThrustManipulator(manipulatorObject, state);

    const float turnSpeed = ReadRequiredLuaNumber(state, 9);
    const float turnForceMult = ReadRequiredLuaNumber(state, 8);
    const float zCapMax = ReadRequiredLuaNumber(state, 7);
    const float yCapMax = ReadRequiredLuaNumber(state, 5);
    const float xCapMax = ReadRequiredLuaNumber(state, 3);
    const float zCapMin = ReadRequiredLuaNumber(state, 6);
    const float yCapMin = ReadRequiredLuaNumber(state, 4);
    const float xCapMin = ReadRequiredLuaNumber(state, 2);

    CThrustManipulatorLuaRuntimeView* const runtimeView =
      reinterpret_cast<CThrustManipulatorLuaRuntimeView*>(manipulator);
    runtimeView->mCapMin.x = xCapMin;
    runtimeView->mCapMin.y = yCapMin;
    runtimeView->mCapMin.z = zCapMin;
    runtimeView->mCapMax.x = xCapMax;
    runtimeView->mCapMax.y = yCapMax;
    runtimeView->mCapMax.z = zCapMax;
    runtimeView->mTurnForceMult = turnForceMult;
    runtimeView->mTurnSpeed = turnSpeed;
    return 0;
  }

  /**
   * Address: 0x00634BE0 (FUN_00634BE0, startup_CBoneEntityManipulatorSerializer)
   *
   * What it does:
   * Initializes one `CBoneEntityManipulator` serializer helper node by
   * rewiring intrusive links, binding load/save callbacks, and publishing one
   * startup vtable lane tag.
   */
  [[maybe_unused]] CBoneEntityManipulatorSerializerStartupNode* startup_CBoneEntityManipulatorSerializer()
  {
    auto* const self =
      reinterpret_cast<gpg::SerHelperBase*>(&gCBoneEntityManipulatorSerializerStartupNode.mHelperNext);
    gCBoneEntityManipulatorSerializerStartupNode.mHelperNext = self;
    gCBoneEntityManipulatorSerializerStartupNode.mHelperPrev = self;
    gCBoneEntityManipulatorSerializerStartupNode.mLoad = &DeserializeCBoneEntityManipulatorSerializerThunk;
    gCBoneEntityManipulatorSerializerStartupNode.mSave = &SerializeCBoneEntityManipulatorSerializerThunk;

    static std::uint8_t sCBoneEntityManipulatorSerializerRuntimeVTableTag = 0;
    gCBoneEntityManipulatorSerializerStartupNode.mVtable = &sCBoneEntityManipulatorSerializerRuntimeVTableTag;
    return &gCBoneEntityManipulatorSerializerStartupNode;
  }

  /**
   * Address: 0x00635110 (FUN_00635110, startup_CBoneEntityManipulatorSerializerSerSaveLoadHelperLane)
   *
   * What it does:
   * Initializes the same global CBone serializer helper node but rebinds the
   * startup vtable lane to the SerSaveLoadHelper variant before wiring
   * deserialize/serialize callbacks.
   */
  [[maybe_unused]] [[nodiscard]] CBoneEntityManipulatorSerializerStartupNode*
  startup_CBoneEntityManipulatorSerializerSerSaveLoadHelperLane()
  {
    auto* const self =
      reinterpret_cast<gpg::SerHelperBase*>(&gCBoneEntityManipulatorSerializerStartupNode.mHelperNext);
    gCBoneEntityManipulatorSerializerStartupNode.mHelperNext = self;
    gCBoneEntityManipulatorSerializerStartupNode.mHelperPrev = self;

    static std::uint8_t sCBoneEntityManipulatorSerializerSerSaveLoadHelperVTableTag = 0;
    gCBoneEntityManipulatorSerializerStartupNode.mVtable =
      &sCBoneEntityManipulatorSerializerSerSaveLoadHelperVTableTag;
    gCBoneEntityManipulatorSerializerStartupNode.mLoad = &DeserializeCBoneEntityManipulatorSerializerThunk;
    gCBoneEntityManipulatorSerializerStartupNode.mSave = &SerializeCBoneEntityManipulatorSerializerThunk;
    return &gCBoneEntityManipulatorSerializerStartupNode;
  }

  /**
   * Address: 0x00634B70 (FUN_00634B70, CBoneEntityManipulatorTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Executes one non-deleting cleanup lane for the CBone manipulator type-info
   * descriptor by running the `gpg::RType` base teardown.
   */
  [[maybe_unused]] void DestroyCBoneEntityManipulatorTypeInfoBody(gpg::RType* const typeInfo) noexcept
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->~RType();
  }

  /**
   * Address: 0x00634C10 (FUN_00634C10, cleanup_CBoneEntityManipulatorSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the `CBoneEntityManipulator` serializer
   * helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CBoneEntityManipulatorSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(gCBoneEntityManipulatorSerializerStartupNode);
  }

  /**
   * Address: 0x00634C40 (FUN_00634C40, cleanup_CBoneEntityManipulatorSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the
   * `CBoneEntityManipulator` serializer helper node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CBoneEntityManipulatorSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(gCBoneEntityManipulatorSerializerStartupNode);
  }

  /**
   * Address: 0x00634C90 (FUN_00634C90, func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBoneEntityManipulator:SetPivot(x, y, z)` Lua binder.
   */
  CScrLuaInitForm* func_CBoneEntityManipulatorSetPivot_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBoneEntityManipulatorSetPivotName,
      &cfunc_CBoneEntityManipulatorSetPivot,
      &CScrLuaMetatableFactory<CBoneEntityManipulator>::Instance(),
      kCBoneEntityManipulatorSetPivotClassName,
      kCBoneEntityManipulatorSetPivotHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00634EA0 (FUN_00634EA0, func_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Entity:AttachBoneToEntityBone(...)` Lua binder.
   */
  CScrLuaInitForm* func_EntityAttachBoneToEntityBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kEntityAttachBoneToEntityBoneName,
      &cfunc_EntityAttachBoneToEntityBone,
      &CScrLuaMetatableFactory<Entity>::Instance(),
      kEntityAttachBoneToEntityBoneClassName,
      kEntityAttachBoneToEntityBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006369F0 (FUN_006369F0, func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetAimingArc(...)` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorSetAimingArcName,
      &cfunc_CBuilderArmManipulatorSetAimingArc,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorSetAimingArcHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00636BF0 (FUN_00636BF0, func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:GetHeadingPitch()` Lua binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorGetHeadingPitchName,
      &cfunc_CBuilderArmManipulatorGetHeadingPitch,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorGetHeadingPitchHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00636D50 (FUN_00636D50, func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CBuilderArmManipulator:SetHeadingPitch(heading, pitch)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCBuilderArmManipulatorSetHeadingPitchName,
      &cfunc_CBuilderArmManipulatorSetHeadingPitch,
      &CScrLuaMetatableFactory<CBuilderArmManipulator>::Instance(),
      kCBuilderArmManipulatorClassName,
      kCBuilderArmManipulatorSetHeadingPitchHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00631F40 (FUN_00631F40, func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateAimController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateAimController_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateAimControllerName,
      &cfunc_CreateAimController,
      nullptr,
      kGlobalLuaFactoryClassName,
      kCreateAimControllerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00636820 (FUN_00636820, func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateBuilderArmController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateBuilderArmController_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateBuilderArmControllerName,
      &cfunc_CreateBuilderArmController,
      nullptr,
      kGlobalLuaFactoryClassName,
      kCreateBuilderArmControllerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00639CA0 (FUN_00639CA0, func_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateFootPlantController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateFootPlantController_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateFootPlantControllerName,
      &cfunc_CreateFootPlantController,
      nullptr,
      kGlobalLuaFactoryClassName,
      kCreateFootPlantControllerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006442A0 (FUN_006442A0, func_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpinDown(flag)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpinDown_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetSpinDownName,
      &cfunc_CRotateManipulatorSetSpinDown,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetSpinDownHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644410 (FUN_00644410, func_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetGoal(degrees)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetGoal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetGoalName,
      &cfunc_CRotateManipulatorSetGoal,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetGoalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006445E0 (FUN_006445E0, func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearGoal()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearGoal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorClearGoalName,
      &cfunc_CRotateManipulatorClearGoal,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorClearGoalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644730 (FUN_00644730, func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetSpeedName,
      &cfunc_CRotateManipulatorSetSpeed,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetSpeedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006448D0 (FUN_006448D0, func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetTargetSpeed(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetTargetSpeed_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetTargetSpeedName,
      &cfunc_CRotateManipulatorSetTargetSpeed,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetTargetSpeedHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644AA0 (FUN_00644AA0, func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetAccel(...)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetAccel_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetAccelName,
      &cfunc_CRotateManipulatorSetAccel,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetAccelHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644C40 (FUN_00644C40, func_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:ClearFollowBone()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorClearFollowBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorClearFollowBoneName,
      &cfunc_CRotateManipulatorClearFollowBone,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorClearFollowBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644DB0 (FUN_00644DB0, func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetFollowBone(bone)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetFollowBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetFollowBoneName,
      &cfunc_CRotateManipulatorSetFollowBone,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetFollowBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00644F50 (FUN_00644F50, func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:GetCurrentAngle()` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorGetCurrentAngle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorGetCurrentAngleName,
      &cfunc_CRotateManipulatorGetCurrentAngle,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorGetCurrentAngleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006450C0 (FUN_006450C0, func_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CRotateManipulator:SetCurrentAngle(angle)` Lua binder.
   */
  CScrLuaInitForm* func_CRotateManipulatorSetCurrentAngle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCRotateManipulatorSetCurrentAngleName,
      &cfunc_CRotateManipulatorSetCurrentAngle,
      &CScrLuaMetatableFactory<CRotateManipulator>::Instance(),
      kCRotateManipulatorClassName,
      kCRotateManipulatorSetCurrentAngleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0064AD30 (FUN_0064AD30, func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CThrustManipulator:SetThrustingParam(...)` Lua binder.
   */
  CScrLuaInitForm* func_CThrustManipulatorSetThrustingParam_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCThrustManipulatorSetThrustingParamName,
      &cfunc_CThrustManipulatorSetThrustingParam,
      &CScrLuaMetatableFactory<CThrustManipulator>::Instance(),
      kCThrustManipulatorClassName,
      kCThrustManipulatorSetThrustingParamHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0064AB60 (FUN_0064AB60, func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateThrustController(...)` Lua binder.
   */
  CScrLuaInitForm* func_CreateThrustController_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateThrustControllerName,
      &cfunc_CreateThrustController,
      nullptr,
      kGlobalLuaFactoryClassName,
      kCreateThrustControllerHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BD22D0 (FUN_00BD22D0, j_func_CreateAimController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAimController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAimController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAimController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22E0 (FUN_00BD22E0, register_CAimManipulatorSetFiringArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetFiringArc_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetFiringArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetFiringArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD22F0 (FUN_00BD22F0, j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetResetPoseTime_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetResetPoseTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetResetPoseTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2300 (FUN_00BD2300, register_CAimManipulatorOnTarget_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorOnTarget_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorOnTarget_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorOnTarget_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2310 (FUN_00BD2310, register_CAimManipulatorSetEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAimManipulatorSetEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2320 (FUN_00BD2320, j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2330 (FUN_00BD2330, j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2340 (FUN_00BD2340, j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24A0 (FUN_00BD24A0, j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBoneEntityManipulatorSetPivot_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBoneEntityManipulatorSetPivot_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBoneEntityManipulatorSetPivot_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD24B0 (FUN_00BD24B0, register_EntityAttachBoneToEntityBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_EntityAttachBoneToEntityBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EntityAttachBoneToEntityBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_EntityAttachBoneToEntityBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD25F0 (FUN_00BD25F0, j_func_CreateBuilderArmController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateBuilderArmController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateBuilderArmController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateBuilderArmController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2600 (FUN_00BD2600, j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetAimingArc_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2610 (FUN_00BD2610, j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorGetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2620 (FUN_00BD2620, j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CBuilderArmManipulatorSetHeadingPitch_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2A60 (FUN_00BD2A60, register_CreateFootPlantController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateFootPlantController_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateFootPlantController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateFootPlantController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C80 (FUN_00BD2C80, j_func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorSetPrecedence_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorSetPrecedence_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorSetPrecedence_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2C90 (FUN_00BD2C90, register_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CA0 (FUN_00BD2CA0, register_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IAniManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2CB0 (FUN_00BD2CB0, j_func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_IAniManipulatorDestroy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IAniManipulatorDestroy_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_IAniManipulatorDestroy_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2760 (FUN_00BD2760, j_func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateCollisionDetector_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateCollisionDetector_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateCollisionDetector_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2770 (FUN_00BD2770, j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2780 (FUN_00BD2780, j_func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorEnable_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorEnable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorEnable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2790 (FUN_00BD2790, register_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorDisable_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CCollisionManipulatorDisable_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorDisable_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD27A0 (FUN_00BD27A0, j_func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CCollisionManipulatorWatchBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CCollisionManipulatorWatchBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CCollisionManipulatorWatchBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E30 (FUN_00BD2E30, j_func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateAnimator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateAnimator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateAnimator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E40 (FUN_00BD2E40, register_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorPlayAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorPlayAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorPlayAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E50 (FUN_00BD2E50, register_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E60 (FUN_00BD2E60, j_func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetRate_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E70 (FUN_00BD2E70, register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E80 (FUN_00BD2E80, j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2E90 (FUN_00BD2E90, register_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EA0 (FUN_00BD2EA0, register_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetAnimationTime_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetAnimationTime_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetAnimationTime_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EB0 (FUN_00BD2EB0, register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorGetAnimationDuration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EC0 (FUN_00BD2EC0, register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetBoneEnabled_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2ED0 (FUN_00BD2ED0, register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetOverwriteMode_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EE0 (FUN_00BD2EE0, j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD2EF0 (FUN_00BD2EF0, register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3050 (FUN_00BD3050, j_func_CreateRotator_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateRotator_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateRotator_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateRotator_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3060 (FUN_00BD3060, register_CRotateManipulatorSetSpinDown_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpinDown_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetSpinDown_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpinDown_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3070 (FUN_00BD3070, register_CRotateManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3080 (FUN_00BD3080, j_func_CRotateManipulatorClearGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorClearGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3090 (FUN_00BD3090, j_func_CRotateManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30A0 (FUN_00BD30A0, j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetTargetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetTargetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetTargetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30B0 (FUN_00BD30B0, j_func_CRotateManipulatorSetAccel_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetAccel_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetAccel_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetAccel_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30C0 (FUN_00BD30C0, register_CRotateManipulatorClearFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorClearFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorClearFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorClearFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30D0 (FUN_00BD30D0, j_func_CRotateManipulatorSetFollowBone_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetFollowBone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorSetFollowBone_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetFollowBone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30E0 (FUN_00BD30E0, j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorGetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CRotateManipulatorGetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorGetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD30F0 (FUN_00BD30F0, register_CRotateManipulatorSetCurrentAngle_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CRotateManipulatorSetCurrentAngle_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CRotateManipulatorSetCurrentAngle_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CRotateManipulatorSetCurrentAngle_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3230 (FUN_00BD3230, j_func_CreateSlaver_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlaver_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlaver_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlaver_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3240 (FUN_00BD3240, register_CSlaveManipulatorSetMaxRate_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlaveManipulatorSetMaxRate_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlaveManipulatorSetMaxRate_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlaveManipulatorSetMaxRate_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3500 (FUN_00BD3500, j_func_CreateSlider_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateSlider_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateSlider_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateSlider_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3510 (FUN_00BD3510, register_CSlideManipulatorSetWorldUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetWorldUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetWorldUnits_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetWorldUnits_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3520 (FUN_00BD3520, register_CSlideManipulatorSetSpeed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetSpeed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetSpeed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetSpeed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3530 (FUN_00BD3530, j_func_CSlideManipulatorSetAcceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetAcceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetAcceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetAcceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3540 (FUN_00BD3540, register_CSlideManipulatorSetDeceleration_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetDeceleration_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorSetDeceleration_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetDeceleration_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3550 (FUN_00BD3550, j_func_CSlideManipulatorSetGoal_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorSetGoal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CSlideManipulatorSetGoal_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorSetGoal_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD3560 (FUN_00BD3560, register_CSlideManipulatorBeenDestroyed_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CSlideManipulatorBeenDestroyed_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CSlideManipulatorBeenDestroyed_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CSlideManipulatorBeenDestroyed_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD36A0 (FUN_00BD36A0, j_func_CreateStorageManip_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateStorageManip_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateStorageManip_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateStorageManip_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37E0 (FUN_00BD37E0, j_func_CreateThrustController_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CreateThrustController_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CreateThrustController_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CreateThrustController_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD37F0 (FUN_00BD37F0, j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CThrustManipulatorSetThrustingParam_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CThrustManipulatorSetThrustingParam_LuaFuncDef()
  {
    return ForwardManipulatorLuaThunk<&func_CThrustManipulatorSetThrustingParam_LuaFuncDef>();
  }
} // namespace moho
