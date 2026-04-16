#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"

struct lua_State;

namespace moho
{
  class CAniActor;
  class Entity;
  class Sim;
  class Unit;

  struct SAniManipBinding
  {
    std::int32_t mBoneIndex; // +0x00
    std::int32_t mFlags;     // +0x04

    static gpg::RType* sType;
  };

  static_assert(offsetof(SAniManipBinding, mBoneIndex) == 0x00, "SAniManipBinding::mBoneIndex offset must be 0x00");
  static_assert(offsetof(SAniManipBinding, mFlags) == 0x04, "SAniManipBinding::mFlags offset must be 0x04");
  static_assert(sizeof(SAniManipBinding) == 0x08, "SAniManipBinding size must be 0x08");

  struct SAniManipBindingStorage
  {
    SAniManipBinding* mBegin;           // +0x00
    SAniManipBinding* mEnd;             // +0x04
    SAniManipBinding* mCapacityEnd;     // +0x08
    SAniManipBinding* mInlineStorage;   // +0x0C
    SAniManipBinding mInlineEntries[2]; // +0x10
  };

  static_assert(
    offsetof(SAniManipBindingStorage, mBegin) == 0x00, "SAniManipBindingStorage::mBegin offset must be 0x00"
  );
  static_assert(offsetof(SAniManipBindingStorage, mEnd) == 0x04, "SAniManipBindingStorage::mEnd offset must be 0x04");
  static_assert(
    offsetof(SAniManipBindingStorage, mCapacityEnd) == 0x08, "SAniManipBindingStorage::mCapacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(SAniManipBindingStorage, mInlineStorage) == 0x0C,
    "SAniManipBindingStorage::mInlineStorage offset must be 0x0C"
  );
  static_assert(
    offsetof(SAniManipBindingStorage, mInlineEntries) == 0x10,
    "SAniManipBindingStorage::mInlineEntries offset must be 0x10"
  );
  static_assert(sizeof(SAniManipBindingStorage) == 0x20, "SAniManipBindingStorage size must be 0x20");

  class IAniManipulator : public CScriptEvent
  {
  public:
    /**
     * Address: 0x0063B5D0 (FUN_0063B5D0, ??0IAniManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds script-event base state and initializes intrusive ordering links
     * plus inline watched-bone storage sentinels.
     */
    IAniManipulator();

    /**
     * Address: 0x0063B640 (FUN_0063B640, ??0IAniManipulator@Moho@@QAE@PAVSim@1@PAVCAniActor@1@H@Z)
     *
     * What it does:
     * Same as default construction but binds initial owning sim/actor pointers,
     * marks manipulator enabled, and sets precedence.
     */
    IAniManipulator(Sim* sim, CAniActor* ownerActor, int precedence);

    /**
     * Address: 0x00634330 (scalar deleting thunk)
     * Address: 0x0062FD20 (FUN_0062FD20, scalar deleting body)
     * Address: 0x0062FC70 (FUN_0062FC70, ??1IAniManipulator@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0 (primary CTaskEvent/CScriptEvent view)
     */
    ~IAniManipulator() override;

    /**
     * Address: 0x0062FC30 (FUN_0062FC30, ?GetClass@IAniManipulator@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0062FC50 (FUN_0062FC50, ?GetDerivedObjectRef@IAniManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00A82547 (_purecall in IAniManipulator vtable slot 1)
     *
     * VFTable SLOT: 1 (primary CTaskEvent/CScriptEvent view)
     */
    virtual bool ManipulatorUpdate();

    /**
     * Address: 0x0063B6D0 (FUN_0063B6D0, ?AddWatchBone@IAniManipulator@Moho@@QAEHH@Z)
     *
     * What it does:
     * Appends one `{boneIndex, 0x8000}` watched-bone binding and returns its
     * insertion index.
     */
    int AddWatchBone(int boneIndex);

  protected:
    void ResetWatchBoneStorage();

  public:
    static gpg::RType* sType;

    TDatListItem<IAniManipulator, void> mActorOrderLink; // +0x44
    bool mEnabled;                                       // +0x4C
    std::uint8_t mEnabledPad[3]{};                       // +0x4D
    CAniActor* mOwnerActor;                              // +0x50
    Sim* mOwnerSim;                                      // +0x54
    std::int32_t mPrecedence;                            // +0x58
    std::uint32_t mUnknown5C;                            // +0x5C
    SAniManipBindingStorage mWatchBones;                 // +0x60
  };

  class CFootPlantManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x006392E0 (FUN_006392E0, ??0CFootPlantManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds `IAniManipulator` base lanes then initializes foot-plant weak-link
     * and bone/stance tuning lanes to zero defaults.
     */
    CFootPlantManipulator();

    bool ManipulatorUpdate() override;

    WeakPtr<Unit> mGoalUnit;         // +0x80
    std::int32_t mFootBoneIndex;     // +0x88
    std::int32_t mKneeBoneIndex;     // +0x8C
    std::int32_t mHipBoneIndex;      // +0x90
    bool mStraightLegs;              // +0x94
    std::uint8_t mPad95_97[0x3]{};   // +0x95
    float mMaxFootFall;              // +0x98
    float mHalfLegSpan;              // +0x9C
  };
  static_assert(offsetof(CFootPlantManipulator, mGoalUnit) == 0x80, "CFootPlantManipulator::mGoalUnit offset must be 0x80");
  static_assert(
    offsetof(CFootPlantManipulator, mFootBoneIndex) == 0x88,
    "CFootPlantManipulator::mFootBoneIndex offset must be 0x88"
  );
  static_assert(
    offsetof(CFootPlantManipulator, mStraightLegs) == 0x94,
    "CFootPlantManipulator::mStraightLegs offset must be 0x94"
  );
  static_assert(
    offsetof(CFootPlantManipulator, mMaxFootFall) == 0x98,
    "CFootPlantManipulator::mMaxFootFall offset must be 0x98"
  );
  static_assert(sizeof(CFootPlantManipulator) == 0xA0, "CFootPlantManipulator size must be 0xA0");

  class CBoneEntityManipulator : public IAniManipulator
  {
  public:
    /**
     * Address: 0x00634400 (FUN_00634400, ??0CBoneEntityManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds `IAniManipulator` base lanes then clears goal/target weak links,
     * resets reference-bone index, and zeroes pivot coordinates.
     */
    CBoneEntityManipulator();

    /**
     * Address: 0x00634630 (FUN_00634630, ??1CBoneEntityManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks both goal/target weak-link lanes from owner chains, clears link
     * state, then forwards to `IAniManipulator` teardown.
     */
    ~CBoneEntityManipulator() override;

    bool ManipulatorUpdate() override;

    WeakPtr<Unit> mGoalUnit;           // +0x80
    WeakPtr<Entity> mTargetEntity;     // +0x88
    std::int32_t mReferenceBoneIndex;  // +0x90
    Wm3::Vector3f mPivot;              // +0x94
  };
  static_assert(
    offsetof(CBoneEntityManipulator, mGoalUnit) == 0x80,
    "CBoneEntityManipulator::mGoalUnit offset must be 0x80"
  );
  static_assert(
    offsetof(CBoneEntityManipulator, mTargetEntity) == 0x88,
    "CBoneEntityManipulator::mTargetEntity offset must be 0x88"
  );
  static_assert(
    offsetof(CBoneEntityManipulator, mReferenceBoneIndex) == 0x90,
    "CBoneEntityManipulator::mReferenceBoneIndex offset must be 0x90"
  );
  static_assert(
    offsetof(CBoneEntityManipulator, mPivot) == 0x94,
    "CBoneEntityManipulator::mPivot offset must be 0x94"
  );
  static_assert(sizeof(CBoneEntityManipulator) == 0xA0, "CBoneEntityManipulator size must be 0xA0");

  using IAniManipulatorSetPrecedence_LuaFuncDef = ::moho::CScrLuaBinder;
  using IAniManipulatorEnable_LuaFuncDef = ::moho::CScrLuaBinder;
  using IAniManipulatorDisable_LuaFuncDef = ::moho::CScrLuaBinder;
  using IAniManipulatorDestroy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x0063BAE0 (FUN_0063BAE0, func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:SetPrecedence(integer)` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorSetPrecedence_LuaFuncDef();

  /**
   * Address: 0x0063BC80 (FUN_0063BC80, func_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorEnable_LuaFuncDef();

  /**
   * Address: 0x0063BDB0 (FUN_0063BDB0, func_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDisable_LuaFuncDef();

  /**
   * Address: 0x0063BEE0 (FUN_0063BEE0, func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDestroy_LuaFuncDef();

  /**
   * Address: 0x0063BAC0 (FUN_0063BAC0, cfunc_IAniManipulatorSetPrecedence)
   *
   * lua_State *
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorSetPrecedenceL`.
   */
  int cfunc_IAniManipulatorSetPrecedence(lua_State* luaContext);

  /**
   * Address: 0x0063BC60 (FUN_0063BC60, cfunc_IAniManipulatorEnable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorEnableL`.
   */
  int cfunc_IAniManipulatorEnable(lua_State* luaContext);

  /**
   * Address: 0x0063BD90 (FUN_0063BD90, cfunc_IAniManipulatorDisable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDisableL`.
   */
  int cfunc_IAniManipulatorDisable(lua_State* luaContext);

  /**
   * Address: 0x0063BEC0 (FUN_0063BEC0, cfunc_IAniManipulatorDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDestroyL`.
   */
  int cfunc_IAniManipulatorDestroy(lua_State* luaContext);

  /**
   * Address: 0x0063BB40 (FUN_0063BB40, cfunc_IAniManipulatorSetPrecedenceL)
   *
   * LuaPlus::LuaState *
   *
   * What it does:
   * Reads `(manipulator, precedence)`, reorders the manipulator in owner-actor
   * precedence order, and returns the manipulator Lua object.
   */
  int cfunc_IAniManipulatorSetPrecedenceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0063BCE0 (FUN_0063BCE0, cfunc_IAniManipulatorEnableL)
   *
   * What it does:
   * Reads `(manipulator)`, marks it enabled, and returns no Lua values.
   */
  int cfunc_IAniManipulatorEnableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0063BE10 (FUN_0063BE10, cfunc_IAniManipulatorDisableL)
   *
   * What it does:
   * Reads `(manipulator)`, marks it disabled, and returns no Lua values.
   */
  int cfunc_IAniManipulatorDisableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0063BF40 (FUN_0063BF40, cfunc_IAniManipulatorDestroyL)
   *
   * What it does:
   * Reads an optional manipulator object and destroys it when present.
   */
  int cfunc_IAniManipulatorDestroyL(LuaPlus::LuaState* state);

  class IAniManipulatorSerializer
  {
  public:
    /**
     * Address: 0x0063BA10 (FUN_0063BA10, Moho::IAniManipulatorSerializer::Deserialize)
     *
     * What it does:
     * Deserializes IAniManipulator base serialization fields
     * (`CScriptEvent`, enabled flag, owner pointers, precedence, watch-bones).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0063BA20 (FUN_0063BA20, Moho::IAniManipulatorSerializer::Serialize)
     *
     * What it does:
     * Serializes IAniManipulator base serialization fields
     * (`CScriptEvent`, enabled flag, owner pointers, precedence, watch-bones).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0063C540 (FUN_0063C540, sub_63C540)
     * Slot: 0
     *
     * What it does:
     * Installs IAniManipulator load/save callbacks into RTTI serialization hooks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class IAniManipulatorTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0063B520 (FUN_0063B520, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~IAniManipulatorTypeInfo() override;

    /**
     * Address: 0x0063B510 (FUN_0063B510, ?GetName@IAniManipulatorTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0063B4E0 (FUN_0063B4E0, ?Init@IAniManipulatorTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `IAniManipulator` (`sizeof = 0x80`) and
     * registers `CScriptEvent` as a base type.
     */
    void Init() override;
  };

  static_assert(
    offsetof(IAniManipulator, mActorOrderLink) == 0x44, "IAniManipulator::mActorOrderLink offset must be 0x44"
  );
  static_assert(offsetof(IAniManipulator, mEnabled) == 0x4C, "IAniManipulator::mEnabled offset must be 0x4C");
  static_assert(offsetof(IAniManipulator, mOwnerActor) == 0x50, "IAniManipulator::mOwnerActor offset must be 0x50");
  static_assert(offsetof(IAniManipulator, mOwnerSim) == 0x54, "IAniManipulator::mOwnerSim offset must be 0x54");
  static_assert(offsetof(IAniManipulator, mPrecedence) == 0x58, "IAniManipulator::mPrecedence offset must be 0x58");
  static_assert(offsetof(IAniManipulator, mUnknown5C) == 0x5C, "IAniManipulator::mUnknown5C offset must be 0x5C");
  static_assert(offsetof(IAniManipulator, mWatchBones) == 0x60, "IAniManipulator::mWatchBones offset must be 0x60");
  static_assert(sizeof(IAniManipulator) == 0x80, "IAniManipulator size must be 0x80");
  static_assert(sizeof(IAniManipulatorSerializer) == 0x14, "IAniManipulatorSerializer size must be 0x14");
  static_assert(sizeof(IAniManipulatorTypeInfo) == 0x64, "IAniManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x0063B480 (FUN_0063B480, sub_63B480)
   *
   * What it does:
   * Constructs/preregisters startup RTTI storage for IAniManipulator.
   */
  [[nodiscard]] gpg::RType* register_IAniManipulatorTypeInfo_00();

  /**
   * Address: 0x00BFADC0 (FUN_00BFADC0, sub_BFADC0)
   *
   * What it does:
   * Releases startup-owned IAniManipulator RTTI storage.
   */
  void cleanup_IAniManipulatorTypeInfo();

  /**
   * Address: 0x00BD2C20 (FUN_00BD2C20, sub_BD2C20)
   *
   * What it does:
   * Registers IAniManipulator RTTI startup ownership and installs exit cleanup.
   */
  int register_IAniManipulatorTypeInfo_AtExit();

  /**
   * Address: 0x00BFAE20 (FUN_00BFAE20, Moho::IAniManipulatorSerializer::~IAniManipulatorSerializer)
   *
   * What it does:
   * Unlinks IAniManipulator serializer helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_IAniManipulatorSerializer();

  /**
   * Address: 0x00BD2C40 (FUN_00BD2C40, register_IAniManipulatorSerializer)
   *
   * What it does:
   * Initializes IAniManipulator serializer helper callbacks and installs exit cleanup.
   */
  void register_IAniManipulatorSerializer();
} // namespace moho
