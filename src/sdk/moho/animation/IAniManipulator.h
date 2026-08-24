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
    static gpg::RType* sPointerType;

    /**
     * Address: 0x0063DA40 (FUN_0063DA40, Moho::IAniManipulator::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `IAniManipulator*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

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
    static gpg::RType* sType;

    /**
     * Address: 0x006392E0 (FUN_006392E0, ??0CFootPlantManipulator@Moho@@QAE@XZ)
     *
     * What it does:
     * Builds `IAniManipulator` base lanes then initializes foot-plant weak-link
     * and bone/stance tuning lanes to zero defaults.
     */
    CFootPlantManipulator();

    /**
     * Address: 0x00639380 (FUN_00639380, ??0CFootPlantManipulator@Moho@@QAE@@Z)
     * Mangled: ??0CFootPlantManipulator@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::CFootPlantManipulator::CFootPlantManipulator(
     *   Moho::Unit *unit, Moho::CFootPlantManipulator *this,
     *   LuaPlus::LuaObject *footBone, int kneeBone, int hipBone,
     *   LuaPlus::LuaObject *straightLegs, float maxFootFall);
     *
     * What it does:
     * Constructs one foot-plant manipulator owned by `unit`'s sim/actor pair,
     * head-inserts an intrusive goal weak link into the unit's weak chain,
     * stores foot/knee/hip bone indices plus stance tuning fields, materializes
     * Lua userdata for script binding, registers each watched bone in the
     * IAniManipulator binding storage, and computes the half-leg span from the
     * actor pose's foot/hip composite-transform vertical separation.
     */
    CFootPlantManipulator(
      Unit* unit, int footBoneIndex, int kneeBoneIndex, int hipBoneIndex,
      bool straightLegs, float maxFootFall
    );

    /**
     * Address: 0x006395F0 (FUN_006395F0, Moho::CFootPlantManipulator::MoveManipulator)
     *
     * IDA signature:
     * void __thiscall Moho::CFootPlantManipulator::MoveManipulator(CFootPlantManipulator *this);
     *
     * VFTable SLOT: 1 (primary IAniManipulator view; `??_7CFootPlantManipulator@Moho@@6B@`
     * head is 0x00E21B14, this address sits at 0x00E21B18, the slot the base
     * leaves as `_purecall` at 0x00A82547).
     *
     * What it does:
     * Solves the two-segment leg chain so the watched foot bone reaches the
     * terrain (or raised-platform) height under it: samples the height field
     * beneath the foot, clamps that target by the half-leg span and the
     * per-manipulator maximum foot fall, then swings hip and knee by equal and
     * opposite arccos-approximated rolls and applies a final knee correction
     * whose sign flips when the foot is behind the hip forward axis or the
     * manipulator was built with straight legs.
     */
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
    static gpg::RType* sType;

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

    /**
     * Address: 0x00634460 (FUN_00634460, ??0CBoneEntityManipulator@Moho@@QAE@PAVEntity@1@PAVUnit@1@HHH@Z_0)
     *
     * What it does:
     * Builds one bone-attach manipulator owned by `goalUnit`'s sim/actor pair,
     * head-inserts the goal-unit and target-entity intrusive weak links,
     * materializes the Lua binding object, registers the watched unit bone,
     * seeds `mPivot` from that bone's skeleton bounds, runs an initial solve,
     * and (when `markSkipInterp`) flags the watched pose bone to skip the next
     * interpolation step.
     */
    CBoneEntityManipulator(
      Entity* targetEntity, Unit* goalUnit,
      int watchedBoneIndex, int referenceBoneIndex, bool markSkipInterp
    );

    /**
     * Address: 0x006347E0 (FUN_006347E0, Moho::CBoneEntityManipulator::MoveManipulator)
     *
     * IDA signature:
     * void __thiscall Moho::CBoneEntityManipulator::MoveManipulator(CBoneEntityManipulator *this);
     *
     * VFTable SLOT: 1 (`??_7CBoneEntityManipulator@Moho@@6B@` = 0x00E21548,
     * this address is stored at 0x00E2154C; the same slot in
     * `??_7IAniManipulator@Moho@@6B@` (0x00E213A0) holds `_purecall`
     * 0x00A82547, which is the slot `ManipulatorUpdate` declares). IDA's
     * `MoveManipulator` label is a family-wide proximity artifact - every
     * sibling manipulator carries it on the body that occupies this same slot.
     * The constructor additionally calls it non-virtually at 0x006345D1 for
     * the initial solve.
     *
     * What it does:
     * Drives the watched pose bone to track the target entity bone. With a live
     * target: sets the bone local transform to the target bone's world pose,
     * offset by the pivot rotated into that bone's frame, and accumulates the
     * running max displacement from the goal unit position. With no target:
     * parks the bone at (0, -10000, 0) with identity orientation and resets the
     * pose max-offset to -inf.
     */
    bool ManipulatorUpdate() override;

    WeakPtr<Unit> mGoalUnit;           // +0x80
    WeakPtr<Entity> mTargetEntity;     // +0x88
    std::int32_t mReferenceBoneIndex;  // +0x90
    Wm3::Vector3f mPivot;              // +0x94

  private:
    /**
     * Address: 0x00634700 (FUN_00634700)
     *
     * What it does:
     * Seeds `mPivot` with the center of the watched bone's skeleton-space
     * bounding box (per-component midpoint of the SAniSkelBone min/max bounds).
     */
    void InitPivotFromBoneBounds();
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

  /**
   * Owns reflected metadata for `CFootPlantManipulator`.
   */
  class CFootPlantManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006390C0 (FUN_006390C0, ctor lane)
     *
     * What it does:
     * Preregisters the `CFootPlantManipulator` RTTI descriptor during startup.
     * In the binary this constructor body is inlined into the `.CRT$XCL`
     * provider wrapper (`register_CFootPlantManipulatorTypeInfo`, 0x00BD2A00)
     * that constructs the file-scope singleton, rather than being emitted as
     * a standalone `__thiscall` symbol.
     */
    CFootPlantManipulatorTypeInfo();

    /**
     * Address: 0x00639170 (FUN_00639170, Moho::CFootPlantManipulatorTypeInfo::dtr)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes and
     * restores the `gpg::RObject` vftable. Defaulted in source: the
     * compiler-generated `~RType()` reproduces this behavior, matching every
     * other manipulator TypeInfo dtor in this family.
     */
    ~CFootPlantManipulatorTypeInfo() override = default;

    /**
     * Address: 0x00639160 (FUN_00639160, Moho::CFootPlantManipulatorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00639120 (FUN_00639120, Moho::CFootPlantManipulatorTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CFootPlantManipulatorTypeInfo) == 0x64, "CFootPlantManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD2A00 (FUN_00BD2A00, register_CFootPlantManipulatorTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CFootPlantManipulatorTypeInfo` singleton
   * and installs process-exit cleanup.
   */
  void register_CFootPlantManipulatorTypeInfo();

  /**
   * Owns reflected metadata for `CBoneEntityManipulator`.
   */
  class CBoneEntityManipulatorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00634A60 (FUN_00634A60, ctor lane)
     *
     * What it does:
     * Preregisters the `CBoneEntityManipulator` RTTI descriptor during
     * startup. In the binary this constructor body is inlined into the
     * `.CRT$XCL` provider wrapper (`register_CBoneEntityManipulatorTypeInfo`,
     * 0x00BD2440) that constructs the file-scope singleton, rather than being
     * emitted as a standalone `__thiscall` symbol.
     */
    CBoneEntityManipulatorTypeInfo();

    /**
     * Address: 0x00634B10 (FUN_00634B10, Moho::CBoneEntityManipulatorTypeInfo::dtr)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes and
     * restores the `gpg::RObject` vftable. Defaulted in source: the
     * compiler-generated `~RType()` reproduces this behavior, matching every
     * other manipulator TypeInfo dtor in this family.
     */
    ~CBoneEntityManipulatorTypeInfo() override = default;

    /**
     * Address: 0x00634B00 (FUN_00634B00, Moho::CBoneEntityManipulatorTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00634AC0 (FUN_00634AC0, Moho::CBoneEntityManipulatorTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CBoneEntityManipulatorTypeInfo) == 0x64, "CBoneEntityManipulatorTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD2440 (FUN_00BD2440, register_CBoneEntityManipulatorTypeInfo)
   *
   * What it does:
   * Constructs the startup-owned `CBoneEntityManipulatorTypeInfo` singleton
   * and installs process-exit cleanup.
   */
  void register_CBoneEntityManipulatorTypeInfo();

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
