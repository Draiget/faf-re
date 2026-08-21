// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/UserCommandQueue.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/math/Vector3f.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/WeakEntitySet.h"
#include "platform/Platform.h"
#include "Wm3AxisAlignedBox3.h"

#include <cstddef>
#include <cstdint>
#include "boost/shared_ptr.h"

struct lua_State;

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  struct SSTIEntityVariableData;
  enum class EUnitCommandType : std::int32_t;
  class UserEntity;
  struct UserCommandIssueHelper;
  struct UserCommandQueue;
  // Opaque cross-TU handle to the runtime user command-issue helper / command-graph
  // anchor-history object (same binary object surfaced under two names). Used only as
  // an incomplete pointer by the IssueDockCommand worker.
  struct QueuedUserCommandRecord;
  struct UserCommand;
  class UserUnitWeapon;
  class IUnit;
  class CWldSession;
  struct REntityBlueprint;
  struct RUnitBlueprint;
  struct SCoordsVec2;
  struct SFootprint;
  struct SOccupationResult;
  struct SOCellPos;
} // namespace moho

namespace moho
{
  /**
   * VFTABLE: 0x00E4D93C
   * COL:  0x00E9F48C
   */
  class MOHO_EMPTY_BASES UserUnit
    : public UserEntity
    , public IUnit
    , public CScriptObject
  {
  public:
    /**
     * Address: 0x008BF9B0 (FUN_008BF9B0, Moho::UserUnit::~UserUnit)
     * Deleting-destructor thunk: 0x008BF990 (FUN_008BF990)
     * Slot: 0
     *
     * What it does:
     * Unfiles the unit from every registry that can still name it - the army's
     * quick-select avatar run, the idle engineer/factory sets, the session
     * selection - hands its selection over to the recorded inheritor, and drops
     * both command queues.
     */
    ~UserUnit() override;

    /**
     * Address: 0x008C0A30 (FUN_008C0A30)
     * Slot: 1
     * Demangled: moho::UserUnit::Tick
     *
     * What it does:
     * Per-beat update hook for UI unit state.
     */
    void Tick(std::int32_t seqNo) override;

    /**
     * Address: 0x008BF120 (FUN_008BF120)
     * Slot: 2
     *
     * What it does:
     * Returns this object as the const UserUnit identity view.
     */
    [[nodiscard]] const UserUnit* IsUserUnit() const override;

    /**
     * Address: 0x008BF110 (FUN_008BF110)
     * Slot: 3
     *
     * What it does:
     * Returns this object as the mutable UserUnit identity view.
     */
    [[nodiscard]] UserUnit* IsUserUnit() override;

    /**
     * Address: 0x008BF170 (FUN_008BF170)
     * Slot: 4
     *
     * What it does:
     * Reads uniform render scale from the unit blueprint through the embedded IUnit bridge.
     */
    [[nodiscard]] float GetUniformScale() const override;

    /**
     * Address: 0x008BF150 (FUN_008BF150)
     * Slot: 5
     *
     * What it does:
     * Returns this unit's primary command queue (const slot).
     */
    [[nodiscard]] const UserCommandQueue* GetCommandQueue() const override;

    /**
     * Address: 0x008BF130 (FUN_008BF130)
     * Slot: 6
     *
     * What it does:
     * Returns this unit's primary command queue (mutable slot).
     */
    [[nodiscard]] UserCommandQueue* GetCommandQueue() override;

    /**
     * Address: 0x008BF160 (FUN_008BF160)
     * Slot: 7
     *
     * What it does:
     * Returns this unit's factory command queue (const slot).
     */
    [[nodiscard]] const UserCommandQueue* GetFactoryCommandQueue() const override;

    /**
     * Address: 0x008BF140 (FUN_008BF140)
     * Slot: 8
     *
     * What it does:
     * Returns this unit's factory command queue (mutable slot).
     */
    [[nodiscard]] UserCommandQueue* GetFactoryCommandQueue() override;

    /**
     * Address: 0x008B8EB0 (FUN_008B8EB0)
     * Slot: 9
     * Demangled: public: virtual void __thiscall moho::UserEntity::UpdateEntityData(struct moho::SSTIEntityVariableData
     * const near &)
     */
    void UpdateEntityData(const SSTIEntityVariableData& variableData) override;

    /**
     * Address: 0x008C09B0 (FUN_008C09B0)
     * Slot: 10
     * Demangled: moho::UserUnit::UpdateVisibility
     */
    void UpdateVisibility() override;

    /**
     * Address: 0x008B8530 (FUN_008B8530)
     * Slot: 11
     * Demangled: public: virtual bool __thiscall moho::UserEntity::RequiresUIRefresh(void)const
     *
     * What it does:
     * Returns replicated UI-dirty state from the UserEntity variable-data block.
     */
    [[nodiscard]] bool RequiresUIRefresh() const override;

    /**
     * Address: 0x008C0500 (FUN_008C0500)
     * Slot: 12
     * Demangled: moho::UserUnit::IsSelectable
     *
     * What it does:
     * Returns whether this unit should be selectable in user UI state.
     */
    [[nodiscard]] bool IsSelectable() const override;

    /**
     * Address: 0x008BEFB0 (FUN_008BEFB0)
     * Slot: 13
     * Demangled: moho::UserUnit::IsBeingBuilt
     *
     * What it does:
     * Returns replicated "being built" state from the UserEntity variable-data block.
     */
    [[nodiscard]] bool IsBeingBuilt() const override;

    /**
     * Address: 0x008C1350 (FUN_008C1350)
     * Slot: 14
     * Demangled: moho::UserUnit::NotifyFocusArmyUnitDamaged
     *
     * What it does:
     * Imports the UI game-main module and calls
     * `OnFocusArmyUnitDamaged(thisLuaObject)`.
     */
    void NotifyFocusArmyUnitDamaged() override;

    /**
     * Address: 0x008C00E0 (FUN_008C00E0)
     * Slot: 15
     * Demangled: moho::UserUnit::CreateMeshInstance
     *
     * What it does:
     * Creates one unit mesh-instance with team-color setup and pose reuse from
     * unit variable-data shared-pose lanes.
     */
    void CreateMeshInstance(bool forUnitPose) override;

    /**
     * Address: 0x008C04D0 (FUN_008C04D0)
     * Slot: 16
     * Demangled: protected: virtual void __thiscall moho::UserEntity::DestroyMeshInstance(void)
     */
    void DestroyMeshInstance() override;

    // ---- IUnit sub-object ----
    //
    // Slot order is the one the binary's secondary vtable
    // `??_7UserUnit@Moho@@6BIUnit@Moho@@@` (0x00E4D9AC) lists, which matches
    // `IUnit`'s declaration order exactly. Slots 0/1 (`IsUnit`) keep `IUnit`'s
    // own bodies - they are not overridden here - and slots 2/3/13
    // (`IsUserUnit` x2, `IsBeingBuilt`) are adjustor thunks onto the overrides
    // already declared above for the primary vtable.

    /** Address: 0x008BEF00 - IUnit slot 4. Returns `mParams.mEntityId`. */
    [[nodiscard]] EntId GetEntityId() const override;

    /** Address: 0x008BEF10 - IUnit slot 5. Returns the live transform's translation. */
    [[nodiscard]] const Wm3::Vec3f& GetPosition() const override;

    /** Address: 0x008BEF20 - IUnit slot 6. Returns the live replicated transform. */
    [[nodiscard]] const VTransform& GetTransform() const override;

    /** Address: 0x008BEF30 - IUnit slot 7. Returns `mParams.mBlueprint` as a unit blueprint. */
    [[nodiscard]] const RUnitBlueprint* GetBlueprint() const override;

    /** Address: 0x008BEF60 - IUnit slot 8. Copies out the script object's Lua handle. */
    [[nodiscard]] LuaPlus::LuaObject GetLuaObject() override;

    /** Address: 0x008BEF80 - IUnit slot 9. The UI never scales transport load; always 1. */
    [[nodiscard]] float CalcTransportLoadFactor() const override;

    /** Address: 0x008BEF90 - IUnit slot 10. Returns the replicated death flag. */
    [[nodiscard]] bool IsDead() const override;

    /**
     * Address: 0x008BEFA0 - IUnit slot 11.
     *
     * Always false: destruction is queued on the sim side, and the UI copy has
     * no queue of its own to report.
     */
    [[nodiscard]] bool DestroyQueued() const override;

    /**
     * Address: 0x008C04E0 - IUnit slot 12.
     *
     * True for every motion type between `Land` and `AmphibiousFloating`; only
     * `None` and `Special` are immobile.
     */
    [[nodiscard]] bool IsMobile() const override;

    /**
     * Address: 0x008BEFC0 - IUnit slot 14.
     *
     * Always false: the UI unit has no navigator, so nothing can report it idle.
     */
    [[nodiscard]] bool IsNavigatorIdle() const override;

    /** Address: 0x008BF020 - IUnit slot 15. Tests one bit of the replicated state mask. */
    [[nodiscard]] bool IsUnitState(EUnitState state) const override;

    /** Address: 0x008BEF50 - IUnit slot 16. */
    [[nodiscard]] UnitAttributes& GetAttributes() override;

    /** Address: 0x008BEF40 - IUnit slot 17. */
    [[nodiscard]] const UnitAttributes& GetAttributes() const override;

    /** Address: 0x008BF0C0 - IUnit slot 18. Named string stat under this unit's stats root. */
    [[nodiscard]] StatItem* GetStat(gpg::StrArg statPath, const std::string& defaultValue) override;

    /** Address: 0x008BF0B0 - IUnit slot 19. Named float stat under this unit's stats root. */
    [[nodiscard]] StatItem* GetStat(gpg::StrArg statPath, const float& defaultValue) override;

    /** Address: 0x008BF0A0 - IUnit slot 20. Named stat, created when absent. */
    [[nodiscard]] StatItem* GetStat(gpg::StrArg statPath, const int& defaultValue) override;

    /** Address: 0x008BF080 - IUnit slot 21. Named stat, null when absent. */
    [[nodiscard]] StatItem* GetStat(gpg::StrArg statPath) override;

    // ---- CScriptObject sub-object ----
    // `??_7UserUnit@Moho@@6BCScriptObject@Moho@@@` (0x00E4DA08).

    /** Address: 0x008BEEC0 - CScriptObject slot 0. */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /** Address: 0x008BEEE0 - CScriptObject slot 1. */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef() override;

    /// Reflected type handle, cached on first use at 0x010C77AC.
    static gpg::RType* sType;

    /**
     * Address: 0x008BFC50 (FUN_008BFC50)
     * Slot: 17
     * Demangled: moho::UserUnit::FindWeaponBy
     *
     * What it does:
     * Aggregates min/max ranges across weapon runtime entries that match
     * the requested range-category filter (`6` means any category).
     */
    virtual bool FindWeaponBy(std::int32_t rangeCategoryFilter, float* outMinRange, float* outMaxRange) const;

    /**
     * Address: 0x008BFD70 (FUN_008BFD70)
     * Slot: 18
     * Demangled: moho::UserUnit::GetWaterIntel
     *
     * What it does:
     * Returns active intel ranges (`omni`, `radar`, `sonar`) unless Intel
     * toggle state currently disables this block.
     *
     * Naming note:
     * Emit labels this slot as `GetWaterIntel`, but binary behavior and
     * patch-side callsites use it as a general intel-range query.
     */
    virtual bool GetIntelRanges(float* outOmniRange, float* outRadarRange, float* outSonarRange) const;

    /**
     * Address: 0x008BFE50 (FUN_008BFE50)
     * Slot: 19
     * Demangled: moho::UserUnit::GetMaxCounterIntel
     *
     * What it does:
     * Computes the largest active counter-intel radius from replicated
     * intel ranges and blueprint jam/spoof maxima.
     */
    virtual bool GetMaxCounterIntel(float* outMaxCounterIntelRange) const;

    /**
     * Address: 0x008BEFD0 (FUN_008BEFD0)
     * Slot: 20
     * Demangled: moho::UserUnit::GetAutoMode
     *
     * What it does:
     * Returns UI mirror of auto-mode state.
     */
    virtual bool GetAutoMode() const;

    /**
     * Address: 0x008BEFE0 (FUN_008BEFE0)
     * Slot: 21
     * Demangled: moho::UserUnit::IsAutoSurfaceMode
     *
     * What it does:
     * Returns UI mirror of auto-surface mode state.
     */
    virtual bool IsAutoSurfaceMode() const;

    /**
     * Address: 0x008BEFF0 (FUN_008BEFF0)
     * Slot: 22
     * Demangled: moho::UserUnit::Func1
     *
     * What it does:
     * Returns UI mirror of repeat-queue state.
     */
    virtual bool Func1() const;

    /**
     * Address: 0x008BF000 (FUN_008BF000)
     * Slot: 23
     * Demangled: moho::UserUnit::IsOverchargePaused
     *
     * What it does:
     * Returns whether overcharge is currently paused in UI state.
     */
    virtual bool IsOverchargePaused() const;

    /**
     * Address: 0x008BF010 (FUN_008BF010)
     * Slot: 24
     * Demangled: moho::UserUnit::GetCustomName
     *
     * What it does:
     * Returns the in-object custom-name storage anchor at offset +0x1DC.
     */
    virtual char* GetCustomName();

    /**
     * Address: 0x008BF060 (FUN_008BF060)
     * Slot: 25
     * Demangled: moho::UserUnit::GetFuel
     *
     * What it does:
     * Returns UI fuel ratio.
     */
    virtual float GetFuel() const;

    /**
     * Address: 0x008BF070 (FUN_008BF070)
     * Slot: 26
     * Demangled: moho::UserUnit::GetShield
     *
     * What it does:
     * Returns UI shield ratio.
     */
    virtual float GetShield() const;

    /**
     * Address: 0x008C0D30 (FUN_008C0D30, Moho::UserUnit::CanAttackTarget)
     *
     * What it does:
     * Evaluates whether this unit can attack one optional target entity,
     * including layer/category filters and optional range checks.
     */
    [[nodiscard]] bool CanAttackTarget(const UserEntity* targetEntity, bool rangeCheck) const;

    /**
     * Address: 0x00852950 (FUN_00852950, Moho::UserUnit::GetSkirt)
     *
     * What it does:
     * Samples this unit's current world XZ position and writes the resolved
     * blueprint skirt rectangle into `outSkirtRect`.
     */
    [[nodiscard]] gpg::Rect2f* GetSkirt(gpg::Rect2f* outSkirtRect) const;

    /**
     * Address: 0x0083EEC0 (FUN_0083EEC0, moho::UserUnit::DoOnDetectAdjacencyBonusFor)
     *
     * What it does:
     * Invokes `/lua/ui/game/gamemain.lua:OnDetectAdjacencyBonus(unitObject, blueprintObject)`
     * and returns the callback boolean result.
     */
    [[nodiscard]] bool DoOnDetectAdjacencyBonusFor(const RUnitBlueprint* blueprint);

    /**
     * Address: 0x00893080 (FUN_00893080, Moho::UserUnit::AddSelectionSet)
     *
     * What it does:
     * Inserts one selection-set name into this unit's persisted selection-set
     * container.
     */
    void AddSelectionSet(const char* selectionSetName);

    /**
     * Address: 0x008BFF30 (FUN_008BFF30, Moho::UserUnit::AddToSelectionSet)
     *
     * IDA signature:
     * void __stdcall Moho::UserUnit::AddToSelectionSet(Moho::UserUnit *a1, Moho::UserUnit *a2);
     *
     * What it does:
     * Copies every selection-set name owned by `source` onto `target`, calling
     * `/lua/ui/game/selection.lua:AddUnitToSelectionSet(name, unit)` for each so
     * the UI-side set membership follows the engine-side one.
     */
    static void AddToSelectionSet(UserUnit* target, UserUnit* source);
    /**
     * Address: 0x008BF420 (FUN_008BF420, ??0UserUnit@Moho@@QAE@@Z)
     * Mangled: ??0UserUnit@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::UserUnit *__thiscall Moho::UserUnit::UserUnit(
     *   Moho::CWldSession *session, Moho::UserUnit *this, Moho::SCreateUnitParams *params);
     *
     * What it does:
     * Builds one client-side unit from a sim create packet: runs the UserEntity,
     * IUnit and CScriptObject subobjects, copies the constant data, allocates the
     * primary command manager (plus a second one for factories), and files the
     * unit either into its army's quick-select avatar run or, failing that, into
     * the engineer classification.
     */
    UserUnit(CWldSession* session, const SCreateUnitParams& params);

    UserUnit(const UserUnit&) = delete;
    UserUnit& operator=(const UserUnit&) = delete;

    /**
     * Address: 0x008C0750 (FUN_008C0750, Moho::UserUnit::UpdateUnitData)
     *
     * IDA signature:
     * void __thiscall Moho::UserUnit::UpdateUnitData(
     *   Moho::UserUnit *this, Moho::SSTIUnitVariableData *a2, int *result);
     *
     * What it does:
     * Applies one replicated variable-data payload from a sync beat: assigns the
     * payload, records the sync mask, re-seats both shared poses, re-resolves the
     * creator weak reference (inheriting the creator's selection sets when a
     * factory built this unit), and refreshes the command managers on a refresh
     * flag.
     */
    void UpdateUnitData(const SSTIUnitVariableData& payload, std::uint32_t intelStateFlags);

    /**
     * Address: 0x008BF190 (FUN_008BF190, Moho::UserUnit::RemoveSelectionSet)
     *
     * What it does:
     * Removes one selection-set name from this unit's persisted
     * selection-set container.
     */
    void RemoveSelectionSet(const char* selectionSetName);

    /**
     * Address: 0x008BF220 (FUN_008BF220, Moho::UserUnit::HasSelectionSet)
     *
     * What it does:
     * Returns whether this unit currently stores one named selection-set key.
     */
    bool HasSelectionSet(const char* selectionSetName) const;

    [[nodiscard]] bool IsRepeatQueueEnabled() const;

  public:
    // The three RTTI base records are real base classes: `UserEntity` is the
    // primary at +0x00 (0x148 bytes), `IUnit` the sub-object at +0x148
    // (0x08 bytes) and `CScriptObject` the one at +0x150 (0x34 bytes). The
    // constructor (FUN_008BF420) walks them in exactly that order and the
    // class-hierarchy descriptor records the same two secondary offsets
    // (0x148 / 0x150), so the members below start where it copies
    // `SCreateUnitParams::mConstDat`.

    /// The create packet's constant data, copied wholesale by the constructor
    /// at 0x008BF4B4..0x008BF4E1. Same 0x10-byte layout the sim publishes.
    SCreateUnitConstantData mUnitConstDat;               // 0x0184
    /// Zeroed by the constructor at 0x008BF590, just before the replicated
    /// variable-data payload is constructed.
    std::uint8_t mReserved0194{}; // 0x0194
    std::uint8_t pad_0195_0198[0x0198 - 0x0195]{};
    /// The replicated per-beat payload the sim publishes for this unit.
    /// `CWldSession::DoBeat` hands one of these to `UserUnit::UpdateUnitData`,
    /// which assigns it over this member, so every live-state field the UI
    /// reads about a unit lives inside it.
    ///
    /// This region used to be flattened into ad-hoc fields and padding here,
    /// which restated the sim-side layout a second time and got three names
    /// wrong: +0x1A2 is `mIsBusy` (not a selectable override), +0x3A8 is the
    /// low byte of `mScriptbits`, and +0x290/+0x294 are the weapon-info
    /// fastvector's begin/end. The bytes are unchanged.
    SSTIUnitVariableData mUnitVarDat; // 0x0198

    /// `mUnitVarDat.mCreator` resolved to a live entity and held weakly;
    /// `UpdateUnitData` re-points it whenever the replicated id changes.
    /// `mUnitVarDat.mCreator` resolved to a live entity and held weakly;
    /// `UpdateUnitData` re-points it whenever the replicated id changes.
    WeakPtr<UserEntity> mCreator;                        // 0x03C0
    UserCommandQueue* mManager;        // 0x03C8
    UserCommandQueue* mFactoryManager; // 0x03CC
    msvc8::set<msvc8::string> mSelectionSets; // 0x03D0
    bool mQueueEmptyCached;          // 0x03DC
    bool mIsEngineer; // 0x03DD
    bool mIsFactory;  // 0x03DE
    std::uint8_t pad_03DF_03E0[0x03E0 - 0x03DF]{};
    std::uint32_t mIntelStateFlags; // 0x03E0
    std::uint8_t pad_03E4_03E8[0x3E8 - 0x03E4]{};
  };
  // Enforced unconditionally: the whole sim->UI unit handoff writes through
  // these offsets, and the class only reaches them because `UserEntity`,
  // `IUnit` and `CScriptObject` are real bases. If one of those three ever
  // changes size the asserts below are what catches it.
  static_assert(sizeof(UserUnit) == 0x3E8, "UserUnit size must be 0x3E8");
  static_assert(
    sizeof(UserEntity) == 0x148, "UserUnit's primary base must occupy 0x000..0x148"
  );
  static_assert(offsetof(UserUnit, mUnitVarDat) == 0x0198, "UserUnit::mUnitVarDat offset must be 0x0198");
  static_assert(offsetof(UserUnit, mUnitConstDat) == 0x0184, "UserUnit::mUnitConstDat offset must be 0x0184");
  static_assert(offsetof(UserUnit, mCreator) == 0x03C0, "UserUnit::mCreator offset must be 0x03C0");
  static_assert(
    offsetof(UserUnit, mManager) == 0x03C8, "UserUnit::mManager offset must be 0x03C8"
  );
  static_assert(
    offsetof(UserUnit, mFactoryManager) == 0x03CC,
    "UserUnit::mFactoryManager offset must be 0x03CC"
  );
  static_assert(offsetof(UserUnit, mSelectionSets) == 0x03D0, "UserUnit::mSelectionSets offset must be 0x03D0");
  static_assert(offsetof(UserUnit, mQueueEmptyCached) == 0x03DC, "UserUnit::mQueueEmptyCached offset must be 0x03DC");
  static_assert(
    offsetof(UserUnit, mIsEngineer) == 0x03DD, "UserUnit::mIsEngineer offset must be 0x03DD"
  );
  static_assert(offsetof(UserUnit, mIsFactory) == 0x03DE, "UserUnit::mIsFactory offset must be 0x03DE");
  static_assert(offsetof(UserUnit, mIntelStateFlags) == 0x03E0, "UserUnit::mIntelStateFlags offset must be 0x03E0");

  /**
   * VFTABLE: 0x00E4DA4C
   * COL:  0x00E9F3C4
   */
  using UserUnitCanAttackTarget_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA5C
   * COL:  0x00E9F328
   */
  using UserUnitGetFootPrintSize_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA64
   * COL:  0x00E9F2D8
   */
  using UserUnitGetUnitId_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA6C
   * COL:  0x00E9F288
   */
  using UserUnitGetEntityId_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA74
   * COL:  0x00E9F238
   */
  using UserUnitGetBlueprint_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA7C
   * COL:  0x00E9F1E8
   */
  using UserUnitHasUnloadCommandQueuedUp_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA84
   * COL:  0x00E9F198
   */
  using UserUnitProcessInfo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA8C
   * COL:  0x00E9F148
   */
  using UserUnitIsAutoMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA94
   * COL:  0x00E9F0F8
   */
  using UserUnitIsAutoSurfaceMode_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DA9C
   * COL:  0x00E9F0A8
   */
  using UserUnitIsRepeatQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAA4
   * COL:  0x00E9F058
   */
  using UserUnitIsInCategory_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAAC
   * COL:  0x00E9F008
   */
  using UserUnitGetStat_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAB4
   * COL:  0x00E9EFB8
   */
  using UserUnitIsStunned_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DABC
   * COL:  0x00E9EF68
   */
  using UserUnitSetCustomName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAC4
   * COL:  0x00E9EF18
   */
  using UserUnitGetCustomName_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DACC
   * COL:  0x00E9EEC8
   */
  using UserUnitAddSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAD4
   * COL:  0x00E9EE78
   */
  using UserUnitRemoveSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DADC
   * COL:  0x00E9EE28
   */
  using UserUnitHasSelectionSet_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAE4
   * COL:  0x00E9EDD8
   */
  using UserUnitGetSelectionSets_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAEC
   * COL:  0x00E9ED88
   */
  using UserUnitGetHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAF4
   * COL:  0x00E9ED38
   */
  using UserUnitGetMaxHealth_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DAFC
   * COL:  0x00E9ECE8
   */
  using UserUnitGetBuildRate_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB04
   * COL:  0x00E9EC98
   */
  using UserUnitIsOverchargePaused_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB0C
   * COL:  0x00E9EC48
   */
  using UserUnitIsDead_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB14
   * COL:  0x00E9EBF8
   */
  using UserUnitIsIdle_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB1C
   * COL:  0x00E9EBA8
   */
  using UserUnitGetFocus_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB24
   * COL:  0x00E9EB58
   */
  using UserUnitGetGuardedEntity_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB2C
   * COL:  0x00E9EB08
   */
  using UserUnitGetCreator_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB34
   * COL:  0x00E9EAB8
   */
  using UserUnitGetPosition_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB3C
   * COL:  0x00E9EA68
   */
  using UserUnitGetArmy_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB44
   * COL:  0x00E9EA18
   */
  using UserUnitGetFuelRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB4C
   * COL:  0x00E9E9C8
   */
  using UserUnitGetShieldRatio_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB54
   * COL:  0x00E9E978
   */
  using UserUnitGetWorkProgress_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB5C
   * COL:  0x00E9E928
   */
  using UserUnitGetEconData_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E4DB64
   * COL:  0x00E9E8D8
   */
  using UserUnitGetCommandQueue_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x008B73E0 (FUN_008B73E0)
   *
   * What it does:
   * Rebuilds/resolves one user-unit command queue and returns whether it
   * currently contains the supplied command-issue helper.
   */
  [[nodiscard]] bool UserUnitManagerContainsCommandIssueHelper(
    UserCommandQueue* manager,
    const UserCommandIssueHelper* helper
  ) noexcept;

  [[nodiscard]] UserCommandIssueHelper*
    FindCommandIssueHelperInSession(CWldSession* session, CmdId commandId) noexcept;

  [[nodiscard]] EUnitCommandType
    ResolveCommandIssueHelperCommandType(const UserCommandIssueHelper& helper) noexcept;

  struct SSelectionSetUserEntity;

  // Exposes the file-local func_GetEntitiesUnderCursor (FUN_008B43F0) to the
  // recovered `ISSUE_IncreaseCommandCount` keystone in CWldSession.cpp: rebuilds
  // (when dirty) and returns the helper's cached cursor-entity weak-set as the
  // shared selection-set type both TUs iterate (identical head/size tree layout).
  [[nodiscard]] SSelectionSetUserEntity*
    ResolveCommandIssueCursorEntities(UserCommandIssueHelper& helper) noexcept;

  struct SSelectionNodeUserEntity;

  // Exposes the file-local weak-owner decode - the `slot - 8` adjust every
  // weak-set walk in the binary open-codes - so other TUs iterating a shared
  // cursor-entity set resolve nodes to entities without restating it. Returns
  // null for both the null and the `(void*)8` tombstone slot.
  [[nodiscard]] UserEntity* ResolveWeakEntitySetNodeEntity(const SSelectionNodeUserEntity& node) noexcept;

  /**
   * The UI-side command-target payload MSVC8 mangled names as
   * `Moho::UserTarget` (see `?ISSUE_SetCommandTarget@Moho@@YAXPAVUserCommand@1@ABVUserTarget@1@@Z`
   * on the `Moho::ISSUE_SetCommandTarget` linker symbol at 0x008B0EE0). Named
   * `UserCommandTargetView` here to match this file's existing `*RuntimeView`
   * convention for byte-precise cross-TU payload shapes.
   *
   * Layout evidence: `sub_8BECD0` (0x008BECD0), `sub_8BED50` (0x008BED50) and
   * `sub_8BEE30` (0x008BEE30) all read this exact 0x18-byte shape
   * (type@0/link@4/position@0xC) from the raw command-target pointer
   * `func_ProcessCommandDrag` (CWldSession.cpp) and `Moho::ISSUE_SetCommandTarget`
   * (Sim.cpp) pass around.
   */
  enum class UserTargetType : std::int32_t
  {
    None = 0,
    Entity = 1,
    Position = 2,
  };

  struct UserEntityWeakLinkView
  {
    std::uintptr_t ownerLinkSlot;        // +0x00
    UserEntityWeakLinkView* nextInOwner; // +0x04
  };
  static_assert(sizeof(UserEntityWeakLinkView) == 0x08, "UserEntityWeakLinkView size must be 0x08");

  struct UserCommandTargetView
  {
    UserTargetType targetType;           // +0x00
    UserEntityWeakLinkView targetEntity; // +0x04
    Wm3::Vector3<float> position;        // +0x0C
  };
  static_assert(
    offsetof(UserCommandTargetView, targetEntity) == 0x04, "UserCommandTargetView::targetEntity offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandTargetView, position) == 0x0C, "UserCommandTargetView::position offset must be 0x0C"
  );
  static_assert(sizeof(UserCommandTargetView) == 0x18, "UserCommandTargetView size must be 0x18");

  /**
   * Address: 0x008BED50 (FUN_008BED50, sub_8BED50)
   *
   * What it does:
   * Resolves one command-target world position: returns entity position when
   * target type is `Entity` and weak owner resolves, returns inline target
   * position for `Position`, otherwise returns `Invalid<Wm3::Vector3f>()`.
   * Defined in UserUnit.cpp; declared here so `Moho::ISSUE_SetCommandTarget`
   * (Sim.cpp) can resolve the drag-target world position it publishes.
   */
  [[nodiscard]] Wm3::Vector3<float> ResolvePositionFromTarget(const UserCommandTargetView& target) noexcept;

  /**
   * Address: 0x008BEE30 (FUN_008BEE30)
   *
   * What it does:
   * Resolves one command-target entity owner when target type is `Entity`
   * (`1`) and the weak-owner slot is non-null; returns null otherwise.
   * Defined in UserUnit.cpp; declared here so `Moho::ISSUE_SetCommandTarget`
   * (Sim.cpp) can resolve the transport/ferry-beacon category checks its own
   * body runs against the drag target.
   */
  [[nodiscard]] UserEntity* DecodeEntityFromCommandTargetIfEntity(const UserCommandTargetView* target) noexcept;

  /**
   * Local command-issue ring-queue event payload, as read by the helper-side
   * (UserUnit.cpp) teardown lane. Byte-compatible with
   * `moho::CommandIssueUpdateEventRuntimeView` (Sim.cpp, CommandIssueHelper.h-typed
   * `CAiTarget target` member) - both describe the same 0x50-byte
   * `UserCommandIssueLocalEvent` binary object (CommandIssueHelper.h
   * forward-declares the canonical name); this is the flatter view
   * UserUnit.cpp's own teardown lane already used before that fully-typed
   * model existed. `targetEntityWeak` sits at the same absolute offset
   * (+0x1C) as `CommandIssueUpdateEventRuntimeView::target.targetEntity`
   * (CAiTarget's own +0x04 field, at target's own +0x18 base).
   */
  struct UserCommandIssueWeakSetRuntimeView
  {
    void* allocatorProxy;           // +0x00
    SSelectionNodeUserEntity* head; // +0x04
    std::uint32_t size;             // +0x08
  };
  static_assert(
    offsetof(UserCommandIssueWeakSetRuntimeView, head) == 0x04,
    "UserCommandIssueWeakSetRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueWeakSetRuntimeView, size) == 0x08,
    "UserCommandIssueWeakSetRuntimeView::size offset must be 0x08"
  );
  static_assert(
    sizeof(UserCommandIssueWeakSetRuntimeView) == 0x0C, "UserCommandIssueWeakSetRuntimeView size must be 0x0C"
  );

  struct UserCommandIssueCellVectorRuntimeView
  {
    void* begin;       // +0x00
    void* end;         // +0x04
    void* capacityEnd; // +0x08
    void** inlineBase; // +0x0C
    std::uint8_t pad_0010_0018[0x08];
  };
  static_assert(
    offsetof(UserCommandIssueCellVectorRuntimeView, end) == 0x04,
    "UserCommandIssueCellVectorRuntimeView::end offset must be 0x04"
  );
  static_assert(
    offsetof(UserCommandIssueCellVectorRuntimeView, capacityEnd) == 0x08,
    "UserCommandIssueCellVectorRuntimeView::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueCellVectorRuntimeView, inlineBase) == 0x0C,
    "UserCommandIssueCellVectorRuntimeView::inlineBase offset must be 0x0C"
  );
  static_assert(
    sizeof(UserCommandIssueCellVectorRuntimeView) == 0x18, "UserCommandIssueCellVectorRuntimeView size must be 0x18"
  );

  struct UserCommandIssueLocalEventRuntimeView
  {
    CmdId commandId;                              // +0x00
    std::uint32_t eventType;                      // +0x04
    UserCommandIssueWeakSetRuntimeView entitySet; // +0x08
    std::int32_t countDelta;                      // +0x14
    std::uint8_t pad_0018_001C[0x04];
    SSelectionWeakRefUserEntity targetEntityWeak; // +0x1C
    std::uint8_t pad_0024_0038[0x14];
    UserCommandIssueCellVectorRuntimeView cells;  // +0x38
  };
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, entitySet) == 0x08,
    "UserCommandIssueLocalEventRuntimeView::entitySet offset must be 0x08"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, countDelta) == 0x14,
    "UserCommandIssueLocalEventRuntimeView::countDelta offset must be 0x14"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, targetEntityWeak) == 0x1C,
    "UserCommandIssueLocalEventRuntimeView::targetEntityWeak offset must be 0x1C"
  );
  static_assert(
    offsetof(UserCommandIssueLocalEventRuntimeView, cells) == 0x38,
    "UserCommandIssueLocalEventRuntimeView::cells offset must be 0x38"
  );
  static_assert(
    sizeof(UserCommandIssueLocalEventRuntimeView) == 0x50, "UserCommandIssueLocalEventRuntimeView size must be 0x50"
  );

  /**
   * Address: 0x008B4800 (FUN_008B4800)
   *
   * What it does:
   * Releases dynamic command-cell storage back to inline capacity, detaches
   * target weak-owner linkage, and destroys the local weak-entity set lane.
   * Defined in UserUnit.cpp; declared here so the Sim.cpp local command-issue
   * update-event keystone can destroy its local event through the same
   * canonical teardown the binary uses (byte-compatible with
   * `CommandIssueUpdateEventRuntimeView`, see the type's own doc comment
   * above).
   */
  void DestroyCommandIssueLocalEvent(UserCommandIssueLocalEventRuntimeView& event) noexcept;

  /**
   * Address: 0x008B6F60 (struct_UserUnitManager::Get) plus the first-live scan
   * its callers open-code around it - twice per iteration in the queued-build
   * ghost refresh at FUN_008534F0 (0x008535F8 and 0x00853634).
   *
   * What it does:
   * Rebuilds one user-unit command queue and returns the first live
   * command-issue helper in it, or null when the queue holds none. This is the
   * unit's *current* order.
   */
  [[nodiscard]] UserCommandIssueHelper* ResolveUserUnitFrontCommandIssueHelper(UserCommandQueue* manager) noexcept;

  /**
   * Address: 0x008B7320 (FUN_008B7320, struct_UserUnitManager::Get) - general
   * cross-TU form of the file-local `GetLastQueuedUserCommandHelper`
   * (returns the most recent non-null queued helper, scanning backward from
   * the logical tail and skipping retired slots), for callers that need to
   * pass an arbitrary `UserCommandQueue*` (e.g. a unit's factory command
   * queue, not just its primary one). `GetLastQueuedUserCommandAnchor`
   * above is the narrower unit-primary-queue-only bridge; this is the
   * general accessor the mouse-drag "resolve group move anchor" keystone
   * (`ResolveGroupMoveAnchorOrDetectPatrol`, CWldSession.cpp) needs.
   */
  [[nodiscard]] UserCommandIssueHelper* GetUserUnitManagerLastQueuedHelper(UserCommandQueue* manager) noexcept;

  /**
   * Address: 0x008B6E60 (FUN_008B6E60, struct_UserUnitManager::reset)
   *
   * What it does:
   * Clears one user-unit command-issue queue and pushes a reset marker entry,
   * marking the resolved-link range dirty. Exposed so the client-side
   * `ISSUE_Command` keystone (Sim.cpp) can reset a unit queue on a clearing
   * command.
   */
  void ResetUserUnitManagerState(UserCommandQueue* manager, std::int32_t commandType);

  /**
   * Address: 0x008B6DE0 (FUN_008B6DE0, struct_UserUnitManager::add)
   *
   * What it does:
   * Appends one pending command-issue helper to a user-unit command queue and
   * enqueues the matching select-unit update event. Exposed so the client-side
   * `ISSUE_Command` keystone (Sim.cpp) can enqueue an issued command per unit.
   */
  void UserUnitManagerAdd(UserCommandQueue* manager, UserCommandIssueHelper* helper, CmdId cmdId, bool clearFlag);

  /**
   * Address: 0x0081D030 (FUN_0081D030, struct_UserUnitManager queue-length accessor)
   *
   * What it does:
   * Returns the number of resolved command-queue link entries currently held by
   * one user-unit command manager (the depth the client-side `ISSUE_Command`
   * keystone caps at 500 before enqueuing).
   */
  [[nodiscard]] std::int32_t GetUserUnitManagerQueueSize(UserCommandQueue* managerPtr) noexcept;

  /**
   * Address: 0x0081DD00 inlines this exact tail dereference
   * (`struct_UserUnitManager::Get(...)->_M_finish - 2`, i.e. the raw last
   * resolved link entry's helper pointer) with no null-skip - unlike
   * `GetLastQueuedUserCommandHelper`/`ResolveUserUnitFrontCommandIssueHelper`,
   * which both walk skipping retired (null) slots. Used to test whether a
   * specific helper is still the very last order queued (nothing queued
   * after it yet), which the mouse-drag "restart as patrol" gate
   * (`CanRestartMoveCommandAsPatrol`, CWldSession.cpp) needs to reject an
   * in-place restart when there is nothing after `helper` to revise.
   *
   * What it does:
   * Rebuilds `manager`'s resolved command-queue link range and returns the
   * helper pointer stored in its last entry, or null when the range is
   * empty.
   */
  [[nodiscard]] UserCommandIssueHelper* GetUserUnitManagerQueueTailHelperRaw(UserCommandQueue* manager) noexcept;

  /**
   * Address: 0x0081E4E0 inlines this scan.
   *
   * What it does:
   * Walks `manager`'s resolved command-queue link entries front to back and
   * returns the first entry whose blueprint pointer equals
   * `candidateBlueprint` AND whose own command-graph anchor world position
   * (`Moho::ResolveCommandGraphAnchorWorldPosition`) snaps to the same
   * footprint cell as `dragPosition` - i.e. an already-queued build order
   * for the same structure at the same spot. Returns null when the queue
   * is empty or no entry matches both conditions. Backs the mouse-drag
   * "detect colocated queued build order" keystone
   * (`FindColocatedQueuedBuildOrder`, CWldSession.cpp).
   */
  [[nodiscard]] UserCommandIssueHelper* FindColocatedQueuedBuildOrderInManager(
    UserCommandQueue* manager,
    const Wm3::Vector3f& dragPosition,
    const REntityBlueprint* candidateBlueprint
  ) noexcept;

  /**
   * Address: 0x0081DD00 inlines this scan (`struct_UserUnitManager::Get(...)`
   * walked from `_M_start` to `_M_finish`, calling `sub_8B4140`
   * unconditionally on each resolved link entry's helper pointer - no
   * null-skip, matching the binary exactly).
   *
   * What it does:
   * Returns true when every resolved command-queue link entry in `manager`
   * currently resolves (via `ResolveCommandIssueHelperCommandType`) to
   * `commandType`. Used to confirm a unit's whole queued order run is
   * homogeneous before allowing an in-place drag restart.
   */
  [[nodiscard]] bool UserUnitManagerQueueHasUniformCommandType(
    UserCommandQueue* manager, EUnitCommandType commandType
  ) noexcept;

  /**
   * Address: 0x0081DEF0 inlines this scan.
   *
   * What it does:
   * Walks `manager`'s resolved command-queue link entries front to back.
   * Once the scan reaches `helper` itself, every entry from that point on
   * (inclusive) whose resolved command type equals `matchCommandType` is
   * reissued in place as `restartCommandType` - through the active sim
   * driver's `SetCommandType` plus a mirrored local "set-type" ring event
   * (`Moho::ReissueCommandIssueEntryAsType`, Sim.cpp). Entries before
   * `helper`, and non-matching entries after it, are left untouched. No-op
   * when `helper` never appears in the queue. Backs the mouse-drag
   * "restart as patrol" keystone (`RestartMoveCommandAsPatrol`,
   * CWldSession.cpp).
   */
  void RestartQueuedCommandsFromHelper(
    UserCommandQueue* manager,
    UserCommandIssueHelper* helper,
    EUnitCommandType matchCommandType,
    EUnitCommandType restartCommandType
  ) noexcept;

  /**
   * Address: 0x008B4720 (FUN_008B4720, sub_8B4720)
   *
   * What it does:
   * Appends a "select unit" local update event to one command-issue helper's
   * ring queue (when needed) and inserts `unit` into that event's weak-set.
   * Defined in Sim.cpp; declared here so `UserUnitManagerAdd` can invoke it.
   */
  void QueueCommandIssueSelectUnitEvent(UserCommandIssueHelper* helper, CmdId cmdId, UserUnit* unit);

  /**
   * VFTABLE: 0x00E4DB6C
   * COL:  0x00E9E888
   */
  using UserUnitGetMissileInfo_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x008C1430 (FUN_008C1430, ?USERUNIT_CanOccupy@Moho@@YA_NAAVCWldSession@1@ABUSFootprint@1@AAUSOCellPos@1@@Z)
   *
   * What it does:
   * Validates one build footprint origin against map bounds and rejects
   * placement when it strictly overlaps a visible non-mobile unit footprint.
   */
  bool USERUNIT_CanOccupy(CWldSession& session, const SFootprint& footprint, SOCellPos& position);

  /**
   * Address: 0x008C1880 (FUN_008C1880, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@_NPAUSBuildInfo@1@PBVUserCommand@1@@Z)
   *
   * What it does:
   * Runs world-space placement validation, then rejects when nearby static/dead
   * visible units or queued mobile-build commands overlap the candidate skirt.
   */
  bool USERUNIT_CanBeBuiltAt(
    CWldSession& session,
    const RUnitBlueprint* buildBlueprint,
    const SCoordsVec2& buildPosition,
    bool allowCommandOverlap,
    SOccupationResult* buildInfo,
    const UserCommand* ignoredCommand
  );

  /**
   * Address: 0x008C1BC0 (FUN_008C1BC0, ?USERUNIT_CanBeBuiltAt@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSOCellPos@1@_NPAUSBuildInfo@1@@Z)
   *
   * What it does:
   * Converts one cell-origin placement probe into world-space center
   * coordinates and forwards to the world-space buildability path.
   */
  bool USERUNIT_CanBeBuiltAt(
    CWldSession& session,
    const RUnitBlueprint* buildBlueprint,
    const SOCellPos& cellPosition,
    bool allowCommandOverlap,
    SOccupationResult* buildInfo
  );

  /**
   * Address: 0x008C1610 (FUN_008C1610, ?USERUNIT_WithinBuildDistance@Moho@@YA_NAAVCWldSession@1@PBVRUnitBlueprint@1@ABUSCoordsVec2@1@@Z)
   *
   * What it does:
   * Checks whether all currently selected user units are within each unit's
   * own build-distance limit from the snapped placement center for one
   * candidate blueprint footprint.
   */
  bool USERUNIT_WithinBuildDistance(
    CWldSession& session, const RUnitBlueprint* buildBlueprint, const SCoordsVec2& buildPosition
  );

  /**
   * Address: 0x008C1C30 (FUN_008C1C30, ?USERUNIT_GetBounds@Moho@@YA?AV?$AxisAlignedBox3@M@Wm3@@PBVRUnitBlueprint@1@ABV?$Vector3@M@3@@Z)
   *
   * What it does:
   * Builds one world-space unit bounds AABB from blueprint collision/skirt
   * lanes and one world position sample.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f USERUNIT_GetBounds(
    const RUnitBlueprint* unitBlueprint,
    const Wm3::Vector3f& worldPosition
  );

  /**
   * Address: 0x008377E0 (FUN_008377E0, func_GetUserUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `UserUnit*`, raising Lua errors for missing or
   * type-mismatched game-object payloads while allowing destroyed-object slots.
   */
  [[nodiscard]] UserUnit* GetUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

  /**
   * Typed accessor for the embedded IUnit bridge subobject at UserUnit+0x148.
   */
  [[nodiscard]] const IUnit* GetIUnitBridge(const UserUnit* self) noexcept;
  [[nodiscard]] IUnit* GetIUnitBridge(UserUnit* self) noexcept;

  /**
   * Address: 0x008C1220 (FUN_008C1220, sub_8C1220)
   *
   * What it does:
   * Collects the target unit blueprints of every pending `Upgrade` command in
   * `unit`'s active command queue into `out` (each queued upgrade helper's
   * build blueprint upcast to `RUnitBlueprint`).
   */
  void CollectUpgradeCommandTargetBlueprints(UserUnit* unit, msvc8::set<const RUnitBlueprint*>& out);

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker (FUN_00840A70):
   * whether one candidate platform unit is currently idle enough (not busy, no
   * pending command-queue entries) to be a dock target. Wraps the file-local
   * `IsDockTargetQueueIdle` (FUN_008C0D00).
   */
  [[nodiscard]] bool USERUNIT_IsDockTargetIdle(const UserUnit* unit) noexcept;

  /**
   * Bridge for the recovered `cfunc_IssueDockCommandL` worker: resolves one
   * unit's most recent queued command-issue helper (via `GetCommandQueue` +
   * FUN_008B7320) as an opaque cross-TU anchor-history handle, or `nullptr` when
   * the unit has no queued command.
   */
  [[nodiscard]] const QueuedUserCommandRecord* GetLastQueuedUserCommandAnchor(const UserUnit* unit) noexcept;

  /**
   * Address: 0x008C2010 (FUN_008C2010, cfunc_UserUnitCanAttackTarget)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitCanAttackTargetL`.
   */
  int cfunc_UserUnitCanAttackTarget(lua_State* luaContext);

  /**
   * Address: 0x008C2030 (FUN_008C2030, func_UserUnitCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:CanAttackTarget(target, rangeCheck)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitCanAttackTarget_LuaFuncDef();

  /**
   * Address: 0x008C2090 (FUN_008C2090, cfunc_UserUnitCanAttackTargetL)
   *
   * What it does:
   * Resolves one user-unit, one target-entity, and one range-check flag; then
   * pushes whether the unit can attack that target.
   */
  int cfunc_UserUnitCanAttackTargetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C21D0 (FUN_008C21D0, cfunc_UserUnitGetFootPrintSize)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetFootPrintSizeL`.
   */
  int cfunc_UserUnitGetFootPrintSize(lua_State* luaContext);

  /**
   * Address: 0x008C21F0 (FUN_008C21F0, func_UserUnitGetFootPrintSize_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFootPrintSize()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetFootPrintSize_LuaFuncDef();

  /**
   * Address: 0x008C2250 (FUN_008C2250, cfunc_UserUnitGetFootPrintSizeL)
   *
   * What it does:
   * Returns the larger footprint axis (`max(SizeX, SizeZ)`) for one user unit.
   */
  int cfunc_UserUnitGetFootPrintSizeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2340 (FUN_008C2340, cfunc_UserUnitGetUnitId)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetUnitIdL`.
   */
  int cfunc_UserUnitGetUnitId(lua_State* luaContext);

  /**
   * Address: 0x008C2360 (FUN_008C2360, func_UserUnitGetUnitId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetUnitId()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetUnitId_LuaFuncDef();

  /**
   * Address: 0x008C23C0 (FUN_008C23C0, cfunc_UserUnitGetUnitIdL)
   *
   * What it does:
   * Pushes one user-unit blueprint id string.
   */
  int cfunc_UserUnitGetUnitIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2620 (FUN_008C2620, cfunc_UserUnitGetBlueprint)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBlueprintL`.
   */
  int cfunc_UserUnitGetBlueprint(lua_State* luaContext);

  /**
   * Address: 0x008C2640 (FUN_008C2640, func_UserUnitGetBlueprint_LuaFuncDef)
   *
   * What it does:
   * Publishes the `blueprint = UserUnit:GetBlueprint()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetBlueprint_LuaFuncDef();

  /**
   * Address: 0x008C26A0 (FUN_008C26A0, cfunc_UserUnitGetBlueprintL)
   *
   * What it does:
   * Resolves one user unit and pushes its Lua blueprint object.
   */
  int cfunc_UserUnitGetBlueprintL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2B60 (FUN_008C2B60, cfunc_UserUnitIsAutoMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsAutoModeL`.
   */
  int cfunc_UserUnitIsAutoMode(lua_State* luaContext);

  /**
   * Address: 0x008C2B80 (FUN_008C2B80, func_UserUnitIsAutoMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsAutoMode()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsAutoMode_LuaFuncDef();

  /**
   * Address: 0x008C2BE0 (FUN_008C2BE0, cfunc_UserUnitIsAutoModeL)
   *
   * What it does:
   * Pushes one user-unit auto-mode flag.
   */
  int cfunc_UserUnitIsAutoModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2CA0 (FUN_008C2CA0, cfunc_UserUnitIsAutoSurfaceMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsAutoSurfaceModeL`.
   */
  int cfunc_UserUnitIsAutoSurfaceMode(lua_State* luaContext);

  /**
   * Address: 0x008C2CC0 (FUN_008C2CC0, func_UserUnitIsAutoSurfaceMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsAutoSurfaceMode()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsAutoSurfaceMode_LuaFuncDef();

  /**
   * Address: 0x008C2D20 (FUN_008C2D20, cfunc_UserUnitIsAutoSurfaceModeL)
   *
   * What it does:
   * Pushes one user-unit auto-surface-mode flag.
   */
  int cfunc_UserUnitIsAutoSurfaceModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2DE0 (FUN_008C2DE0, cfunc_UserUnitIsRepeatQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsRepeatQueueL`.
   */
  int cfunc_UserUnitIsRepeatQueue(lua_State* luaContext);

  /**
   * Address: 0x008C2E00 (FUN_008C2E00, func_UserUnitIsRepeatQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsRepeatQueue()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsRepeatQueue_LuaFuncDef();

  /**
   * Address: 0x008C2E60 (FUN_008C2E60, cfunc_UserUnitIsRepeatQueueL)
   *
   * What it does:
   * Pushes one user-unit repeat-queue flag.
   */
  int cfunc_UserUnitIsRepeatQueueL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C24A0 (FUN_008C24A0, cfunc_UserUnitGetEntityId)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_UserUnitGetEntityIdL`.
   */
  int cfunc_UserUnitGetEntityId(lua_State* luaContext);

  /**
   * Address: 0x008C24C0 (FUN_008C24C0, func_UserUnitGetEntityId_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetEntityId()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetEntityId_LuaFuncDef();

  /**
   * Address: 0x008C2520 (FUN_008C2520, cfunc_UserUnitGetEntityIdL)
   *
   * What it does:
   * Validates one `UserUnit` argument and pushes its entity id as string.
   */
  int cfunc_UserUnitGetEntityIdL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2790 (FUN_008C2790, cfunc_UserUnitHasUnloadCommandQueuedUp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitHasUnloadCommandQueuedUpL`.
   */
  int cfunc_UserUnitHasUnloadCommandQueuedUp(lua_State* luaContext);

  /**
   * Address: 0x008C27B0 (FUN_008C27B0, func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:HasUnloadCommandQueuedUp()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef();

  /**
   * Address: 0x008C2810 (FUN_008C2810, cfunc_UserUnitHasUnloadCommandQueuedUpL)
   *
   * What it does:
   * Returns whether the transport this unit is attached to already has an
   * unload command queued.
   */
  int cfunc_UserUnitHasUnloadCommandQueuedUpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C29D0 (FUN_008C29D0, cfunc_UserUnitProcessInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitProcessInfoL`.
   */
  int cfunc_UserUnitProcessInfo(lua_State* luaContext);

  /**
   * Address: 0x008C29F0 (FUN_008C29F0, func_UserUnitProcessInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:ProcessInfoPair(key, value)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitProcessInfo_LuaFuncDef();

  /**
   * Address: 0x008C2A50 (FUN_008C2A50, cfunc_UserUnitProcessInfoL)
   *
   * What it does:
   * Validates `UserUnit`, key, and value arguments, then forwards one
   * process-info pair update to the active sim driver.
   */
  int cfunc_UserUnitProcessInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3580 (FUN_008C3580, cfunc_UserUnitSetCustomName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitSetCustomNameL`.
   */
  int cfunc_UserUnitSetCustomName(lua_State* luaContext);

  /**
   * Address: 0x008C35A0 (FUN_008C35A0, func_UserUnitSetCustomName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:SetCustomName(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitSetCustomName_LuaFuncDef();

  /**
   * Address: 0x008C3600 (FUN_008C3600, cfunc_UserUnitSetCustomNameL)
   *
   * What it does:
   * Validates one `UserUnit` and one custom-name string, then forwards the
   * update as a `ProcessInfoPair("CustomName", value)` command.
   */
  int cfunc_UserUnitSetCustomNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3880 (FUN_008C3880, cfunc_UserUnitAddSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitAddSelectionSetL`.
   */
  int cfunc_UserUnitAddSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C38A0 (FUN_008C38A0, func_UserUnitAddSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:AddSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitAddSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3900 (FUN_008C3900, cfunc_UserUnitAddSelectionSetL)
   *
   * What it does:
   * Resolves one `UserUnit` plus one selection-set name and inserts the name
   * into the unit's selection-set container.
   */
  int cfunc_UserUnitAddSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C39E0 (FUN_008C39E0, cfunc_UserUnitRemoveSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitRemoveSelectionSetL`.
   */
  int cfunc_UserUnitRemoveSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C3A00 (FUN_008C3A00, func_UserUnitRemoveSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:RemoveSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitRemoveSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3A60 (FUN_008C3A60, cfunc_UserUnitRemoveSelectionSetL)
   *
   * What it does:
   * Resolves one `UserUnit` plus one selection-set name and erases that name
   * from the unit's selection-set container.
   */
  int cfunc_UserUnitRemoveSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3CD0 (FUN_008C3CD0, cfunc_UserUnitGetSelectionSets)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetSelectionSetsL`.
   */
  int cfunc_UserUnitGetSelectionSets(lua_State* luaContext);

  /**
   * Address: 0x008C3CF0 (FUN_008C3CF0, func_UserUnitGetSelectionSets_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetSelectionSets()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetSelectionSets_LuaFuncDef();

  /**
   * Address: 0x008C3D50 (FUN_008C3D50, cfunc_UserUnitGetSelectionSetsL)
   *
   * What it does:
   * Returns a Lua array of selection-set names currently attached to one
   * `UserUnit`.
   */
  int cfunc_UserUnitGetSelectionSetsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C2F20 (FUN_008C2F20, cfunc_UserUnitIsInCategory)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsInCategoryL`.
   */
  int cfunc_UserUnitIsInCategory(lua_State* luaContext);

  /**
   * Address: 0x008C2F40 (FUN_008C2F40, func_UserUnitIsInCategory_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsInCategory(category)` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsInCategory_LuaFuncDef();

  /**
   * Address: 0x008C2FA0 (FUN_008C2FA0, cfunc_UserUnitIsInCategoryL)
   *
   * What it does:
   * Returns whether one `UserUnit` matches one category string argument.
   */
  int cfunc_UserUnitIsInCategoryL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3EA0 (FUN_008C3EA0, cfunc_UserUnitGetHealth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetHealthL`.
   */
  int cfunc_UserUnitGetHealth(lua_State* luaContext);

  /**
   * Address: 0x008C3EC0 (FUN_008C3EC0, func_UserUnitGetHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetHealth()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetHealth_LuaFuncDef();

  /**
   * Address: 0x008C3F20 (FUN_008C3F20, cfunc_UserUnitGetHealthL)
   *
   * What it does:
   * Returns current health for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3FE0 (FUN_008C3FE0, cfunc_UserUnitGetMaxHealth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMaxHealthL`.
   */
  int cfunc_UserUnitGetMaxHealth(lua_State* luaContext);

  /**
   * Address: 0x008C4000 (FUN_008C4000, func_UserUnitGetMaxHealth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetMaxHealth()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetMaxHealth_LuaFuncDef();

  /**
   * Address: 0x008C4060 (FUN_008C4060, cfunc_UserUnitGetMaxHealthL)
   *
   * What it does:
   * Returns max health for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetMaxHealthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4120 (FUN_008C4120, cfunc_UserUnitGetBuildRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBuildRateL`.
   */
  int cfunc_UserUnitGetBuildRate(lua_State* luaContext);

  /**
   * Address: 0x008C4140 (FUN_008C4140, func_UserUnitGetBuildRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetBuildRate()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetBuildRate_LuaFuncDef();

  /**
   * Address: 0x008C41A0 (FUN_008C41A0, cfunc_UserUnitGetBuildRateL)
   *
   * What it does:
   * Returns current build-rate value for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetBuildRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4270 (FUN_008C4270, cfunc_UserUnitIsOverchargePaused)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsOverchargePausedL`.
   */
  int cfunc_UserUnitIsOverchargePaused(lua_State* luaContext);

  /**
   * Address: 0x008C4290 (FUN_008C4290, func_UserUnitIsOverchargePaused_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsOverchargePaused()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x008C42F0 (FUN_008C42F0, cfunc_UserUnitIsOverchargePausedL)
   *
   * What it does:
   * Returns overcharge-paused state for one user-unit as Lua boolean.
   */
  int cfunc_UserUnitIsOverchargePausedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C43B0 (FUN_008C43B0, cfunc_UserUnitIsDead)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsDeadL`.
   */
  int cfunc_UserUnitIsDead(lua_State* luaContext);

  /**
   * Address: 0x008C43D0 (FUN_008C43D0, func_UserUnitIsDead_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsDead()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitIsDead_LuaFuncDef();

  /**
   * Address: 0x008C4430 (FUN_008C4430, cfunc_UserUnitIsDeadL)
   *
   * What it does:
   * Returns true when input user-unit is missing or reports dead.
   */
  int cfunc_UserUnitIsDeadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4DA0 (FUN_008C4DA0, cfunc_UserUnitGetFuelRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFuelRatioL`.
   */
  int cfunc_UserUnitGetFuelRatio(lua_State* luaContext);

  /**
   * Address: 0x008C4DC0 (FUN_008C4DC0, func_UserUnitGetFuelRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFuelRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetFuelRatio_LuaFuncDef();

  /**
   * Address: 0x008C4E20 (FUN_008C4E20, cfunc_UserUnitGetFuelRatioL)
   *
   * What it does:
   * Returns current fuel ratio for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetFuelRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4EE0 (FUN_008C4EE0, cfunc_UserUnitGetShieldRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetShieldRatioL`.
   */
  int cfunc_UserUnitGetShieldRatio(lua_State* luaContext);

  /**
   * Address: 0x008C4F00 (FUN_008C4F00, func_UserUnitGetShieldRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetShieldRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x008C4F60 (FUN_008C4F60, cfunc_UserUnitGetShieldRatioL)
   *
   * What it does:
   * Returns current shield ratio for one user-unit as Lua number.
   */
  int cfunc_UserUnitGetShieldRatioL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5020 (FUN_008C5020, cfunc_UserUnitGetWorkProgress)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetWorkProgressL`.
   */
  int cfunc_UserUnitGetWorkProgress(lua_State* luaContext);

  /**
   * Address: 0x008C5040 (FUN_008C5040, func_UserUnitGetWorkProgress_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetWorkProgress()` Lua binder definition.
   */
  CScrLuaInitForm* func_UserUnitGetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x008C50A0 (FUN_008C50A0, cfunc_UserUnitGetWorkProgressL)
   *
   * What it does:
   * Returns current unit work-progress ratio as Lua number.
   */
  int cfunc_UserUnitGetWorkProgressL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C30E0 (FUN_008C30E0, cfunc_UserUnitGetStat)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetStatL`.
   */
  int cfunc_UserUnitGetStat(lua_State* luaContext);

  /**
   * Address: 0x008C3100 (FUN_008C3100, func_UserUnitGetStat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetStat(name[, defaultVal])` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetStat_LuaFuncDef();

  /**
   * Address: 0x008C3160 (FUN_008C3160, cfunc_UserUnitGetStatL)
   *
   * What it does:
   * Resolves one stat query (with optional default) and pushes one stat-table
   * result, or `nil`.
   */
  int cfunc_UserUnitGetStatL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3440 (FUN_008C3440, cfunc_UserUnitIsStunned)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitIsStunnedL`.
   */
  int cfunc_UserUnitIsStunned(lua_State* luaContext);

  /**
   * Address: 0x008C3460 (FUN_008C3460, func_UserUnitIsStunned_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsStunned()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsStunned_LuaFuncDef();

  /**
   * Address: 0x008C34C0 (FUN_008C34C0, cfunc_UserUnitIsStunnedL)
   *
   * What it does:
   * Pushes one stunned-state boolean from replicated user-unit runtime state.
   */
  int cfunc_UserUnitIsStunnedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3700 (FUN_008C3700, cfunc_UserUnitGetCustomName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCustomNameL`.
   */
  int cfunc_UserUnitGetCustomName(lua_State* luaContext);

  /**
   * Address: 0x008C3720 (FUN_008C3720, func_UserUnitGetCustomName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCustomName()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCustomName_LuaFuncDef();

  /**
   * Address: 0x008C3780 (FUN_008C3780, cfunc_UserUnitGetCustomNameL)
   *
   * What it does:
   * Pushes one custom-name string (or `nil` when empty).
   */
  int cfunc_UserUnitGetCustomNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C3B40 (FUN_008C3B40, cfunc_UserUnitHasSelectionSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitHasSelectionSetL`.
   */
  int cfunc_UserUnitHasSelectionSet(lua_State* luaContext);

  /**
   * Address: 0x008C3B60 (FUN_008C3B60, func_UserUnitHasSelectionSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:HasSelectionSet(name)` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitHasSelectionSet_LuaFuncDef();

  /**
   * Address: 0x008C3BC0 (FUN_008C3BC0, cfunc_UserUnitHasSelectionSetL)
   *
   * What it does:
   * Pushes one boolean membership result for the provided selection-set name.
   */
  int cfunc_UserUnitHasSelectionSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4500 (FUN_008C4500, cfunc_UserUnitIsIdle)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsIdleL`.
   */
  int cfunc_UserUnitIsIdle(lua_State* luaContext);

  /**
   * Address: 0x008C4520 (FUN_008C4520, func_UserUnitIsIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:IsIdle()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitIsIdle_LuaFuncDef();

  /**
   * Address: 0x008C4580 (FUN_008C4580, cfunc_UserUnitIsIdleL)
   *
   * What it does:
   * Pushes one idle-state boolean derived from busy + queue-empty state.
   */
  int cfunc_UserUnitIsIdleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4660 (FUN_008C4660, cfunc_UserUnitGetFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFocusL`.
   */
  int cfunc_UserUnitGetFocus(lua_State* luaContext);

  /**
   * Address: 0x008C4680 (FUN_008C4680, func_UserUnitGetFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetFocus()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetFocus_LuaFuncDef();

  /**
   * Address: 0x008C46E0 (FUN_008C46E0, cfunc_UserUnitGetFocusL)
   *
   * What it does:
   * Pushes focused target user-unit Lua object, or `nil` when unresolved.
   */
  int cfunc_UserUnitGetFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C47F0 (FUN_008C47F0, cfunc_UserUnitGetGuardedEntity)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetGuardedEntityL`.
   */
  int cfunc_UserUnitGetGuardedEntity(lua_State* luaContext);

  /**
   * Address: 0x008C4810 (FUN_008C4810, func_UserUnitGetGuardedEntity_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetGuardedEntity()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetGuardedEntity_LuaFuncDef();

  /**
   * Address: 0x008C4870 (FUN_008C4870, cfunc_UserUnitGetGuardedEntityL)
   *
   * What it does:
   * Pushes guarded-target user-unit Lua object, or `nil` when unresolved.
   */
  int cfunc_UserUnitGetGuardedEntityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4980 (FUN_008C4980, cfunc_UserUnitGetCreator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCreatorL`.
   */
  int cfunc_UserUnitGetCreator(lua_State* luaContext);

  /**
   * Address: 0x008C49A0 (FUN_008C49A0, func_UserUnitGetCreator_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCreator()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCreator_LuaFuncDef();

  /**
   * Address: 0x008C4A00 (FUN_008C4A00, cfunc_UserUnitGetCreatorL)
   *
   * What it does:
   * Pushes creator user-unit Lua object, or `nil` when unavailable.
   */
  int cfunc_UserUnitGetCreatorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4AF0 (FUN_008C4AF0, cfunc_UserUnitGetPosition)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetPositionL`.
   */
  int cfunc_UserUnitGetPosition(lua_State* luaContext);

  /**
   * Address: 0x008C4B10 (FUN_008C4B10, func_UserUnitGetPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetPosition()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetPosition_LuaFuncDef();

  /**
   * Address: 0x008C4B70 (FUN_008C4B70, cfunc_UserUnitGetPositionL)
   *
   * What it does:
   * Pushes world position as one Lua VECTOR3 object.
   */
  int cfunc_UserUnitGetPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C4C50 (FUN_008C4C50, cfunc_UserUnitGetArmy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetArmyL`.
   */
  int cfunc_UserUnitGetArmy(lua_State* luaContext);

  /**
   * Address: 0x008C4C70 (FUN_008C4C70, func_UserUnitGetArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetArmy()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetArmy_LuaFuncDef();

  /**
   * Address: 0x008C4CD0 (FUN_008C4CD0, cfunc_UserUnitGetArmyL)
   *
   * What it does:
   * Pushes one-based army index for the unit owner, preserving `-1` sentinel.
   */
  int cfunc_UserUnitGetArmyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5160 (FUN_008C5160, cfunc_UserUnitGetEconData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetEconDataL`.
   */
  int cfunc_UserUnitGetEconData(lua_State* luaContext);

  /**
   * Address: 0x008C5180 (FUN_008C5180, func_UserUnitGetEconData_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetEconData()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetEconData_LuaFuncDef();

  /**
   * Address: 0x008C51E0 (FUN_008C51E0, cfunc_UserUnitGetEconDataL)
   *
   * What it does:
   * Pushes one Lua table with per-second economy lanes for this user unit.
   */
  int cfunc_UserUnitGetEconDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5400 (FUN_008C5400, cfunc_UserUnitGetCommandQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetCommandQueueL`.
   */
  int cfunc_UserUnitGetCommandQueue(lua_State* luaContext);

  /**
   * Address: 0x008C5420 (FUN_008C5420, func_UserUnitGetCommandQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetCommandQueue()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetCommandQueue_LuaFuncDef();

  /**
   * Address: 0x008C5480 (FUN_008C5480, cfunc_UserUnitGetCommandQueueL)
   *
   * What it does:
   * Pushes one Lua array of queued command descriptors (`ID`, `type`,
   * `position`) for this user unit.
   */
  int cfunc_UserUnitGetCommandQueueL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5750 (FUN_008C5750, cfunc_UserUnitGetMissileInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UserUnitGetMissileInfoL`.
   */
  int cfunc_UserUnitGetMissileInfo(lua_State* luaContext);

  /**
   * Address: 0x008C5770 (FUN_008C5770, func_UserUnitGetMissileInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `UserUnit:GetMissileInfo()` Lua binder.
   */
  CScrLuaInitForm* func_UserUnitGetMissileInfo_LuaFuncDef();

  /**
   * Address: 0x008C57D0 (FUN_008C57D0, cfunc_UserUnitGetMissileInfoL)
   *
   * What it does:
   * Pushes one Lua table with tactical/nuke silo build and storage counters.
   */
  int cfunc_UserUnitGetMissileInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00836360 (FUN_00836360, cfunc_SetCurrentFactoryForQueueDisplay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SetCurrentFactoryForQueueDisplayL`.
   */
  int cfunc_SetCurrentFactoryForQueueDisplay(lua_State* luaContext);

  /**
   * Address: 0x00836380 (FUN_00836380, func_SetCurrentFactoryForQueueDisplay_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `SetCurrentFactoryForQueueDisplay(unit)` Lua binder.
   */
  CScrLuaInitForm* func_SetCurrentFactoryForQueueDisplay_LuaFuncDef();

  /**
   * Address: 0x008363E0 (FUN_008363E0, cfunc_SetCurrentFactoryForQueueDisplayL)
   *
   * What it does:
   * Rebuilds current UI factory queue view from one optional user-unit object
   * and pushes the resulting queue table (or nil).
   */
  int cfunc_SetCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008C5930 (FUN_008C5930, cfunc_GetBlueprintUser)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetBlueprintUserL`.
   */
  int cfunc_GetBlueprintUser(lua_State* luaContext);

  /**
   * Address: 0x008C5950 (FUN_008C5950, func_GetBlueprintUser_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua `GetBlueprint` binder.
   */
  CScrLuaInitForm* func_GetBlueprintUser_LuaFuncDef();

  /**
   * Address: 0x008C59B0 (FUN_008C59B0, cfunc_GetBlueprintUserL)
   *
   * What it does:
   * Resolves one `UserUnit` Lua object argument and pushes its unit blueprint
   * Lua object result.
   */
  int cfunc_GetBlueprintUserL(LuaPlus::LuaState* state);

} // namespace moho
