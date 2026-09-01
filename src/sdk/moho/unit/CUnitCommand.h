#pragma once
#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "Broadcaster.h"
#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiTarget.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptObject.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class RRef;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class Entity;
  class Unit;
  class CCommandDb;
  class CAiFormationInstance;
  class Sim;
  struct SOCellPos;
  struct SSTICommandIssueData;
  struct SSyncData;

  struct SCommandUnitSet
  {
    // Command unit-set uses 0x8 as an erased/tombstone entry marker.
    static constexpr std::uintptr_t kErasedEntryTag = 8u;

    static bool IsUsableEntry(const CScriptObject* scriptObject)
    {
      return scriptObject != nullptr && reinterpret_cast<std::uintptr_t>(scriptObject) != kErasedEntryTag;
    }

    [[nodiscard]] static CScriptObject* EntryFromUnit(Unit* unit) noexcept;
    [[nodiscard]] static Unit* UnitFromEntry(CScriptObject* entry) noexcept;
    [[nodiscard]] static const Unit* UnitFromEntry(const CScriptObject* entry) noexcept;
    [[nodiscard]] static EntId EntryEntityId(const CScriptObject* entry) noexcept;
    [[nodiscard]] std::size_t LowerBoundByEntityId(EntId targetId) const noexcept;
    [[nodiscard]] bool InsertUnitSorted(Unit* unit);
    [[nodiscard]] bool RemoveUnitSorted(Unit* unit);

    /**
     * Self-linked intrusive-node prefix (ground truth: `FUN_006E81B0` inits
     * both slots to `&this->mUnitSet` before touching `mVec`, at absolute
     * +0xF0/+0xF4 relative to a `CUnitCommand*`). Never observed linked to
     * any other `SCommandUnitSet`; role beyond "self-linked sentinel" is not
     * yet identified. Field order (this member first) matches
     * `TDatListItem`'s own construction-order convention; the exact
     * mPrev/mNext-vs-decompiler's-next/previous naming is immaterial for a
     * self-linked node since both slots hold the identical value either way.
     */
    TDatListItem<SCommandUnitSet, void> mListNode;

    // Ground truth: start/end/capacity/originalVec == &mVec+0x08 (an empty,
    // 4-element-inline SBO vector) until the set holds a 5th unit, matching
    // FastVectorN<CScriptObject*,4>'s own 0x20-byte shape exactly
    // (FastVector.h's own `FastVectorN<uint,4> must be 0x20` size assert).
    gpg::core::FastVectorN<CScriptObject*, 4> mVec;
  };

  static_assert(sizeof(SCommandUnitSet) == 0x28, "moho::SCommandUnitSet size must be 0x28");

  class CUnitCommand : public CScriptObject, public Broadcaster
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;
    [[nodiscard]] static gpg::RType* StaticGetClass();
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x006E7CF0 (FUN_006E7CF0, Moho::CUnitCommand::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CUnitCommand`, resolved
     * via RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x006E7D10 (FUN_006E7D10, Moho::CUnitCommand::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x006E8140 (FUN_006E8140, Moho::CUnitCommand::dtr)
     * VFTable SLOT: 2
     *
     * What it does:
     * Runs `DestroyInternal()` teardown; the compiler-generated scalar
     * deleting destructor (matching the binary's own vtable-slot-2 thunk)
     * conditionally frees storage afterward.
     */
    ~CUnitCommand() override;

    /**
       * Address: 0x006E81B0 (FUN_006E81B0)
     *
     * What it does:
     * Initializes one command from issue payload lanes, updates sim command
     * digest/counter state, and links coordinating-order relationships.
     */
    CUnitCommand(Sim* sim, const SSTICommandIssueData& issueData);

    /**
       * Address: 0x006E81B0 (FUN_006E81B0)
     *
     * What it does:
     * Initializes one command from issue payload lanes while forcing the
     * resolved command id used by digest/map insertion paths.
     */
    CUnitCommand(Sim* sim, const SSTICommandIssueData& issueData, CmdId resolvedCommandId);

    /**
     * Address: 0x006E7D40 (FUN_006E7D40, ?GetCoordinateWith@CUnitCommand@Moho@@QBE?AV?$vector@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@V?$allocator@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@@std@@@std@@XZ)
     *
     * What it does:
     * Returns a by-value snapshot of this command's coordinating-order weak links.
     */
    [[nodiscard]] msvc8::vector<WeakPtr<CUnitCommand>> GetCoordinatingOrdersSnapshot() const;

    /**
     * Address: 0x006E91C0 (FUN_006E91C0, Moho::CUnitCommand::MemberConstruct)
     *
     * What it does:
     * Allocates one `CUnitCommand`, default-constructs it, and returns it as an
     * unowned construct result.
     */
    static void MemberConstruct(gpg::SerConstructResult* result);

    /**
     * Address: 0x006ECB80 (FUN_006ECB80, Moho::CUnitCommand::MemberDeserialize)
     * Address: 0x006EC1B0 (FUN_006EC1B0)
     *
     * What it does:
     * Loads the serialized command payload lanes into this command instance.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCommand* command, int version);

    /**
     * Address: 0x006ECE20 (FUN_006ECE20, Moho::CUnitCommand::MemberSerialize)
     * Address: 0x006EB750 (FUN_006EB750)
     * Address: 0x006EC1C0 (FUN_006EC1C0)
     *
     * What it does:
     * Saves the serialized command payload lanes from this command instance.
     */
    static void MemberSerialize(CUnitCommand* command, gpg::WriteArchive* archive, int version);

    /**
     * Address: 0x006E8B40 (FUN_006E8B40)
     *
     * What it does:
     * Adds `unit` into the command's unit-set and inserts this command weak-ref
     * into `queue` at `index` (negative index means append-relative insertion).
     */
    void AddUnit(Unit* unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue, int index);

    /**
     * Address: 0x006E8CC0 (FUN_006E8CC0)
     *
     * What it does:
     * Adds one live unit into this command's unit-set and formation lanes
     * without touching external command-queue links.
     */
    void AddUnit(Unit* unit);

    /**
     * Address: 0x006E8C20 (FUN_006E8C20)
     *
     * What it does:
     * Removes `unit` from the command's unit-set and erases this command
     * from the provided command queue.
     */
    void RemoveUnit(Unit* unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue);

    /**
     * Address: 0x006E8D10 (FUN_006E8D10)
     *
     * What it does:
     * Removes `unit` from the command's unit-set without touching queue links.
     */
    void RemoveUnit(Unit* unit);

    /**
     * Address: 0x006E8D70 (FUN_006E8D70, Moho::CUnitCommand::FormRemoveUnit)
     *
     * What it does:
     * Removes `unit` from the active formation lane and releases the formation
     * instance when that lane becomes empty.
     */
    static void FormRemoveUnit(Unit* unit, CUnitCommand* command);

    /**
     * Address: 0x006E88D0 (FUN_006E88D0, Moho::CUnitCommand::Move)
     *
     * What it does:
     * Keeps formation membership in sync for multi-unit commands and creates a
     * new formation instance when the command first needs one.
     */
    static void Move(Unit* unit, CUnitCommand* command);

    /**
     * Address: 0x006E8A00 (FUN_006E8A00, Moho::CUnitCommand::InFormation)
     *
     * What it does:
     * Returns the active formation instance when `unit` already belongs to the
     * command's formation lane.
     */
    [[nodiscard]] static CAiFormationInstance* InFormation(Unit* unit, CUnitCommand* command);

    /**
     * Address: 0x006E8A30 (FUN_006E8A30, Moho::CUnitCommand::GetPosition)
     *
     * What it does:
     * Resolves the cell position used by formation and non-formation move
     * dispatch paths.
     */
    [[nodiscard]] static SOCellPos* GetPosition(CUnitCommand* command, Unit* unit, SOCellPos* dest);

    /**
     * Address: 0x005D5980 (FUN_005D5980, Moho::CUnitCommand::GetFocus)
     *
     * What it does:
     * Returns the command target's focus entity when the weak target link is
     * valid.
     */
    [[nodiscard]] static Entity* GetFocus(CUnitCommand* command);

    /**
     * Address: 0x005F55F0 (FUN_005F55F0, Moho::CUnitCommand::GetTarget)
     *
     * What it does:
     * Returns the focused target unit when the command target resolves to a
     * live unit entity.
     */
    [[nodiscard]] static Unit* GetTarget(CUnitCommand* command);

    /**
     * Address: 0x005F24E0 (FUN_005F24E0, Moho::CUnitCommand::IsCoordinating)
     *
     * What it does:
     * Returns true when this command has at least one coordinating-order link.
     */
    [[nodiscard]] bool IsCoordinating() const;

    /**
     * Address: 0x006E90A0 (FUN_006E90A0, Moho::CUnitCommand::IsDone)
     *
     * What it does:
     * Returns true when this command is done and all coordinating-order peers
     * that still resolve are done as well.
     */
    [[nodiscard]] bool IsDone() const;

    /**
     * Address: 0x006F1650 (FUN_006F1650)
     * @param amount
     */
    void IncreaseCount(int amount);

    /**
     * Address: 0x006F16A0 (FUN_006F16A0)
     * @param amount
     */
    void DecreaseCount(int amount);

    /**
     * Address: 0x006E8820 (FUN_006E8820)
     */
    void SetTarget(const CAiTarget& target);

    /**
      * Alias of FUN_005BF810 (non-canonical helper lane).
     *
     * What it does:
     * Refreshes cached command blip/transform state for the current frame.
     */
    void RefreshBlipState();

    /**
     * Address: 0x006E9000 (FUN_006E9000, ?CoordinateWith@CUnitCommand@Moho@@QAEXPAV12@@Z)
     *
     * What it does:
     * Adds a one-way coordinating-order link from this command to `other`
     * when command types are compatible.
     */
    void CoordinateWith(CUnitCommand* other);

    /**
     * Address: 0x006E8720 (FUN_006E8720)
     *
     * IDA signature:
     * Moho::WeakObject_IUnit *__thiscall sub_6E8720(
     *   Moho::RUnitBlueprint *blueprint, Moho::WeakPtr_Unit *command,
     *   Moho::CArmyImpl *army, float x, float y, float z);
     *
     * What it does:
     * Spawns this command's ferry beacon: builds a complete, unlinked unit of
     * `blueprint` at `(x, y, z)` with identity orientation, stores it in the
     * command's beacon weak lane, and returns it back out of that lane.
     */
    [[nodiscard]] static Unit* CreateFerryBeacon(
      const RUnitBlueprint* blueprint,
      CUnitCommand& command,
      CArmyImpl* army,
      float x,
      float y,
      float z
    );

    /**
     * Address: 0x0060DAE0 (FUN_0060DAE0, Moho::CUnitCommand::GetFerryBeacon)
     *
     * IDA signature:
     * Moho::Unit *__usercall GetFerryBeacon@<eax>(CUnitCommand *a1@<eax>);
     *
     * What it does:
     * Resolves the ferry beacon this command spawned, or null once the
     * beacon has gone away.
     */
    [[nodiscard]] Unit* GetFerryBeacon() const;

  private:
    /**
     * Address: 0x006E7FF0 (FUN_006E7FF0, ??0CUnitCommand@Moho@@AAE@XZ)
     *
     * What it does:
     * Default-initializes one command instance for serializer construction flow.
     */
    CUnitCommand();

    friend class CUnitCommandConstruct;
    friend class CCommandDb;

    /**
     * Address: 0x006E8500 (FUN_006E8500)
     *
     * Internal teardown, run from the real destructor. The compiler-generated
     * scalar deleting destructor (vtable slot 2) wraps `~CUnitCommand()` with
     * the conditional `operator delete` the binary's own thunk at 0x006E8140
     * performs by hand - no separate static helper is needed once the class
     * has a real virtual destructor.
     */
    void DestroyInternal();

    /**
     * Address: 0x006E8DC0 (FUN_006E8DC0)
     *
     * Rebuilds cached unit/event payload state when pending updates exist.
     */
    void RefreshPublishedCommandEvent(bool forceRefresh, SSyncData* syncData);

  public:
    // Placeholder for unresolved leading subobject/layout slice.
    void* unk0;
    Sim* mSim;
    SSTICommandConstantData mConstDat;
    SSTICommandVariableData mVarDat;
    // Ground truth: never written in the constructor (FUN_006E81B0), sits
    // immediately before mUnitSet at +0xEC. Purpose not yet identified.
    void* unk1;
    SCommandUnitSet mUnitSet;
    CAiFormationInstance* mFormationInstance;
    CAiTarget mTarget;
    // Monotonic per-command serial assigned from Sim counter (not mConstDat.cmd).
    CmdId mInstanceSerial;
    bool mHasPublishedCommandEvent;
    bool mNeedsUpdate;
    bool mUnknownFlag142;
    bool mUnknownFlag143;
    msvc8::vector<WeakPtr<CUnitCommand>> mCoordinatingOrders;
    bool mUnknownFlag154;
    /**
     * The ferry beacon this command spawned, held by the engine's intrusive
     * weak pointer - not `boost::weak_ptr`. Two independent readings agree:
     * `CreateFerryBeaconUnit` (0x006E87D2) calls `WeakPtr<Unit>::Set` on
     * `this + 0x158` and then decodes the object back out with the `-4`
     * owner-slot adjustment, and `MemberSerialize`/`MemberDeserialize` already
     * reflect the field through `WeakPtr<Unit>::sType`.
     */
    WeakPtr<Unit> mUnit;
    LuaPlus::LuaObject mArgs;
    int32_t mUnknownTailInt;
  };

  // Both asserts verified directly against FUN_006E81B0's raw disassembly
  // (field-by-field, every `[ebp+XX]` write in the real constructor) -
  // unconditional, not MOHO_ABI_MSVC8_COMPAT-guarded: that macro is never
  // defined anywhere in this tree (checked, zero /D definitions), so a
  // guarded assert here would silently never compile-check this layout.
  static_assert(sizeof(CUnitCommand) == 0x178, "CUnitCommand size must be 0x178");
  // mUnit is the ferry-beacon weak lane read by Unit::GetTransportFerryBeacon (+0x158).
  static_assert(offsetof(CUnitCommand, mUnit) == 0x158, "CUnitCommand::mUnit offset must be 0x158");

  /**
   * Address: 0x0128E638 (FUN_0128E638, SimGetCommandQueueInsert)
   *
   * What it does:
   * Serializes one command record into a Lua table row and appends it to the
   * destination command-queue Lua array.
   */
  void SimGetCommandQueueInsert(LuaPlus::LuaObject& queueArray, const CUnitCommand& command);
} // namespace moho
