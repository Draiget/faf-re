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

    gpg::core::FastVector<CScriptObject*> mVec;
  };

  class CUnitCommand : public Broadcaster
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;
    [[nodiscard]] static gpg::RType* StaticGetClass();
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x006E7D10 (FUN_006E7D10, Moho::CUnitCommand::GetDerivedObjectRef)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef();

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
     * Address: 0x006F1650
     * @param amount
     */
    void IncreaseCount(int amount);

    /**
     * Address: 0x006F16A0
     * @param amount
     */
    void DecreaseCount(int amount);

    /**
     * Address: 0x006E8820
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
     * Internal teardown used by the deleting destructor.
     */
    void DestroyInternal();

    /**
     * Address: 0x006E8140 (FUN_006E8140, Moho::CUnitCommand::dtr)
     *
     * What it does:
     * Executes non-deleting teardown and conditionally frees object storage
     * when `deleteFlag & 1` is set.
     */
    static CScriptObject* DestroyWithDeleteFlag(CScriptObject* object, std::uint8_t deleteFlag);

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
    // Likely list/sentinel related storage near +0xF0/+0xF4.
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
    boost::weak_ptr<Unit> mUnit;
    LuaPlus::LuaObject mArgs;
    int32_t mUnknownTailInt;
  };

#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(sizeof(CUnitCommand) == 0x178, "CUnitCommand size must be 0x178");
#endif

  /**
   * Address: 0x0128E638 (FUN_0128E638, SimGetCommandQueueInsert)
   *
   * What it does:
   * Serializes one command record into a Lua table row and appends it to the
   * destination command-queue Lua array.
   */
  void SimGetCommandQueueInsert(LuaPlus::LuaObject& queueArray, const CUnitCommand& command);
} // namespace moho
