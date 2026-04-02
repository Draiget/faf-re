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
  class RType;
  class WriteArchive;
}

namespace moho
{
  class Unit;
  class CAiFormationInstance;
  class Sim;
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
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006E81B0 (FUN_006E81B0, ??0CUnitCommand@Moho@@QAE@PAVSim@1@ABUSSTICommandIssueData@1@@Z)
     *
     * What it does:
     * Initializes one command from issue payload lanes, updates sim command
     * digest/counter state, and links coordinating-order relationships.
     */
    CUnitCommand(Sim* sim, const SSTICommandIssueData& issueData);

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
     *
     * What it does:
     * Loads the serialized command payload lanes into this command instance.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCommand* command, int version);

    /**
     * Address: 0x006ECE20 (FUN_006ECE20, Moho::CUnitCommand::MemberSerialize)
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
     * Address: 0x005BF810 (FUN_005BF810)
     *
     * What it does:
     * Refreshes cached command blip/transform state for the current frame.
     */
    void RefreshBlipState();

  private:
    friend class CUnitCommandConstruct;

    /**
     * Address: 0x006E8500 (FUN_006E8500)
     *
     * Internal teardown used by the deleting destructor.
     */
    void DestroyInternal();

    /**
     * Address: 0x006E8DC0 (FUN_006E8DC0)
     *
     * Rebuilds cached unit/event payload state when pending updates exist.
     */
    void RefreshPublishedCommandEvent(bool forceRefresh, SSyncData* syncData);

    /**
     * Address: 0x006E9000 (FUN_006E9000)
     *
     * Links compatible commands into the coordinating-order ring.
     */
    void LinkCoordinatingOrder(CUnitCommand* other);

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
