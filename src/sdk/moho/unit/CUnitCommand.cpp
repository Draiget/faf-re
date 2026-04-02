#include "CUnitCommand.h"

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "moho/ai/CAiFormationInstance.h"
#include "moho/command/CCommandDb.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/Entity.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/misc/CountedObject.h"
#include "moho/misc/WeakPtr.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  using CommandOwnerSlotNode = WeakPtr<CUnitCommand>;
  using BroadcasterOwnerSlotNode = WeakPtr<Broadcaster>;
  using EntityOwnerSlotNode = WeakPtr<Entity>;

  [[nodiscard]] bool IsUsableCommandUnitEntry(const CScriptObject* const entry) noexcept
  {
    return SCommandUnitSet::IsUsableEntry(entry);
  }

  static_assert(sizeof(CommandOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "CommandOwnerSlotNode size");
  static_assert(sizeof(BroadcasterOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "BroadcasterOwnerSlotNode size");
  static_assert(sizeof(EntityOwnerSlotNode) == sizeof(std::uintptr_t) * 2u, "EntityOwnerSlotNode size");

  constexpr std::uint32_t kNoTargetEntityId = 0xF0000000u;
  constexpr const char* kCommandTypeKey = "CommandType";
  constexpr const char* kXKey = "X";
  constexpr const char* kYKey = "Y";
  constexpr const char* kZKey = "Z";
  constexpr const char* kTargetIdKey = "TargetId";
  constexpr const char* kBlueprintIdKey = "BlueprintId";

  template <typename TValue>
  void SetCommandQueueField(LuaPlus::LuaObject& row, const char* key, const TValue& value);

  template <>
  void SetCommandQueueField<std::int32_t>(LuaPlus::LuaObject& row, const char* const key, const std::int32_t& value)
  {
    row.SetInteger(key, value);
  }

  template <>
  void SetCommandQueueField<float>(LuaPlus::LuaObject& row, const char* const key, const float& value)
  {
    row.SetNumber(key, value);
  }

  template <>
  void SetCommandQueueField<const char*>(LuaPlus::LuaObject& row, const char* const key, const char* const& value)
  {
    row.SetString(key, value ? value : "");
  }

  [[nodiscard]] const char* ResolveBlueprintId(const CUnitCommand& command) noexcept
  {
    const REntityBlueprint* const blueprint = command.mConstDat.blueprint;
    if (!blueprint) {
      return nullptr;
    }

    const char* const blueprintId = blueprint->mBlueprintId.c_str();
    return (blueprintId && blueprintId[0] != '\0') ? blueprintId : nullptr;
  }

  struct CUnitCommandDestroyRuntimeView
  {
    std::uint8_t pad_0000_0034[0x34];
    BroadcasterOwnerSlotNode broadcasterOwnerChainNode;
    std::uint8_t pad_003C_00F0[0xB4];
    CommandOwnerSlotNode unitSetOwnerChainNode;
    std::uint8_t pad_00F8_0118[0x20];
    CountedObject* formationObject;
    std::uint8_t pad_011C_0120[0x04];
    CommandOwnerSlotNode coordinatingOrdersOwnerChainNode;
    std::uint8_t pad_0128_0158[0x30];
    EntityOwnerSlotNode sidecarOwnerChainNode;
  };
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, broadcasterOwnerChainNode) == 0x34,
    "CUnitCommandDestroyRuntimeView::broadcasterOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, unitSetOwnerChainNode) == 0xF0,
    "CUnitCommandDestroyRuntimeView::unitSetOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, formationObject) == 0x118,
    "CUnitCommandDestroyRuntimeView::formationObject"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, coordinatingOrdersOwnerChainNode) == 0x120,
    "CUnitCommandDestroyRuntimeView::coordinatingOrdersOwnerChainNode"
  );
  static_assert(
    offsetof(CUnitCommandDestroyRuntimeView, sidecarOwnerChainNode) == 0x158,
    "CUnitCommandDestroyRuntimeView::sidecarOwnerChainNode"
  );

  void ReleaseIntrusiveRefcountedObject(CountedObject*& object)
  {
    if (!object) {
      return;
    }

    (void)object->ReleaseReference();
    object = nullptr;
  }

  void CopyIssueDataToVariablePayload(const SSTICommandIssueData& issueData, SSTICommandVariableData& variableData)
  {
    variableData = SSTICommandVariableData{};
    variableData.v1 = issueData.unk04;
    variableData.v2 = issueData.mIndex;
    variableData.mCmdType = issueData.mCommandType;
    variableData.mTarget1 = issueData.mTarget;
    variableData.mTarget2 = issueData.mTarget2;
    variableData.v14 = issueData.unk38;

    variableData.mCells.clear();
    variableData.mCells.reserve(issueData.mCells.Size());
    for (std::size_t i = 0; i < issueData.mCells.Size(); ++i) {
      variableData.mCells.push_back(issueData.mCells[i]);
    }

    variableData.v19 = issueData.unk64;
    variableData.v20 = issueData.unk68;
    variableData.mMaxCount = issueData.unk6C;
    variableData.mCount = issueData.unk70;
    variableData.v23 = issueData.unk74;
  }

} // namespace

CScriptObject* SCommandUnitSet::EntryFromUnit(Unit* const unit) noexcept
{
  if (!unit) {
    return nullptr;
  }

  auto* const raw = reinterpret_cast<std::uint8_t*>(unit);
  return reinterpret_cast<CScriptObject*>(raw + sizeof(IUnit));
}

Unit* SCommandUnitSet::UnitFromEntry(CScriptObject* const entry) noexcept
{
  return const_cast<Unit*>(UnitFromEntry(static_cast<const CScriptObject*>(entry)));
}

const Unit* SCommandUnitSet::UnitFromEntry(const CScriptObject* const entry) noexcept
{
  if (!entry) {
    return nullptr;
  }

  // Command unit-set stores CScriptObject subobject pointers for Unit entries.
  // Unit complete-object base is sizeof(IUnit) bytes before that subobject.
  const auto* const raw = reinterpret_cast<const std::uint8_t*>(entry);
  return reinterpret_cast<const Unit*>(raw - sizeof(IUnit));
}

EntId SCommandUnitSet::EntryEntityId(const CScriptObject* const entry) noexcept
{
  if (!entry || !SCommandUnitSet::IsUsableEntry(entry)) {
    return static_cast<EntId>(0x7FFFFFFF);
  }

  const Unit* const unit = UnitFromEntry(entry);
  return unit ? unit->GetEntityId() : static_cast<EntId>(0x7FFFFFFF);
}

std::size_t SCommandUnitSet::LowerBoundByEntityId(const EntId targetId) const noexcept
{
  std::size_t first = 0;
  std::size_t count = mVec.size();
  while (count != 0) {
    const std::size_t step = count / 2;
    const std::size_t probeIndex = first + step;
    const EntId probeId = EntryEntityId(mVec[probeIndex]);
    if (probeId < targetId) {
      first = probeIndex + 1;
      count -= step + 1;
    } else {
      count = step;
    }
  }

  return first;
}

bool SCommandUnitSet::InsertUnitSorted(Unit* const unit)
{
  if (!unit) {
    return false;
  }

  const EntId unitId = unit->GetEntityId();
  const std::size_t index = LowerBoundByEntityId(unitId);
  CScriptObject* const entry = EntryFromUnit(unit);
  const std::size_t size = mVec.size();

  if (index < size && mVec[index] == entry) {
    return false;
  }

  if (size == mVec.Capacity()) {
    mVec.Reserve(size != 0 ? (size * 2) : 4u);
  }

  CScriptObject** const begin = mVec.start_;
  if (size > index) {
    std::memmove(begin + index + 1, begin + index, (size - index) * sizeof(*begin));
  }

  begin[index] = entry;
  mVec.end_ = begin + size + 1;
  return true;
}

bool SCommandUnitSet::RemoveUnitSorted(Unit* const unit)
{
  const EntId unitId = unit ? unit->GetEntityId() : 0;
  const std::size_t index = LowerBoundByEntityId(unitId);
  const std::size_t size = mVec.size();
  if (index >= size) {
    return false;
  }

  CScriptObject* const expected = EntryFromUnit(unit);
  if (mVec[index] != expected) {
    return false;
  }

  CScriptObject** const begin = mVec.start_;
  if (index + 1 < size) {
    std::memmove(begin + index, begin + index + 1, (size - index - 1) * sizeof(*begin));
  }

  mVec.end_ = begin + size - 1;
  return true;
}

/**
 * Address: 0x006E81B0 (FUN_006E81B0, ??0CUnitCommand@Moho@@QAE@PAVSim@1@ABUSSTICommandIssueData@1@@Z)
 *
 * What it does:
 * Initializes one command from issue payload lanes, updates sim command
 * digest/counter state, and links coordinating-order relationships.
 */
CUnitCommand::CUnitCommand(Sim* const sim, const SSTICommandIssueData& issueData)
  : unk0(nullptr)
  , mSim(sim)
  , mConstDat{}
  , mVarDat{}
  , unk1(nullptr)
  , mUnitSet{}
  , mFormationInstance(nullptr)
  , mTarget{}
  , mInstanceSerial(0)
  , mHasPublishedCommandEvent(false)
  , mNeedsUpdate(true)
  , mUnknownFlag142(false)
  , mUnknownFlag143(false)
  , mCoordinatingOrders{}
  , mUnknownFlag154(false)
  , mUnit()
  , mArgs(issueData.mObject)
  , mUnknownTailInt(0)
{
  mPrev = this;
  mNext = this;

  mConstDat.cmd = issueData.nextCommandId;
  mConstDat.unk0 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(issueData.unk38));
  mConstDat.origin = issueData.mOri;
  mConstDat.unk1 = issueData.unk4C;
  mConstDat.blueprint = static_cast<REntityBlueprint*>(issueData.mBlueprint);
  mConstDat.unk2 = SCR_ToString(issueData.mObject);

  CopyIssueDataToVariablePayload(issueData, mVarDat);
  mUnitSet.mVec = gpg::core::FastVector<CScriptObject*>{};
  mTarget.DecodeFromSSTITarget(issueData.mTarget, sim);

  if (!sim) {
    return;
  }

  const std::uint32_t commandSerial = sim->mReserved98C;
  sim->mReserved98C = commandSerial + 1u;
  mInstanceSerial = static_cast<CmdId>(commandSerial);

  sim->Logf("Creating command 0x%08x, type=%d\n", mConstDat.cmd, static_cast<int>(mVarDat.mCmdType));
  sim->mContext.Update(&mConstDat.cmd, sizeof(mConstDat.cmd));
  const std::int32_t commandTypeValue = static_cast<std::int32_t>(mVarDat.mCmdType);
  sim->mContext.Update(&commandTypeValue, sizeof(commandTypeValue));

  if (!sim->mCommandDB || issueData.unk04 == -1) {
    return;
  }

  const auto it = sim->mCommandDB->commands.find(static_cast<CmdId>(issueData.unk04));
  if (it == sim->mCommandDB->commands.end()) {
    return;
  }

  CUnitCommand* const coordinatingCommand = &it->second;
  if (!coordinatingCommand) {
    return;
  }

  const msvc8::vector<WeakPtr<CUnitCommand>> coordinatingPeers = coordinatingCommand->GetCoordinatingOrdersSnapshot();
  for (const WeakPtr<CUnitCommand>& peerWeak : coordinatingPeers) {
    CUnitCommand* const peer = peerWeak.GetObjectPtr();
    if (!peer || peer == this) {
      continue;
    }

    peer->LinkCoordinatingOrder(this);
    LinkCoordinatingOrder(peer);
  }

  coordinatingCommand->LinkCoordinatingOrder(this);
  LinkCoordinatingOrder(coordinatingCommand);
}

/**
 * Address: 0x006E7D40 (FUN_006E7D40, ?GetCoordinateWith@CUnitCommand@Moho@@QBE?AV?$vector@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@V?$allocator@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@@std@@@std@@XZ)
 *
 * What it does:
 * Returns a by-value snapshot of this command's coordinating-order weak links.
 */
msvc8::vector<WeakPtr<CUnitCommand>> CUnitCommand::GetCoordinatingOrdersSnapshot() const
{
  return mCoordinatingOrders;
}

/**
 * Address: 0x006E8B40 (FUN_006E8B40)
 *
 * What it does:
 * Adds `unit` into this command's unit-set and inserts this command weak-ref
 * into `queue` at `index` (negative index inserts relative to queue end).
 */
void CUnitCommand::AddUnit(Unit* const unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue, const int index)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return;
  }

  if (!mUnitSet.InsertUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;
  InsertWeakPtrVectorObjectAt(queue, this, NormalizeWeakPtrVectorInsertIndex(queue, index));

  if (mFormationInstance) {
    mFormationInstance->AddUnit(unit);
  }
}

/**
 * Address: 0x006E8C20 (FUN_006E8C20)
 *
 * What it does:
 * Removes `unit` from this command's unit-set and removes this command weak-ref
 * from the provided queue.
 */
void CUnitCommand::RemoveUnit(Unit* const unit, msvc8::vector<WeakPtr<CUnitCommand>>& queue)
{
  if (!mUnitSet.RemoveUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;

  if (mFormationInstance) {
    mFormationInstance->RemoveUnit(unit);
    if (mFormationInstance && mFormationInstance->UnitCount() == 0) {
      CountedObject* formationObject = reinterpret_cast<CountedObject*>(mFormationInstance);
      ReleaseIntrusiveRefcountedObject(formationObject);
      mFormationInstance = nullptr;
    }
  }

  (void)RemoveWeakPtrVectorObject(queue, this);
}

/**
 * Address: 0x006E8D10 (FUN_006E8D10)
 *
 * What it does:
 * Removes `unit` from this command's unit-set without touching queue links.
 */
void CUnitCommand::RemoveUnit(Unit* const unit)
{
  if (!mUnitSet.RemoveUnitSorted(unit)) {
    return;
  }

  mNeedsUpdate = true;

  if (mFormationInstance) {
    mFormationInstance->RemoveUnit(unit);
    if (mFormationInstance && mFormationInstance->UnitCount() == 0) {
      CountedObject* formationObject = reinterpret_cast<CountedObject*>(mFormationInstance);
      ReleaseIntrusiveRefcountedObject(formationObject);
      mFormationInstance = nullptr;
    }
  }
}

// 0x006F1650
void CUnitCommand::IncreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  const int newCount = mVarDat.mCount + amount;

  mVarDat.mCount = newCount;
  if (newCount > mVarDat.mMaxCount) {
    mVarDat.mMaxCount = newCount;
  }

  mNeedsUpdate = true;
}

// 0x006F16A0
void CUnitCommand::DecreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  int newCount = mVarDat.mCount - amount;
  if (newCount < 0) {
    newCount = 0;
  }

  mVarDat.mCount = newCount;
  mNeedsUpdate = true;
}

// 0x006E8820
void CUnitCommand::SetTarget(const CAiTarget& target)
{
  mTarget = target;
  mTarget.EncodeToSSTITarget(mVarDat.mTarget1);
  mNeedsUpdate = true;
}

/**
 * Address: 0x005BF810 (FUN_005BF810)
 *
 * What it does:
 * Compatibility forwarder for legacy callsites that still dispatch the recon
 * blip refresh slot through `CUnitCommand`.
 */
void CUnitCommand::RefreshBlipState()
{
  auto* const blip = reinterpret_cast<ReconBlip*>(this);
  if (!blip) {
    return;
  }

  blip->Refresh();
}

/**
 * Address: 0x006E8500 (FUN_006E8500)
 *
 * What it does:
 * Performs CUnitCommand teardown: unlinks intrusive nodes, releases
 * coordinating-order/formation references, clears command-unit vectors, and
 * resets command-owned transient payload storage.
 */
void CUnitCommand::DestroyInternal()
{
  auto& runtime = *reinterpret_cast<CUnitCommandDestroyRuntimeView*>(this);

  // +0x158/+0x15C: intrusive weak-owner link pair used by command sidecar ownership.
  auto& sidecarLink = runtime.sidecarOwnerChainNode;
  Entity* const sidecarEntity = sidecarLink.GetObjectPtr();
  if (sidecarEntity) {
    sidecarEntity->Destroy();
    sidecarLink.UnlinkFromOwnerChain();
    sidecarLink.ClearLinkState();
  }

  mArgs = LuaPlus::LuaObject{};

  // +0x148..+0x154: coordinating-order vector storage (8-byte owner-link elements).
  mCoordinatingOrders = msvc8::vector<WeakPtr<CUnitCommand>>{};

  // +0x120 list node mirrors binary helper 0x0057D490 unlink shape.
  runtime.coordinatingOrdersOwnerChainNode.UnlinkFromOwnerChain();

  // +0x118 intrusive-refcounted formation object.
  ReleaseIntrusiveRefcountedObject(runtime.formationObject);

  // +0x0F8 command unit-set vector payload.
  mUnitSet.mVec = gpg::core::FastVector<CScriptObject*>{};
  runtime.unitSetOwnerChainNode.UnlinkFromOwnerChain();

  // +0x0068 legacy msvc8::string payload in constant command data.
  mConstDat.unk2 = msvc8::string{};

  // +0x0034 broadcaster/list base slice.
  runtime.broadcasterOwnerChainNode.UnlinkFromOwnerChain();
}

/**
 * Address: 0x006E8DC0 (FUN_006E8DC0)
 *
 * What it does:
 * Rebuilds published command-event membership from the live command-unit set
 * and toggles publish state for empty/non-empty results.
 */
void CUnitCommand::RefreshPublishedCommandEvent(const bool forceRefresh, SSyncData* const syncData)
{
  if (!mNeedsUpdate && !forceRefresh) {
    return;
  }

  mNeedsUpdate = false;
  auto& publishedUnitEntityIds = mVarDat.mEntIds;

  if (mUnitSet.mVec.empty()) {
    if (mHasPublishedCommandEvent) {
      if (syncData) {
        syncData->QueuePendingCommandEventRemoval(mConstDat.cmd);
      }
      mHasPublishedCommandEvent = false;
    }
    return;
  }

  publishedUnitEntityIds = msvc8::vector<EntId>{};
  for (CScriptObject* const entry : mUnitSet.mVec) {
    if (!IsUsableCommandUnitEntry(entry)) {
      continue;
    }

    Unit* const unit = SCommandUnitSet::UnitFromEntry(entry);
    if (!unit || unit->mVisibilityState == 0u) {
      continue;
    }

    publishedUnitEntityIds.push_back(unit->id_);
  }

  if (publishedUnitEntityIds.empty()) {
    if (mHasPublishedCommandEvent) {
      if (syncData) {
        syncData->QueuePendingCommandEventRemoval(mConstDat.cmd);
      }
      mHasPublishedCommandEvent = false;
    }
    return;
  }

  // 0x006E7BD0/0x006E9360/0x006E7C50/0x006E93F0 event blob helpers remain
  // in the unresolved event-dispatch chain; keep publish state transitions exact.
  if (!mHasPublishedCommandEvent) {
    mHasPublishedCommandEvent = true;
  }
}

/**
 * Address: 0x006E9000 (FUN_006E9000)
 *
 * What it does:
 * Links compatible commands into each other's coordinating-order vector.
 */
void CUnitCommand::LinkCoordinatingOrder(CUnitCommand* const other)
{
  if (!other) {
    return;
  }

  if (other->mVarDat.mCmdType != mVarDat.mCmdType) {
    return;
  }

  auto*& ownerSlotHead = reinterpret_cast<CommandOwnerSlotNode*&>(this->Broadcaster::mNext);
  CommandOwnerSlotNode temp{};
  temp.ownerLinkSlot = &ownerSlotHead;
  temp.nextInOwner = ownerSlotHead;
  ownerSlotHead = &temp;

  auto& coordinatingOrders = other->mCoordinatingOrders;
  coordinatingOrders.push_back(temp);
  temp.UnlinkFromOwnerChain();
}

/**
 * Address: 0x0128E638 (FUN_0128E638, SimGetCommandQueueInsert)
 *
 * What it does:
 * Builds one command-queue Lua row from `command` and appends it to
 * `queueArray`.
 */
void moho::SimGetCommandQueueInsert(LuaPlus::LuaObject& queueArray, const CUnitCommand& command)
{
  LuaPlus::LuaState* const state = queueArray.GetActiveState();
  if (!state) {
    return;
  }

  LuaPlus::LuaObject row(state);
  row.AssignNewTable(state, 0, 0);

  SetCommandQueueField<std::int32_t>(row, kCommandTypeKey, static_cast<std::int32_t>(command.mVarDat.mCmdType));
  SetCommandQueueField<float>(row, kXKey, command.mVarDat.mTarget1.mPos.x);
  SetCommandQueueField<float>(row, kYKey, command.mVarDat.mTarget1.mPos.y);
  SetCommandQueueField<float>(row, kZKey, command.mVarDat.mTarget1.mPos.z);

  const std::uint32_t targetEntityId = command.mVarDat.mTarget1.mEntityId;
  if (targetEntityId != kNoTargetEntityId) {
    char targetIdText[0x10] = {};
    std::snprintf(targetIdText, sizeof(targetIdText), "%d", static_cast<std::int32_t>(targetEntityId));
    SetCommandQueueField<const char*>(row, kTargetIdKey, targetIdText);
  }

  if (const char* const blueprintId = ResolveBlueprintId(command)) {
    SetCommandQueueField<const char*>(row, kBlueprintIdKey, blueprintId);
  }

  queueArray.SetObject(queueArray.GetN() + 1, row);
}
