#include "moho/ai/CAiBuilderImpl.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/BVSet.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  using RebuildMapStorage = std::map<unsigned int, const RUnitBlueprint*>;
  using FactoryCommandQueueStorage = msvc8::vector<WeakPtr<CUnitCommand>>;

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Unit));
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

  [[nodiscard]] gpg::RType* CachedRebuildMapType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(RebuildMapStorage));
      if (!type) {
        type = ResolveTypeByAnyName(
          {"std::map<unsigned int,Moho::RUnitBlueprint const *>", "map<unsigned int,Moho::RUnitBlueprint const *>"}
        );
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedFactoryCommandQueueType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(FactoryCommandQueueStorage));
      if (!type) {
        type = ResolveTypeByAnyName(
          {"std::vector<Moho::WeakPtr<Moho::CUnitCommand>>", "vector<WeakPtr<CUnitCommand>>"}
        );
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeUnitRef(Unit* unit)
  {
    gpg::RRef out{};
    gpg::RType* const staticType = CachedUnitType();
    out.mObj = nullptr;
    out.mType = staticType;
    if (!unit || !staticType) {
      out.mObj = unit;
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*unit));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!isDerived) {
      out.mObj = unit;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(unit) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] Unit* ReadPointerUnit(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = CachedUnitType();
    if (!expectedType || !tracked.type) {
      return static_cast<Unit*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<Unit*>(upcast.mObj);
    }

    const char* const expected = expectedType->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "Unit",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  void WritePointerUnit(gpg::WriteArchive* const archive, Unit* const unit, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef objectRef = MakeUnitRef(unit);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  [[nodiscard]] std::uint32_t EncodeRebuildKey(const SOCellPos& cellPos) noexcept
  {
    const int x = static_cast<int>(cellPos.x);
    const int z = static_cast<int>(cellPos.z);
    return static_cast<std::uint32_t>(x * 10000 + z);
  }

  [[nodiscard]] SOCellPos DecodeRebuildKey(const std::uint32_t key) noexcept
  {
    const int signedKey = static_cast<std::int32_t>(key);
    SOCellPos cellPos{};
    cellPos.x = static_cast<std::int16_t>(signedKey / 10000);
    cellPos.z = static_cast<std::int16_t>(signedKey % 10000);
    return cellPos;
  }



  [[nodiscard]] bool HasSeabedOccupancy(const SFootprint& footprint) noexcept
  {
    const auto mask = static_cast<std::uint8_t>(footprint.mOccupancyCaps);
    return (mask & static_cast<std::uint8_t>(EOccupancyCaps::OC_SEABED)) != 0u;
  }

  [[nodiscard]] Entity* FindEntityById(CEntityDb* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      Entity* const entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
  }

  [[nodiscard]] bool IsTransportTargetEntityAllowed(const Entity* entity)
  {
    if (!entity) {
      return false;
    }

    return entity->IsInCategory("FERRYBEACON") || entity->IsInCategory("TRANSPORTATION") ||
           entity->IsInCategory("AIRSTAGINGPLATFORM");
  }

} // namespace

gpg::RType* CAiBuilderImpl::sType = nullptr;

/**
 * Address: 0x0059FAB0 (FUN_0059FAB0, default ctor)
 */
CAiBuilderImpl::CAiBuilderImpl()
  : mOwnerUnit(nullptr)
  , mIsFactory(0)
  , mIsOnTarget(1)
  , mFactoryQueueDirty(1)
  , mPad0B(0)
  , mAimTarget(Wm3::Vector3f::Zero())
  , mRebuildStructures{}
  , mFactoryCommands()
{

}

/**
 * Address: 0x0059F920 (FUN_0059F920, unit ctor)
 */
CAiBuilderImpl::CAiBuilderImpl(Unit* const unit)
  : mOwnerUnit(unit)
  , mIsFactory(0)
  , mIsOnTarget(1)
  , mFactoryQueueDirty(0)
  , mPad0B(0)
  , mAimTarget(Wm3::Vector3f::Zero())
  , mRebuildStructures{}
  , mFactoryCommands()
{

}

/**
 * Address: 0x0059FB50 (FUN_0059FB50, scalar deleting thunk)
 * Address: 0x0059F9C0 (FUN_0059F9C0, core dtor)
 */
CAiBuilderImpl::~CAiBuilderImpl()
{
  BuilderClearFactoryCommandQueue();
  // `mRebuildStructures`' teardown is `~map()`, which MSVC emits for the member.
}

/**
 * Address: 0x005A2460 (FUN_005A2460, Moho::CAiBuilderImpl::MemberDeserialize)
 *
 * What it does:
 * Reads builder runtime state from archive lanes and marks the command queue
 * dirty for post-load revalidation.
 */
void CAiBuilderImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  mOwnerUnit = ReadPointerUnit(archive, owner);

  bool value = false;
  archive->ReadBool(&value);
  mIsFactory = value ? 1u : 0u;
  archive->ReadBool(&value);
  mIsOnTarget = value ? 1u : 0u;

  if (gpg::RType* const vector3Type = CachedVector3fType()) {
    archive->Read(vector3Type, &mAimTarget, owner);
  }

  if (gpg::RType* const rebuildMapType = CachedRebuildMapType()) {
    archive->Read(rebuildMapType, &mRebuildStructures, owner);
  }

  if (gpg::RType* const commandQueueType = CachedFactoryCommandQueueType()) {
    archive->Read(commandQueueType, &mFactoryCommands, owner);
  }

  mFactoryQueueDirty = 1u;
}

// Addresses 0x005A1CE0/0x005A21E0 (the "ThunkA"/"ThunkB" serializer-load
// duplicates formerly modeled here) are dead: zero data_refs/call_edges for
// both, and no source-level caller anywhere in src/sdk/**.
// `CAiBuilderImplSerializer::Deserialize` (CAiBuilderImplSerializer.cpp,
// wired via that class's ctor) already calls
// `CAiBuilderImpl::MemberDeserialize` directly.

/**
 * Address: 0x005A2550 (FUN_005A2550, Moho::CAiBuilderImpl::MemberSerialize)
 *
 * What it does:
 * Writes builder runtime state to archive lanes.
 */
void CAiBuilderImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  WritePointerUnit(archive, mOwnerUnit, owner);
  archive->WriteBool(mIsFactory != 0u);
  archive->WriteBool(mIsOnTarget != 0u);

  if (gpg::RType* const vector3Type = CachedVector3fType()) {
    archive->Write(vector3Type, &mAimTarget, owner);
  }

  if (gpg::RType* const rebuildMapType = CachedRebuildMapType()) {
    archive->Write(rebuildMapType, &mRebuildStructures, owner);
  }

  if (gpg::RType* const commandQueueType = CachedFactoryCommandQueueType()) {
    archive->Write(commandQueueType, &mFactoryCommands, owner);
  }
}

/**
 * Address: 0x0059FAA0 (FUN_0059FAA0)
 */
bool CAiBuilderImpl::BuilderIsFactory() const
{
  return mIsFactory != 0;
}

/**
 * Address: 0x0059FA90 (FUN_0059FA90)
 */
void CAiBuilderImpl::BuilderSetIsFactory(const bool isFactory)
{
  mIsFactory = static_cast<std::uint8_t>(isFactory);
}

/**
 * Address: 0x0059EEF0 (FUN_0059EEF0)
 *
 * Ground truth (`FUN_0059EEF0.c`, `Moho::CAiBuilderImpl::IssueRallyPoint`)
 * re-derived term-by-term: the rotation matches the engine scalar-first
 * `Moho::QuatToMatrix` formula exactly, not the generic `Quaternion::Rotate`
 * (upstream WildMagic, `.w`-scalar `ToMat3()`) this replaces.
 */
void CAiBuilderImpl::BuilderSetUpInitialRally()
{
  if (!mOwnerUnit || !mOwnerUnit->SimulationRef) {
    return;
  }

  const RUnitBlueprint* const blueprint = mOwnerUnit->GetBlueprint();
  if (!blueprint) {
    return;
  }

  const VTransform& transform = mOwnerUnit->GetTransform();
  const Wm3::Vector3f localRally{blueprint->Economy.InitialRallyX, 0.0f, blueprint->Economy.InitialRallyZ};
  Wm3::Vector3f rotatedRally{};
  MultQuadVec(&rotatedRally, &localRally, &transform.orient_);
  const Wm3::Vector3f rallyWorldPos = transform.pos_ + rotatedRally;

  // Sim-internal issue, not the ICommandSink one. 0x0059F1D6 calls
  // `UNIT_IssueFactoryCommand(issueData, mUnit->mSim, entitySet, 1)` -
  // `IssueFactoryCommandToSelectedUnits` here - over a locally built
  // `EntitySetTemplate_Unit` holding just this factory. Routing it through
  // `Sim::IssueFactoryCommand` instead put it behind `ValidateNewCommandId`,
  // which reads the network command id this payload never carries: the rally
  // point was rejected every time with "ignoring issue of cmd id 0xffffffff
  // ... the id's source (255) is wrong (should be 0)", so a new factory came
  // up with no rally point at all.
  SEntitySetTemplateUnit factorySet{};
  (void)factorySet.AddUnit(mOwnerUnit);

  SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_Move);
  issueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
  issueData.mTarget.mEntityId = 0xF0000000u;
  issueData.mTarget.mPos = rallyWorldPos;

  (void)IssueFactoryCommandToSelectedUnits(mOwnerUnit->SimulationRef, factorySet, issueData, true);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F220 (FUN_0059F220)
 */
void CAiBuilderImpl::BuilderValidateFactoryCommandQueue()
{
  if (mIsFactory == 0) {
    return;
  }

  std::size_t index = 0;
  while (index < mFactoryCommands.size()) {
    CUnitCommand* const command = mFactoryCommands[index].GetObjectPtr();
    if (!command) {
      EraseWeakVectorEntry(mFactoryCommands, index);
      mFactoryQueueDirty = 1;
      continue;
    }

    if (command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
      ++index;
      continue;
    }

    bool shouldRemove = true;
    if (mOwnerUnit && mOwnerUnit->SimulationRef && command->mVarDat.mTarget1.mType == EAiTargetType::AITARGET_Entity) {
      const EntId targetId = static_cast<EntId>(command->mVarDat.mTarget1.mEntityId);
      Entity* const entity = FindEntityById(mOwnerUnit->SimulationRef->mEntityDB, targetId);
      shouldRemove = !IsTransportTargetEntityAllowed(entity);
    }

    if (!shouldRemove) {
      ++index;
      continue;
    }

    command->RemoveUnit(mOwnerUnit);
    EraseWeakVectorEntry(mFactoryCommands, index);
    mFactoryQueueDirty = 1;
  }

  if (BuilderIsFactoryQueueEmpty()) {
    BuilderSetUpInitialRally();
  }
}

/**
 * Address: 0x0059F440 (FUN_0059F440)
 */
bool CAiBuilderImpl::BuilderIsFactoryQueueEmpty() const
{
  return mFactoryCommands.empty();
}

/**
 * Address: 0x0059EED0 (FUN_0059EED0)
 */
bool CAiBuilderImpl::BuilderIsFactoryQueueDirty() const
{
  return mFactoryQueueDirty != 0;
}

/**
 * Address: 0x0059EEE0 (FUN_0059EEE0)
 */
void CAiBuilderImpl::BuilderSetFactoryQueueDirty(const bool dirty)
{
  mFactoryQueueDirty = static_cast<std::uint8_t>(dirty);
}

/**
 * Address: 0x0059F470 (FUN_0059F470)
 */
msvc8::vector<WeakPtr<CUnitCommand>>& CAiBuilderImpl::BuilderGetFactoryCommandQueue()
{
  return mFactoryCommands;
}

/**
 * Address: 0x0059F480 (FUN_0059F480)
 */
bool CAiBuilderImpl::BuilderIsBusy() const
{
  if (!mOwnerUnit || !mOwnerUnit->CommandQueue) {
    return false;
  }

  const CUnitCommandQueue* const queue = mOwnerUnit->CommandQueue;
  if (!queue || queue->mCommandVec.empty()) {
    return false;
  }

  const CUnitCommand* const command = queue->mCommandVec.front().GetObjectPtr();
  if (!command) {
    return false;
  }

  switch (command->mVarDat.mCmdType) {
  case EUnitCommandType::UNITCOMMAND_BuildFactory:
  case EUnitCommandType::UNITCOMMAND_BuildMobile:
  case EUnitCommandType::UNITCOMMAND_Script:
  case EUnitCommandType::UNITCOMMAND_Upgrade:
    return true;
  default:
    return false;
  }
}

/**
 * Address: 0x0059F4D0 (FUN_0059F4D0)
 */
void CAiBuilderImpl::BuilderAddFactoryCommand(CUnitCommand* const command, const int index)
{
  if (!command) {
    return;
  }

  command->AddUnit(mOwnerUnit, mFactoryCommands, index);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F500 (FUN_0059F500)
 */
bool CAiBuilderImpl::BuilderContainsCommand(CUnitCommand* const command)
{
  if (!command) {
    return false;
  }

  for (std::size_t i = 0; i < mFactoryCommands.size(); ++i) {
    if (mFactoryCommands[i].GetObjectPtr() == command) {
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x0059F540 (FUN_0059F540)
 */
CUnitCommand* CAiBuilderImpl::BuilderGetFactoryCommand(const int index)
{
  if (index < 0) {
    return nullptr;
  }

  const std::size_t idx = static_cast<std::size_t>(index);
  if (idx >= mFactoryCommands.size()) {
    return nullptr;
  }

  return mFactoryCommands[idx].GetObjectPtr();
}

/**
 * Address: 0x0059F580 (FUN_0059F580)
 */
void CAiBuilderImpl::BuilderRemoveFactoryCommand(CUnitCommand* const command)
{
  if (!command) {
    return;
  }

  command->RemoveUnit(mOwnerUnit, mFactoryCommands);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F5A0 (FUN_0059F5A0)
 */
void CAiBuilderImpl::BuilderClearFactoryCommandQueue()
{
  while (!mFactoryCommands.empty()) {
    CUnitCommand* const command = mFactoryCommands.back().GetObjectPtr();
    if (!command) {
      mFactoryCommands.pop_back();
      continue;
    }

    command->RemoveUnit(mOwnerUnit, mFactoryCommands);
  }

  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F600 (FUN_0059F600)
 */
void CAiBuilderImpl::BuilderSetAimTarget(const Wm3::Vector3f target)
{
  mAimTarget = target;
  if (mOwnerUnit && Wm3::Vector3f::LengthSq(target) > 0.0f) {
    mOwnerUnit->RunScript("OnPrepareArmToBuild");
  }
}

/**
 * Address: 0x0059F650 (FUN_0059F650)
 */
Wm3::Vector3f CAiBuilderImpl::BuilderGetAimTarget() const
{
  return mAimTarget;
}

/**
 * Address: 0x0059F670 (FUN_0059F670)
 */
void CAiBuilderImpl::BuilderSetOnTarget(const bool onTarget)
{
  mIsOnTarget = static_cast<std::uint8_t>(onTarget);
}

/**
 * Address: 0x0059F680 (FUN_0059F680)
 */
bool CAiBuilderImpl::BuilderGetOnTarget() const
{
  return mIsOnTarget != 0;
}

/**
 * Address: 0x0059F690 (FUN_0059F690)
 */
void CAiBuilderImpl::BuilderAddRebuildStructure(const SOCellPos& cellPos, const RUnitBlueprint* const blueprint)
{
  mRebuildStructures[EncodeRebuildKey(cellPos)] = blueprint;
}

/**
 * Address: 0x0059F6C0 (FUN_0059F6C0)
 */
void CAiBuilderImpl::BuilderRemoveRebuildStructure(const SOCellPos& cellPos)
{
  (void)mRebuildStructures.erase(EncodeRebuildKey(cellPos));
}

/**
 * Address: 0x0059F710 (FUN_0059F710)
 */
void CAiBuilderImpl::BuilderClearRebuildStructure()
{
  mRebuildStructures.clear();
}

/**
 * Address: 0x0059F740 (FUN_0059F740)
 */
const RUnitBlueprint* CAiBuilderImpl::BuilderGetNextRebuildStructure(SOCellPos& outCellPos)
{
  outCellPos = {0, 0};

  if (!mOwnerUnit || mRebuildStructures.empty()) {
    return nullptr;
  }

  const Sim* const sim = mOwnerUnit->SimulationRef;
  const STIMap* const mapData = sim ? sim->mMapData : nullptr;
  const CHeightField* const heightField = (mapData && mapData->mHeightField) ? mapData->mHeightField.get() : nullptr;
  const Wm3::Vector3f unitPos = mOwnerUnit->GetPosition();

  const RUnitBlueprint* bestBlueprint = nullptr;
  SOCellPos bestCell{0, 0};
  float bestDist = std::numeric_limits<float>::infinity();

  for (const auto& [encodedCell, blueprint] : mRebuildStructures) {
    if (!blueprint) {
      continue;
    }

    const SOCellPos cellPos = DecodeRebuildKey(encodedCell);
    const float centerX = static_cast<float>(cellPos.x) + static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f;
    const float centerZ = static_cast<float>(cellPos.z) + static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f;

    float centerY = 0.0f;
    if (heightField) {
      centerY = heightField->GetElevation(centerX, centerZ);
      if (!HasSeabedOccupancy(blueprint->mFootprint) && mapData && mapData->mWaterEnabled != 0 &&
          mapData->mWaterElevation > centerY) {
        centerY = mapData->mWaterElevation;
      }
    }

    const float dx = centerX - unitPos.x;
    const float dy = centerY - unitPos.y;
    const float dz = centerZ - unitPos.z;
    const float distSq = (dx * dx) + (dy * dy) + (dz * dz);

    if (distSq >= bestDist) {
      continue;
    }

    if (!sim || !sim->mOGrid) {
      continue;
    }

    if (OCCUPY_FootprintFits(*sim->mOGrid, cellPos, blueprint->mFootprint, EOccupancyCaps::OC_ANY) ==
        static_cast<EOccupancyCaps>(0u)) {
      continue;
    }

    bestDist = distSq;
    bestBlueprint = blueprint;
    bestCell = cellPos;
  }

  outCellPos = bestCell;
  return bestBlueprint;
}
