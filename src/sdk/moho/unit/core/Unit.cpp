// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/Unit.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <new>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/StatItem.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"

using namespace moho;

namespace
{
  // Guard condition recovered from Unit::ToggleScriptBit: state 14 == UNITSTATE_Attached.
  constexpr EUnitState kTransportScriptBitGuardState = UNITSTATE_Attached;
  constexpr std::uint32_t kCommandCapPause = 0x00020000u;  // RULEUCC_Pause
  constexpr std::uint32_t kToggleCapGeneric = 0x00000040u; // RULEUTC_GenericToggle

  [[nodiscard]] std::int32_t PickUniformIndexFromU32(const std::uint32_t randomValue, const std::uint32_t count) noexcept
  {
    const std::uint64_t product = static_cast<std::uint64_t>(randomValue) * static_cast<std::uint64_t>(count);
    return static_cast<std::int32_t>(product >> 32u);
  }

  [[nodiscard]] bool HasFootprintFlag(const EFootprintFlags value, const EFootprintFlags flag) noexcept
  {
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
  }

  [[nodiscard]] Wm3::Vector3f ForwardXZ(const Unit& unit) noexcept
  {
    Wm3::Vector3f forward = unit.GetTransform().orient_.Rotate({0.0f, 0.0f, 1.0f});
    forward.y = 0.0f;
    return Wm3::Vector3f::NormalizeOrZero(forward);
  }

  struct CollisionDBRect
  {
    std::uint16_t xPos;
    std::uint16_t zPos;
    std::uint16_t xSize;
    std::uint16_t zSize;
  };

  [[nodiscard]] CollisionDBRect COORDS_OgridRectToCollisionRect(const gpg::Rect2i& ogridRect) noexcept
  {
    // Address: 0x004FCAA0 (FUN_004FCAA0)
    const std::int32_t xPos = std::clamp(ogridRect.x0 >> 2, 0, 0xFFFF);
    const std::int32_t zPos = std::clamp(ogridRect.z0 >> 2, 0, 0xFFFF);
    const std::int32_t xEnd = (ogridRect.x1 + 3) >> 2;
    const std::int32_t zEnd = (ogridRect.z1 + 3) >> 2;

    CollisionDBRect collisionRect{};
    collisionRect.xPos = static_cast<std::uint16_t>(xPos);
    collisionRect.zPos = static_cast<std::uint16_t>(zPos);

    const std::int32_t maxXSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.xPos);
    const std::int32_t maxZSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.zPos);
    const std::int32_t xSpan =
      std::clamp(xEnd - static_cast<std::int32_t>(collisionRect.xPos), std::int32_t{1}, maxXSpan);
    const std::int32_t zSpan =
      std::clamp(zEnd - static_cast<std::int32_t>(collisionRect.zPos), std::int32_t{1}, maxZSpan);

    collisionRect.xSize = static_cast<std::uint16_t>(xSpan);
    collisionRect.zSize = static_cast<std::uint16_t>(zSpan);
    return collisionRect;
  }

  [[nodiscard]] bool IsCollisionRectEquivalentToZero(const gpg::Rect2i& ogridRect) noexcept
  {
    const gpg::Rect2i zeroRect{};
    const CollisionDBRect currentCollisionRect = COORDS_OgridRectToCollisionRect(ogridRect);
    const CollisionDBRect zeroCollisionRect = COORDS_OgridRectToCollisionRect(zeroRect);
    return currentCollisionRect.xPos == zeroCollisionRect.xPos &&
      currentCollisionRect.zPos == zeroCollisionRect.zPos &&
      currentCollisionRect.xSize == zeroCollisionRect.xSize &&
      currentCollisionRect.zSize == zeroCollisionRect.zSize;
  }

  [[nodiscard]] gpg::Rect2i GetReservedOgridRect(const Unit& unit) noexcept
  {
    return {
      unit.ReservedOgridRectMinX,
      unit.ReservedOgridRectMinZ,
      unit.ReservedOgridRectMaxX,
      unit.ReservedOgridRectMaxZ,
    };
  }

  void FillReservedOgridRect(Unit& unit, const bool occupied) noexcept
  {
    if (!unit.SimulationRef || !unit.SimulationRef->mOGrid) {
      return;
    }

    const gpg::Rect2i ogridRect = GetReservedOgridRect(unit);
    unit.SimulationRef->mOGrid->mOccupation.FillRect(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      occupied
    );
  }

  /**
   * Address: 0x0062EAC0 (FUN_0062EAC0, func_UnitMoreInLineToOther)
   */
  [[nodiscard]] const Unit* UnitMoreInLineToOther(const Unit* const a1, const Unit* const a2) noexcept
  {
    if (!a1 || !a2) {
      return nullptr;
    }

    const Wm3::Vector3f a2Forward = ForwardXZ(*a2);
    const Wm3::Vector3f a1Forward = ForwardXZ(*a1);
    const Wm3::Vector3f a2ToA1 = Wm3::Vector3f::NormalizeOrZero(a1->GetPosition() - a2->GetPosition());
    const Wm3::Vector3f a1ToA2 = Wm3::Vector3f::NormalizeOrZero(a2->GetPosition() - a1->GetPosition());

    const float a2Alignment = Wm3::Vector3f::Dot(a2ToA1, a2Forward);
    const float a1Alignment = Wm3::Vector3f::Dot(a1ToA2, a1Forward);
    if (a2Alignment <= 0.0f && a1Alignment <= 0.0f) {
      return nullptr;
    }
    return (a2Alignment <= a1Alignment) ? a2 : a1;
  }

  class ExtraDataPairBuffer
  {
  public:
    explicit ExtraDataPairBuffer(SExtraUnitData* out) noexcept
      : out_(out)
    {}

    [[nodiscard]] SExtraUnitDataPair* begin() const noexcept
    {
      return out_ ? out_->pairsBegin : nullptr;
    }

    [[nodiscard]] SExtraUnitDataPair* end() const noexcept
    {
      return out_ ? out_->pairsEnd : nullptr;
    }

    [[nodiscard]] bool push_back(const SExtraUnitDataPair& pair) noexcept
    {
      if (!out_) {
        return false;
      }

      if (out_->pairsEnd == out_->pairsCapacityEnd) {
        const std::size_t nextCount = count() + 1u;
        if (!reserve(nextCount)) {
          return false;
        }
      }

      *out_->pairsEnd++ = pair;
      return true;
    }

  private:
    [[nodiscard]] std::size_t count() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsEnd - out_->pairsBegin);
    }

    [[nodiscard]] std::size_t capacity() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsCapacityEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsCapacityEnd - out_->pairsBegin);
    }

    [[nodiscard]] bool reserve(const std::size_t requiredCapacity) noexcept
    {
      const std::size_t oldCapacity = capacity();
      if (oldCapacity >= requiredCapacity) {
        return true;
      }

      std::size_t newCapacity = oldCapacity == 0u ? 4u : oldCapacity;
      while (newCapacity < requiredCapacity) {
        newCapacity *= 2u;
      }

      const std::size_t oldCount = count();
      auto* const newStorage =
        static_cast<SExtraUnitDataPair*>(::operator new(newCapacity * sizeof(SExtraUnitDataPair), std::nothrow));
      if (!newStorage) {
        return false;
      }

      if (oldCount != 0u) {
        std::copy_n(out_->pairsBegin, oldCount, newStorage);
      }

      auto* const oldStorage = out_->pairsBegin;
      auto* const inlineStorage = out_->pairsInlineBegin ? out_->pairsInlineBegin : &out_->inlinePair;
      if (oldStorage && oldStorage != inlineStorage) {
        ::operator delete(oldStorage);
      }
      out_->pairsBegin = newStorage;
      out_->pairsEnd = newStorage + oldCount;
      out_->pairsCapacityEnd = newStorage + newCapacity;
      return true;
    }

  private:
    SExtraUnitData* out_;
  };
} // namespace

void SBeatResourceAccumulators::Clear() noexcept
{
  maintenanceEnergy = 0.0f;
  maintenanceMass = 0.0f;
  resourcesSpentEnergy = 0.0f;
  resourcesSpentMass = 0.0f;
}

bool Unit::NeedsKillCleanup() const noexcept
{
  return mNeedsKillCleanup;
}

void Unit::ClearBeatResourceAccumulators() noexcept
{
  mBeatResourceAccumulators.Clear();
}

CIntel* Unit::GetIntelManager() noexcept
{
  return mIntelManager;
}

CIntel const* Unit::GetIntelManager() const noexcept
{
  return mIntelManager;
}

SSTIUnitVariableData& Unit::VarDat() noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData*>(mVarDatHead);
}

SSTIUnitVariableData const& Unit::VarDat() const noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData const*>(mVarDatHead);
}

// 0x006A4BC0
Unit const* Unit::IsUnit() const
{
  return this;
}

// 0x006A4BB0
Unit* Unit::IsUnit()
{
  return this;
}

// 0x006A48E0
UserUnit const* Unit::IsUserUnit() const
{
  return nullptr;
}

// 0x006A48D0
UserUnit* Unit::IsUserUnit()
{
  return nullptr;
}

// 0x006A49A0
EntId Unit::GetEntityId() const
{
  return id_;
}

// 0x006A49B0
Wm3::Vec3f const& Unit::GetPosition() const
{
  return GetPositionWm3();
}

// 0x006A49C0
VTransform const& Unit::GetTransform() const
{
  return GetTransformWm3();
}

// 0x006A8B20
RUnitBlueprint const* Unit::GetBlueprint() const
{
  const REntityBlueprint* const blueprint = BluePrint;
  return blueprint ? blueprint->IsUnitBlueprint() : nullptr;
}

/**
 * Address: 0x006AAF50 (?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
 * the list is empty. Returns true on all paths.
 */
bool Unit::PickTargetPoint(std::int32_t& outTargetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  const std::uint32_t targetBoneCount =
    (blueprint != nullptr) ? static_cast<std::uint32_t>(blueprint->AI.TargetBones.size()) : 0u;

  if (targetBoneCount == 0u || !SimulationRef || !SimulationRef->mRngState) {
    outTargetPoint = -1;
    return true;
  }

  const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
  outTargetPoint = PickUniformIndexFromU32(randomValue, targetBoneCount);
  return true;
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

// 0x006A8B30
float Unit::CalcTransportLoadFactor() const
{
  return 1.0f;
}

// 0x006A49F0
bool Unit::IsDead() const
{
  return Dead != 0;
}

// 0x006A4A00
bool Unit::DestroyQueued() const
{
  return DestroyQueuedFlag != 0;
}

// 0x006A4A10
bool Unit::IsMobile() const
{
  return UnitMotion != nullptr;
}

// 0x006A4A20
bool Unit::IsBeingBuilt() const
{
  return BeingBuilt != 0;
}

// 0x006A7DC0
bool Unit::IsNavigatorIdle() const
{
  return !AiNavigator || AiNavigator->GetStatus() == 0;
}

// 0x006A4AF0
bool Unit::IsUnitState(const EUnitState state) const
{
  const std::uint32_t bit = static_cast<std::uint32_t>(state);
  if (bit >= 64u) {
    return false;
  }
  return (UnitStateMask & (1ull << bit)) != 0ull;
}

/**
 * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
 */
Unit* Unit::GetGuardedUnit() const
{
  return GuardedUnitRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
 */
bool Unit::IsHigherPriorityThan(const Unit* const other) const
{
  if (!other) {
    return true;
  }

  if (IsUnitState(UNITSTATE_Immobile) || IsUnitState(UNITSTATE_Upgrading)) {
    return true;
  }
  if (other->IsUnitState(UNITSTATE_Immobile) || other->IsUnitState(UNITSTATE_Upgrading)) {
    return false;
  }

  if (mIsNaval) {
    if (!other->mIsNaval) {
      return true;
    }
  } else if (other->mIsNaval) {
    return false;
  }

  const bool thisIgnoreStructures = HasFootprintFlag(GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  const bool otherIgnoreStructures =
    HasFootprintFlag(other->GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  if (thisIgnoreStructures) {
    if (!otherIgnoreStructures) {
      return true;
    }
  } else if (otherIgnoreStructures) {
    return false;
  }

  if (const RUnitBlueprint* const blueprint = GetBlueprint()) {
    if (blueprint->Air.CanFly && mCurrentLayer != LAYER_Air) {
      return true;
    }
  }
  if (const RUnitBlueprint* const blueprint = other->GetBlueprint()) {
    if (blueprint->Air.CanFly && other->mCurrentLayer != LAYER_Air) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_WaitingForTransport) && !other->IsUnitState(UNITSTATE_WaitingForTransport)) {
    return true;
  }

  if (GetGuardedUnit() == other) {
    return false;
  }
  if (other->GetGuardedUnit() == this) {
    return true;
  }

  bool inSharedFormation = false;
  if (mInfoCache.mFormationLayer && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer) {
    inSharedFormation = true;

    const Unit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
    if (formationLead == this) {
      return true;
    }
    if (formationLead == other) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_Moving) && !other->IsUnitState(UNITSTATE_Moving)) {
    return false;
  }
  if (!IsUnitState(UNITSTATE_Moving) && other->IsUnitState(UNITSTATE_Moving)) {
    return true;
  }

  if (inSharedFormation) {
    if (mInfoCache.mFormationPriorityOrder != other->mInfoCache.mFormationPriorityOrder) {
      return mInfoCache.mFormationPriorityOrder < other->mInfoCache.mFormationPriorityOrder;
    }
    return other->mInfoCache.mFormationDistanceMetric > mInfoCache.mFormationDistanceMetric;
  }

  const SFootprint& thisFootprint = GetFootprint();
  const SFootprint& otherFootprint = other->GetFootprint();
  const std::uint8_t thisFootprintSize = std::max(thisFootprint.mSizeX, thisFootprint.mSizeZ);
  const std::uint8_t otherFootprintSize = std::max(otherFootprint.mSizeX, otherFootprint.mSizeZ);
  if (thisFootprintSize > otherFootprintSize) {
    return true;
  }
  if (thisFootprintSize != otherFootprintSize) {
    return false;
  }

  if (const Unit* const moreInLine = UnitMoreInLineToOther(other, this)) {
    return moreInLine == this;
  }

  return static_cast<std::uint32_t>(GetEntityId()) < static_cast<std::uint32_t>(other->GetEntityId());
}

/**
 * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
 */
void Unit::ReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  FreeOgridRect();

  ReservedOgridRectMinX = ogridRect.x0;
  ReservedOgridRectMinZ = ogridRect.z0;
  ReservedOgridRectMaxX = ogridRect.x1;
  ReservedOgridRectMaxZ = ogridRect.z1;

  FillReservedOgridRect(*this, true);
}

/**
 * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
 */
void Unit::FreeOgridRect()
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  if (!IsCollisionRectEquivalentToZero(reservedRect)) {
    FillReservedOgridRect(*this, false);
  }

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;
}

/**
 * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
 */
bool Unit::CanReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  const bool hadReservation = !IsCollisionRectEquivalentToZero(reservedRect);
  if (hadReservation) {
    FillReservedOgridRect(*this, false);
  }

  bool canReserve = true;
  if (SimulationRef && SimulationRef->mOGrid) {
    canReserve = !SimulationRef->mOGrid->mOccupation.GetRectOr(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      true
    );
  }

  if (hadReservation) {
    FillReservedOgridRect(*this, true);
  }

  return canReserve;
}

// 0x006A4990
UnitAttributes& Unit::GetAttributes()
{
  return Attributes;
}

// 0x006A4980
UnitAttributes const& Unit::GetAttributes() const
{
  return Attributes;
}

// 0x006A4B90
StatItem* Unit::GetStat(gpg::StrArg name, const std::string&)
{
  return moho::ResolveStatString(mConstDat.mStatsRoot, name);
}

// 0x006A4B70
StatItem* Unit::GetStat(gpg::StrArg name, const float&)
{
  return moho::ResolveStatFloat(mConstDat.mStatsRoot, name);
}

// 0x006A4B50
StatItem* Unit::GetStat(gpg::StrArg name, const int&)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot, name, 1);
}

// 0x006A4B30
StatItem* Unit::GetStat(gpg::StrArg name)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot, name, 0);
}

// 0x006A73A0
void Unit::SetAutoMode(const bool enabled)
{
  AutoMode = enabled;
  CallbackStr(enabled ? "OnAutoModeOn" : "OnAutoModeOff");
}

// 0x006A73E0
void Unit::SetAutoSurfaceMode(const bool enabled)
{
  AutoSurfaceMode = enabled;
}

// 0x006A4A30
bool Unit::IsAutoMode() const
{
  return AutoMode;
}

// 0x006A4A40
bool Unit::IsAutoSurfaceMode() const
{
  return AutoSurfaceMode;
}

// 0x006A4A50
void Unit::SetCustomName(const std::string name)
{
  CustomName = name.c_str();
}

// 0x006A4AB0
std::string Unit::GetCustomName() const
{
  return std::string(CustomName.c_str(), CustomName.size());
}

// 0x006A8790
void Unit::KillCleanup()
{
  mNeedsKillCleanup = false;

  if (AiAttacker) {
    AiAttacker->WeaponsOnDestroy();
  }

  auto* commandDispatch = AiCommandDispatch;
  AiCommandDispatch = nullptr;
  delete commandDispatch;

  if (CommandQueue) {
    CommandQueue->MarkForUnitKillCleanup();
  }

  auto* attacker = AiAttacker;
  AiAttacker = nullptr;
  delete attacker;

  auto* transport = AiTransport;
  AiTransport = nullptr;
  delete transport;

  auto* navigator = AiNavigator;
  AiNavigator = nullptr;
  delete navigator;

  auto* steering = AiSteering;
  AiSteering = nullptr;
  delete steering;

  auto* builder = AiBuilder;
  AiBuilder = nullptr;
  delete builder;

  auto* siloBuild = AiSiloBuild;
  AiSiloBuild = nullptr;
  delete siloBuild;

  CUnitCommandQueue* queue = CommandQueue;
  CommandQueue = nullptr;
  if (queue) {
    queue->DestroyForUnitKillCleanup();
    ::operator delete(queue);
  }
}

/**
 * Address: 0x006ACB20 (FUN_006ACB20)
 *
 * What it does:
 * Appends unit-side sync extra-data records into the provided output buffer.
 */
void Unit::GetExtraData(SExtraUnitData* out) const
{
  if (!out) {
    return;
  }
  ExtraDataPairBuffer pairBuffer{out};

  if (AiAttacker) {
    const int count = AiAttacker->GetWeaponCount();
    for (int i = 0; i < count; ++i) {
      CAiAttackerImpl::WeaponExtraData weaponExtra{};
      if (!AiAttacker->TryGetWeaponExtraData(i, weaponExtra)) {
        continue;
      }

      SExtraUnitDataPair pair{};
      pair.key = weaponExtra.key;
      pair.value = CAiAttackerImpl::ReadExtraDataValue(weaponExtra.ref);
      (void)pairBuffer.push_back(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      (void)pairBuffer.push_back(pair);
    }
  }

  out->unitEntityId = id_;
}

// 0x006A73F0
void Unit::SetPaused(const bool paused)
{
  const UnitAttributes& attributes = GetAttributes();
  const bool canToggle =
    (attributes.commandCapsMask & kCommandCapPause) != 0u || (attributes.toggleCapsMask & kToggleCapGeneric) != 0u;
  if (!canToggle) {
    return;
  }

  if (paused) {
    if (!IsPaused) {
      CallbackStr("OnPaused");
    }
  } else if (IsPaused) {
    CallbackStr("OnUnpaused");
  }

  IsPaused = paused;
  MarkNeedsSyncGameData();
}

// 0x006A7450
void Unit::SetRepeatQueue(const bool enabled)
{
  if (enabled) {
    if (!RepeatQueueEnabled) {
      CallbackStr("OnStartRepeatQueue");
    }
  } else if (RepeatQueueEnabled) {
    CallbackStr("OnStopRepeatQueue");
  }

  RepeatQueueEnabled = enabled;
  MarkNeedsSyncGameData();
}

// 0x006A7490
void Unit::ToggleScriptBit(const int bitIndex)
{
  const std::uint32_t shift = static_cast<std::uint32_t>(static_cast<std::uint8_t>(bitIndex)) & 0x1Fu;
  const std::uint32_t mask = 1u << shift;

  const UnitAttributes& attributes = GetAttributes();
  if ((attributes.toggleCapsMask & mask) == 0u) {
    return;
  }

  if (IsUnitState(kTransportScriptBitGuardState) && IsInCategory("TRANSPORTATION")) {
    return;
  }

  if ((ScriptBitMask & mask) != 0u) {
    ScriptBitMask &= ~mask;
    CallbackInt("OnScriptBitClear", bitIndex);
  } else {
    ScriptBitMask |= mask;
    CallbackInt("OnScriptBitSet", bitIndex);
  }

  MarkNeedsSyncGameData();
}

// 0x006A97C0
void Unit::SetFireState(const std::int32_t fireState)
{
  if (FireState == fireState) {
    return;
  }

  FireState = fireState;
  MarkNeedsSyncGameData();
}
