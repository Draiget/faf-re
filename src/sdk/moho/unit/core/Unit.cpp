// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/Unit.h"

#include <algorithm>
#include <cstdint>
#include <new>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTransportCommandOps.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/StatItem.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/CUnitCommandQueue.h"

using namespace moho;

namespace
{
  // Guard condition recovered from Unit::ToggleScriptBit: state 14 == UNITSTATE_Attached.
  constexpr EUnitState kTransportScriptBitGuardState = UNITSTATE_Attached;
  constexpr std::uint32_t kCommandCapPause = 0x00020000u;  // RULEUCC_Pause
  constexpr std::uint32_t kToggleCapGeneric = 0x00000040u; // RULEUTC_GenericToggle

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
      pairBuffer.push_back(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      pairBuffer.push_back(pair);
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
