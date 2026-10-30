#include "headless/ReplayViewPacketCheck.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see ReplayViewPacketCheck.h.

namespace faf::headless
{
  namespace
  {
    /** 64-bit FNV-1a, field by field. */
    class CDigest
    {
    public:
      template <typename T>
      void Add(const T& value) noexcept
      {
        static_assert(std::is_arithmetic_v<T> || std::is_enum_v<T>);
        Bytes(&value, sizeof(value));
      }

      void Bytes(const void* const data, const std::size_t size) noexcept
      {
        const auto* const bytes = static_cast<const unsigned char*>(data);
        for (std::size_t i = 0; i < size; ++i) {
          mHash ^= bytes[i];
          mHash *= 0x100000001B3ull;
        }
      }

      void Text(const char* const text) noexcept { Bytes(text, text != nullptr ? std::strlen(text) + 1u : 0u); }

      [[nodiscard]] std::uint64_t Value() const noexcept { return mHash; }

    private:
      std::uint64_t mHash = 0xCBF29CE484222325ull;
    };

    void AddTransform(CDigest& digest, const moho::VTransform& transform) noexcept
    {
      digest.Add(transform.orient_.x);
      digest.Add(transform.orient_.y);
      digest.Add(transform.orient_.z);
      digest.Add(transform.orient_.w);
      digest.Add(transform.pos_.x);
      digest.Add(transform.pos_.y);
      digest.Add(transform.pos_.z);
    }

    void AddEntityBlock(CDigest& digest, const moho::SSTIEntityVariableData& data)
    {
      digest.Text(data.mMeshBlueprint != nullptr ? data.mMeshBlueprint->mBlueprintId.c_str() : nullptr);
      digest.Add(data.mScale.x);
      digest.Add(data.mScale.y);
      digest.Add(data.mScale.z);
      digest.Add(data.mHealth);
      digest.Add(data.mMaxHealth);
      digest.Add(data.mIsBeingBuilt);
      digest.Add(data.mIsDead);
      digest.Add(data.mRequestRefreshUI);
      digest.Add(data.mDestroyedByKill);
      AddTransform(digest, data.mCurTransform);
      AddTransform(digest, data.mLastTransform);
      digest.Add(data.mCurImpactValue);
      digest.Add(data.mFractionComplete);
      digest.Add(data.mAttachmentParentRef);
      digest.Add(static_cast<std::uint32_t>(data.mAuxValueVector.size()));
      for (const moho::SSTIEntityAttachInfo& child : data.mAuxValueVector) {
        digest.Add(child.mAttachedEntityId);
      }
      digest.Add(data.mScrollBeatStart);
      digest.Add(data.mScrollBeatEnd);
      digest.Add(data.mVisibilityHidden);
      digest.Add(data.mVisibilityMode);
      digest.Add(data.mLayerMask);
      digest.Add(data.mUsingAltFootprint);
      digest.Add(data.mUsingAltFootprintSecondary);
      digest.Add(data.mIntelAttributes.GetRange(moho::ENTATTR_Vision));
    }

    void AddUnitBlock(CDigest& digest, const moho::SSTIUnitVariableData& data, const std::int32_t reconFlags)
    {
      digest.Add(reconFlags);
      digest.Add(data.mCreator);
      digest.Add(data.mAutoMode);
      digest.Add(data.mIsBusy);
      digest.Add(data.mFuelRatio);
      digest.Add(data.mShieldRatio);
      digest.Add(data.mStunTicks);
      digest.Add(data.mIsPaused);
      digest.Add(data.mJobType);
      digest.Add(data.mFireState);
      digest.Add(data.mWorkProgress);
      digest.Add(data.mTacticalSiloBuildCount);
      digest.Add(data.mNukeSiloBuildCount);
      digest.Add(data.mTacticalSiloStorageCount);
      digest.Add(data.mNukeSiloStorageCount);
      digest.Add(data.mFocusUnit);
      digest.Add(data.mGuardedUnit);
      digest.Add(data.mTargetBlip);
      digest.Add(data.mScriptbits);
      digest.Add(data.mUnitStates);
      digest.Add(data.mDidRefresh);
      digest.Add(static_cast<std::uint32_t>(data.mCommands.size()));
      for (const moho::CmdId command : data.mCommands) {
        digest.Add(command);
      }
      digest.Add(static_cast<std::uint32_t>(data.mBuildQueue.size()));
      for (const moho::CmdId command : data.mBuildQueue) {
        digest.Add(command);
      }
    }

    template <class TRecord>
    [[nodiscard]] std::vector<const TRecord*> ById(const msvc8::vector<TRecord>& records)
    {
      std::vector<const TRecord*> sorted;
      sorted.reserve(records.size());
      for (const TRecord& record : records) {
        sorted.push_back(&record);
      }
      std::sort(sorted.begin(), sorted.end(), [](const TRecord* const lhs, const TRecord* const rhs) {
        return static_cast<std::uint32_t>(lhs->mEntityId) < static_cast<std::uint32_t>(rhs->mEntityId);
      });
      return sorted;
    }

    [[nodiscard]] std::uint64_t IdsDigest(const msvc8::vector<moho::EntId>& ids)
    {
      std::vector<std::uint32_t> sorted;
      for (const moho::EntId id : ids) {
        sorted.push_back(static_cast<std::uint32_t>(id));
      }
      std::sort(sorted.begin(), sorted.end());
      CDigest digest;
      for (const std::uint32_t id : sorted) {
        digest.Add(id);
      }
      return digest.Value();
    }
  } // namespace

  CReplayViewPacketCheck::CReplayViewPacketCheck(const std::int32_t army, const std::string& path)
    : mArmy(army)
  {
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
    }
  }

  CReplayViewPacketCheck::~CReplayViewPacketCheck()
  {
    Uninstall();
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayViewPacketCheck::Install()
  {
    moho::Sim::SetSyncObserver(this);
  }

  void CReplayViewPacketCheck::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayViewPacketCheck::OnBeatChanges(moho::Sim& sim, const moho::SSyncData& packet)
  {
    if (sim.mSyncFilter.focusArmy == -1) {
      remote::CViewPackets::OnBeatChanges(sim, packet); // rebuilds, then OnViewPackets
      return;
    }
    if (sim.mSyncFilter.focusArmy == mArmy) {
      WriteDigest(sim.mCurBeat, packet, false);
    }
  }

  void CReplayViewPacketCheck::OnViewPackets(moho::Sim& sim)
  {
    if (mArmy >= 0 && mArmy < ArmyCount()) {
      WriteDigest(sim.mCurBeat, Packet(mArmy), true);
    }
  }

  void CReplayViewPacketCheck::WriteDigest(const std::uint32_t beat, const moho::SSyncData& packet, const bool rebuilt)
  {
    if (mFile == nullptr) {
      return;
    }
    mRebuilt = rebuilt;
    ++mBeats;

    CDigest creates;
    for (const moho::SCreateEntityParams* const params : ById(packet.mNewEntities)) {
      creates.Add(params->mEntityId);
      creates.Text(params->mBlueprint != nullptr ? params->mBlueprint->mBlueprintId.c_str() : nullptr);
      creates.Add(params->mTickCreated);
    }
    CDigest unitCreates;
    for (const moho::SCreateUnitParams* const params : ById(packet.mNewUnits)) {
      unitCreates.Add(params->mEntityId);
      unitCreates.Text(params->mBlueprint != nullptr ? params->mBlueprint->mBlueprintId.c_str() : nullptr);
      unitCreates.Add(params->mTickCreated);
      unitCreates.Add(params->mConstDat.mBuildStateTag);
      unitCreates.Add(params->mConstDat.mFake);
      unitCreates.Add(params->mConstDat.mStatsRoot ? 1 : 0);
    }
    CDigest entities;
    for (const moho::SEntityVariableUpdateEntry* const update : ById(packet.mEntityUpdates)) {
      entities.Add(update->mEntityId);
      AddEntityBlock(entities, update->mVariableData);
    }
    CDigest units;
    for (const moho::SUnitVariableUpdateEntry* const update : ById(packet.mUnitUpdates)) {
      units.Add(update->mEntityId);
      AddUnitBlock(units, update->mVariableData, update->mReconFlags);
    }

    std::fprintf(
      mFile, "%u %zu %zu %zu %zu %zu %zu %016llx %016llx %016llx %016llx %016llx %016llx\n", beat,
      static_cast<std::size_t>(packet.mNewEntities.size()), static_cast<std::size_t>(packet.mNewUnits.size()),
      static_cast<std::size_t>(packet.mEntityUpdates.size()), static_cast<std::size_t>(packet.mUnitUpdates.size()),
      static_cast<std::size_t>(packet.mDeleteIds.size()), static_cast<std::size_t>(packet.mEraseIds.size()),
      static_cast<unsigned long long>(creates.Value()), static_cast<unsigned long long>(unitCreates.Value()),
      static_cast<unsigned long long>(entities.Value()), static_cast<unsigned long long>(units.Value()),
      static_cast<unsigned long long>(IdsDigest(packet.mDeleteIds)),
      static_cast<unsigned long long>(IdsDigest(packet.mEraseIds))
    );
  }

  std::string CReplayViewPacketCheck::Summary() const
  {
    char text[160];
    std::snprintf(
      text, sizeof(text), "view-packets: army %d, %llu beats written (%s)", mArmy,
      static_cast<unsigned long long>(mBeats), mRebuilt ? "rebuilt from the change set" : "the sim's own packet"
    );
    return text;
  }
} // namespace faf::headless
