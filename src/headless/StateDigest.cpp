#include "headless/StateDigest.h"

#include <cstddef>
#include <cstring>
#include <type_traits>

#include "gpg/core/streams/Stream.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"

// Engine addition: see StateDigest.h. Moved from ReplayRunner.cpp unchanged, so the server writes the same digests.

namespace faf::headless
{
  namespace
  {
    /** 64-bit FNV-1a over the fields added, in order. */
    class CStateDigest
    {
    public:
      template <typename T>
      void Add(
        const T& value
      ) noexcept
      {
        static_assert(std::is_arithmetic_v<T> || std::is_enum_v<T>);
        Bytes(&value, sizeof(value));
      }

      void Bytes(
        const void* const data,
        const std::size_t size
      ) noexcept
      {
        const auto* const bytes = static_cast<const unsigned char*>(data);
        for (std::size_t i = 0; i < size; ++i) {
          mHash ^= bytes[i];
          mHash *= 0x100000001B3ull;
        }
      }

      void Text(
        const char* const text
      ) noexcept
      {
        Bytes(text, text != nullptr ? std::strlen(text) + 1u : 0u);
      }

      [[nodiscard]] std::uint64_t Value() const noexcept
      {
        return mHash;
      }

    private:
      std::uint64_t mHash = 0xCBF29CE484222325ull;
    };

    void AddTransform(
      CStateDigest& digest,
      const moho::VTransform& transform
    ) noexcept
    {
      digest.Add(transform.orient_.x);
      digest.Add(transform.orient_.y);
      digest.Add(transform.orient_.z);
      digest.Add(transform.orient_.w);
      digest.Add(transform.pos_.x);
      digest.Add(transform.pos_.y);
      digest.Add(transform.pos_.z);
    }
  } // namespace

  [[nodiscard]] std::uint64_t DigestPublishedState(
    const moho::SSyncData& packet
  )
  {
    CStateDigest digest;
    digest.Add(packet.mCurBeat);
    digest.Add(packet.mCurTick);
    for (const moho::SCreateEntityParams& params : packet.mNewEntities) {
      digest.Add(params.mEntityId);
      digest.Text(params.mBlueprint != nullptr ? params.mBlueprint->mBlueprintId.c_str() : nullptr);
    }
    for (const moho::SCreateUnitParams& params : packet.mNewUnits) {
      digest.Add(params.mEntityId);
      digest.Text(params.mBlueprint != nullptr ? params.mBlueprint->mBlueprintId.c_str() : nullptr);
    }
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const moho::SSTIEntityVariableData& data = update.mVariableData;
      digest.Add(update.mEntityId);
      digest.Add(data.mScale.x);
      digest.Add(data.mScale.y);
      digest.Add(data.mScale.z);
      digest.Add(data.mHealth);
      digest.Add(data.mMaxHealth);
      digest.Add(data.mIsBeingBuilt);
      digest.Add(data.mIsDead);
      digest.Add(data.mDestroyedByKill);
      AddTransform(digest, data.mCurTransform);
      AddTransform(digest, data.mLastTransform);
      digest.Add(data.mCurImpactValue);
      digest.Add(data.mFractionComplete);
      digest.Add(data.mAttachmentParentRef);
      digest.Add(data.mVisibilityHidden);
      digest.Add(data.mVisibilityMode);
      digest.Add(data.mLayerMask);
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const moho::SSTIUnitVariableData& data = update.mVariableData;
      digest.Add(update.mEntityId);
      digest.Add(update.mReconFlags);
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
      digest.Add(data.mProduced.ENERGY);
      digest.Add(data.mProduced.MASS);
      digest.Add(data.mResourcesSpent.ENERGY);
      digest.Add(data.mResourcesSpent.MASS);
      digest.Add(data.mMaintainenceCost.ENERGY);
      digest.Add(data.mMaintainenceCost.MASS);
      digest.Add(data.mFocusUnit);
      digest.Add(data.mGuardedUnit);
      digest.Add(data.mTargetBlip);
      digest.Add(data.mScriptbits);
      digest.Add(data.mUnitStates);
      for (const moho::CmdId id : data.mCommands) {
        digest.Add(id);
      }
      for (const moho::CmdId id : data.mBuildQueue) {
        digest.Add(id);
      }
    }
    for (const moho::EntId id : packet.mEraseIds) {
      digest.Add(id);
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      digest.Add(id);
    }
    for (const moho::SSTIArmyVariableData& army : packet.mArmyUpdates) {
      const moho::SEconTotals& economy = army.mEconomyTotals;
      for (const auto* pair :
           {&economy.mStored,
            &economy.mIncome,
            &economy.mReclaimed,
            &economy.mLastUseRequested,
            &economy.mLastUseActual}) {
        digest.Add(pair->ENERGY);
        digest.Add(pair->MASS);
      }
      digest.Add(economy.mMaxStorage.ENERGY);
      digest.Add(economy.mMaxStorage.MASS);
    }
    // The Lua `Sync` bytes, read whole and rewound for the decode that follows.
    if (packet.mStream != nullptr) {
      char buffer[4096];
      for (;;) {
        const std::size_t read = packet.mStream->Read(buffer, sizeof(buffer));
        if (read == 0) {
          break;
        }
        digest.Bytes(buffer, read);
      }
      (void)packet.mStream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, 0);
    }
    return digest.Value();
  }
} // namespace faf::headless
