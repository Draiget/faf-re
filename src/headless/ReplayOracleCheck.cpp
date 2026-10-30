#include "headless/ReplayOracleCheck.h"

#include <algorithm>
#include <cstdio>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "remote/SpatialOracle.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ReplayOracleCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kLoggedDifferences = 20;

    constexpr const char* kKindNames[] = {"units", "blips", "props", "projectiles", "other"};
  } // namespace

  CReplayOracleCheck::CReplayOracleCheck(const std::string& digestPath)
    : mDigestsWanted(!digestPath.empty())
  {
    if (mDigestsWanted && fopen_s(&mDigests, digestPath.c_str(), "w") != 0) {
      mDigests = nullptr;
    }
  }

  CReplayOracleCheck::~CReplayOracleCheck()
  {
    Uninstall();
    if (mDigests != nullptr) {
      std::fclose(mDigests);
    }
  }

  bool CReplayOracleCheck::IsOpen() const noexcept
  {
    return !mDigestsWanted || mDigests != nullptr;
  }

  void CReplayOracleCheck::Install()
  {
    moho::Sim::SetSyncObserver(&CReplayOracleCheck::Observe, this);
  }

  void CReplayOracleCheck::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr, nullptr);
  }

  void CReplayOracleCheck::Observe(moho::Sim& sim, void* const context)
  {
    static_cast<CReplayOracleCheck*>(context)->OnSync(sim);
  }

  void CReplayOracleCheck::OnSync(moho::Sim& sim)
  {
    const std::int32_t focusArmy = sim.mSyncFilter.focusArmy;
    const std::lock_guard<std::mutex> guard(mLock);
    ++mBeats;
    mFocusArmy = focusArmy;
    if (sim.mEntityDB == nullptr) {
      return;
    }

    for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
      moho::Entity* const entity = idAndEntity.second;
      if (entity == nullptr) {
        continue;
      }

      EKind kind = kOther;
      if (entity->IsUnit() != nullptr) {
        kind = kUnit;
      } else if (entity->IsReconBlip() != nullptr) {
        kind = kBlip;
      } else if (entity->IsProp() != nullptr) {
        kind = kProp;
      } else if (entity->IsProjectile() != nullptr) {
        kind = kProjectile;
      }
      SCounts& counts = mCounts[kind];
      ++counts.checked;

      const remote::SViewVisibility oracle = remote::ResolveViewVisibility(sim, focusArmy, *entity);
      const bool simPublished = entity->mInterfaceCreated != 0u;
      const moho::EUserEntityVisibilityMode simMode = entity->mVarDat.mVisibilityMode;

      const char* difference = nullptr;
      if (oracle.published && !simPublished) {
        ++counts.onlyOracle;
        difference = "oracle publishes, sim has no interface";
      } else if (!oracle.published && simPublished) {
        ++counts.onlySim;
        difference = "sim has an interface, oracle does not publish";
      } else if (oracle.published) {
        ++counts.published;
        if (oracle.mode != simMode) {
          ++counts.modeDiffers;
          difference = "mode differs";
        } else {
          counts.sent += remote::CanViewSee(sim, focusArmy, *entity) ? 1u : 0u;
          counts.meshShown += remote::ViewShowsMesh(sim, focusArmy, *entity) ? 1u : 0u;
        }
      }

      if (difference != nullptr && mExamples.size() < kLoggedDifferences) {
        char line[320];
        std::snprintf(
          line, sizeof(line),
          "beat %u id 0x%08X %s: %s (army %d; oracle published=%d mode=%d; sim interface=%d flag=%d mode=%d; "
          "viz focus/ally/enemy/neutral %d/%d/%d/%d; destroying=%d)",
          sim.mCurBeat, static_cast<unsigned>(entity->id_), kKindNames[kind], difference, entity->GetArmyIndex(),
          oracle.published ? 1 : 0, static_cast<int>(oracle.mode), simPublished ? 1 : 0,
          static_cast<int>(entity->mVarDat.mVisibilityHidden), static_cast<int>(simMode), entity->mVizToFocusPlayer,
          entity->mVizToAllies, entity->mVizToEnemies, entity->mVizToNeutrals,
          static_cast<int>(entity->mOnDestroyDispatched)
        );
        mExamples.emplace_back(line);
      }
    }

    CompareSpatial(sim, focusArmy);
    if (mDigests != nullptr) {
      WriteDigests(sim, focusArmy);
    }
  }

  void CReplayOracleCheck::CompareSpatial(moho::Sim& sim, const std::int32_t focusArmy)
  {
    mSpatial.Build(sim);
    const std::int32_t armyCount = static_cast<std::int32_t>(sim.mArmiesList.size());
    const std::int32_t first = focusArmy == -1 ? 0 : focusArmy;
    const std::int32_t last = focusArmy == -1 ? armyCount - 1 : focusArmy;
    for (std::int32_t army = first; army <= last; ++army) {
      remote::CollectViewEntitiesBruteForce(sim, army, mBruteIds);
      mSpatial.CollectViewEntities(sim, army, mSpatialIds);
      ++mSpatialViews;
      if (mBruteIds == mSpatialIds) {
        continue;
      }
      ++mSpatialDiffers;
      if (mExamples.size() < kLoggedDifferences) {
        const auto mismatch = std::mismatch(mBruteIds.begin(), mBruteIds.end(), mSpatialIds.begin(), mSpatialIds.end());
        char line[200];
        std::snprintf(
          line, sizeof(line), "beat %u army %d: spatial set differs (brute %zu, spatial %zu; first brute 0x%08X spatial 0x%08X)",
          sim.mCurBeat, army, mBruteIds.size(), mSpatialIds.size(),
          mismatch.first != mBruteIds.end() ? *mismatch.first : 0u, mismatch.second != mSpatialIds.end() ? *mismatch.second : 0u
        );
        mExamples.emplace_back(line);
      }
    }
  }

  void CReplayOracleCheck::WriteDigests(moho::Sim& sim, const std::int32_t focusArmy)
  {
    const std::int32_t armyCount = static_cast<std::int32_t>(sim.mArmiesList.size());
    const std::int32_t first = focusArmy == -1 ? 0 : focusArmy;
    const std::int32_t last = focusArmy == -1 ? armyCount - 1 : focusArmy;
    for (std::int32_t army = first; army <= last; ++army) {
      std::uint64_t hash = 0xCBF29CE484222325ull; // 64-bit FNV-1a
      const auto add = [&hash](const std::uint32_t value) {
        for (int shift = 0; shift < 32; shift += 8) {
          hash ^= (value >> shift) & 0xFFu;
          hash *= 0x100000001B3ull;
        }
      };
      std::uint32_t entities = 0;
      std::uint32_t visible = 0;
      for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
        moho::Entity* const entity = idAndEntity.second;
        if (entity == nullptr) {
          continue;
        }
        const remote::SViewVisibility view = remote::ResolveViewVisibility(sim, army, *entity);
        const bool sent = remote::CanViewSee(sim, army, *entity);
        const bool shown = remote::ViewShowsMesh(sim, army, *entity);
        ++entities;
        visible += sent ? 1u : 0u;
        add(static_cast<std::uint32_t>(entity->id_));
        add(
          (view.published ? 1u : 0u) | (sent ? 2u : 0u) | (shown ? 4u : 0u) | (static_cast<std::uint32_t>(view.mode) << 8)
        );
      }
      std::fprintf(
        mDigests, "%u %d %u %u %016llx\n", sim.mCurBeat, army, entities, visible, static_cast<unsigned long long>(hash)
      );
    }
  }

  std::uint64_t CReplayOracleCheck::Failures() const noexcept
  {
    const std::lock_guard<std::mutex> guard(mLock);
    std::uint64_t failures = 0;
    for (const SCounts& counts : mCounts) {
      failures += counts.onlyOracle + counts.onlySim + counts.modeDiffers;
    }
    failures += mSpatialDiffers;
    return failures;
  }

  std::string CReplayOracleCheck::Summary() const
  {
    const std::uint64_t failures = Failures();
    const std::lock_guard<std::mutex> guard(mLock);
    char text[256];
    std::snprintf(
      text, sizeof(text), "oracle check: focus %d, %llu beats, %llu entity-beats differ", mFocusArmy,
      static_cast<unsigned long long>(mBeats), static_cast<unsigned long long>(failures)
    );
    std::string summary = text;
    std::snprintf(
      text, sizeof(text), "; spatial oracle: %llu army-beats, %llu differ from brute force",
      static_cast<unsigned long long>(mSpatialViews), static_cast<unsigned long long>(mSpatialDiffers)
    );
    summary += text;
    for (std::size_t kind = 0; kind < kKindCount; ++kind) {
      const SCounts& counts = mCounts[kind];
      std::snprintf(
        text, sizeof(text),
        "\n  %s: %llu checked, %llu published by both, %llu only by the oracle, %llu only by the sim, %llu mode "
        "differs; sent %llu, mesh shown %llu",
        kKindNames[kind], static_cast<unsigned long long>(counts.checked),
        static_cast<unsigned long long>(counts.published), static_cast<unsigned long long>(counts.onlyOracle),
        static_cast<unsigned long long>(counts.onlySim), static_cast<unsigned long long>(counts.modeDiffers),
        static_cast<unsigned long long>(counts.sent), static_cast<unsigned long long>(counts.meshShown)
      );
      summary += text;
    }
    for (const std::string& example : mExamples) {
      summary += "\n  " + example;
    }
    return summary;
  }
} // namespace faf::headless
