#include "headless/ReplayOracleCheck.h"

#include <cstdio>

#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ReplayOracleCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::size_t kLoggedDifferences = 20;

    constexpr const char* kKindNames[] = {"units", "blips", "props", "projectiles", "other"};
  } // namespace

  CReplayOracleCheck::~CReplayOracleCheck()
  {
    Uninstall();
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
        } else if (oracle.mode == moho::EUserEntityVisibilityMode::ReconGrid) {
          ++counts.reconGrid;
          if (remote::CanViewSee(sim, focusArmy, *entity)) {
            ++counts.reconGridSeen;
          }
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
  }

  std::uint64_t CReplayOracleCheck::Failures() const noexcept
  {
    const std::lock_guard<std::mutex> guard(mLock);
    std::uint64_t failures = 0;
    for (const SCounts& counts : mCounts) {
      failures += counts.onlyOracle + counts.onlySim + counts.modeDiffers;
    }
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
    for (std::size_t kind = 0; kind < kKindCount; ++kind) {
      const SCounts& counts = mCounts[kind];
      std::snprintf(
        text, sizeof(text),
        "\n  %s: %llu checked, %llu published by both, %llu only by the oracle, %llu only by the sim, %llu mode "
        "differs; ReconGrid %llu, in sight %llu",
        kKindNames[kind], static_cast<unsigned long long>(counts.checked),
        static_cast<unsigned long long>(counts.published), static_cast<unsigned long long>(counts.onlyOracle),
        static_cast<unsigned long long>(counts.onlySim), static_cast<unsigned long long>(counts.modeDiffers),
        static_cast<unsigned long long>(counts.reconGrid), static_cast<unsigned long long>(counts.reconGridSeen)
      );
      summary += text;
    }
    for (const std::string& example : mExamples) {
      summary += "\n  " + example;
    }
    return summary;
  }
} // namespace faf::headless
