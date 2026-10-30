#include "remote/client/OracleGolden.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see OracleGolden.h.

namespace faf::remote::client
{
  namespace
  {
    constexpr std::size_t kLoggedDifferences = 30; // the live grid does not explain them
    constexpr std::size_t kLoggedExplained = 5;    // it does
    constexpr std::size_t kKeptBeats = 256; // the sim runs at most sim_ReplayLead beats ahead

    struct SOracleEntity
    {
      std::uint32_t id = 0;
      bool shown = false;
      std::uint8_t kind = 0; // 0 other, 1 unit, 2 blip, 3 prop, 4 projectile
      std::int32_t mode = 0;
    };

    struct SOracleBeat
    {
      std::int32_t focusArmy = -1;
      std::vector<SOracleEntity> published; // by id, as the entity DB walks them
    };

    constexpr const char* kKindNames[] = {"other", "unit", "blip", "prop", "projectile"};

    class COracleGolden
    {
    public:
      explicit COracleGolden(std::FILE* file)
        : mFile(file)
      {
        std::fprintf(mFile, "# beat focus compared agree oracle-only client-only orphan-client no-mesh live-grid\n");
      }

      static void ObserveSim(moho::Sim& sim, void* const context)
      {
        static_cast<COracleGolden*>(context)->OnSimSync(sim);
      }

      static void ObserveBeat(moho::CWldSession& session, const std::int32_t beat, void* const context)
      {
        static_cast<COracleGolden*>(context)->OnClientBeat(session, beat);
      }

    private:
      void OnSimSync(moho::Sim& sim)
      {
        SOracleBeat entry;
        entry.focusArmy = sim.mSyncFilter.focusArmy;
        if (sim.mEntityDB != nullptr) {
          for (const auto& idAndEntity : sim.mEntityDB->mAllUnits) {
            moho::Entity* const entity = idAndEntity.second;
            if (entity == nullptr) {
              continue;
            }
            const SViewVisibility view = ResolveViewVisibility(sim, entry.focusArmy, *entity);
            if (!view.published) {
              continue;
            }
            SOracleEntity record;
            record.id = static_cast<std::uint32_t>(entity->id_);
            record.shown = ViewShowsMesh(sim, entry.focusArmy, *entity);
            record.mode = static_cast<std::int32_t>(view.mode);
            if (entity->IsUnit() != nullptr) {
              record.kind = 1;
            } else if (entity->IsReconBlip() != nullptr) {
              record.kind = 2;
            } else if (entity->IsProp() != nullptr) {
              record.kind = 3;
            } else if (entity->IsProjectile() != nullptr) {
              record.kind = 4;
            }
            entry.published.push_back(record);
          }
        }

        mSim.store(&sim);
        const std::lock_guard<std::mutex> guard(mLock);
        mBeats[static_cast<std::int32_t>(sim.mCurBeat)] = std::move(entry);
        while (mBeats.size() > kKeptBeats) {
          mBeats.erase(mBeats.begin());
        }
      }

      void OnClientBeat(moho::CWldSession& session, const std::int32_t beat)
      {
        SOracleBeat oracle;
        {
          const std::lock_guard<std::mutex> guard(mLock);
          const auto found = mBeats.find(beat);
          if (found == mBeats.end()) {
            ++mMissingBeats;
            return;
          }
          oracle = std::move(found->second);
          mBeats.erase(mBeats.begin(), std::next(found));
        }
        if (oracle.focusArmy != session.FocusArmy) {
          ++mOtherFocusBeats;
          return;
        }

        std::unordered_set<std::uint32_t> orphans;
        for (moho::UserEntity* const entity : session.mOrphans) {
          if (entity != nullptr) {
            orphans.insert(static_cast<std::uint32_t>(entity->mParams.mEntityId));
          }
        }

        std::uint64_t compared = 0;
        std::uint64_t agree = 0;
        std::uint64_t oracleOnly = 0;
        std::uint64_t clientOnly = 0;
        std::uint64_t orphanClient = 0;
        std::uint64_t noMesh = 0;
        std::uint64_t liveGrid = 0; // differences the live grid explains (`LiveGridAnswer`)

        std::unordered_set<std::uint32_t> oracleIds;
        oracleIds.reserve(oracle.published.size());
        for (const SOracleEntity& record : oracle.published) {
          oracleIds.insert(record.id);
          const auto client = session.mEntities.find(record.id);
          const moho::UserEntity* const userEntity = client != session.mEntities.end() ? client->second : nullptr;
          if (userEntity != nullptr && userEntity->mMeshInstance == nullptr) {
            ++noMesh;
            continue;
          }
          const bool drawn = userEntity != nullptr && userEntity->mMeshInstance->isHidden == 0u;
          ++compared;
          if (drawn == record.shown) {
            ++agree;
            continue;
          }
          if (record.shown) {
            ++oracleOnly;
          } else {
            ++clientOnly;
          }
          const int live = LiveGridAnswer(oracle.focusArmy, record, userEntity);
          if (live >= 0 && (live != 0) == drawn) {
            ++liveGrid;
          }
          LogDifference(beat, oracle.focusArmy, record, userEntity, drawn, live);
        }

        // Client entities the sim no longer publishes: orphaned props and anything unexplained.
        for (const auto& [id, userEntity] : session.mEntities) {
          if (userEntity == nullptr || userEntity->mMeshInstance == nullptr
              || userEntity->mMeshInstance->isHidden != 0u || oracleIds.count(id) != 0u) {
            continue;
          }
          if (orphans.count(id) != 0u) {
            ++orphanClient;
          } else {
            ++clientOnly;
            ++compared;
            SOracleEntity unknown;
            unknown.id = id;
            LogDifference(beat, oracle.focusArmy, unknown, userEntity, true, -1);
          }
        }

        mTotalCompared += compared;
        mTotalAgree += agree;
        mTotalOracleOnly += oracleOnly;
        mTotalClientOnly += clientOnly;
        mTotalOrphanClient += orphanClient;
        mTotalLiveGrid += liveGrid;
        ++mComparedBeats;
        std::fprintf(
          mFile, "%d %d %llu %llu %llu %llu %llu %llu %llu\n", beat, oracle.focusArmy,
          static_cast<unsigned long long>(compared), static_cast<unsigned long long>(agree),
          static_cast<unsigned long long>(oracleOnly), static_cast<unsigned long long>(clientOnly),
          static_cast<unsigned long long>(orphanClient), static_cast<unsigned long long>(noMesh),
          static_cast<unsigned long long>(liveGrid)
        );
        if (mComparedBeats % 500u == 0u) {
          std::fflush(mFile);
          LogTotals();
        }
      }

      /**
       * For a plain entity in mode ReconGrid: the grid test on the sim's grids as they are now, at
       * the client entity's position. That is what `UserEntity::UpdateVisibility` read while
       * `DoBeat` ran (the client's grids are the sim's, shared), possibly a few beats after the
       * oracle's answer. 1 or 0; -1 when it does not apply. A difference this answer matches comes
       * from the sim having moved on, not from the oracle.
       */
      [[nodiscard]] int LiveGridAnswer(
        const std::int32_t focusArmy, const SOracleEntity& record, const moho::UserEntity* const userEntity
      ) const
      {
        moho::Sim* const sim = mSim.load();
        if (sim == nullptr || userEntity == nullptr || record.kind == 1 || record.kind == 2
            || record.mode != static_cast<std::int32_t>(moho::EUserEntityVisibilityMode::ReconGrid)) {
          return -1;
        }
        const bool sees = ViewCanSeePoint(
          *sim, focusArmy, userEntity->mVariableData.mCurTransform.pos_,
          userEntity->mVariableData.UsesUnderwaterReconGrid()
        );
        return sees ? 1 : 0;
      }

      void LogDifference(
        const std::int32_t beat, const std::int32_t focusArmy, const SOracleEntity& record,
        const moho::UserEntity* const userEntity, const bool drawn, const int live
      )
      {
        // Differences the live grid does not explain are logged first-come; the explained ones
        // only up to a few, so they cannot crowd the others out.
        const bool explained = live >= 0 && (live != 0) == drawn;
        std::size_t& logged = explained ? mLoggedExplained : mLoggedDifferences;
        if (logged >= (explained ? kLoggedExplained : kLoggedDifferences)) {
          return;
        }
        ++logged;
        const int clientMode =
          userEntity != nullptr ? static_cast<int>(userEntity->mVariableData.mVisibilityMode) : -1;
        gpg::Logf(
          "ORACLEGOLDEN diff beat=%d focus=%d id=0x%08X kind=%s oracle-mode=%d oracle-shown=%d client=%s "
          "client-mode=%d drawn=%d live-grid=%d",
          beat, focusArmy, record.id, kKindNames[record.kind], record.mode, record.shown ? 1 : 0,
          userEntity != nullptr ? "present" : "absent", clientMode, drawn ? 1 : 0, live
        );
      }

      void LogTotals()
      {
        gpg::Logf(
          "ORACLEGOLDEN totals beats=%llu compared=%llu agree=%llu oracle-only=%llu client-only=%llu "
          "orphan-client=%llu live-grid=%llu missing-beats=%llu other-focus-beats=%llu",
          static_cast<unsigned long long>(mComparedBeats), static_cast<unsigned long long>(mTotalCompared),
          static_cast<unsigned long long>(mTotalAgree), static_cast<unsigned long long>(mTotalOracleOnly),
          static_cast<unsigned long long>(mTotalClientOnly), static_cast<unsigned long long>(mTotalOrphanClient),
          static_cast<unsigned long long>(mTotalLiveGrid), static_cast<unsigned long long>(mMissingBeats),
          static_cast<unsigned long long>(mOtherFocusBeats)
        );
      }

      std::FILE* mFile;
      std::mutex mLock; // the sim's thread fills mBeats, the client's empties it
      std::map<std::int32_t, SOracleBeat> mBeats;
      std::uint64_t mComparedBeats = 0;
      std::uint64_t mMissingBeats = 0;
      std::uint64_t mOtherFocusBeats = 0;
      std::uint64_t mTotalCompared = 0;
      std::uint64_t mTotalAgree = 0;
      std::uint64_t mTotalOracleOnly = 0;
      std::uint64_t mTotalClientOnly = 0;
      std::uint64_t mTotalOrphanClient = 0;
      std::uint64_t mTotalLiveGrid = 0;
      std::atomic<moho::Sim*> mSim{nullptr}; // the sim, for `LiveGridAnswer` on the client's thread
      std::size_t mLoggedDifferences = 0;
      std::size_t mLoggedExplained = 0;
    };
  } // namespace

  bool InstallOracleGoldenFromCommandLine()
  {
    msvc8::vector<msvc8::string> args;
    if (!moho::CFG_GetArgOption("/oraclegolden", 1, &args) || args.empty()) {
      return false;
    }
    std::FILE* file = nullptr;
    if (fopen_s(&file, args[0].c_str(), "w") != 0 || file == nullptr) {
      gpg::Warnf("/oraclegolden: cannot write %s", args[0].c_str());
      return false;
    }
    // Lives as long as the process: both observers may still fire while the session ends.
    static COracleGolden* const golden = new COracleGolden(file);
    moho::Sim::SetSyncObserver(&COracleGolden::ObserveSim, golden);
    moho::CWldSession::SetBeatObserver(&COracleGolden::ObserveBeat, golden);
    gpg::Logf("ORACLEGOLDEN installed, writing %s", args[0].c_str());
    return true;
  }
} // namespace faf::remote::client
