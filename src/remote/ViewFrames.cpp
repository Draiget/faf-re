#include "remote/ViewFrames.h"

#include <algorithm>
#include <unordered_set>
#include <utility>

#include "moho/command/CCommandDb.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "remote/VisibilityOracle.h"

// Engine addition, server mode: see ViewFrames.h.

namespace faf::remote
{
  CViewFrames::CViewFrames(const wire::SContentTables& tables, const wire::SFrameCodec& codec)
    : mTables(tables)
    , mCodec(codec)
  {}

  CViewFrames::~CViewFrames() = default;

  void CViewFrames::ClearUnheldReferences(wire::SViewFrame& frame)
  {
    constexpr std::uint32_t kNone = 0xF0000000u; // the sim's invalid entity id (`EntityId.h`)
    // The records are in ascending id order (`SViewFrame::entities`) and only their fields change
    // below, so a held id is found by binary search, without a set of every id per view and beat.
    const std::vector<wire::SEntityRecord>& records = frame.entities;
    const auto unheld = [&records](const std::uint32_t id) {
      if (id == kNone) {
        return false;
      }
      const auto found = std::lower_bound(
        records.begin(), records.end(), id, [](const wire::SEntityRecord& record, const std::uint32_t value) {
          return record.id < value;
        }
      );
      return found == records.end() || found->id != id;
    };
    for (wire::SEntityRecord& record : frame.entities) {
      if (unheld(record.appearance.attachParent)) {
        record.appearance.attachParent = wire::SAppearance::kNoAttachParent;
      }
      std::vector<std::uint32_t>& attachments = record.appearance.attachments;
      attachments.erase(std::remove_if(attachments.begin(), attachments.end(), unheld), attachments.end());
      if (!record.isUnit) {
        continue;
      }
      const wire::SUnitDetail& shared = *record.unit.detail;
      if (!unheld(shared.creator) && !unheld(shared.selectionInheritor) && !unheld(shared.focusUnit)
          && !unheld(shared.guardedUnit) && !unheld(shared.targetBlip)) {
        continue; // shared with the builder's world as it is
      }
      wire::SUnitDetail detail = shared;
      for (std::uint32_t* const field :
           {&detail.creator, &detail.selectionInheritor, &detail.focusUnit, &detail.guardedUnit, &detail.targetBlip}) {
        if (unheld(*field)) {
          *field = kNone;
        }
      }
      record.unit.detail.Assign(detail);
    }
  }

  void CViewFrames::OnViewPackets(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    while (mBuilders.size() < armyCount) {
      mIdMaps.push_back(std::make_unique<CViewIdMap>(static_cast<std::int32_t>(mBuilders.size())));
      mRetiring.emplace_back();
      mRetired.emplace_back();
      mBuilders.push_back(std::make_unique<CViewFrameBuilder>(mTables, mCodec));
      mFrames.emplace_back();
      mPreviousFrames.emplace_back();
      mHavePrevious.push_back(false);
      mWithheld.push_back(0u);
    }
    // The frames built before this beat become the previous ones (in `buildFrame`, which also
    // lets go of the older ones). A view's frame exists once it has been built (its id comes from
    // its builder, starting at 0).
    for (std::size_t army = 0; army < armyCount; ++army) {
      if (mBuilt.size() <= army) {
        mBuilt.push_back(false);
      }
      if (mBuilt[army]) {
        mHavePrevious[army] = true;
      }
    }

    // The sim's entities in ascending id order with what the oracle reads from each, once for
    // every view (plan WPR.35): a frame's records are in that order too, so each view finds its
    // records' facts in one forward pass.
    mEntityIndex.clear();
    mEntityPointers.clear();
    if (sim.mEntityDB != nullptr) {
      mEntityIndex.reserve(sim.mEntityDB->mAllUnits.size());
      mEntityPointers.reserve(sim.mEntityDB->mAllUnits.size());
      for (const auto& [id, entity] : sim.mEntityDB->mAllUnits) {
        mEntityIndex.emplace_back(id, SEntityFacts{});
        mEntityPointers.push_back(entity);
      }
    }
    const auto readFacts = [this](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        mEntityIndex[i].second = ReadEntityFacts(*mEntityPointers[i]);
      }
    };
    constexpr std::size_t kFactsGrain = 256;
    if (Parallel() && mEntityIndex.size() > kFactsGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(mEntityIndex.size(), kFactsGrain, readFacts);
    } else {
      readFacts(0u, mEntityIndex.size());
    }

    // Each view's builder, id map and frame are its own; the sim is only read (plan I3), so the
    // views can be built on the sim's workers (plan WP5.7, `SetParallel`).
    const auto buildFrame = [&](const std::size_t army) {
      const auto view = static_cast<std::int32_t>(army);
      // On this worker: a frame's records hold only the view's own shared values, no sim object.
      if (mBuilt[army]) {
        mPreviousFrames[army] = std::move(mFrames[army]);
      }
      if (!HasView(view)) {
        mFrames[army] = wire::SViewFrame{};
        mWithheld[army] = 0u;
        return;
      }
      CViewFrameBuilder& builder = *mBuilders[army];
      const moho::SSyncData& packet = Packet(view);
      builder.Apply(packet);

      // Plan §6: a plain entity in mode ReconGrid goes out only while the view sees it. A record
      // the sim no longer has (an orphan) stays.
      std::uint32_t withheld = 0;
      auto index = mEntityIndex.cbegin();
      wire::SViewFrame frame = builder.Build(sim.mCurBeat, [&](const wire::SEntityRecord& record) {
        while (index != mEntityIndex.cend() && index->first < record.id) {
          ++index;
        }
        if (index == mEntityIndex.cend() || index->first != record.id || CanViewSee(sim, view, index->second)) {
          return true;
        }
        ++withheld;
        return false;
      });

      if (mIdMapsOn) {
        // Plan WP5.12: a record may name an entity this view holds no record of (a visible enemy
        // guarding a hidden unit, a transport's hidden cargo). The client cannot resolve such an
        // id, but its number still says the entity exists, so the view gets the sim's "none".
        ClearUnheldReferences(frame);
      }

      if (mIdMapsOn) {
        // Plan WP5.9: the view's own ids. A command is the view's own when its top byte is one of
        // the command sources allowed to command the view's army (`UserCommandIssue.cpp:372`
        // packs the client's source there).
        CViewIdMap& map = *mIdMaps[army];
        // What the last beat retired goes first: its frame could still name those ids (a unit's
        // target blip deleted on the same beat), and named them with the ids the view had. A
        // command retires once the sim's command database no longer has it: the sim deletes a
        // finished command while it publishes the beat's commands (`CCommandDB::PublishSyncData`),
        // after the walk this observer sees, so a command released on one beat goes on the next.
        map.AdvanceTo(sim.mCurBeat);
        map.RetireEntities(mRetired[army]);
        if (const moho::CCommandDB* const commands = sim.mCommandDB; commands != nullptr) {
          map.RetireCommandsUnless([commands](const std::uint32_t simId) {
            return commands->commands.find(simId) != commands->commands.end();
          });
        }
        const moho::BVIntSet* sources = nullptr;
        if (army < packet.mArmyUpdates.size()) {
          sources = &packet.mArmyUpdates[army].mValidCommandSources;
        }
        map.Translate(frame, [sources](const std::uint32_t commandId) {
          return sources != nullptr && sources->Contains(commandId >> 24u);
        });
        // A deleted or erased entity's id retires once the client holds no record of it (an
        // orphan keeps its view id while it is shown).
        std::unordered_set<std::uint32_t>& retiring = mRetiring[army];
        retiring.insert(packet.mDeleteIds.begin(), packet.mDeleteIds.end());
        retiring.insert(packet.mEraseIds.begin(), packet.mEraseIds.end());
        std::vector<std::uint32_t>& next = mRetired[army];
        next.clear();
        for (auto it = retiring.begin(); it != retiring.end();) {
          if (builder.Holds(*it)) {
            ++it;
            continue;
          }
          next.push_back(*it);
          it = retiring.erase(it);
        }
      }

      mFrames[army] = std::move(frame);
      mWithheld[army] = withheld;
    };
    if (Parallel() && armyCount > 1u) {
      moho::CSimWorkerPool::Get().ParallelFor(armyCount, 1u, [&buildFrame](const std::size_t begin, const std::size_t end) {
        for (std::size_t army = begin; army < end; ++army) {
          buildFrame(army);
        }
      });
    } else {
      for (std::size_t army = 0; army < armyCount; ++army) {
        buildFrame(army);
      }
    }
    // The sim's stats trees the builders let go of are dropped here, on the sim thread, in army order.
    for (std::size_t army = 0; army < armyCount; ++army) {
      mBuilders[army]->ReleaseDropped();
      mBuilt[army] = true;
    }
    AddBuildTime();
    mLastSim = &sim;
    OnViewFrames(sim);
  }
} // namespace faf::remote
