#include "remote/ViewFrames.h"

#include <algorithm>
#include <cstdio>
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

  namespace
  {
    constexpr std::uint32_t kNone = 0xF0000000u; // the sim's invalid entity id (`EntityId.h`)

    /** References `unheld` says the view holds no record of become the sim's "none" (plan WP5.12). */
    template <class Unheld>
    void ClearRecordReferences(wire::SEntityRecord& record, const Unheld& unheld)
    {
      if (unheld(record.appearance.attachParent)) {
        record.appearance.attachParent = wire::SAppearance::kNoAttachParent;
      }
      std::vector<std::uint32_t>& attachments = record.appearance.attachments;
      attachments.erase(std::remove_if(attachments.begin(), attachments.end(), unheld), attachments.end());
      if (!record.isUnit) {
        return;
      }
      const wire::SUnitDetail& shared = *record.unit.detail;
      if (!unheld(shared.creator) && !unheld(shared.selectionInheritor) && !unheld(shared.focusUnit)
          && !unheld(shared.guardedUnit) && !unheld(shared.targetBlip)) {
        return; // shared with the builder's world as it is
      }
      wire::SUnitDetail detail = shared;
      for (std::uint32_t* const field :
           {&detail.creator, &detail.selectionInheritor, &detail.focusUnit, &detail.guardedUnit, &detail.targetBlip}) {
        if (unheld(*field)) {
          *field = kNone;
        }
      }
      (void)record.unit.detail.Assign(detail);
    }

    /** One bit of a 64-bit filter for a sim id. */
    [[nodiscard]] constexpr std::uint64_t ReferenceBit(const std::uint32_t id) noexcept
    {
      return std::uint64_t{1} << ((id * 0x9E3779B1u) >> 26u);
    }

    /** A filter of the sim ids `record` names: a false hit only costs a look at the record. */
    [[nodiscard]] std::uint64_t ReferenceFilter(const wire::SEntityRecord& record) noexcept
    {
      std::uint64_t filter = 0;
      const auto add = [&filter](const std::uint32_t id) {
        if (id != kNone) {
          filter |= ReferenceBit(id);
        }
      };
      add(record.appearance.attachParent);
      for (const std::uint32_t id : record.appearance.attachments) {
        add(id);
      }
      if (record.isUnit) {
        const wire::SUnitDetail& detail = *record.unit.detail;
        add(detail.creator);
        add(detail.selectionInheritor);
        add(detail.focusUnit);
        add(detail.guardedUnit);
        add(detail.targetBlip);
      }
      return filter;
    }
  } // namespace

  void CViewFrames::ClearUnheldReferences(wire::SViewFrame& frame)
  {
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
      ClearRecordReferences(record, unheld);
    }
  }

  void CViewFrames::AdvanceIdMap(moho::Sim& sim, const std::size_t army, CViewIdMap& map)
  {
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
  }

  void CViewFrames::BuildHeldFrame(moho::Sim& sim, const std::size_t army, const moho::SSyncData& packet)
  {
    CViewFrameBuilder& builder = *mBuilders[army];
    SHeldView& held = mHeld[army];
    const auto view = static_cast<std::int32_t>(army);
    builder.TrackChanges();
    builder.Apply(packet, Direct(static_cast<std::int32_t>(army)));
    const wire::SViewFrame stamp = builder.StartFrame(sim.mCurBeat);
    held.baselineId = held.frameId != 0u ? held.frameId : wire::kNoBaseline;
    held.frameId = stamp.frameId;
    held.beat = stamp.beat;

    const std::size_t slots = builder.SlotCount();
    if (held.records.size() < slots) {
      held.records.grow_to(slots);
      held.sent.resize(slots, 0u);
      held.keep.resize(slots, 0u);
      held.references.resize(slots, 0u);
    }
    held.candidates.clear();
    held.removed.clear();
    held.created.clear();
    held.changed.clear();
    held.before.clear();

    // What left the world, then what the oracle lets into this beat's frame (plan §6: a plain
    // entity in mode ReconGrid goes out only while the view sees it; a record the sim no longer
    // has, an orphan, stays). A record that comes or goes can change the records that name it.
    std::uint64_t membership = 0;
    for (const CViewFrameBuilder::SErasedRecord& erased : builder.ErasedRecords()) {
      if (held.sent[erased.slot] != 0u) {
        held.removed.push_back(held.records[erased.slot].id);
        held.sent[erased.slot] = 0u;
        --held.count;
        membership |= ReferenceBit(erased.id);
      }
    }
    std::uint32_t withheld = 0;
    auto index = mEntityIndex.cbegin();
    builder.ForEachRecord([&](const std::uint32_t id, const std::uint32_t slot) {
      while (index != mEntityIndex.cend() && index->first < id) {
        ++index;
      }
      const bool keep = index == mEntityIndex.cend() || index->first != id || CanViewSee(sim, view, index->second);
      held.keep[slot] = keep ? 1u : 0u;
      withheld += keep ? 0u : 1u;
      if (keep != (held.sent[slot] != 0u)) {
        held.candidates.push_back(id);
        membership |= ReferenceBit(id);
      }
    });
    held.candidates.insert(held.candidates.end(), builder.TouchedIds().begin(), builder.TouchedIds().end());
    if (membership != 0u) {
      builder.ForEachRecord([&](const std::uint32_t id, const std::uint32_t slot) {
        if (held.sent[slot] != 0u && (held.references[slot] & membership) != 0u) {
          held.candidates.push_back(id);
        }
      });
    }
    std::sort(held.candidates.begin(), held.candidates.end());
    held.candidates.erase(std::unique(held.candidates.begin(), held.candidates.end()), held.candidates.end());

    // Plan WP5.9: the view's own ids. A command is the view's own when its top byte is one of
    // the command sources allowed to command the view's army (`UserCommandIssue.cpp:372` packs
    // the client's source there).
    CViewIdMap& map = *mIdMaps[army];
    AdvanceIdMap(sim, army, map);
    const moho::BVIntSet* sources = nullptr;
    if (army < packet.mArmyUpdates.size()) {
      sources = &packet.mArmyUpdates[army].mValidCommandSources;
    }
    const CViewIdMap::OwnCommandTest isOwnCommand = [sources](const std::uint32_t commandId) {
      return sources != nullptr && sources->Contains(commandId >> 24u);
    };

    // In ascending sim id order, as a whole frame hands out new view ids.
    const auto unheld = [&builder, &held](const std::uint32_t id) {
      if (id == kNone) {
        return false;
      }
      std::uint32_t slot = 0;
      return !builder.FindSlot(id, slot) || held.keep[slot] == 0u;
    };
    for (const std::uint32_t id : held.candidates) {
      std::uint32_t slot = 0;
      if (!builder.FindSlot(id, slot)) {
        continue;
      }
      const bool wasSent = held.sent[slot] != 0u;
      if (held.keep[slot] == 0u) {
        if (wasSent) {
          held.removed.push_back(held.records[slot].id);
          held.sent[slot] = 0u;
          --held.count;
        }
        continue;
      }
      wire::SEntityRecord next = builder.RecordAt(slot);
      held.references[slot] = ReferenceFilter(next);
      ClearRecordReferences(next, unheld);
      map.TranslateRecord(next, isOwnCommand);
      if (!wasSent) {
        held.records[slot] = std::move(next);
        held.sent[slot] = 1u;
        ++held.count;
        held.created.push_back(&held.records[slot]);
        continue;
      }
      const std::uint32_t fields = wire::ChangedFields(held.records[slot], next);
      if (fields != 0u) {
        const wire::SEntityRecord& before = held.before.push_back(std::move(held.records[slot]));
        held.changed.push_back({fields, &held.records[slot], &before}); // elements stay in place
      }
      held.records[slot] = std::move(next);
    }
    std::sort(held.removed.begin(), held.removed.end());
    std::sort(held.created.begin(), held.created.end(), [](const wire::SEntityRecord* const a, const wire::SEntityRecord* const b) {
      return a->id < b->id;
    });
    std::sort(held.changed.begin(), held.changed.end(), [](const wire::SFrameChange& a, const wire::SFrameChange& b) {
      return a.after->id < b.after->id;
    });
    mWithheld[army] = withheld;
    if (mHeldCheck) {
      CheckHeldFrame(sim, army, isOwnCommand);
    }
    builder.ClearChanges();
  }

  void CViewFrames::CheckHeldFrame(moho::Sim& sim, const std::size_t army, const CViewIdMap::OwnCommandTest& isOwnCommand)
  {
    CViewFrameBuilder& builder = *mBuilders[army];
    SHeldView& held = mHeld[army];
    const auto report = [&held, army, &sim](const char* const what, const std::uint32_t id) {
      if (++held.mismatches <= 5u) {
        std::fprintf(stderr, "view frames check: view %zu beat %u: %s (id %08x)\n", army, sim.mCurBeat, what, id);
      }
    };
    if (!held.checkMap) {
      held.checkMap = std::make_unique<CViewIdMap>(static_cast<std::int32_t>(army));
    }
    wire::SViewFrame whole{};
    whole.frameId = held.frameId;
    whole.beat = held.beat;
    builder.FillFrame(whole, [&builder, &held](const wire::SEntityRecord& record) {
      std::uint32_t slot = 0;
      return builder.FindSlot(record.id, slot) && held.keep[slot] != 0u;
    });
    ClearUnheldReferences(whole);
    AdvanceIdMap(sim, army, *held.checkMap);
    held.checkMap->Translate(whole, isOwnCommand);

    std::vector<const wire::SEntityRecord*> kept;
    kept.reserve(held.count);
    builder.ForEachRecord([&](const std::uint32_t, const std::uint32_t slot) {
      if (held.sent[slot] != 0u) {
        kept.push_back(&held.records[slot]);
      }
    });
    std::sort(kept.begin(), kept.end(), [](const wire::SEntityRecord* const a, const wire::SEntityRecord* const b) {
      return a->id < b->id;
    });
    if (kept.size() != whole.entities.size()) {
      report("record count differs", static_cast<std::uint32_t>(kept.size()));
    } else {
      for (std::size_t i = 0; i < kept.size(); ++i) {
        if (!(*kept[i] == whole.entities[i])) {
          report("record differs", whole.entities[i].id);
        }
      }
    }
    wire::BitWriter heldBytes;
    wire::BitWriter wholeBytes;
    const bool heldOk = EncodeHeldFrame(static_cast<std::int32_t>(army), heldBytes);
    const bool wholeOk = wire::EncodeFrame(whole, held.haveCheckPrevious ? &held.checkPrevious : nullptr, mCodec, wholeBytes);
    if (heldOk != wholeOk || !std::equal(heldBytes.Bytes().begin(), heldBytes.Bytes().end(), wholeBytes.Bytes().begin(), wholeBytes.Bytes().end())) {
      report("bytes differ", 0u);
    }
    held.checkPrevious = std::move(whole);
    held.haveCheckPrevious = true;
  }

  bool CViewFrames::EncodeHeldFrame(const std::int32_t army, wire::BitWriter& writer) const
  {
    const SHeldView& held = mHeld[static_cast<std::size_t>(army)];
    wire::SFrameChanges changes{};
    changes.frameId = held.frameId;
    changes.baselineId = held.baselineId;
    changes.beat = held.beat;
    changes.entityCount = held.count;
    changes.removed = held.removed;
    changes.created = held.created;
    changes.changed = held.changed;
    return wire::EncodeFrameChanges(changes, mCodec, writer);
  }

  std::uint64_t CViewFrames::HeldMismatches() const noexcept
  {
    std::uint64_t mismatches = 0;
    for (const SHeldView& held : mHeld) {
      mismatches += held.mismatches;
    }
    return mismatches;
  }

  void CViewFrames::OnViewPackets(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    while (mBuilders.size() < armyCount) {
      mIdMaps.push_back(std::make_unique<CViewIdMap>(static_cast<std::int32_t>(mBuilders.size())));
      mRetiring.emplace_back();
      mRetired.emplace_back();
      mBuilders.push_back(std::make_unique<CViewFrameBuilder>(mTables, mCodec));
      mHeld.emplace_back();
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
      if (mHeldOn) {
        BuildHeldFrame(sim, army, packet);
      } else {
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
          AdvanceIdMap(sim, army, map);
          const moho::BVIntSet* sources = nullptr;
          if (army < packet.mArmyUpdates.size()) {
            sources = &packet.mArmyUpdates[army].mValidCommandSources;
          }
          map.Translate(frame, [sources](const std::uint32_t commandId) {
            return sources != nullptr && sources->Contains(commandId >> 24u);
          });
        }

        mFrames[army] = std::move(frame);
        mWithheld[army] = withheld;
      }
      if (mIdMapsOn) {
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
