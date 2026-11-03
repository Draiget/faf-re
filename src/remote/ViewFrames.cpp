#include "remote/ViewFrames.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
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
    , mSharedRecords(tables, codec)
  {}

  CViewFrames::~CViewFrames() = default;

  namespace
  {
    constexpr std::uint32_t kNone = 0xF0000000u; // the sim's invalid entity id (`EntityId.h`)
    constexpr std::uint32_t kNoOwn = 0xFFFFFFFFu; // `SHeldView::ownSlot`: the view's record is the world's

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

    /** Whether the view's record differs from the world's: ids to renumber, or names it cannot hold. */
    template <class Unheld>
    [[nodiscard]] bool NeedsOwnRecord(const wire::SEntityRecord& record, const CViewIdMap& map, const Unheld& unheld)
    {
      if (record.isUnit || map.MapsEntity(record.id)) {
        return true;
      }
      const auto differs = [&map, &unheld](const std::uint32_t id) {
        return id != kNone && (map.MapsEntity(id) || unheld(id));
      };
      if (differs(record.appearance.attachParent)) {
        return true;
      }
      return std::any_of(record.appearance.attachments.begin(), record.appearance.attachments.end(), differs);
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
      map.RetireCommands(mReleasedCommands);
      map.RetireNewCommandsUnless([commands](const std::uint32_t simId) {
        return commands->commands.find(simId) != commands->commands.end();
      });
    }
  }

  void CViewFrames::BuildHeldFrame(moho::Sim& sim, const std::size_t army, const moho::SSyncData& packet)
  {
    CViewFrameBuilder& builder = *mBuilders[army];
    SHeldView& held = mHeld[army];
    builder.TrackChanges();
    builder.ClearBefore();
    builder.Apply(packet, Direct(static_cast<std::int32_t>(army)));
    const wire::SViewFrame stamp = builder.StartFrame(sim.mCurBeat);
    held.baselineId = held.frameId != 0u ? held.frameId : wire::kNoBaseline;
    held.frameId = stamp.frameId;
    held.beat = stamp.beat;

    const std::size_t slots = builder.SlotCount();
    if (held.ownSlot.size() < slots) {
      held.ownSlot.resize(slots, kNoOwn);
      held.sent.resize(slots, 0u);
      held.keep.resize(slots, 0u);
      held.references.resize(slots, 0u);
    }
    held.candidates.clear();
    held.removed.clear();
    held.created.clear();
    held.changed.clear();
    held.before.clear();

    const auto takeOwn = [&held](const std::uint32_t slot) -> wire::SEntityRecord& {
      std::uint32_t index;
      if (!held.ownFree.empty()) {
        index = held.ownFree.back();
        held.ownFree.pop_back();
      } else {
        index = static_cast<std::uint32_t>(held.own.size());
        held.own.grow_to(held.own.size() + 1u);
      }
      held.ownSlot[slot] = index;
      return held.own[index];
    };
    const auto dropOwn = [&held](const std::uint32_t slot) {
      const std::uint32_t index = held.ownSlot[slot];
      if (index != kNoOwn) {
        held.own[index] = wire::SEntityRecord{}; // lets go of what the record shares
        held.ownFree.push_back(index);
        held.ownSlot[slot] = kNoOwn;
      }
    };

    // What left the world, then what the oracle lets into this beat's frame (plan §6: a plain
    // entity in mode ReconGrid goes out only while the view sees it; a record the sim no longer
    // has, an orphan, stays). A record that comes or goes can change the records that name it.
    std::uint64_t membership = 0;
    for (const CViewFrameBuilder::SErasedRecord& erased : builder.ErasedRecords()) {
      if (held.sent[erased.slot] != 0u) {
        const std::uint32_t own = held.ownSlot[erased.slot];
        held.removed.push_back(own != kNoOwn ? held.own[own].id : erased.id);
        dropOwn(erased.slot);
        held.sent[erased.slot] = 0u;
        --held.count;
        membership |= ReferenceBit(erased.id);
      }
    }
    std::uint32_t withheld = 0;
    const std::uint32_t viewBit = std::uint32_t{1} << army;
    auto index = mEntityIndex.cbegin();
    builder.ForEachRecord([&](const std::uint32_t id, const std::uint32_t slot) {
      while (index != mEntityIndex.cend() && index->id < id) {
        ++index;
      }
      const bool keep = index == mEntityIndex.cend() || index->id != id || (index->views & viewBit) != 0u;
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
    std::size_t cursor = 0;
    for (const std::uint32_t id : held.candidates) {
      std::uint32_t slot = 0;
      if (!builder.FindSlotFrom(cursor, id, slot)) {
        continue;
      }
      const bool wasSent = held.sent[slot] != 0u;
      const wire::SEntityRecord& world = builder.RecordAt(slot);
      const std::uint32_t own = held.ownSlot[slot];
      if (held.keep[slot] == 0u) {
        if (wasSent) {
          held.removed.push_back(own != kNoOwn ? held.own[own].id : world.id);
          dropOwn(slot);
          held.sent[slot] = 0u;
          --held.count;
        }
        builder.UnwatchRecord(slot);
        continue;
      }
      held.references[slot] = ReferenceFilter(world);
      if (!NeedsOwnRecord(world, map, unheld)) {
        // The client's record is the world's, without a copy; the elements stay in place.
        if (!wasSent) {
          held.sent[slot] = 1u;
          ++held.count;
          held.created.push_back(&world);
        } else if (own != kNoOwn) {
          const std::uint32_t fields = wire::ChangedFields(held.own[own], world);
          if (fields != 0u) {
            held.changed.push_back({fields, &world, &held.before.push_back(held.own[own])});
          }
          dropOwn(slot);
        } else if (const wire::SEntityRecord* const before = builder.RecordBefore(slot); before != nullptr) {
          const std::uint32_t fields = wire::ChangedFields(*before, world);
          if (fields != 0u) {
            held.changed.push_back({fields, &world, before});
          }
        }
        builder.WatchRecord(slot);
        continue;
      }
      wire::SEntityRecord next = world;
      ClearRecordReferences(next, unheld);
      map.TranslateRecord(next, isOwnCommand);
      if (!wasSent) {
        wire::SEntityRecord& created = takeOwn(slot);
        created = std::move(next);
        held.sent[slot] = 1u;
        ++held.count;
        held.created.push_back(&created);
      } else if (own != kNoOwn) {
        wire::SEntityRecord& record = held.own[own];
        const std::uint32_t fields = wire::ChangedFields(record, next);
        if (fields != 0u) {
          const wire::SEntityRecord& before = held.before.push_back(std::move(record));
          held.changed.push_back({fields, &record, &before}); // elements stay in place
        }
        record = std::move(next);
      } else {
        const wire::SEntityRecord* const saved = builder.RecordBefore(slot);
        const wire::SEntityRecord& before = saved != nullptr ? *saved : world;
        wire::SEntityRecord& record = takeOwn(slot);
        record = std::move(next);
        const std::uint32_t fields = wire::ChangedFields(before, record);
        if (fields != 0u) {
          held.changed.push_back({fields, &record, &before});
        }
      }
      builder.UnwatchRecord(slot);
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
        const std::uint32_t own = held.ownSlot[slot];
        kept.push_back(own != kNoOwn ? &held.own[own] : &builder.RecordAt(slot));
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
    std::uint64_t mismatches = mEntityIndexMismatches;
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

    // The sim's entities in ascending id order with the views that keep each, worked out once for
    // every view (plan WPR.35): a frame's records are in that order too, so each view finds its
    // records' answers in one forward pass. An entity that didn't sync keeps last beat's answer
    // unless that answer depends on more than the entity, so most entities aren't read at all.
    mLastEntityIndex.swap(mEntityIndex);
    mLastEntityPointers.swap(mEntityPointers);
    mEntityIndex.clear();
    mEntityPointers.clear();
    mEntityReads.clear();
    if (sim.mEntityDB != nullptr) {
      mEntityIndex.reserve(sim.mEntityDB->mAllUnits.size());
      mEntityPointers.reserve(sim.mEntityDB->mAllUnits.size());
      const std::vector<SChangedEntity>& changed = Entities();
      std::size_t last = 0;
      std::size_t next = 0;
      for (const auto& [id, entity] : sim.mEntityDB->mAllUnits) {
        const auto key = static_cast<std::uint32_t>(id);
        while (last < mLastEntityIndex.size() && mLastEntityIndex[last].id < key) {
          ++last;
        }
        while (next < changed.size() && static_cast<std::uint32_t>(changed[next].entity->id_) < key) {
          ++next;
        }
        const bool synced = next < changed.size() && changed[next].entity == entity;
        if (!synced && last < mLastEntityIndex.size() && mLastEntityIndex[last].id == key && mLastEntityPointers[last] == entity
            && !mLastEntityIndex[last].readEveryBeat) {
          mEntityIndex.push_back(mLastEntityIndex[last]);
        } else {
          mEntityReads.push_back(static_cast<std::uint32_t>(mEntityIndex.size()));
          mEntityIndex.push_back({key, 0u, false});
        }
        mEntityPointers.push_back(entity);
      }
    }
    const auto readFacts = [this, &sim, armyCount](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        const std::uint32_t entry = mEntityReads[i];
        const SEntityFacts facts = ReadEntityFacts(*mEntityPointers[entry]);
        mEntityIndex[entry].views = ViewsThatSee(sim, armyCount, facts);
        mEntityIndex[entry].readEveryBeat = !ViewsFollowFactsAlone(facts);
      }
    };
    constexpr std::size_t kFactsGrain = 256;
    if (Parallel() && mEntityReads.size() > kFactsGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(mEntityReads.size(), kFactsGrain, readFacts);
    } else {
      readFacts(0u, mEntityReads.size());
    }
    if (mHeldCheck) {
      for (std::size_t i = 0; i < mEntityIndex.size(); ++i) {
        const SEntityFacts facts = ReadEntityFacts(*mEntityPointers[i]);
        if (ViewsThatSee(sim, armyCount, facts) != mEntityIndex[i].views && ++mEntityIndexMismatches <= 5u) {
          std::fprintf(
            stderr, "view frames check: beat %u: entity %08x kept views %08x, a read says %08x (kind %d)\n", sim.mCurBeat, mEntityIndex[i].id,
            mEntityIndex[i].views, ViewsThatSee(sim, armyCount, facts), static_cast<int>(facts.kind)
          );
        }
      }
    }

    // The commands the sim released since last beat, once for every view (`AdvanceIdMap`).
    mLastCommands.swap(mLiveCommands);
    mLiveCommands.clear();
    if (const moho::CCommandDB* const commands = sim.mCommandDB; commands != nullptr) {
      for (const auto& [id, command] : commands->commands) {
        mLiveCommands.push_back(static_cast<std::uint32_t>(id));
      }
    }
    mReleasedCommands.clear();
    std::set_difference(
      mLastCommands.begin(), mLastCommands.end(), mLiveCommands.begin(), mLiveCommands.end(), std::back_inserter(mReleasedCommands)
    );

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
        const std::uint32_t viewBit = std::uint32_t{1} << army;
        auto index = mEntityIndex.cbegin();
        wire::SViewFrame frame = builder.Build(sim.mCurBeat, [&](const wire::SEntityRecord& record) {
          while (index != mEntityIndex.cend() && index->id < record.id) {
            ++index;
          }
          if (index == mEntityIndex.cend() || index->id != record.id || (index->views & viewBit) != 0u) {
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
