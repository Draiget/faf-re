#include "headless/ReplayViewFrameStats.h"

#include <algorithm>
#include <functional>
#include <unordered_set>
#include <utility>

#include "moho/entity/EntityDb.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"
#include "remote/VisibilityOracle.h"
#include "remote/wire/BitStream.h"

// Engine addition, server mode: see ReplayViewFrameStats.h.

namespace faf::headless
{
  namespace
  {
    /** The fields a record names other entities in (the spy's reference check). */
    constexpr const char* kSpyFields[7] = {"attachment parent", "attachment", "creator", "selection inheritor",
                                           "focus", "guarded unit", "target blip"};

    /** The codec `--wire-stats` uses: positions over the map, no dead reckoning. */
    [[nodiscard]] remote::wire::SFrameCodec MakeCodec(const float mapSizeX, const float mapSizeZ)
    {
      remote::wire::SFrameCodec codec{};
      codec.position = remote::wire::SPositionQuantizer::ForMap(mapSizeX, mapSizeZ);
      codec.maxEntities = 1u << 20;
      return codec;
    }
  } // namespace

  CReplayViewFrameStats::CReplayViewFrameStats(
    const std::string& path, const remote::wire::SContentTables& tables, const float mapSizeX, const float mapSizeZ
  )
    : remote::CViewFrames(tables, MakeCodec(mapSizeX, mapSizeZ))
    , mCodec(MakeCodec(mapSizeX, mapSizeZ))
    , mReckonedCodec(MakeCodec(mapSizeX, mapSizeZ))
    , mTables(&tables)
  {
    mReckonedCodec.deadReckoning = true;
    if (fopen_s(&mFile, path.c_str(), "w") != 0) {
      mFile = nullptr;
      return;
    }
    std::fprintf(mFile, "beat,army,entities,withheld,delta_bytes,grid_bytes,reckoned_bytes\n");
  }

  CReplayViewFrameStats::~CReplayViewFrameStats()
  {
    Uninstall();
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void CReplayViewFrameStats::Install()
  {
    moho::Sim::SetSyncObserver(this);
  }

  void CReplayViewFrameStats::Uninstall()
  {
    moho::Sim::SetSyncObserver(nullptr);
  }

  void CReplayViewFrameStats::OnViewFrames(moho::Sim& sim)
  {
    const auto armyCount = static_cast<std::size_t>(ArmyCount());
    while (mPrevious.size() < armyCount) {
      mPrevious.emplace_back();
      mHavePrevious.push_back(false);
      mBytes.push_back(0);
      mEntities.push_back(0);
      mGridBytes.push_back(0);
      remote::wire::SReckoningScheme scheme{};
      scheme.tolerance = 16; // plan WP7.5's 16-step scheme, as --wire-stats measures it
      scheme.window = 1;
      mReckoners.emplace_back(scheme);
      mPreviousReckoned.emplace_back();
      mReckonedBytes.push_back(0);
      mAnchoredByFamily.emplace_back();
      mAnchoredByBlueprint.emplace_back();
    }
    ++mBeats;

    for (std::size_t army = 0; army < armyCount; ++army) {
      const remote::wire::SViewFrame& frame = Frame(static_cast<std::int32_t>(army));
      const remote::wire::SViewFrame* const baseline = mHavePrevious[army] ? &mPrevious[army] : nullptr;
      remote::wire::BitWriter writer;
      if (!remote::wire::EncodeFrame(frame, baseline, mCodec, writer)) {
        ++mEncodeFailures;
        continue;
      }
      remote::wire::BitReader reader(writer.Bytes());
      remote::wire::SViewFrame decoded{};
      if (!remote::wire::DecodeFrame(reader, baseline, mCodec, decoded) || !(decoded == frame)) {
        ++mRoundTripFailures;
      }
      if (mSpyOn) {
        Spy(sim, army, decoded); // what the client holds after the wire
      }
      const auto bytes = static_cast<std::uint32_t>(writer.Bytes().size());
      if (IdMapsOn()) {
        CheckIds(frame, IdMap(static_cast<std::int32_t>(army)));
      }
      if (mChannelOn) {
        SendOverChannel(army, frame, sim.mCurBeat);
      }

      // The same frame with dead reckoning, against this view's previous reckoned frame.
      remote::wire::SViewFrame reckoned = frame;
      mReckoners[army].Apply(reckoned, mReckonedCodec);
      for (const remote::wire::SEntityRecord& record : reckoned.entities) {
        if (record.farPosition || record.anchorBeat != reckoned.beat) {
          continue;
        }
        ++mAnchoredByFamily[army][record.id >> 28];
        if (!record.isUnit) {
          ++mAnchoredByBlueprint[army][record.blueprint];
        }
      }
      remote::wire::BitWriter reckonedWriter;
      std::uint32_t reckonedBytes = 0;
      if (remote::wire::EncodeFrame(
            reckoned, mHavePrevious[army] ? &mPreviousReckoned[army] : nullptr, mReckonedCodec, reckonedWriter
          )) {
        reckonedBytes = static_cast<std::uint32_t>(reckonedWriter.Bytes().size());
        mReckonedBytes[army] += reckonedBytes;
      } else {
        ++mEncodeFailures;
      }
      mPreviousReckoned[army] = std::move(reckoned);
      const std::uint32_t gridBytes = SendGrids(sim, army);
      mBytes[army] += bytes;
      mEntities[army] += frame.entities.size();
      mGridBytes[army] += gridBytes;
      if (mFile != nullptr) {
        std::fprintf(
          mFile, "%u,%zu,%zu,%u,%u,%u,%u\n", sim.mCurBeat, army, frame.entities.size(),
          Withheld(static_cast<std::int32_t>(army)), bytes, gridBytes, reckonedBytes
        );
      }
      mPrevious[army] = frame;
      mHavePrevious[army] = true;
    }
  }

  std::uint32_t CReplayViewFrameStats::SendGrids(const moho::Sim& sim, const std::size_t view)
  {
    const auto viewIndex = static_cast<std::uint32_t>(view);
    std::uint32_t total = 0;
    for (std::size_t index = 0; index < sim.mArmiesList.size(); ++index) {
      const moho::CArmyImpl* const army = sim.mArmiesList[index];
      // `UserArmy::CanSeeCell` (0x008B17F0): the view's own grids and those of every army that
      // lists the view among its allies.
      if (army == nullptr || (index != view && !army->mVarDat.mAllies.Contains(viewIndex))) {
        continue;
      }
      const moho::CIntelGrid* const grids[2] = {army->mConstDat.mVisionReconGrid.get(), army->mConstDat.mWaterReconGrid.get()};
      for (int kind = 0; kind < 2; ++kind) {
        const moho::CIntelGrid* const grid = grids[kind];
        if (grid == nullptr) {
          continue;
        }
        remote::wire::SGridBits bits;
        bits.width = grid->mWidth;
        bits.height = grid->mHeight;
        bits.cells.resize(static_cast<std::size_t>(grid->mWidth) * grid->mHeight);
        for (std::size_t cell = 0; cell < bits.cells.size(); ++cell) {
          bits.cells[cell] = grid->mGrid[cell] != 0 ? 1u : 0u;
        }

        remote::wire::SGridBits& sent = mSentGrids[{view, index, kind}];
        remote::wire::BitWriter writer;
        if (!remote::wire::EncodeGridDelta(bits, sent.cells.empty() ? nullptr : &sent, writer)) {
          ++mGridFailures;
          continue;
        }
        remote::wire::BitReader reader(writer.Bytes());
        remote::wire::SGridBits decoded;
        if (!remote::wire::DecodeGridDelta(reader, sent.cells.empty() ? nullptr : &sent, 1u << 24, decoded)
            || !(decoded == bits)) {
          ++mGridFailures;
        }
        total += static_cast<std::uint32_t>(writer.Bytes().size());
        sent = std::move(bits);
      }
    }
    return total;
  }

  std::string CReplayViewFrameStats::Summary() const
  {
    std::string summary;
    char text[320];
    std::snprintf(
      text, sizeof(text), "view frames: %llu beats, %zu armies, %llu encode failures, %llu round-trip failures",
      static_cast<unsigned long long>(mBeats), mBytes.size(), static_cast<unsigned long long>(mEncodeFailures),
      static_cast<unsigned long long>(mRoundTripFailures)
    );
    summary = text;
    std::snprintf(
      text, sizeof(text), "; views built in %.2f ms per beat (%s)",
      mBeats > 0 ? BuildSeconds() * 1000.0 / static_cast<double>(mBeats) : 0.0, Parallel() ? "parallel" : "serial"
    );
    summary += text;
    for (std::size_t army = 0; army < mBytes.size(); ++army) {
      // 10 beats a second: bytes per beat x 10 / 1000 = KB/s.
      const double beats = mBeats > 0 ? static_cast<double>(mBeats) : 1.0;
      std::snprintf(
        text, sizeof(text),
        "\n  army %zu: %.0f entities and %.0f bytes per frame on average (%.1f KB/s; with dead reckoning %.1f KB/s); "
        "grids %.0f bytes per beat (%.2f KB/s)",
        army, static_cast<double>(mEntities[army]) / beats, static_cast<double>(mBytes[army]) / beats,
        static_cast<double>(mBytes[army]) / beats * 10.0 / 1000.0,
        static_cast<double>(mReckonedBytes[army]) / beats * 10.0 / 1000.0, static_cast<double>(mGridBytes[army]) / beats,
        static_cast<double>(mGridBytes[army]) / beats * 10.0 / 1000.0
      );
      summary += text;

      const remote::CDeadReckoner& reckoner = mReckoners[army];
      const remote::CDeadReckoner::SReanchorCauses& causes = reckoner.Causes();
      std::snprintf(
        text, sizeof(text),
        "\n    re-anchors %.1f per beat (units %llu, stopped %llu, after 1 beat %llu, 2-3 %llu, 4-9 %llu, 10+ %llu)",
        static_cast<double>(reckoner.Reanchors()) / beats, static_cast<unsigned long long>(causes.units),
        static_cast<unsigned long long>(causes.stopped), static_cast<unsigned long long>(causes.afterBeats[0]),
        static_cast<unsigned long long>(causes.afterBeats[1]), static_cast<unsigned long long>(causes.afterBeats[2]),
        static_cast<unsigned long long>(causes.afterBeats[3])
      );
      summary += text;

      // Anchored records by id family: units, projectiles, props, blips (`(army | 0x300) << 20`,
      // ReconBlip.cpp), shields (0x400, 0x007764B2), script entities (`_c_CreateEntity`'s 0x500,
      // 0x006924F3); then the non-unit blueprints anchored most.
      const std::array<std::uint64_t, 16>& families = mAnchoredByFamily[army];
      std::snprintf(
        text, sizeof(text),
        "\n    anchored per beat: units %.1f, projectiles %.1f, props %.1f, blips %.1f, shields %.1f, script entities %.1f; most:",
        static_cast<double>(families[0]) / beats, static_cast<double>(families[1]) / beats,
        static_cast<double>(families[2]) / beats, static_cast<double>(families[3]) / beats,
        static_cast<double>(families[4]) / beats, static_cast<double>(families[5]) / beats
      );
      summary += text;
      for (std::size_t nibble = 6; nibble < families.size(); ++nibble) {
        if (families[nibble] != 0u) {
          std::snprintf(
            text, sizeof(text), " (family %zX %.1f)", nibble, static_cast<double>(families[nibble]) / beats
          );
          summary += text;
        }
      }
      std::vector<std::pair<std::uint64_t, std::uint32_t>> top;
      for (const auto& [blueprint, count] : mAnchoredByBlueprint[army]) {
        top.emplace_back(count, blueprint);
      }
      std::sort(top.begin(), top.end(), std::greater<>{});
      for (std::size_t i = 0; i < top.size() && i < 5; ++i) {
        std::string_view name = mTables->blueprints.Name(top[i].second);
        if (name.empty()) {
          name = "(no-blueprint)";
        }
        std::snprintf(
          text, sizeof(text), " %.*s %.1f", static_cast<int>(name.size()), name.data(),
          static_cast<double>(top[i].first) / beats
        );
        summary += text;
      }
      if (mChannelOn && army < mChannels.size()) {
        const SChannel& channel = mChannels[army];
        std::snprintf(
          text, sizeof(text),
          "\n    channel (%u %% lost, acks %u beats late): %.1f KB/s, %llu frames lost, %llu sent in full, %zu kept at the end",
          mLossPercent, mAckDelay, static_cast<double>(channel.bytes) / beats * 10.0 / 1000.0,
          static_cast<unsigned long long>(channel.lost), static_cast<unsigned long long>(channel.server.FullFrames()),
          channel.server.Kept()
        );
        summary += text;
      }
      if (IdMapsOn()) {
        const remote::CViewIdMap& map = IdMap(static_cast<std::int32_t>(army));
        std::snprintf(
          text, sizeof(text),
          "\n    view ids: %llu entities and %llu commands renumbered, %zu and %zu live at the end, %llu overflows",
          static_cast<unsigned long long>(map.EntitiesMapped()), static_cast<unsigned long long>(map.CommandsMapped()),
          map.LiveEntities(), map.LiveCommands(), static_cast<unsigned long long>(map.Overflows())
        );
        summary += text;
      }
    }
    if (mSpyOn) {
      std::snprintf(
        text, sizeof(text),
        "\n  spy: %llu records held, %llu outside the view, %llu orphans; %llu references, not held:",
        static_cast<unsigned long long>(mSpyRecords), static_cast<unsigned long long>(mSpyOutside),
        static_cast<unsigned long long>(mSpyOrphans), static_cast<unsigned long long>(mSpyReferences)
      );
      summary += text;
      for (std::size_t field = 0; field < mSpyUnheld.size(); ++field) {
        std::snprintf(
          text, sizeof(text), "%s %s %llu", field == 0 ? "" : ",", kSpyFields[field],
          static_cast<unsigned long long>(mSpyUnheld[field])
        );
        summary += text;
      }
      for (const std::string& example : mSpyExamples) {
        summary += "\n    " + example;
      }
    }
    if (mChannelOn) {
      std::snprintf(
        text, sizeof(text), "\n  channel: %llu frames arrived and did not decode to the frame sent",
        static_cast<unsigned long long>(mChannelFailures)
      );
      summary += text;
    }
    if (IdMapsOn()) {
      std::snprintf(
        text, sizeof(text), "\n  view ids checked in the frames: %llu, not mapping back to their family and source: %llu",
        static_cast<unsigned long long>(mIdsChecked), static_cast<unsigned long long>(mIdFailures)
      );
      summary += text;
    }
    return summary;
  }

  void CReplayViewFrameStats::SendOverChannel(
    const std::size_t army, const remote::wire::SViewFrame& frame, const std::uint32_t beat
  )
  {
    while (mChannels.size() <= army) {
      SChannel channel{};
      channel.random.seed(static_cast<std::uint32_t>(0x5EED0000u + mChannels.size())); // the same losses every run
      mChannels.push_back(std::move(channel));
    }
    SChannel& channel = mChannels[army];

    // Acknowledgements due by now reach the server first.
    while (!channel.acks.empty() && channel.acks.front().first <= beat) {
      channel.server.Ack(channel.acks.front().second);
      channel.acks.pop_front();
    }

    remote::wire::BitWriter writer;
    if (!remote::wire::EncodeFrame(frame, channel.server.Baseline(), mCodec, writer)) {
      ++mChannelFailures;
      return;
    }
    channel.server.Sent(frame);
    channel.bytes += writer.Bytes().size();

    if (std::uniform_int_distribution<std::uint32_t>(0u, 99u)(channel.random) < mLossPercent) {
      ++channel.lost;
      return;
    }
    remote::wire::SViewFrame decoded{};
    if (!channel.client.Decode(writer.Bytes(), mCodec, decoded) || !(decoded == frame)) {
      ++mChannelFailures;
      return;
    }
    channel.acks.emplace_back(beat + mAckDelay, channel.client.Newest());
  }

  void CReplayViewFrameStats::Spy(const moho::Sim& sim, const std::size_t army, const remote::wire::SViewFrame& held)
  {
    const auto viewArmy = static_cast<std::int32_t>(army);
    const remote::CViewIdMap* const map = IdMapsOn() ? &IdMap(viewArmy) : nullptr;
    const auto example = [&](const char* what, const std::uint32_t id, const std::uint32_t named) {
      if (mSpyExamples.size() < 12u) {
        char text[160];
        std::snprintf(text, sizeof(text), "beat %u, army %d: %s 0x%08x names 0x%08x", held.beat, viewArmy, what, id, named);
        mSpyExamples.emplace_back(text);
      }
    };

    // Every record must be one the oracle lets this view have.
    std::unordered_set<std::uint32_t> ids;
    ids.reserve(held.entities.size());
    for (const remote::wire::SEntityRecord& record : held.entities) {
      ids.insert(record.id);
      ++mSpyRecords;
      std::uint32_t simId = record.id;
      if (map != nullptr && !map->EntityToSim(record.id, simId)) {
        ++mSpyOutside;
        example("record without a sim id", record.id, record.id);
        continue;
      }
      moho::Entity* entity = nullptr;
      if (sim.mEntityDB != nullptr) {
        const auto found = sim.mEntityDB->mAllUnits.find(simId);
        entity = found != sim.mEntityDB->mAllUnits.end() ? found->second : nullptr;
      }
      if (entity == nullptr) {
        ++mSpyOrphans;
        continue;
      }
      if (!remote::ResolveViewVisibility(sim, viewArmy, *entity).published || !remote::CanViewSee(sim, viewArmy, *entity)) {
        ++mSpyOutside;
        example("record outside the view", record.id, simId);
      }
    }

    // Every entity a record names must be one the client holds.
    const auto reference = [&](const std::size_t field, const std::uint32_t owner, const std::uint32_t named) {
      if (named == 0xF0000000u) {
        return; // the sim's "none"
      }
      ++mSpyReferences;
      if (ids.count(named) == 0u) {
        ++mSpyUnheld[field];
        example(kSpyFields[field], owner, named);
      }
    };
    for (const remote::wire::SEntityRecord& record : held.entities) {
      reference(0, record.id, record.appearance.attachParent);
      for (const std::uint32_t child : record.appearance.attachments) {
        reference(1, record.id, child);
      }
      if (!record.isUnit) {
        continue;
      }
      const remote::wire::SUnitDetail& detail = *record.unit.detail;
      reference(2, record.id, detail.creator);
      reference(3, record.id, detail.selectionInheritor);
      reference(4, record.id, detail.focusUnit);
      reference(5, record.id, detail.guardedUnit);
      reference(6, record.id, detail.targetBlip);
    }
  }

  void CReplayViewFrameStats::CheckIds(const remote::wire::SViewFrame& frame, const remote::CViewIdMap& map)
  {
    const auto entity = [&](const std::uint32_t viewId) {
      if (!map.MapsEntity(viewId)) {
        return;
      }
      ++mIdsChecked;
      std::uint32_t simId = 0;
      if (!map.EntityToSim(viewId, simId) || (simId & 0xFFF00000u) != (viewId & 0xFFF00000u)) {
        ++mIdFailures;
      }
    };
    const auto command = [&](const std::int32_t value) {
      const auto viewId = static_cast<std::uint32_t>(value);
      if ((viewId & 0xFF000000u) != 0x80000000u) {
        return; // the client's own command keeps its id
      }
      ++mIdsChecked;
      std::uint32_t simId = 0;
      if (!map.CommandToSim(viewId, simId)) {
        ++mIdFailures;
      }
    };
    for (const remote::wire::SEntityRecord& record : frame.entities) {
      entity(record.id);
      if (record.appearance.attachParent != remote::wire::SAppearance::kNoAttachParent) {
        entity(record.appearance.attachParent);
      }
      for (const std::uint32_t child : record.appearance.attachments) {
        entity(child);
      }
      if (!record.isUnit) {
        continue;
      }
      const remote::wire::SUnitDetail& detail = *record.unit.detail;
      entity(detail.creator);
      entity(detail.selectionInheritor);
      entity(detail.focusUnit);
      entity(detail.guardedUnit);
      entity(detail.targetBlip);
      for (const std::int32_t value : detail.commands) {
        command(value);
      }
      for (const std::int32_t value : detail.buildQueue) {
        command(value);
      }
    }
  }
} // namespace faf::headless
