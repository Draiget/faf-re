// Plan WP5.14: the command-records lane (src/remote/wire/CommandLane.h): its framing, the server's per-view routes of
// the sim's command records (src/remote/CommandRecords.h: units cut to the view's army, descriptors when a command
// first has one of them, deltas, removals, releases, ids translated, a whole lane after a reconnect), and the client's
// end (the receiver, which drops a record of a command it wasn't sent, and src/remote/client/CommandLaneApplier.h,
// which turns a lane into the beat packet's command lists).

#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTICommandVariableData.h"
// A whole `SSyncData` is made here: every element type of its lanes.
#include "moho/render/CDecalTypes.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SDesyncInfo.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"
#include "remote/CommandRecords.h"
#include "remote/client/CommandLaneApplier.h"
#include "remote/wire/CommandLane.h"

namespace
{
  using faf::remote::CCommandBook;
  using faf::remote::CCommandViewRoute;
  using faf::remote::wire::CCommandLaneReceiver;
  using faf::remote::wire::DecodeCommandLane;
  using faf::remote::wire::EncodeCommandLane;
  using faf::remote::wire::kNoCommandEntity;
  using faf::remote::wire::SCommandData;
  using faf::remote::wire::SCommandDescriptor;
  using faf::remote::wire::SCommandLane;
  using faf::remote::wire::SCommandTarget;
  using faf::remote::wire::SCommandUpdate;

  [[nodiscard]] std::uint32_t Bits(
    const float value
  )
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  [[nodiscard]] SCommandLane SampleLane()
  {
    SCommandLane lane;
    SCommandDescriptor descriptor;
    descriptor.id = 0x80000007u;
    descriptor.formation = 3;
    descriptor.origin = {0.0f, 0.5f, -0.0f, 1.0f};
    descriptor.scale = 1.25f;
    descriptor.blueprint = 42u;
    descriptor.script = "{ TaskName = \"EnhanceTask\", Enhancement = \"AdvancedEngineering\" }";
    lane.descriptors.push_back(descriptor);

    SCommandUpdate update;
    update.id = 0x80000007u;
    update.data.units = {0x00100003u, 0x00100009u};
    update.data.type = 7;
    update.data.target1 = {2, kNoCommandEntity, {100.5f, 20.25f, -0.0f}};
    update.data.target2 = {1, 0x30200001u, {}};
    update.data.extra = -1;
    update.data.cells = {{5, -6}, {7, 8}};
    update.data.maxCount = 5;
    update.data.count = 2;
    update.data.flags = 0xABCDu;
    update.fields = faf::remote::wire::kCommandAllFields;
    lane.updates.push_back(update);

    SCommandUpdate empty;
    empty.id = 0x01000002u;
    lane.updates.push_back(empty); // no field: the sim published it again unchanged
    lane.removals = {0x80000003u};
    lane.releases = {0x80000001u, 0x01000005u};
    return lane;
  }
} // namespace

// The lane's bytes read back as written: every field of a descriptor and of a record, a record with no field, the
// removals and releases; a -0 and a NaN keep their bits; an empty lane is no byte.
TEST(
  CommandLane,
  RoundTripsEveryField
)
{
  SCommandLane lane = SampleLane();
  lane.updates[0].data.target2.position = {std::numeric_limits<float>::quiet_NaN(), 0.0f, 0.0f};
  std::vector<std::uint8_t> bytes;
  EncodeCommandLane(lane, bytes);
  ASSERT_FALSE(bytes.empty());

  SCommandLane read;
  ASSERT_TRUE(DecodeCommandLane(bytes, read));
  EXPECT_FALSE(read.whole);
  ASSERT_EQ(read.descriptors.size(), 1u);
  EXPECT_EQ(read.descriptors[0], lane.descriptors[0]);
  EXPECT_EQ(Bits(read.descriptors[0].origin[2]), Bits(-0.0f));
  ASSERT_EQ(read.updates.size(), 2u);
  EXPECT_EQ(read.updates[0].fields, faf::remote::wire::kCommandAllFields);
  EXPECT_EQ(read.updates[0].data, lane.updates[0].data);
  EXPECT_EQ(Bits(read.updates[0].data.target1.position[2]), Bits(-0.0f));
  EXPECT_TRUE(std::isnan(read.updates[0].data.target2.position[0]));
  EXPECT_EQ(read.updates[1].id, 0x01000002u);
  EXPECT_EQ(read.updates[1].fields, 0u);
  EXPECT_EQ(read.removals, lane.removals);
  EXPECT_EQ(read.releases, lane.releases);

  SCommandLane whole;
  whole.whole = true;
  EncodeCommandLane(whole, bytes);
  ASSERT_FALSE(bytes.empty()); // a whole lane with nothing in it still says so
  ASSERT_TRUE(DecodeCommandLane(bytes, read));
  EXPECT_TRUE(read.whole);
  EXPECT_TRUE(read.descriptors.empty());

  EncodeCommandLane(SCommandLane{}, bytes);
  EXPECT_TRUE(bytes.empty());
  ASSERT_TRUE(DecodeCommandLane(bytes, read));
  EXPECT_TRUE(read.Empty());
}

// Damaged bytes don't decode: cut anywhere, a field this build doesn't know, a count past the lane's end, a byte after
// it, unknown flags.
TEST(
  CommandLane,
  RefusesDamagedBytes
)
{
  std::vector<std::uint8_t> bytes;
  EncodeCommandLane(SampleLane(), bytes);
  SCommandLane read;
  for (std::size_t cut = 1; cut < bytes.size(); ++cut) {
    const std::vector<std::uint8_t> shorter(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(cut));
    EXPECT_FALSE(DecodeCommandLane(shorter, read)) << "cut to " << cut << " bytes";
  }
  std::vector<std::uint8_t> longer = bytes;
  longer.push_back(0u);
  EXPECT_FALSE(DecodeCommandLane(longer, read));

  EXPECT_FALSE(DecodeCommandLane(std::vector<std::uint8_t>{2u, 0u, 0u, 0u, 0u}, read)); // flags
  // An update naming a field past those this build knows.
  EXPECT_FALSE(DecodeCommandLane(std::vector<std::uint8_t>{0u, 0u, 1u, 5u, 0x80u, 0x02u, 0u, 0u}, read));
  // A count of descriptors far past the bytes.
  EXPECT_FALSE(DecodeCommandLane(std::vector<std::uint8_t>{0u, 0x7Fu, 0u, 0u, 0u}, read));
}

// Deltas: only the fields that changed go, and applying them to what the receiver holds gives the whole record.
TEST(
  CommandLane,
  DeltasCarryOnlyChangedFields
)
{
  SCommandData held = SampleLane().updates[0].data;
  SCommandData now = held;
  EXPECT_EQ(faf::remote::wire::CommandFieldsChanged(held, now), 0u);
  now.count = 3;
  now.target1.position[0] = 101.0f;
  const std::uint32_t fields = faf::remote::wire::CommandFieldsChanged(held, now);
  EXPECT_EQ(fields, faf::remote::wire::kCommandCounts | faf::remote::wire::kCommandTarget1);
  now.target1.position[2] = 0.0f; // -0 to +0 is a change too
  EXPECT_NE(faf::remote::wire::CommandFieldsChanged(held, now) & faf::remote::wire::kCommandTarget1, 0u);

  SCommandUpdate update;
  update.fields = fields;
  update.data = now;
  update.data.units.clear(); // not carried: the receiver keeps its own
  SCommandData applied = held;
  faf::remote::wire::ApplyCommandFields(applied, update);
  EXPECT_EQ(applied.units, held.units);
  EXPECT_EQ(applied.count, 3);
  EXPECT_EQ(applied.target1, now.target1);
}

// The receiver: a record or a removal of a command it wasn't sent is dropped and counted, never handed on (the session
// would dereference a helper it can't find); a removal ends what it holds, so a later record is dropped too.
TEST(
  CommandLane,
  ReceiverDropsRecordsOfCommandsNotSent
)
{
  CCommandLaneReceiver receiver;
  CCommandLaneReceiver::SBeat beat;
  std::vector<std::uint8_t> bytes;

  SCommandLane stray;
  SCommandUpdate update;
  update.id = 0x80000010u;
  update.fields = faf::remote::wire::kCommandCounts;
  update.data.count = 1;
  stray.updates.push_back(update);
  stray.removals.push_back(0x80000011u);
  EncodeCommandLane(stray, bytes);
  ASSERT_TRUE(receiver.Apply(bytes, beat));
  EXPECT_TRUE(beat.updates.empty());
  EXPECT_TRUE(beat.removals.empty());
  EXPECT_EQ(receiver.Counts().droppedUpdates, 1u);
  EXPECT_EQ(receiver.Counts().droppedRemovals, 1u);

  SCommandLane described;
  SCommandDescriptor descriptor;
  descriptor.id = 0x80000010u;
  described.descriptors.push_back(descriptor);
  described.updates.push_back(update);
  EncodeCommandLane(described, bytes);
  ASSERT_TRUE(receiver.Apply(bytes, beat));
  ASSERT_EQ(beat.updates.size(), 1u);
  EXPECT_EQ(beat.updates[0].second.count, 1);
  EXPECT_EQ(beat.updates[0].second.maxCount, -1); // the rest from the defaults a descriptor gives

  SCommandLane removed;
  removed.removals.push_back(0x80000010u);
  removed.updates.push_back(update); // in the same lane, before the removal: still held
  EncodeCommandLane(removed, bytes);
  ASSERT_TRUE(receiver.Apply(bytes, beat));
  EXPECT_EQ(beat.updates.size(), 1u);
  EXPECT_EQ(beat.removals.size(), 1u);
  EncodeCommandLane(stray, bytes);
  ASSERT_TRUE(receiver.Apply(bytes, beat));
  EXPECT_TRUE(beat.updates.empty());
  EXPECT_EQ(receiver.Counts().droppedUpdates, 2u);

  const std::vector<std::uint8_t> damaged = {0u, 0x7Fu};
  EXPECT_FALSE(receiver.Apply(damaged, beat));
  EXPECT_EQ(receiver.Counts().failures, 1u);
  EXPECT_EQ(receiver.Held(), 0u);
}

namespace
{
  // A server's sim and two views, as the tests below drive them: armies 0 and 1, units 0x001000xx of army 0 and
  // 0x002000xx of army 1; commands of source 1 are view 0's own.
  struct SBookFixture
  {
    CCommandBook book;
    std::map<std::uint32_t, std::uint8_t> armies;
    moho::SSyncData packet;
    std::uint32_t nextViewCommand = 0x80000000u;
    std::unordered_map<std::uint32_t, std::uint32_t> viewCommands; // view 0's command ids
    std::unordered_map<std::uint32_t, std::uint32_t> heldEntities; // view 0's entities: sim id to view id

    SBookFixture()
    {
      for (std::uint32_t serial = 1; serial < 16u; ++serial) {
        armies[0x00100000u | serial] = 0u;
        armies[0x00200000u | serial] = 1u;
      }
    }

    void Describe(
      const std::uint32_t id
    )
    {
      moho::SSTICommandConstantData descriptor{};
      descriptor.cmd = static_cast<std::int32_t>(id);
      descriptor.mFormationScriptIndex = -1;
      descriptor.unk1 = 1.0f;
      descriptor.blueprint = nullptr;
      packet.mPublishedCommandDescriptors.push_back(descriptor);
    }
    void Publish(
      const std::uint32_t id,
      const std::vector<std::uint32_t>& units,
      const std::int32_t count = -1,
      const std::uint32_t target = kNoCommandEntity
    )
    {
      moho::SSyncPublishedCommandPacket published{};
      published.commandId = static_cast<moho::CmdId>(id);
      for (const std::uint32_t unit : units) {
        published.variableData.mEntIds.push_back(static_cast<moho::EntId>(unit));
      }
      published.variableData.mCmdType = static_cast<moho::EUnitCommandType>(2);
      published.variableData.mCount = count;
      if (target != kNoCommandEntity) {
        published.variableData.mTarget1.mType = moho::EAiTargetType::AITARGET_Entity;
        published.variableData.mTarget1.mEntityId = target;
      }
      packet.mPublishedCommandPackets.push_back(published);
    }
    void Beat()
    {
      book.TakeBeat(packet, [this](const std::uint32_t unit) {
        const auto found = armies.find(unit);
        return found != armies.end() ? found->second : CCommandBook::kNoArmy;
      }, {});
      packet = moho::SSyncData{};
    }
    [[nodiscard]] CCommandViewRoute::STranslate Translate()
    {
      CCommandViewRoute::STranslate translate;
      translate.isOwn = [](const std::uint32_t id) {
        return (id >> 24u) == 1u;
      };
      translate.command = [this, own = translate.isOwn](const std::uint32_t id) {
        if (own(id)) {
          return id;
        }
        const auto [it, made] = viewCommands.try_emplace(id, 0u);
        if (made) {
          it->second = ++nextViewCommand;
        }
        return it->second;
      };
      translate.entity = [this](const std::uint32_t id) {
        const auto found = heldEntities.find(id);
        return found != heldEntities.end() ? found->second : kNoCommandEntity;
      };
      return translate;
    }
  };
} // namespace

// A view gets the commands that hold a unit of its army, those units only, under its own command ids (its own
// commands keep theirs); a command of the other army's units only never reaches it; a target entity goes as the view's
// id of a record it holds, else as none.
TEST(
  CommandRecords,
  ViewGetsItsArmysCommandsUnderItsIds
)
{
  SBookFixture sim;
  sim.heldEntities[0x30000005u] = 0x30000001u; // a blip the view holds under its own serial
  sim.Describe(0x80000001u);                   // a factory's rally order (the sim's own)
  sim.Publish(0x80000001u, {0x00100001u, 0x00200001u}, -1, 0x30000005u);
  sim.Describe(0x01000004u); // view 0's own order
  sim.Publish(0x01000004u, {0x00100002u}, -1, 0x00200007u);
  sim.Describe(0x02000001u); // army 1's
  sim.Publish(0x02000001u, {0x00200002u});
  sim.Beat();

  CCommandViewRoute view0;
  SCommandLane lane;
  view0.Write(sim.book, 0, false, false, sim.Translate(), lane);
  ASSERT_EQ(lane.descriptors.size(), 2u);
  ASSERT_EQ(lane.updates.size(), 2u);
  EXPECT_EQ(lane.descriptors[0].id, 0x80000001u); // the view's first serial
  EXPECT_EQ(lane.updates[0].data.units, std::vector<std::uint32_t>({0x00100001u}));
  EXPECT_EQ(lane.updates[0].data.target1.entity, 0x30000001u);
  EXPECT_EQ(lane.descriptors[1].id, 0x01000004u);                   // its own id
  EXPECT_EQ(lane.updates[1].data.target1.entity, kNoCommandEntity); // an entity it holds no record of
  EXPECT_EQ(view0.Counts().unitsLeftOut, 2u);
  EXPECT_EQ(view0.Counts().targetsWithheld, 1u);
  EXPECT_EQ(view0.Counts().targetsRenumbered, 1u);

  // Watching everything (focus -1): every unit of every command.
  CCommandViewRoute observer;
  observer.Write(sim.book, 0, true, false, sim.Translate(), lane);
  EXPECT_EQ(lane.descriptors.size(), 3u);
  EXPECT_EQ(lane.updates[0].data.units.size(), 2u);
}

// Over beats: a record sends only what changed; a command whose units of the view's army all leave is removed, and
// described again when one comes back; a release goes under the id the view was given, and a release of the view's own
// command it was never shown goes too (its client's pool takes the id back), while other armies' releases don't.
TEST(
  CommandRecords,
  DeltasRemovalsAndReleasesFollowTheFocusedSim
)
{
  SBookFixture sim;
  CCommandViewRoute view0;
  SCommandLane lane;
  CCommandLaneReceiver client;
  CCommandLaneReceiver::SBeat beat;
  std::vector<std::uint8_t> bytes;
  const auto send = [&] {
    sim.Beat();
    view0.Write(sim.book, 0, false, false, sim.Translate(), lane);
    EncodeCommandLane(lane, bytes);
    ASSERT_TRUE(client.Apply(bytes, beat));
  };

  sim.Describe(0x80000002u);
  sim.Publish(0x80000002u, {0x00100001u, 0x00100002u}, 5);
  send();
  ASSERT_EQ(beat.descriptors.size(), 1u);
  const std::uint32_t viewId = beat.descriptors[0].id;

  sim.Publish(0x80000002u, {0x00100001u, 0x00100002u}, 4); // a factory's count goes down
  send();
  ASSERT_EQ(lane.updates.size(), 1u);
  EXPECT_EQ(lane.updates[0].fields, faf::remote::wire::kCommandCounts);
  EXPECT_LE(bytes.size(), 10u); // flags, counts, the id (2 bytes), the fields, the two ints
  ASSERT_EQ(beat.updates.size(), 1u);
  EXPECT_EQ(beat.updates[0].second.units.size(), 2u); // the client keeps what didn't change
  EXPECT_EQ(beat.updates[0].second.count, 4);

  sim.Publish(0x80000002u, {0x00100001u, 0x00100002u}, 4); // published again, nothing changed
  send();
  ASSERT_EQ(lane.updates.size(), 1u);
  EXPECT_EQ(lane.updates[0].fields, 0u);

  sim.Publish(0x80000002u, {0x00200003u}, 4); // only another army's unit left: the focused sim removes it
  send();
  EXPECT_TRUE(lane.updates.empty());
  EXPECT_EQ(beat.removals, std::vector<std::uint32_t>({viewId}));
  EXPECT_EQ(client.Held(), 0u);

  sim.Publish(0x80000002u, {0x00200003u, 0x00100004u}, 4); // one of its units again: described again, whole
  send();
  ASSERT_EQ(beat.descriptors.size(), 1u);
  EXPECT_EQ(beat.descriptors[0].id, viewId);
  ASSERT_EQ(beat.updates.size(), 1u);
  EXPECT_EQ(beat.updates[0].second.units, std::vector<std::uint32_t>({0x00100004u}));
  EXPECT_EQ(beat.updates[0].second.count, 4);

  sim.packet.mPendingCommandEventRemovals.push_back(static_cast<moho::CmdId>(0x80000002u));
  sim.packet.mPendingReleasedCommandIds.push_back(static_cast<moho::CmdId>(0x80000002u));
  sim.packet.mPendingReleasedCommandIds.push_back(static_cast<moho::CmdId>(0x01000009u)); // its own, never shown
  sim.packet.mPendingReleasedCommandIds.push_back(static_cast<moho::CmdId>(0x80000077u)); // never its
  send();
  EXPECT_EQ(beat.removals, std::vector<std::uint32_t>({viewId}));
  EXPECT_EQ(beat.releases, std::vector<std::uint32_t>({viewId, 0x01000009u}));
  EXPECT_EQ(sim.book.Live(), 0u);
  EXPECT_EQ(client.Counts().droppedUpdates, 0u);
  EXPECT_EQ(client.Counts().droppedRemovals, 0u);
}

// A view that comes back holding nothing (a reconnect) gets every shown command with one of its units, whole, and the
// lane says so: its client lets go of whatever else it held, and then holds exactly what a client that never left
// holds.
TEST(
  CommandRecords,
  WholeLaneAfterReconnectEqualsNeverLeaving
)
{
  SBookFixture sim;
  CCommandViewRoute view0;
  CCommandLaneReceiver stayed;
  CCommandLaneReceiver returning;
  SCommandLane lane;
  CCommandLaneReceiver::SBeat beat;
  std::vector<std::uint8_t> bytes;
  const auto send = [&](const bool whole, CCommandLaneReceiver& to) {
    view0.Write(sim.book, 0, false, whole, sim.Translate(), lane);
    EncodeCommandLane(lane, bytes);
    ASSERT_TRUE(to.Apply(bytes, beat));
  };

  for (std::uint32_t i = 1; i <= 4u; ++i) {
    sim.Describe(0x80000000u | i);
    sim.Publish(0x80000000u | i, {0x00100000u | i}, static_cast<std::int32_t>(i));
  }
  sim.Beat();
  send(false, stayed);
  (void)returning.Apply(bytes, beat); // the returning client saw this beat too, then lost the next ones

  sim.Publish(0x80000002u, {0x00100002u}, 9);
  sim.packet.mPendingCommandEventRemovals.push_back(static_cast<moho::CmdId>(0x80000003u));
  sim.packet.mPendingReleasedCommandIds.push_back(static_cast<moho::CmdId>(0x80000003u));
  sim.Describe(0x80000005u);
  sim.Publish(0x80000005u, {0x00100005u});
  sim.Beat();
  send(false, stayed); // lost by the returning client

  sim.Publish(0x80000004u, {0x00200001u}); // army 1's unit only now: the view no longer shows it
  sim.Beat();
  send(false, stayed);
  ASSERT_EQ(beat.removals.size(), 1u);

  sim.Publish(0x80000001u, {0x00100001u}, 7);
  sim.Beat();
  send(true, returning); // the returning client's whole lane
  EXPECT_TRUE(lane.whole);
  EXPECT_EQ(view0.Counts().wholes, 1u);
  EXPECT_EQ(returning.Counts().forgotten, 2u); // 0x80000003 (released) and 0x80000004 (no longer shown)

  // It holds what the server shows it (the book's records, cut to its army), and what the client that never left held
  // of the commands this beat didn't change.
  ASSERT_EQ(returning.Held(), 3u); // 0x80000001, 0x80000002, 0x80000005
  EXPECT_EQ(stayed.Held(), 3u);
  for (const std::uint32_t simId : {0x80000002u, 0x80000005u}) {
    const std::uint32_t viewId = sim.viewCommands.at(simId);
    ASSERT_NE(stayed.Find(viewId), nullptr);
    ASSERT_NE(returning.Find(viewId), nullptr);
    EXPECT_EQ(*stayed.Find(viewId), *returning.Find(viewId));
  }
  for (const std::uint32_t simId : {0x80000001u, 0x80000002u, 0x80000005u}) {
    const std::uint32_t viewId = sim.viewCommands.at(simId);
    const SCommandData* const held = returning.Find(viewId);
    ASSERT_NE(held, nullptr) << std::hex << simId;
    const CCommandBook::SCommand* const truth = sim.book.Find(simId);
    ASSERT_NE(truth, nullptr);
    EXPECT_EQ(held->count, truth->data.count);
    EXPECT_EQ(held->units, truth->data.units);
  }
  EXPECT_EQ(returning.Find(sim.viewCommands.at(0x80000004u)), nullptr);
}

// The client's applier: a lane into the beat packet's four lists, every field as the session's helpers take it, the
// blueprint resolved from the client's own (none for an ordinal it doesn't have).
TEST(
  CommandLaneApplier,
  FillsThePacketsCommandLists
)
{
  std::vector<const moho::REntityBlueprint*> blueprints(64u, nullptr);
  const auto* const fakeBlueprint = reinterpret_cast<const moho::REntityBlueprint*>(std::uintptr_t{0x1000});
  blueprints[41] = fakeBlueprint; // ordinal 41 is the lane's 42
  faf::remote::client::CCommandLaneApplier applier(blueprints);
  std::vector<std::uint8_t> bytes;
  SCommandLane lane = SampleLane();
  lane.removals.clear();
  lane.updates.pop_back();
  SCommandDescriptor unknown;
  unknown.id = 0x80000008u;
  unknown.blueprint = 63u + 2u; // past the client's table
  lane.descriptors.push_back(unknown);
  EncodeCommandLane(lane, bytes);

  moho::SSyncData packet{};
  ASSERT_TRUE(applier.Apply(bytes, packet));
  ASSERT_EQ(packet.mPublishedCommandDescriptors.size(), 2u);
  const moho::SSTICommandConstantData& constant = packet.mPublishedCommandDescriptors[0];
  EXPECT_EQ(static_cast<std::uint32_t>(constant.cmd), 0x80000007u);
  EXPECT_EQ(constant.mFormationScriptIndex, 3);
  EXPECT_EQ(constant.unk1, 1.25f);
  EXPECT_EQ(constant.blueprint, fakeBlueprint);
  EXPECT_EQ(constant.unk2.view(), lane.descriptors[0].script);
  float origin[4];
  std::memcpy(origin, &constant.origin, sizeof(origin));
  EXPECT_EQ(Bits(origin[2]), Bits(-0.0f));
  EXPECT_EQ(origin[3], 1.0f);
  EXPECT_EQ(packet.mPublishedCommandDescriptors[1].blueprint, nullptr);
  EXPECT_EQ(applier.UnknownBlueprints(), 1u);

  ASSERT_EQ(packet.mPublishedCommandPackets.size(), 1u);
  const moho::SSTICommandVariableData& data = packet.mPublishedCommandPackets[0].variableData;
  EXPECT_EQ(static_cast<std::uint32_t>(packet.mPublishedCommandPackets[0].commandId), 0x80000007u);
  ASSERT_EQ(data.mEntIds.size(), 2u);
  EXPECT_EQ(static_cast<std::uint32_t>(data.mEntIds[1]), 0x00100009u);
  EXPECT_EQ(static_cast<std::int32_t>(data.mCmdType), 7);
  EXPECT_EQ(data.mTarget1.mType, moho::EAiTargetType::AITARGET_Ground);
  EXPECT_EQ(data.mTarget1.mEntityId, kNoCommandEntity);
  EXPECT_EQ(data.mTarget1.mPos.x, 100.5f);
  EXPECT_EQ(data.mTarget2.mEntityId, 0x30200001u);
  EXPECT_EQ(data.v14, -1);
  ASSERT_EQ(data.mCells.size(), 2u);
  EXPECT_EQ(data.mCells[0].x, 5);
  EXPECT_EQ(data.mCells[0].z, -6);
  EXPECT_EQ(data.mMaxCount, 5);
  EXPECT_EQ(data.mCount, 2);
  EXPECT_EQ(data.v23, 0xABCDu);
  ASSERT_EQ(packet.mPendingReleasedCommandIds.size(), 2u);
  EXPECT_TRUE(packet.mPendingCommandEventRemovals.empty());

  // A whole lane: the command it doesn't describe again goes as a removal.
  SCommandLane whole;
  whole.whole = true;
  whole.descriptors.push_back(unknown);
  EncodeCommandLane(whole, bytes);
  moho::SSyncData next{};
  ASSERT_TRUE(applier.Apply(bytes, next));
  ASSERT_EQ(next.mPendingCommandEventRemovals.size(), 1u);
  EXPECT_EQ(static_cast<std::uint32_t>(next.mPendingCommandEventRemovals[0]), 0x80000007u);

  // A record of a command it wasn't sent never reaches the packet.
  SCommandLane stray;
  SCommandUpdate update;
  update.id = 0x80000099u;
  stray.updates.push_back(update);
  EncodeCommandLane(stray, bytes);
  moho::SSyncData third{};
  ASSERT_TRUE(applier.Apply(bytes, third));
  EXPECT_TRUE(third.mPublishedCommandPackets.empty());
  EXPECT_EQ(applier.Counts().droppedUpdates, 1u);
}
