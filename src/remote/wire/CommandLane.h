#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Engine addition, server mode (plan WP5.14): the command-records lane, the eighth lane of a `View` message
// (remote/net/GameLinks.h), after the effects lane. It carries what a lockstep client focused on the view's army gets
// in its beat packet's four command lists (`SSyncData::mPublishedCommandDescriptors`, `mPublishedCommandPackets`,
// `mPendingCommandEventRemovals`, `mPendingReleasedCommandIds`), from which `CWldSession::DoBeat` keeps its
// `UserCommandIssueHelper`s: the records `UserUnit:GetCommandQueue()`, rally points, the enhancement queue and the
// queued-build ghosts read. The server writes it (remote/CommandRecords.h); a client reads it with
// `CCommandLaneReceiver` below and turns it into those lists (remote/client/CommandLaneApplier.h).
//
// An empty lane: nothing changed this beat. Otherwise (varints unsigned LEB128, ints zigzag varints, floats 4 bytes
// little-endian):
//
//   varint flags                       bit 0: whole (the client keeps only the commands this lane describes)
//   varint n, n descriptors            `SSTICommandConstantData`: id, formation index, the origin's 4 floats, the
//                                      formation scale (float), blueprint (varint 0 for none, else the content
//                                      tables' ordinal + 1), the issue's Lua payload (varint length, bytes)
//   varint n, n updates                id, varint fields (`ECommandField`), then each field present in bit order:
//                                      units (varint count, ids), type (int), the two targets (int type, a byte of
//                                      flags: 1 an entity id follows, 2 three floats of position follow), the issue's
//                                      extra int, cells (varint count, x and z ints), max count and count (ints),
//                                      flags (varint)
//   varint n, n ids                    removals: the command is no longer shown (its helper goes)
//   varint n, n ids                    releases: the sim let go of the command (its id may be issued again)
//
// An update carries only the fields that differ from what the receiver holds of that command: a descriptor gives a
// command the defaults of `SCommandData` (those of `SSTICommandVariableData`'s constructor), and each update changes
// what it names. An update with no field still goes: the sim published the command again, which marks its helper's
// data changed (`ApplyBeatCommandPackets`).
//
// Ids are those the view's client knows (remote/ViewIdMap.h): its own commands keep their ids, any other command has
// the view's own number, the same its frames give it in a unit's queue; a target entity is the view's id of a record
// the client holds, or 0xF0000000 (the sim's "none") for one it holds no record of.

namespace faf::remote::wire
{
  /** The sim's "no entity" (`SSTITarget::mEntityId` of a target without one). */
  inline constexpr std::uint32_t kNoCommandEntity = 0xF0000000u;

  /** `SSTITarget`. Floats compare by their bits, so -0 and a NaN's payload go as the sim has them. */
  struct SCommandTarget
  {
    std::int32_t type = 0; // EAiTargetType: 0 none, 1 entity, 2 ground
    std::uint32_t entity = kNoCommandEntity;
    std::array<float, 3> position{};

    bool operator==(
      const SCommandTarget& other
    ) const noexcept
    {
      return type == other.type && entity == other.entity &&
        std::memcmp(position.data(), other.position.data(), sizeof(position)) == 0;
    }
  };

  /** `SOCellPos`. */
  struct SCommandCell
  {
    std::int16_t x = 0;
    std::int16_t z = 0;

    bool operator==(const SCommandCell&) const = default;
  };

  /** `SSTICommandVariableData` as the lane has it, its defaults those of the struct's constructor. */
  struct SCommandData
  {
    std::vector<std::uint32_t> units; // `mEntIds`
    std::int32_t type = 0;            // `mCmdType` (EUnitCommandType)
    SCommandTarget target1;
    SCommandTarget target2;
    std::int32_t extra = 0; // `v14`, the issue's formation selector
    std::vector<SCommandCell> cells;
    std::int32_t maxCount = -1;
    std::int32_t count = -1;
    std::uint32_t flags = 0; // `v23`

    bool operator==(const SCommandData&) const = default;
  };

  /** `SSTICommandConstantData`. */
  struct SCommandDescriptor
  {
    std::uint32_t id = 0;
    std::int32_t formation = -1;   // `mFormationScriptIndex`
    std::array<float, 4> origin{}; // the quaternion's four floats in the struct's order
    float scale = 0.0f;            // `unk1`, the formation's scale
    std::uint32_t blueprint = 0;   // 0 none, else the content tables' blueprint ordinal + 1
    std::string script;            // `unk2`, the issue's Lua payload as text

    bool operator==(
      const SCommandDescriptor& other
    ) const noexcept
    {
      return id == other.id && formation == other.formation &&
        std::memcmp(origin.data(), other.origin.data(), sizeof(origin)) == 0 &&
        std::memcmp(&scale, &other.scale, sizeof(scale)) == 0 && blueprint == other.blueprint && script == other.script;
    }
  };

  /** One bit per field of `SCommandData` an update carries. */
  enum ECommandField : std::uint32_t
  {
    kCommandUnits = 1u << 0,
    kCommandType = 1u << 1,
    kCommandTarget1 = 1u << 2,
    kCommandTarget2 = 1u << 3,
    kCommandExtra = 1u << 4,
    kCommandCells = 1u << 5,
    kCommandCounts = 1u << 6,
    kCommandFlags = 1u << 7,
    kCommandAllFields = (1u << 8) - 1u,
  };

  struct SCommandUpdate
  {
    std::uint32_t id = 0;
    std::uint32_t fields = 0; // the fields of `data` that go; the rest are what the receiver holds
    SCommandData data;
  };

  /** One beat's lane. */
  struct SCommandLane
  {
    bool whole = false;
    std::vector<SCommandDescriptor> descriptors;
    std::vector<SCommandUpdate> updates;
    std::vector<std::uint32_t> removals;
    std::vector<std::uint32_t> releases;

    [[nodiscard]] bool Empty() const noexcept
    {
      return !whole && descriptors.empty() && updates.empty() && removals.empty() && releases.empty();
    }
    void Clear() noexcept
    {
      whole = false;
      descriptors.clear();
      updates.clear();
      removals.clear();
      releases.clear();
    }
  };

  /** The fields in which `now` differs from `held`. */
  [[nodiscard]] std::uint32_t CommandFieldsChanged(const SCommandData& held, const SCommandData& now);
  /** `held` with `update`'s fields. */
  void ApplyCommandFields(SCommandData& held, const SCommandUpdate& update);

  /** `lane` as bytes into `out` (cleared first): nothing for an empty lane. */
  void EncodeCommandLane(const SCommandLane& lane, std::vector<std::uint8_t>& out);
  /**
   * One lane's bytes. False when they don't parse (cut short, a count past the lane's end, bytes after it); `out` is
   * then unspecified.
   */
  [[nodiscard]] bool DecodeCommandLane(std::span<const std::uint8_t> bytes, SCommandLane& out);

  /** What `CCommandLaneReceiver` did with the lanes it took, summed. */
  struct SCommandLaneCounts
  {
    std::uint64_t lanes = 0;    // non-empty lanes read
    std::uint64_t failures = 0; // lanes that didn't decode (nothing of them applied)
    std::uint64_t wholes = 0;
    std::uint64_t descriptors = 0;
    std::uint64_t updates = 0;
    std::uint64_t removals = 0;
    std::uint64_t releases = 0;
    std::uint64_t forgotten = 0;       // commands a whole lane didn't describe again: removed
    std::uint64_t droppedUpdates = 0;  // updates for a command the receiver wasn't sent (or was told to remove)
    std::uint64_t droppedRemovals = 0; // removals of a command it doesn't hold
    std::uint64_t bytes = 0;
  };

  /**
   * A client's end of the lane: the commands it holds and their data. `Apply` turns a lane into what the session's
   * beat takes: every descriptor, every update as the command's whole data, the removals and releases. An update or
   * removal of a command the receiver doesn't hold is dropped and counted: `CWldSession::ApplyBeatCommandPackets` finds
   * no helper for it and has no null check.
   */
  class CCommandLaneReceiver
  {
  public:
    struct SBeat
    {
      std::vector<SCommandDescriptor> descriptors;
      std::vector<std::pair<std::uint32_t, SCommandData>> updates; // each command's whole data after the update
      std::vector<std::uint32_t> removals; // a whole lane's forgotten commands first, then the lane's
      std::vector<std::uint32_t> releases;
      void Clear() noexcept
      {
        descriptors.clear();
        updates.clear();
        removals.clear();
        releases.clear();
      }
    };

    /** One view's lane (empty: nothing). False, with `out` empty and nothing applied, when it doesn't decode. */
    bool Apply(std::span<const std::uint8_t> lane, SBeat& out);

    [[nodiscard]] const SCommandLaneCounts& Counts() const noexcept
    {
      return mCounts;
    }
    [[nodiscard]] std::size_t Held() const noexcept
    {
      return mHeld.size();
    }
    /** A held command's data, or null. */
    [[nodiscard]] const SCommandData* Find(
      const std::uint32_t id
    ) const noexcept
    {
      const auto found = mHeld.find(id);
      return found != mHeld.end() ? &found->second : nullptr;
    }

  private:
    std::unordered_map<std::uint32_t, SCommandData> mHeld;
    SCommandLane mLane;
    SCommandLaneCounts mCounts;
  };
} // namespace faf::remote::wire
