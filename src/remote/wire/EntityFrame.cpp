#include "remote/wire/EntityFrame.h"

#include <bit>

#include "remote/wire/WireVersion.h"

// Engine addition, server mode: see EntityFrame.h.
//
// Wire layout (entities lane):
//   u16 lane version, u32 frame id, u32 baseline id, u32 beat,
//   removed:  varuint count, then per id varuint gap
//   created:  varuint count, then per entity varuint gap + every field
//   changed:  varuint count, then per entity varuint gap + u8 field mask + those fields
// A gap is the id minus the previous id of the same section minus one (the first: the id),
// so ids are strictly ascending by construction.

namespace faf::remote::wire
{
  namespace
  {
    constexpr int kArmyBits = 8;
    constexpr int kFlagBits = 16;
    constexpr int kMinBitsPerItem = 8; // the smallest gap varint

    [[nodiscard]] std::uint32_t Bits(const float value) noexcept
    {
      return std::bit_cast<std::uint32_t>(value);
    }

    [[nodiscard]] bool FitsCodec(const SEntityRecord& record, const SFrameCodec& codec) noexcept
    {
      return record.position[0] <= codec.position.x.MaxQuantized()
          && record.position[1] <= codec.position.y.MaxQuantized()
          && record.position[2] <= codec.position.z.MaxQuantized();
    }

    void WriteFields(BitWriter& writer, const SEntityRecord& record, const std::uint8_t fields, const SFrameCodec& codec)
    {
      if ((fields & kFieldBlueprint) != 0u) {
        writer.WriteVarUint(record.blueprint);
      }
      if ((fields & kFieldArmy) != 0u) {
        writer.WriteBits(record.army, kArmyBits);
      }
      if ((fields & kFieldPosition) != 0u) {
        writer.WriteBits(record.position[0], codec.position.x.bits);
        writer.WriteBits(record.position[1], codec.position.y.bits);
        writer.WriteBits(record.position[2], codec.position.z.bits);
      }
      if ((fields & kFieldOrientation) != 0u) {
        writer.WriteBits(record.orientation, 32);
      }
      if ((fields & kFieldHealth) != 0u) {
        writer.WriteFloatExact(record.health);
      }
      if ((fields & kFieldMaxHealth) != 0u) {
        writer.WriteFloatExact(record.maxHealth);
      }
      if ((fields & kFieldFraction) != 0u) {
        writer.WriteFloatExact(record.fractionComplete);
      }
      if ((fields & kFieldFlags) != 0u) {
        writer.WriteBits(record.flags, kFlagBits);
      }
    }

    void ReadFields(BitReader& reader, SEntityRecord& record, const std::uint8_t fields, const SFrameCodec& codec)
    {
      if ((fields & kFieldBlueprint) != 0u) {
        record.blueprint = reader.ReadVarUint();
      }
      if ((fields & kFieldArmy) != 0u) {
        record.army = static_cast<std::uint8_t>(reader.ReadBits(kArmyBits));
      }
      if ((fields & kFieldPosition) != 0u) {
        record.position[0] = reader.ReadBits(codec.position.x.bits);
        record.position[1] = reader.ReadBits(codec.position.y.bits);
        record.position[2] = reader.ReadBits(codec.position.z.bits);
      }
      if ((fields & kFieldOrientation) != 0u) {
        record.orientation = reader.ReadBits(32);
      }
      if ((fields & kFieldHealth) != 0u) {
        record.health = reader.ReadFloatExact();
      }
      if ((fields & kFieldMaxHealth) != 0u) {
        record.maxHealth = reader.ReadFloatExact();
      }
      if ((fields & kFieldFraction) != 0u) {
        record.fractionComplete = reader.ReadFloatExact();
      }
      if ((fields & kFieldFlags) != 0u) {
        record.flags = static_cast<std::uint16_t>(reader.ReadBits(kFlagBits));
      }
    }

    /** Reads ascending ids by gap; false on overflow. */
    class CIdCursor
    {
    public:
      [[nodiscard]] bool Next(BitReader& reader, std::uint32_t& id) noexcept
      {
        const std::uint64_t gap = reader.ReadVarUint();
        const std::uint64_t next = mFirst ? gap : static_cast<std::uint64_t>(mPrevious) + 1u + gap;
        if (!reader.Ok() || next > 0xFFFFFFFFull) {
          reader.Fail();
          return false;
        }
        mFirst = false;
        mPrevious = static_cast<std::uint32_t>(next);
        id = mPrevious;
        return true;
      }

    private:
      bool mFirst = true;
      std::uint32_t mPrevious = 0;
    };

    void WriteGap(BitWriter& writer, bool& first, std::uint32_t& previous, const std::uint32_t id)
    {
      writer.WriteVarUint(first ? id : id - previous - 1u);
      first = false;
      previous = id;
    }

    /** A section count the remaining bits could carry and the codec allows. */
    [[nodiscard]] bool ReadCount(BitReader& reader, const SFrameCodec& codec, std::uint32_t& count) noexcept
    {
      count = reader.ReadVarUint();
      if (!reader.Ok() || count > codec.maxEntities
          || static_cast<std::uint64_t>(count) * kMinBitsPerItem > reader.BitsLeft()) {
        reader.Fail();
        return false;
      }
      return true;
    }
  } // namespace

  bool SEntityRecord::operator==(const SEntityRecord& other) const noexcept
  {
    return id == other.id && blueprint == other.blueprint && army == other.army && position == other.position
        && orientation == other.orientation && Bits(health) == Bits(other.health)
        && Bits(maxHealth) == Bits(other.maxHealth) && Bits(fractionComplete) == Bits(other.fractionComplete)
        && flags == other.flags;
  }

  std::uint8_t ChangedFields(const SEntityRecord& before, const SEntityRecord& after) noexcept
  {
    std::uint8_t fields = 0;
    if (before.blueprint != after.blueprint) {
      fields |= kFieldBlueprint;
    }
    if (before.army != after.army) {
      fields |= kFieldArmy;
    }
    if (before.position != after.position) {
      fields |= kFieldPosition;
    }
    if (before.orientation != after.orientation) {
      fields |= kFieldOrientation;
    }
    if (Bits(before.health) != Bits(after.health)) {
      fields |= kFieldHealth;
    }
    if (Bits(before.maxHealth) != Bits(after.maxHealth)) {
      fields |= kFieldMaxHealth;
    }
    if (Bits(before.fractionComplete) != Bits(after.fractionComplete)) {
      fields |= kFieldFraction;
    }
    if (before.flags != after.flags) {
      fields |= kFieldFlags;
    }
    return fields;
  }

  bool SViewFrame::IsWellFormed() const noexcept
  {
    for (std::size_t i = 1; i < entities.size(); ++i) {
      if (entities[i - 1].id >= entities[i].id) {
        return false;
      }
    }
    return true;
  }

  SFrameDelta ComputeFrameDelta(const SViewFrame* const baseline, const SViewFrame& frame)
  {
    SFrameDelta delta;
    static const std::vector<SEntityRecord> kEmpty;
    const std::vector<SEntityRecord>& before = baseline != nullptr ? baseline->entities : kEmpty;
    const std::vector<SEntityRecord>& after = frame.entities;
    std::size_t b = 0;
    std::size_t a = 0;
    while (b < before.size() || a < after.size()) {
      if (a == after.size() || (b < before.size() && before[b].id < after[a].id)) {
        delta.removed.push_back(before[b].id);
        ++b;
      } else if (b == before.size() || after[a].id < before[b].id) {
        delta.created.push_back(after[a]);
        ++a;
      } else {
        if (const std::uint8_t fields = ChangedFields(before[b], after[a]); fields != 0u) {
          delta.changed.push_back({fields, after[a]});
        }
        ++a;
        ++b;
      }
    }
    return delta;
  }

  bool EncodeFrame(const SViewFrame& frame, const SViewFrame* const baseline, const SFrameCodec& codec, BitWriter& writer)
  {
    if (!frame.IsWellFormed() || (baseline != nullptr && !baseline->IsWellFormed())
        || frame.entities.size() > codec.maxEntities) {
      return false;
    }
    for (const SEntityRecord& record : frame.entities) {
      if (!FitsCodec(record, codec)) {
        return false;
      }
    }

    const SFrameDelta delta = ComputeFrameDelta(baseline, frame);
    writer.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
    writer.WriteBits(frame.frameId, 32);
    writer.WriteBits(baseline != nullptr ? baseline->frameId : kNoBaseline, 32);
    writer.WriteBits(frame.beat, 32);

    bool first = true;
    std::uint32_t previous = 0;
    writer.WriteVarUint(static_cast<std::uint32_t>(delta.removed.size()));
    for (const std::uint32_t id : delta.removed) {
      WriteGap(writer, first, previous, id);
    }

    first = true;
    writer.WriteVarUint(static_cast<std::uint32_t>(delta.created.size()));
    for (const SEntityRecord& record : delta.created) {
      WriteGap(writer, first, previous, record.id);
      WriteFields(writer, record, kAllEntityFields, codec);
    }

    first = true;
    writer.WriteVarUint(static_cast<std::uint32_t>(delta.changed.size()));
    for (const SFrameDelta::SChange& change : delta.changed) {
      WriteGap(writer, first, previous, change.record.id);
      writer.WriteBits(change.fields, 8);
      WriteFields(writer, change.record, change.fields, codec);
    }
    return true;
  }

  std::uint32_t PeekFrameBaseline(const std::span<const std::uint8_t> bytes) noexcept
  {
    BitReader reader(bytes);
    (void)reader.ReadBits(16);
    (void)reader.ReadBits(32);
    const std::uint32_t baseline = reader.ReadBits(32);
    return reader.Ok() ? baseline : kNoBaseline;
  }

  bool DecodeFrame(BitReader& reader, const SViewFrame* const baseline, const SFrameCodec& codec, SViewFrame& out)
  {
    const std::uint32_t laneVersion = reader.ReadBits(16);
    const std::uint32_t frameId = reader.ReadBits(32);
    const std::uint32_t baselineId = reader.ReadBits(32);
    const std::uint32_t beat = reader.ReadBits(32);
    if (!reader.Ok() || laneVersion != kLaneVersions[static_cast<std::size_t>(ELane::Entities)]) {
      return false;
    }
    if ((baselineId == kNoBaseline) != (baseline == nullptr)
        || (baseline != nullptr && (baseline->frameId != baselineId || !baseline->IsWellFormed()))) {
      return false;
    }

    static const std::vector<SEntityRecord> kEmpty;
    const std::vector<SEntityRecord>& before = baseline != nullptr ? baseline->entities : kEmpty;

    // Removals: every id must be in the baseline. The baseline is ascending, so one forward
    // walk checks them and keeps what stays.
    std::uint32_t removedCount = 0;
    if (!ReadCount(reader, codec, removedCount) || removedCount > before.size()) {
      return false;
    }
    std::vector<SEntityRecord> kept;
    kept.reserve(before.size() - removedCount);
    {
      CIdCursor cursor;
      std::size_t b = 0;
      for (std::uint32_t i = 0; i < removedCount; ++i) {
        std::uint32_t id = 0;
        if (!cursor.Next(reader, id)) {
          return false;
        }
        while (b < before.size() && before[b].id < id) {
          kept.push_back(before[b++]);
        }
        if (b == before.size() || before[b].id != id) {
          return false;
        }
        ++b;
      }
      while (b < before.size()) {
        kept.push_back(before[b++]);
      }
    }

    // Creations: ids must not be in what was kept.
    std::uint32_t createdCount = 0;
    if (!ReadCount(reader, codec, createdCount) || kept.size() + createdCount > codec.maxEntities) {
      return false;
    }
    std::vector<SEntityRecord> created;
    created.reserve(createdCount);
    {
      CIdCursor cursor;
      for (std::uint32_t i = 0; i < createdCount; ++i) {
        SEntityRecord record{};
        if (!cursor.Next(reader, record.id)) {
          return false;
        }
        ReadFields(reader, record, kAllEntityFields, codec);
        if (!reader.Ok()) {
          return false;
        }
        created.push_back(record);
      }
    }

    // Merge kept and created; an id in both is inconsistent.
    std::vector<SEntityRecord> merged;
    merged.reserve(kept.size() + created.size());
    {
      std::size_t k = 0;
      std::size_t c = 0;
      while (k < kept.size() || c < created.size()) {
        if (c == created.size() || (k < kept.size() && kept[k].id < created[c].id)) {
          merged.push_back(kept[k++]);
        } else if (k == kept.size() || created[c].id < kept[k].id) {
          merged.push_back(created[c++]);
        } else {
          return false;
        }
      }
    }

    // Changes: ids must be kept (not created in this frame), fields non-empty.
    std::uint32_t changedCount = 0;
    if (!ReadCount(reader, codec, changedCount)) {
      return false;
    }
    {
      CIdCursor cursor;
      std::size_t m = 0;
      std::size_t c = 0;
      for (std::uint32_t i = 0; i < changedCount; ++i) {
        std::uint32_t id = 0;
        if (!cursor.Next(reader, id)) {
          return false;
        }
        const auto fields = static_cast<std::uint8_t>(reader.ReadBits(8));
        if (!reader.Ok() || fields == 0u) {
          return false;
        }
        while (m < merged.size() && merged[m].id < id) {
          ++m;
        }
        while (c < created.size() && created[c].id < id) {
          ++c;
        }
        if (m == merged.size() || merged[m].id != id || (c < created.size() && created[c].id == id)) {
          return false;
        }
        ReadFields(reader, merged[m], fields, codec);
        if (!reader.Ok()) {
          return false;
        }
      }
    }

    for (const SEntityRecord& record : merged) {
      if (!FitsCodec(record, codec)) {
        return false;
      }
    }

    out.frameId = frameId;
    out.beat = beat;
    out.entities = std::move(merged);
    return true;
  }
} // namespace faf::remote::wire
