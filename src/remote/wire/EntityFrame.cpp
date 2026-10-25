#include "remote/wire/EntityFrame.h"

#include <bit>
#include <utility>

#include "remote/wire/WireVersion.h"

// Engine addition, server mode: see EntityFrame.h.
//
// Wire layout (entities lane):
//   u16 lane version, u32 frame id, u32 baseline id, u32 beat,
//   removed:  varuint count, then per id varuint gap
//   created:  varuint count, then per entity varuint gap + varuint field mask + those fields
//             (the basic fields and the kind always; appearance fields that are not default)
//   changed:  varuint count, then per entity varuint gap + varuint field mask + those fields
// A gap is the id minus the previous id of the same section minus one (the first: the id),
// so ids are strictly ascending by construction. Within a record the kind bit comes first
// (it says whether a unit block can follow), then the fields in mask-bit order.

namespace faf::remote::wire
{
  namespace
  {
    constexpr int kArmyBits = 8;
    constexpr int kFlagBits = 16;
    constexpr int kUnitFlagBits = 8;
    constexpr int kSiloBits = 16;
    constexpr int kYawBits = 16;
    constexpr int kMinBitsPerItem = 8; // the smallest gap varint
    constexpr int kVisualFlagBits = 5;
    constexpr std::uint32_t kCreationRequired = kEntityFields | kFieldKind;

    [[nodiscard]] std::uint32_t Bits(const float value) noexcept
    {
      return std::bit_cast<std::uint32_t>(value);
    }

    [[nodiscard]] std::uint32_t ZigZag(const std::int32_t value) noexcept
    {
      return (static_cast<std::uint32_t>(value) << 1) ^ static_cast<std::uint32_t>(value >> 31);
    }

    [[nodiscard]] std::int32_t UnZigZag(const std::uint32_t value) noexcept
    {
      return static_cast<std::int32_t>(value >> 1) ^ -static_cast<std::int32_t>(value & 1u);
    }

    /** `beat` is the frame's: a dead-reckoned anchor cannot lie in its future. */
    [[nodiscard]] bool FitsCodec(const SEntityRecord& record, const SFrameCodec& codec, const std::uint32_t beat) noexcept
    {
      if (record.farPosition) {
        return record.position == QuantizedPosition{} && record.velocity == std::array<std::int32_t, 3>{}
            && record.anchorBeat == 0u && (!record.yawOnly || record.orientation <= 0xFFFFu);
      }
      const bool motionFits = codec.deadReckoning
                                ? record.anchorBeat <= beat
                                : (record.anchorBeat == 0u && record.velocity == std::array<std::int32_t, 3>{});
      return motionFits && (!record.yawOnly || record.orientation <= 0xFFFFu)
          && record.position[0] <= codec.position.x.MaxQuantized()
          && record.position[1] <= codec.position.y.MaxQuantized()
          && record.position[2] <= codec.position.z.MaxQuantized();
    }

    [[nodiscard]] bool SameUnitFields(const SUnitFields& a, const SUnitFields& b) noexcept
    {
      return Bits(a.fuelRatio) == Bits(b.fuelRatio) && Bits(a.shieldRatio) == Bits(b.shieldRatio)
          && Bits(a.workProgress) == Bits(b.workProgress) && a.unitStates == b.unitStates
          && a.scriptBits == b.scriptBits && a.siloCounts == b.siloCounts && a.unitFlags == b.unitFlags;
    }

    [[nodiscard]] bool SameFloats(const float* a, const float* b, const std::size_t count) noexcept
    {
      for (std::size_t i = 0; i < count; ++i) {
        if (Bits(a[i]) != Bits(b[i])) {
          return false;
        }
      }
      return true;
    }

    /** The appearance fields in which two blocks differ. */
    [[nodiscard]] std::uint32_t AppearanceChanges(const SAppearance& b, const SAppearance& a) noexcept
    {
      std::uint32_t fields = 0;
      if (b.mesh != a.mesh) {
        fields |= kFieldMesh;
      }
      if (!SameFloats(b.scale.data(), a.scale.data(), b.scale.size())) {
        fields |= kFieldScale;
      }
      if (b.attachParent != a.attachParent || b.attachments != a.attachments) {
        fields |= kFieldAttachment;
      }
      if (b.visualFlags != a.visualFlags) {
        fields |= kFieldVisualFlags;
      }
      if (Bits(b.impact) != Bits(a.impact)) {
        fields |= kFieldImpact;
      }
      if (!SameFloats(b.scroll.data(), a.scroll.data(), b.scroll.size())) {
        fields |= kFieldScroll;
      }
      if (b.intel != a.intel) {
        fields |= kFieldIntel;
      }
      return fields;
    }

    void WriteFields(
      BitWriter& writer, const SEntityRecord& record, const std::uint32_t fields, const SFrameCodec& codec,
      const std::uint32_t beat
    )
    {
      if ((fields & kFieldKind) != 0u) {
        writer.WriteBool(record.isUnit);
      }
      if ((fields & kFieldPosition) != 0u) {
        writer.WriteBool(record.farPosition);
      }
      if ((fields & kFieldPosition) != 0u && record.farPosition) {
        for (const float value : record.farValue) {
          writer.WriteFloatExact(value);
        }
      } else if ((fields & kFieldPosition) != 0u) {
        writer.WriteBits(record.position[0], codec.position.x.bits);
        writer.WriteBits(record.position[1], codec.position.y.bits);
        writer.WriteBits(record.position[2], codec.position.z.bits);
        if (codec.deadReckoning) {
          writer.WriteVarUint(beat - record.anchorBeat);
          for (const std::int32_t component : record.velocity) {
            writer.WriteVarUint(ZigZag(component));
          }
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        writer.WriteBool(record.yawOnly);
        writer.WriteBits(record.orientation, record.yawOnly ? kYawBits : 32);
      }
      if ((fields & kFieldHealth) != 0u) {
        writer.WriteFloatExact(record.health);
      }
      if ((fields & kFieldFraction) != 0u) {
        writer.WriteFloatExact(record.fractionComplete);
      }
      if ((fields & kFieldFlags) != 0u) {
        writer.WriteBits(record.flags, kFlagBits);
      }
      if ((fields & kFieldMaxHealth) != 0u) {
        writer.WriteFloatExact(record.maxHealth);
      }
      if ((fields & kFieldBlueprint) != 0u) {
        writer.WriteVarUint(record.blueprint);
      }
      if ((fields & kFieldArmy) != 0u) {
        writer.WriteBits(record.army, kArmyBits);
      }
      const SUnitFields& unit = record.unit;
      if ((fields & kFieldUnitFuel) != 0u) {
        writer.WriteFloatExact(unit.fuelRatio);
      }
      if ((fields & kFieldUnitShield) != 0u) {
        writer.WriteFloatExact(unit.shieldRatio);
      }
      if ((fields & kFieldUnitWork) != 0u) {
        writer.WriteFloatExact(unit.workProgress);
      }
      if ((fields & kFieldUnitStates) != 0u) {
        writer.WriteBits(static_cast<std::uint32_t>(unit.unitStates), 32);
        writer.WriteBits(static_cast<std::uint32_t>(unit.unitStates >> 32), 32);
      }
      if ((fields & kFieldUnitScriptBits) != 0u) {
        writer.WriteBits(unit.scriptBits, 32);
      }
      if ((fields & kFieldUnitSilos) != 0u) {
        for (const std::uint16_t count : unit.siloCounts) {
          writer.WriteBits(count, kSiloBits);
        }
      }
      if ((fields & kFieldUnitFlags) != 0u) {
        writer.WriteBits(unit.unitFlags, kUnitFlagBits);
      }
      const SAppearance& look = record.appearance;
      if ((fields & kFieldMesh) != 0u) {
        writer.WriteVarUint(look.mesh);
      }
      if ((fields & kFieldScale) != 0u) {
        for (const float value : look.scale) {
          writer.WriteFloatExact(value);
        }
      }
      if ((fields & kFieldAttachment) != 0u) {
        writer.WriteBits(look.attachParent, 32);
        writer.WriteVarUint(static_cast<std::uint32_t>(look.attachments.size()));
        for (const std::uint32_t id : look.attachments) {
          writer.WriteBits(id, 32);
        }
      }
      if ((fields & kFieldVisualFlags) != 0u) {
        writer.WriteBits(look.visualFlags, kVisualFlagBits);
      }
      if ((fields & kFieldImpact) != 0u) {
        writer.WriteFloatExact(look.impact);
      }
      if ((fields & kFieldScroll) != 0u) {
        for (const float value : look.scroll) {
          writer.WriteFloatExact(value);
        }
      }
      if ((fields & kFieldIntel) != 0u) {
        for (const std::uint32_t radius : look.intel) {
          writer.WriteVarUint(radius);
        }
      }
    }

    /** Reads `fields` into `record`. Unit fields for a record that is not a unit are refused. */
    [[nodiscard]] bool ReadFields(
      BitReader& reader, SEntityRecord& record, const std::uint32_t fields, const SFrameCodec& codec,
      const std::uint32_t beat
    )
    {
      if ((fields & kFieldKind) != 0u) {
        record.isUnit = reader.ReadBool();
      }
      if ((fields & kUnitFields) != 0u && !record.isUnit) {
        reader.Fail();
        return false;
      }
      if ((fields & kFieldPosition) != 0u) {
        record.farPosition = reader.ReadBool();
      }
      if ((fields & kFieldPosition) != 0u && record.farPosition) {
        for (float& value : record.farValue) {
          value = reader.ReadFloatExact();
        }
        record.position = {};
        record.velocity = {};
        record.anchorBeat = 0;
      } else if ((fields & kFieldPosition) != 0u) {
        record.farValue = {};
        record.position[0] = reader.ReadBits(codec.position.x.bits);
        record.position[1] = reader.ReadBits(codec.position.y.bits);
        record.position[2] = reader.ReadBits(codec.position.z.bits);
        if (codec.deadReckoning) {
          const std::uint32_t age = reader.ReadVarUint();
          if (!reader.Ok() || age > beat) {
            reader.Fail();
            return false;
          }
          record.anchorBeat = beat - age;
          for (std::int32_t& component : record.velocity) {
            component = UnZigZag(reader.ReadVarUint());
          }
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        record.yawOnly = reader.ReadBool();
        record.orientation = reader.ReadBits(record.yawOnly ? kYawBits : 32);
      }
      if ((fields & kFieldHealth) != 0u) {
        record.health = reader.ReadFloatExact();
      }
      if ((fields & kFieldFraction) != 0u) {
        record.fractionComplete = reader.ReadFloatExact();
      }
      if ((fields & kFieldFlags) != 0u) {
        record.flags = static_cast<std::uint16_t>(reader.ReadBits(kFlagBits));
      }
      if ((fields & kFieldMaxHealth) != 0u) {
        record.maxHealth = reader.ReadFloatExact();
      }
      if ((fields & kFieldBlueprint) != 0u) {
        record.blueprint = reader.ReadVarUint();
      }
      if ((fields & kFieldArmy) != 0u) {
        record.army = static_cast<std::uint8_t>(reader.ReadBits(kArmyBits));
      }
      SUnitFields& unit = record.unit;
      if ((fields & kFieldUnitFuel) != 0u) {
        unit.fuelRatio = reader.ReadFloatExact();
      }
      if ((fields & kFieldUnitShield) != 0u) {
        unit.shieldRatio = reader.ReadFloatExact();
      }
      if ((fields & kFieldUnitWork) != 0u) {
        unit.workProgress = reader.ReadFloatExact();
      }
      if ((fields & kFieldUnitStates) != 0u) {
        const std::uint64_t low = reader.ReadBits(32);
        const std::uint64_t high = reader.ReadBits(32);
        unit.unitStates = low | (high << 32);
      }
      if ((fields & kFieldUnitScriptBits) != 0u) {
        unit.scriptBits = reader.ReadBits(32);
      }
      if ((fields & kFieldUnitSilos) != 0u) {
        for (std::uint16_t& count : unit.siloCounts) {
          count = static_cast<std::uint16_t>(reader.ReadBits(kSiloBits));
        }
      }
      if ((fields & kFieldUnitFlags) != 0u) {
        unit.unitFlags = static_cast<std::uint8_t>(reader.ReadBits(kUnitFlagBits));
      }
      SAppearance& look = record.appearance;
      if ((fields & kFieldMesh) != 0u) {
        look.mesh = reader.ReadVarUint();
      }
      if ((fields & kFieldScale) != 0u) {
        for (float& value : look.scale) {
          value = reader.ReadFloatExact();
        }
      }
      if ((fields & kFieldAttachment) != 0u) {
        look.attachParent = reader.ReadBits(32);
        const std::uint32_t count = reader.ReadVarUint();
        if (!reader.Ok() || count > SAppearance::kMaxAttachments
            || static_cast<std::uint64_t>(count) * 32u > reader.BitsLeft()) {
          reader.Fail();
          return false;
        }
        look.attachments.resize(count);
        for (std::uint32_t& id : look.attachments) {
          id = reader.ReadBits(32);
        }
      }
      if ((fields & kFieldVisualFlags) != 0u) {
        look.visualFlags = static_cast<std::uint8_t>(reader.ReadBits(kVisualFlagBits));
      }
      if ((fields & kFieldImpact) != 0u) {
        look.impact = reader.ReadFloatExact();
      }
      if ((fields & kFieldScroll) != 0u) {
        for (float& value : look.scroll) {
          value = reader.ReadFloatExact();
        }
      }
      if ((fields & kFieldIntel) != 0u) {
        for (std::uint32_t& radius : look.intel) {
          radius = reader.ReadVarUint();
        }
      }
      return reader.Ok();
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

  bool SAppearance::operator==(const SAppearance& other) const noexcept
  {
    return AppearanceChanges(*this, other) == 0u;
  }

  bool SEntityRecord::operator==(const SEntityRecord& other) const noexcept
  {
    return id == other.id && blueprint == other.blueprint && army == other.army && position == other.position
        && farPosition == other.farPosition && SameFloats(farValue.data(), other.farValue.data(), farValue.size())
        && velocity == other.velocity && anchorBeat == other.anchorBeat
        && orientation == other.orientation && yawOnly == other.yawOnly && Bits(health) == Bits(other.health)
        && Bits(maxHealth) == Bits(other.maxHealth) && Bits(fractionComplete) == Bits(other.fractionComplete)
        && flags == other.flags && isUnit == other.isUnit && (!isUnit || SameUnitFields(unit, other.unit))
        && appearance == other.appearance;
  }

  std::uint32_t CreationFields(const SEntityRecord& record) noexcept
  {
    return kEntityFields | kFieldKind | (record.isUnit ? kUnitFields : 0u)
         | AppearanceChanges(SAppearance{}, record.appearance);
  }

  std::uint32_t ChangedFields(const SEntityRecord& before, const SEntityRecord& after) noexcept
  {
    std::uint32_t fields = AppearanceChanges(before.appearance, after.appearance);
    if (before.position != after.position || before.velocity != after.velocity || before.anchorBeat != after.anchorBeat
        || before.farPosition != after.farPosition
        || !SameFloats(before.farValue.data(), after.farValue.data(), before.farValue.size())) {
      fields |= kFieldPosition;
    }
    if (before.orientation != after.orientation || before.yawOnly != after.yawOnly) {
      fields |= kFieldOrientation;
    }
    if (Bits(before.health) != Bits(after.health)) {
      fields |= kFieldHealth;
    }
    if (Bits(before.fractionComplete) != Bits(after.fractionComplete)) {
      fields |= kFieldFraction;
    }
    if (before.flags != after.flags) {
      fields |= kFieldFlags;
    }
    if (Bits(before.maxHealth) != Bits(after.maxHealth)) {
      fields |= kFieldMaxHealth;
    }
    if (before.blueprint != after.blueprint) {
      fields |= kFieldBlueprint;
    }
    if (before.army != after.army) {
      fields |= kFieldArmy;
    }
    if (before.isUnit != after.isUnit) {
      // Becoming a unit sends the whole unit block; ceasing to be one sends only the kind.
      fields |= kFieldKind;
      if (after.isUnit) {
        fields |= kUnitFields;
      }
      return fields;
    }
    if (after.isUnit) {
      const SUnitFields& b = before.unit;
      const SUnitFields& a = after.unit;
      if (Bits(b.fuelRatio) != Bits(a.fuelRatio)) {
        fields |= kFieldUnitFuel;
      }
      if (Bits(b.shieldRatio) != Bits(a.shieldRatio)) {
        fields |= kFieldUnitShield;
      }
      if (Bits(b.workProgress) != Bits(a.workProgress)) {
        fields |= kFieldUnitWork;
      }
      if (b.unitStates != a.unitStates) {
        fields |= kFieldUnitStates;
      }
      if (b.scriptBits != a.scriptBits) {
        fields |= kFieldUnitScriptBits;
      }
      if (b.siloCounts != a.siloCounts) {
        fields |= kFieldUnitSilos;
      }
      if (b.unitFlags != a.unitFlags) {
        fields |= kFieldUnitFlags;
      }
    }
    return fields;
  }

  QuantizedPosition PredictPosition(const SEntityRecord& record, const std::uint32_t beat, const SFrameCodec& codec) noexcept
  {
    const std::int64_t elapsed = static_cast<std::int64_t>(beat) - static_cast<std::int64_t>(record.anchorBeat);
    const std::uint32_t limits[3] = {
      codec.position.x.MaxQuantized(), codec.position.y.MaxQuantized(), codec.position.z.MaxQuantized()
    };
    QuantizedPosition predicted{};
    for (int axis = 0; axis < 3; ++axis) {
      const std::int64_t value = static_cast<std::int64_t>(record.position[axis]) + record.velocity[axis] * elapsed;
      predicted[axis] = value < 0 ? 0u : (value > limits[axis] ? limits[axis] : static_cast<std::uint32_t>(value));
    }
    return predicted;
  }

  bool ApplyDeadReckoning(
    SEntityRecord& sent, const QuantizedPosition& actual, const QuantizedPosition& previousActual,
    const std::uint32_t beat, const std::uint32_t tolerance, const SFrameCodec& codec
  ) noexcept
  {
    const QuantizedPosition predicted = PredictPosition(sent, beat, codec);
    bool within = true;
    for (int axis = 0; axis < 3; ++axis) {
      const std::int64_t error = static_cast<std::int64_t>(actual[axis]) - static_cast<std::int64_t>(predicted[axis]);
      if (error > tolerance || -error > tolerance) {
        within = false;
      }
    }
    if (within) {
      return false;
    }
    sent.position = actual;
    for (int axis = 0; axis < 3; ++axis) {
      sent.velocity[axis] =
        static_cast<std::int32_t>(static_cast<std::int64_t>(actual[axis]) - static_cast<std::int64_t>(previousActual[axis]));
    }
    sent.anchorBeat = beat;
    return true;
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
        if (const std::uint32_t fields = ChangedFields(before[b], after[a]); fields != 0u) {
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
      if (!FitsCodec(record, codec, frame.beat)) {
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
      const std::uint32_t fields = CreationFields(record);
      writer.WriteVarUint(fields);
      WriteFields(writer, record, fields, codec, frame.beat);
    }

    first = true;
    writer.WriteVarUint(static_cast<std::uint32_t>(delta.changed.size()));
    for (const SFrameDelta::SChange& change : delta.changed) {
      WriteGap(writer, first, previous, change.record.id);
      writer.WriteVarUint(change.fields);
      WriteFields(writer, change.record, change.fields, codec, frame.beat);
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
        const std::uint32_t fields = reader.ReadVarUint();
        if (!reader.Ok() || (fields & kCreationRequired) != kCreationRequired || (fields & ~kAllFields) != 0u) {
          return false;
        }
        if (!ReadFields(reader, record, fields, codec, beat)) {
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
          merged.push_back(std::move(kept[k++]));
        } else if (k == kept.size() || created[c].id < kept[k].id) {
          merged.push_back(std::move(created[c++])); // ids stay readable below
        } else {
          return false;
        }
      }
    }

    // Changes: ids must be kept (not created in this frame), the mask non-empty and known.
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
        const std::uint32_t fields = reader.ReadVarUint();
        if (!reader.Ok() || fields == 0u || (fields & ~kAllFields) != 0u) {
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
        if (!ReadFields(reader, merged[m], fields, codec, beat)) {
          return false;
        }
      }
    }

    for (const SEntityRecord& record : merged) {
      if (!FitsCodec(record, codec, beat)) {
        return false;
      }
    }

    out.frameId = frameId;
    out.beat = beat;
    out.entities = std::move(merged);
    return true;
  }
} // namespace faf::remote::wire
