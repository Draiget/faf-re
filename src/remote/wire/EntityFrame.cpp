#include "remote/wire/EntityFrame.h"

#include <algorithm>
#include <bit>
#include <cmath>
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

    // Entities 11: a changed position or yaw goes as the step from the client's record when that is shorter,
    // in exponential-Golomb codes of order k (k low bits always, small values in few bits). Horizontal moves of
    // a unit run a few to a few dozen 1/64 steps a beat, height changes far fewer, turns a few hundredths of 2^16.
    constexpr int kStepOrderXZ = 3;
    constexpr int kStepOrderY = 1;
    constexpr int kStepOrderYaw = 3;
    // Entities 13 (#312): a full rotation's three 10-bit packed components (Quantize.cpp's PackQuaternion: the
    // largest component's index in the low 2 bits, then the other three) step by a few units a beat.
    constexpr int kStepOrderQuaternion = 1;
    constexpr int kQuaternionComponentBits = 10;
    constexpr std::uint32_t kQuaternionComponentMask = (1u << kQuaternionComponentBits) - 1u;
    constexpr int kMaxGolombZeros = 26; // more than any step a field this wide can take

    [[nodiscard]] int ExpGolombBits(const std::uint32_t value, const int order) noexcept
    {
      const std::uint64_t shifted = std::uint64_t{value} + (std::uint64_t{1} << order);
      return 2 * static_cast<int>(std::bit_width(shifted)) - 1 - order;
    }

    void WriteExpGolomb(BitWriter& writer, const std::uint32_t value, const int order)
    {
      const std::uint64_t shifted = std::uint64_t{value} + (std::uint64_t{1} << order);
      const int width = static_cast<int>(std::bit_width(shifted));
      if (width - 1 - order > 0) {
        writer.WriteBits(0u, width - 1 - order);
      }
      writer.WriteBits(1u, 1);
      if (width > 1) {
        writer.WriteBits(static_cast<std::uint32_t>(shifted), width - 1);
      }
    }

    [[nodiscard]] std::uint32_t ReadExpGolomb(BitReader& reader, const int order, const int maxZeros = kMaxGolombZeros) noexcept
    {
      int zeros = 0;
      while (reader.ReadBits(1) == 0u) {
        if (!reader.Ok() || ++zeros > maxZeros) {
          reader.Fail();
          return 0u;
        }
      }
      const int rest = zeros + order;
      const std::uint64_t shifted = (std::uint64_t{1} << rest) | (rest > 0 ? reader.ReadBits(rest) : 0u);
      return static_cast<std::uint32_t>(shifted - (std::uint64_t{1} << order));
    }

    /** A position's step from `before`, per axis, zigzagged. */
    [[nodiscard]] std::array<std::uint32_t, 3> PositionSteps(const SEntityRecord& record, const SEntityRecord& before) noexcept
    {
      std::array<std::uint32_t, 3> steps{};
      for (std::size_t axis = 0; axis < 3; ++axis) {
        steps[axis] = ZigZag(static_cast<std::int32_t>(static_cast<std::int64_t>(record.position[axis]) - before.position[axis]));
      }
      return steps;
    }

    /** Whether a changed position may go as its step: both ends in the quantiser's range. */
    [[nodiscard]] bool PositionMayStep(const SEntityRecord& record, const SEntityRecord* const before) noexcept
    {
      return before != nullptr && !before->farPosition && !record.farPosition;
    }

    [[nodiscard]] int PositionStepBits(const std::array<std::uint32_t, 3>& steps) noexcept
    {
      return ExpGolombBits(steps[0], kStepOrderXZ) + ExpGolombBits(steps[1], kStepOrderY) + ExpGolombBits(steps[2], kStepOrderXZ);
    }

    [[nodiscard]] int PositionWholeBits(const SFrameCodec& codec) noexcept
    {
      return codec.position.x.bits + codec.position.y.bits + codec.position.z.bits;
    }

    /** Whether a changed yaw may go as its turn: yaw-only at both ends. */
    [[nodiscard]] bool YawMayStep(const SEntityRecord& record, const SEntityRecord* const before) noexcept
    {
      return before != nullptr && before->yawOnly && record.yawOnly;
    }

    [[nodiscard]] std::uint32_t YawStep(const SEntityRecord& record, const SEntityRecord& before) noexcept
    {
      return ZigZag(static_cast<std::int16_t>(static_cast<std::uint16_t>(record.orientation - before.orientation)));
    }

    /** Whether a changed full orientation is sent with its stepped bit: full at both ends. */
    [[nodiscard]] bool FullMayStep(const SEntityRecord& record, const SEntityRecord* const before) noexcept
    {
      return before != nullptr && !before->yawOnly && !record.yawOnly;
    }

    /** A full orientation's packed components' steps from `before`'s, zigzagged; false when the largest component
     * differs (the components then aren't the same three). */
    [[nodiscard]] bool FullSteps(const std::uint32_t orientation, const std::uint32_t before, std::array<std::uint32_t, 3>& steps) noexcept
    {
      if ((orientation & 3u) != (before & 3u)) {
        return false;
      }
      for (int i = 0; i < 3; ++i) {
        const int shift = 2 + i * kQuaternionComponentBits;
        const auto now = static_cast<std::int32_t>((orientation >> shift) & kQuaternionComponentMask);
        const auto was = static_cast<std::int32_t>((before >> shift) & kQuaternionComponentMask);
        steps[static_cast<std::size_t>(i)] = ZigZag(now - was);
      }
      return true;
    }

    /** The bits of `steps`, or 32 or more when they aren't shorter than the whole orientation. */
    [[nodiscard]] int FullStepBits(const std::array<std::uint32_t, 3>& steps) noexcept
    {
      return ExpGolombBits(steps[0], kStepOrderQuaternion) + ExpGolombBits(steps[1], kStepOrderQuaternion) + ExpGolombBits(steps[2], kStepOrderQuaternion);
    }

    /** `beat` is the frame's: a dead-reckoned anchor cannot lie in its future. */
    [[nodiscard]] bool FitsCodec(const SEntityRecord& record, const SFrameCodec& codec, const std::uint32_t beat) noexcept
    {
      const bool turnFits = codec.orientationReckoning && record.yawOnly
                              ? record.orientationBeat <= beat
                              : (record.orientationBeat == 0u && record.yawRate == 0);
      if (!turnFits || (codec.orientationReckoning && !codec.deadReckoning)
          || (codec.groundFollowing && !codec.deadReckoning)
          || (record.followsGround && (!codec.groundFollowing || record.farPosition))) {
        return false;
      }
      if (record.farPosition) {
        return record.position == QuantizedPosition{} && record.velocity == std::array<std::int32_t, 3>{}
            && record.verticalAcceleration == 0 && record.anchorBeat == 0u
            && (!record.yawOnly || record.orientation <= 0xFFFFu);
      }
      const bool motionFits = codec.deadReckoning
                                ? record.anchorBeat <= beat
                                : (record.anchorBeat == 0u && record.velocity == std::array<std::int32_t, 3>{}
                                   && record.verticalAcceleration == 0);
      return motionFits && (!record.yawOnly || record.orientation <= 0xFFFFu)
          && record.position[0] <= codec.position.x.MaxQuantized()
          && record.position[1] <= codec.position.y.MaxQuantized()
          && record.position[2] <= codec.position.z.MaxQuantized();
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

    void WriteInt(BitWriter& writer, const std::int32_t value)
    {
      writer.WriteVarUint(ZigZag(value));
    }

    [[nodiscard]] std::int32_t ReadInt(BitReader& reader)
    {
      return UnZigZag(reader.ReadVarUint());
    }

    [[nodiscard]] bool SameUnitFields(const SUnitFields& a, const SUnitFields& b) noexcept
    {
      return Bits(a.fuelRatio) == Bits(b.fuelRatio) && Bits(a.shieldRatio) == Bits(b.shieldRatio)
          && Bits(a.workProgress) == Bits(b.workProgress) && a.unitStates == b.unitStates
          && a.scriptBits == b.scriptBits && a.siloCounts == b.siloCounts && a.unitFlags == b.unitFlags
          && a.stats == b.stats && a.buildStateTag == b.buildStateTag && a.fake == b.fake && a.detail == b.detail;
    }

    [[nodiscard]] bool SameDetailScalars(const SUnitDetail& a, const SUnitDetail& b) noexcept
    {
      return a.creator == b.creator && a.creationTick == b.creationTick && a.stunTicks == b.stunTicks
          && a.jobType == b.jobType && a.fireState == b.fireState && a.siloMaxStorage == b.siloMaxStorage
          && a.selectionInheritor == b.selectionInheritor && a.customName == b.customName
          && a.focusUnit == b.focusUnit && a.guardedUnit == b.guardedUnit && a.targetBlip == b.targetBlip
          && a.didRefresh == b.didRefresh && a.reconFlags == b.reconFlags;
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
      if (b.ambientSound != a.ambientSound || b.rumbleSound != a.rumbleSound) {
        fields |= kFieldSounds;
      }
      if (b.underlay != a.underlay) {
        fields |= kFieldUnderlay;
      }
      return fields;
    }

    /**
     * `before`: the record in the baseline (null for a creation); a texture scroll whose new
     * start is the old end (`Entity::SetAnimScroll` shifts it) is sent as one bit and the end.
     */
    void WriteFields(
      BitWriter& writer, const SEntityRecord& record, const std::uint32_t fields, const SFrameCodec& codec,
      const std::uint32_t beat, const SEntityRecord* const before
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
        bool stepped = false;
        if (PositionMayStep(record, before)) {
          const std::array<std::uint32_t, 3> steps = PositionSteps(record, *before);
          stepped = PositionStepBits(steps) < PositionWholeBits(codec);
          writer.WriteBool(stepped);
          if (stepped) {
            WriteExpGolomb(writer, steps[0], kStepOrderXZ);
            WriteExpGolomb(writer, steps[1], kStepOrderY);
            WriteExpGolomb(writer, steps[2], kStepOrderXZ);
          }
        }
        if (!stepped) {
          writer.WriteBits(record.position[0], codec.position.x.bits);
          writer.WriteBits(record.position[1], codec.position.y.bits);
          writer.WriteBits(record.position[2], codec.position.z.bits);
        }
        if (codec.deadReckoning) {
          writer.WriteVarUint(beat - record.anchorBeat);
          for (const std::int32_t component : record.velocity) {
            writer.WriteVarUint(ZigZag(component));
          }
          writer.WriteVarUint(ZigZag(record.verticalAcceleration));
          if (codec.groundFollowing) {
            writer.WriteBool(record.followsGround);
          }
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        writer.WriteBool(record.yawOnly);
        bool turned = false;
        if (YawMayStep(record, before)) {
          const std::uint32_t turn = YawStep(record, *before);
          turned = ExpGolombBits(turn, kStepOrderYaw) < kYawBits;
          writer.WriteBool(turned);
          if (turned) {
            WriteExpGolomb(writer, turn, kStepOrderYaw);
          }
        } else if (FullMayStep(record, before)) {
          std::array<std::uint32_t, 3> steps{};
          turned = FullSteps(record.orientation, before->orientation, steps) && FullStepBits(steps) < 32;
          writer.WriteBool(turned);
          if (turned) {
            for (const std::uint32_t step : steps) {
              WriteExpGolomb(writer, step, kStepOrderQuaternion);
            }
          }
        }
        if (!turned) {
          writer.WriteBits(record.orientation, record.yawOnly ? kYawBits : 32);
        }
        if (codec.orientationReckoning && record.yawOnly) {
          writer.WriteVarUint(beat - record.orientationBeat);
          writer.WriteVarUint(ZigZag(record.yawRate));
        }
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
      if ((fields & kFieldUnitStats) != 0u) {
        writer.WriteVarUint(static_cast<std::uint32_t>(unit.stats->size()));
        for (const SUnitStat& stat : *unit.stats) {
          writer.WriteVarUint(stat.name);
          writer.WriteBits(stat.type, 2);
          writer.WriteBool(stat.realtime);
          if (stat.type == SUnitStat::kString) {
            writer.WriteVarUint(stat.text + 1u);
          } else {
            writer.WriteBits(stat.bits, 32);
          }
        }
      }
      if ((fields & kFieldUnitConstants) != 0u) {
        writer.WriteBits(unit.buildStateTag, 8);
        writer.WriteBits(unit.fake, 8);
      }
      const SUnitDetail& detail = *unit.detail;
      if ((fields & kFieldUnitDetail) != 0u) {
        writer.WriteVarUint(detail.creator);
        WriteInt(writer, detail.creationTick);
        WriteInt(writer, detail.stunTicks);
        WriteInt(writer, detail.jobType);
        WriteInt(writer, detail.fireState);
        WriteInt(writer, detail.siloMaxStorage[0]);
        WriteInt(writer, detail.siloMaxStorage[1]);
        writer.WriteVarUint(detail.selectionInheritor);
        writer.WriteVarUint(detail.customName + 1u);
        writer.WriteVarUint(detail.focusUnit);
        writer.WriteVarUint(detail.guardedUnit);
        writer.WriteVarUint(detail.targetBlip);
        writer.WriteBits(detail.didRefresh, 8);
        WriteInt(writer, detail.reconFlags);
      }
      if ((fields & kFieldUnitEconomy) != 0u) {
        for (const float value : detail.economy) {
          writer.WriteFloatExact(value);
        }
      }
      if ((fields & kFieldUnitQueues) != 0u) {
        for (const std::vector<std::int32_t>* const queue : {&detail.commands, &detail.buildQueue}) {
          writer.WriteVarUint(static_cast<std::uint32_t>(queue->size()));
          for (const std::int32_t id : *queue) {
            WriteInt(writer, id);
          }
        }
      }
      if ((fields & kFieldUnitWeapons) != 0u) {
        writer.WriteVarUint(static_cast<std::uint32_t>(detail.weapons.size()));
        for (const SUnitWeapon& weapon : detail.weapons) {
          WriteCategoryBits(writer, weapon.targets);
          WriteCategoryBits(writer, weapon.secondary);
          writer.WriteVarUint(weapon.layer);
          writer.WriteFloatExact(weapon.minRadius);
          writer.WriteFloatExact(weapon.maxRadius);
          writer.WriteFloatExact(weapon.effectiveRadius);
          writer.WriteVarUint(weapon.minRangeVisual + 1u);
          writer.WriteVarUint(weapon.maxRangeVisual + 1u);
        }
      }
      if ((fields & kFieldUnitAttributes) != 0u) {
        const SUnitAttributes& attributes = detail.attributes;
        writer.WriteVarUint(attributes.blueprint + 1u);
        writer.WriteBits(attributes.reserved04, 32);
        WriteCategoryBits(writer, attributes.restriction);
        for (const float value : attributes.scalars) {
          writer.WriteFloatExact(value);
        }
        writer.WriteBits(attributes.commandCaps, 32);
        writer.WriteBits(attributes.toggleCaps, 32);
        for (const std::uint8_t flag : attributes.flags) {
          writer.WriteBits(flag, 8);
        }
        writer.WriteBits(attributes.reserved6C, 32);
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
        const bool shifted = before != nullptr && Bits(look.scroll[0]) == Bits(before->appearance.scroll[2])
                          && Bits(look.scroll[1]) == Bits(before->appearance.scroll[3]);
        writer.WriteBool(shifted);
        for (std::size_t i = shifted ? 2u : 0u; i < look.scroll.size(); ++i) {
          writer.WriteFloatExact(look.scroll[i]);
        }
      }
      if ((fields & kFieldIntel) != 0u) {
        for (const std::uint32_t radius : look.intel) {
          writer.WriteVarUint(radius);
        }
      }
      // Table ids go as id + 1, so "none" (kNone) is 0.
      if ((fields & kFieldSounds) != 0u) {
        writer.WriteVarUint(look.ambientSound + 1u);
        writer.WriteVarUint(look.rumbleSound + 1u);
      }
      if ((fields & kFieldUnderlay) != 0u) {
        writer.WriteVarUint(look.underlay + 1u);
      }
    }

    /**
     * Reads `fields` into `record`. Unit fields for a record that is not a unit are refused. `change`: `record`
     * holds the baseline's record, which a stepped position or yaw goes from (none for a creation).
     */
    [[nodiscard]] bool ReadFields(
      BitReader& reader, SEntityRecord& record, const std::uint32_t fields, const SFrameCodec& codec,
      const std::uint32_t beat, const bool change
    )
    {
      const bool positionFromBaseline = change && !record.farPosition;
      const QuantizedPosition baselinePosition = record.position;
      const bool yawFromBaseline = change && record.yawOnly;
      const bool fullFromBaseline = change && !record.yawOnly;
      const std::uint32_t baselineOrientation = record.orientation;
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
        record.verticalAcceleration = 0;
        record.anchorBeat = 0;
        record.followsGround = false;
      } else if ((fields & kFieldPosition) != 0u) {
        record.farValue = {};
        if (positionFromBaseline && reader.ReadBool()) {
          const std::uint32_t limits[3] = {codec.position.x.MaxQuantized(), codec.position.y.MaxQuantized(), codec.position.z.MaxQuantized()};
          const int orders[3] = {kStepOrderXZ, kStepOrderY, kStepOrderXZ};
          for (std::size_t axis = 0; axis < 3; ++axis) {
            const std::int64_t value = static_cast<std::int64_t>(baselinePosition[axis]) + UnZigZag(ReadExpGolomb(reader, orders[axis]));
            if (!reader.Ok() || value < 0 || value > limits[axis]) {
              reader.Fail();
              return false;
            }
            record.position[axis] = static_cast<std::uint32_t>(value);
          }
        } else {
          record.position[0] = reader.ReadBits(codec.position.x.bits);
          record.position[1] = reader.ReadBits(codec.position.y.bits);
          record.position[2] = reader.ReadBits(codec.position.z.bits);
        }
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
          record.verticalAcceleration = UnZigZag(reader.ReadVarUint());
          record.followsGround = codec.groundFollowing && reader.ReadBool();
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        record.yawOnly = reader.ReadBool();
        if (yawFromBaseline && record.yawOnly && reader.ReadBool()) {
          const std::uint32_t turn = ReadExpGolomb(reader, kStepOrderYaw);
          if (!reader.Ok() || turn > 0xFFFFu) {
            reader.Fail();
            return false;
          }
          record.orientation = static_cast<std::uint16_t>(baselineOrientation + static_cast<std::uint32_t>(UnZigZag(turn)));
        } else if (fullFromBaseline && !record.yawOnly && reader.ReadBool()) {
          // Entities 13: the baseline's largest component, its three others each stepped.
          std::uint32_t packed = baselineOrientation & 3u;
          for (int i = 0; i < 3; ++i) {
            const int shift = 2 + i * kQuaternionComponentBits;
            const std::uint32_t step = ReadExpGolomb(reader, kStepOrderQuaternion);
            const std::int64_t value = static_cast<std::int64_t>((baselineOrientation >> shift) & kQuaternionComponentMask) + UnZigZag(step);
            if (!reader.Ok() || step > 2u * kQuaternionComponentMask || value < 0 || value > kQuaternionComponentMask) {
              reader.Fail();
              return false;
            }
            packed |= static_cast<std::uint32_t>(value) << shift;
          }
          record.orientation = packed;
        } else {
          record.orientation = reader.ReadBits(record.yawOnly ? kYawBits : 32);
        }
        record.yawRate = 0;
        record.orientationBeat = 0;
        if (codec.orientationReckoning && record.yawOnly) {
          const std::uint32_t age = reader.ReadVarUint();
          if (!reader.Ok() || age > beat) {
            reader.Fail();
            return false;
          }
          record.orientationBeat = beat - age;
          record.yawRate = UnZigZag(reader.ReadVarUint());
        }
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
      if ((fields & kFieldUnitStats) != 0u) {
        const std::uint32_t count = reader.ReadVarUint();
        if (!reader.Ok() || count > SUnitFields::kMaxStats || static_cast<std::uint64_t>(count) * 11u > reader.BitsLeft()) {
          reader.Fail();
          return false;
        }
        std::vector<SUnitStat>& stats = unit.stats.Edit();
        stats.resize(count);
        for (SUnitStat& stat : stats) {
          stat.name = reader.ReadVarUint();
          stat.type = static_cast<std::uint8_t>(reader.ReadBits(2));
          stat.realtime = reader.ReadBool();
          if (stat.type == SUnitStat::kString) {
            stat.text = reader.ReadVarUint() - 1u;
            stat.bits = 0;
          } else {
            stat.bits = reader.ReadBits(32);
            stat.text = SUnitStat{}.text;
          }
        }
        for (std::size_t i = 1; i < stats.size(); ++i) {
          if (stats[i - 1].name >= stats[i].name) {
            reader.Fail(); // names ascending and unique
            return false;
          }
        }
      }
      if ((fields & kFieldUnitConstants) != 0u) {
        unit.buildStateTag = static_cast<std::uint8_t>(reader.ReadBits(8));
        unit.fake = static_cast<std::uint8_t>(reader.ReadBits(8));
      }
      constexpr std::uint32_t kDetailFields =
        kFieldUnitDetail | kFieldUnitEconomy | kFieldUnitQueues | kFieldUnitWeapons | kFieldUnitAttributes;
      if ((fields & kDetailFields) != 0u) {
        SUnitDetail& detail = unit.detail.Edit();
        if ((fields & kFieldUnitDetail) != 0u) {
          detail.creator = reader.ReadVarUint();
          detail.creationTick = ReadInt(reader);
          detail.stunTicks = ReadInt(reader);
          detail.jobType = ReadInt(reader);
          detail.fireState = ReadInt(reader);
          detail.siloMaxStorage[0] = ReadInt(reader);
          detail.siloMaxStorage[1] = ReadInt(reader);
          detail.selectionInheritor = reader.ReadVarUint();
          detail.customName = reader.ReadVarUint() - 1u;
          detail.focusUnit = reader.ReadVarUint();
          detail.guardedUnit = reader.ReadVarUint();
          detail.targetBlip = reader.ReadVarUint();
          detail.didRefresh = static_cast<std::uint8_t>(reader.ReadBits(8));
          detail.reconFlags = ReadInt(reader);
        }
        if ((fields & kFieldUnitEconomy) != 0u) {
          for (float& value : detail.economy) {
            value = reader.ReadFloatExact();
          }
        }
        if ((fields & kFieldUnitQueues) != 0u) {
          for (std::vector<std::int32_t>* const queue : {&detail.commands, &detail.buildQueue}) {
            const std::uint32_t count = reader.ReadVarUint();
            if (!reader.Ok() || count > SUnitDetail::kMaxQueue || static_cast<std::uint64_t>(count) * 8u > reader.BitsLeft()) {
              reader.Fail();
              return false;
            }
            queue->resize(count);
            for (std::int32_t& id : *queue) {
              id = ReadInt(reader);
            }
          }
        }
        if ((fields & kFieldUnitWeapons) != 0u) {
          const std::uint32_t count = reader.ReadVarUint();
          if (!reader.Ok() || count > SUnitDetail::kMaxWeapons || static_cast<std::uint64_t>(count) * 120u > reader.BitsLeft()) {
            reader.Fail();
            return false;
          }
          detail.weapons.resize(count);
          for (SUnitWeapon& weapon : detail.weapons) {
            if (!ReadCategoryBits(reader, weapon.targets) || !ReadCategoryBits(reader, weapon.secondary)) {
              return false;
            }
            weapon.layer = reader.ReadVarUint();
            weapon.minRadius = reader.ReadFloatExact();
            weapon.maxRadius = reader.ReadFloatExact();
            weapon.effectiveRadius = reader.ReadFloatExact();
            weapon.minRangeVisual = reader.ReadVarUint() - 1u;
            weapon.maxRangeVisual = reader.ReadVarUint() - 1u;
          }
        }
        if ((fields & kFieldUnitAttributes) != 0u) {
          SUnitAttributes& attributes = detail.attributes;
          attributes.blueprint = reader.ReadVarUint() - 1u;
          attributes.reserved04 = reader.ReadBits(32);
          if (!ReadCategoryBits(reader, attributes.restriction)) {
            return false;
          }
          for (float& value : attributes.scalars) {
            value = reader.ReadFloatExact();
          }
          attributes.commandCaps = reader.ReadBits(32);
          attributes.toggleCaps = reader.ReadBits(32);
          for (std::uint8_t& flag : attributes.flags) {
            flag = static_cast<std::uint8_t>(reader.ReadBits(8));
          }
          attributes.reserved6C = reader.ReadBits(32);
        }
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
        // `record` holds the baseline's values here (a change) or the defaults (a creation).
        const bool shifted = reader.ReadBool();
        if (shifted) {
          look.scroll[0] = look.scroll[2];
          look.scroll[1] = look.scroll[3];
        }
        for (std::size_t i = shifted ? 2u : 0u; i < look.scroll.size(); ++i) {
          look.scroll[i] = reader.ReadFloatExact();
        }
      }
      if ((fields & kFieldIntel) != 0u) {
        for (std::uint32_t& radius : look.intel) {
          radius = reader.ReadVarUint();
        }
      }
      if ((fields & kFieldSounds) != 0u) {
        look.ambientSound = reader.ReadVarUint() - 1u;
        look.rumbleSound = reader.ReadVarUint() - 1u;
      }
      if ((fields & kFieldUnderlay) != 0u) {
        look.underlay = reader.ReadVarUint() - 1u;
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

    constexpr int kMaxGapZeros = 32; // an order-0 code of any 32-bit gap
  } // namespace

  std::uint32_t CChangeHeaders::Find(const std::uint32_t fields) const noexcept
  {
    std::uint32_t place = 0;
    while (place < mRecentCount && mRecentMasks[place] != fields) {
      ++place;
    }
    return place < mRecentCount ? place : kRecent;
  }

  void CChangeHeaders::Use(const std::uint32_t place, const std::uint32_t fields) noexcept
  {
    // Moved (or, when new, put) to the front; a new mask drops the oldest once all 15 are taken.
    std::uint32_t from = place;
    if (place == kRecent) {
      from = mRecentCount < kRecent ? mRecentCount++ : kRecent - 1u;
    }
    for (std::uint32_t i = from; i > 0u; --i) {
      mRecentMasks[i] = mRecentMasks[i - 1u];
    }
    mRecentMasks[0] = fields;
  }

  void CChangeHeaders::Write(BitWriter& writer, const std::uint32_t id, const std::uint32_t fields)
  {
    if (mFirst) {
      writer.WriteVarUint(id);
    } else {
      WriteExpGolomb(writer, id - mPrevious - 1u, 0);
    }
    mFirst = false;
    mPrevious = id;
    const std::uint32_t place = Find(fields);
    WriteExpGolomb(writer, place, 0);
    if (place == kRecent) {
      writer.WriteVarUint(fields);
    }
    Use(place, fields);
  }

  bool CChangeHeaders::Read(BitReader& reader, std::uint32_t& id, std::uint32_t& fields) noexcept
  {
    const std::uint64_t gap = mFirst ? reader.ReadVarUint() : ReadExpGolomb(reader, 0, kMaxGapZeros);
    const std::uint64_t next = mFirst ? gap : static_cast<std::uint64_t>(mPrevious) + 1u + gap;
    if (!reader.Ok() || next > 0xFFFFFFFFull) {
      reader.Fail();
      return false;
    }
    mFirst = false;
    mPrevious = static_cast<std::uint32_t>(next);
    id = mPrevious;
    const std::uint32_t place = ReadExpGolomb(reader, 0, 4);
    if (!reader.Ok() || place > kRecent || (place != kRecent && place >= mRecentCount)) {
      reader.Fail();
      return false;
    }
    fields = place == kRecent ? reader.ReadVarUint() : mRecentMasks[place];
    if (!reader.Ok()) {
      return false;
    }
    Use(place, fields);
    return true;
  }

  int CChangeHeaders::Bits(const std::uint32_t id, const std::uint32_t fields) noexcept
  {
    const auto varintBits = [](std::uint32_t value) {
      int bits = 8;
      while (value >= 0x80u) {
        value >>= 7;
        bits += 8;
      }
      return bits;
    };
    int bits = mFirst ? varintBits(id) : ExpGolombBits(id - mPrevious - 1u, 0);
    mFirst = false;
    mPrevious = id;
    const std::uint32_t place = Find(fields);
    bits += ExpGolombBits(place, 0) + (place == kRecent ? varintBits(fields) : 0);
    Use(place, fields);
    return bits;
  }

  namespace
  {
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

  void WriteCategoryBits(BitWriter& writer, const SCategoryBits& bits)
  {
    writer.WriteVarUint(bits.firstWord);
    writer.WriteVarUint(static_cast<std::uint32_t>(bits.words.size()));
    for (const std::uint32_t word : bits.words) {
      writer.WriteBits(word, 32);
    }
  }

  bool ReadCategoryBits(BitReader& reader, SCategoryBits& bits)
  {
    bits.firstWord = reader.ReadVarUint();
    const std::uint32_t count = reader.ReadVarUint();
    if (!reader.Ok() || count > SCategoryBits::kMaxWords || static_cast<std::uint64_t>(count) * 32u > reader.BitsLeft()) {
      reader.Fail();
      return false;
    }
    bits.words.resize(count);
    for (std::uint32_t& word : bits.words) {
      word = reader.ReadBits(32);
    }
    return reader.Ok();
  }

  bool SUnitWeapon::operator==(const SUnitWeapon& other) const noexcept
  {
    return targets == other.targets && secondary == other.secondary && layer == other.layer
        && Bits(minRadius) == Bits(other.minRadius) && Bits(maxRadius) == Bits(other.maxRadius)
        && Bits(effectiveRadius) == Bits(other.effectiveRadius) && minRangeVisual == other.minRangeVisual
        && maxRangeVisual == other.maxRangeVisual;
  }

  bool SUnitAttributes::operator==(const SUnitAttributes& other) const noexcept
  {
    return blueprint == other.blueprint && reserved04 == other.reserved04 && restriction == other.restriction
        && SameFloats(scalars.data(), other.scalars.data(), scalars.size()) && commandCaps == other.commandCaps
        && toggleCaps == other.toggleCaps && flags == other.flags && reserved6C == other.reserved6C;
  }

  bool SUnitDetail::operator==(const SUnitDetail& other) const noexcept
  {
    return SameDetailScalars(*this, other) && SameFloats(economy.data(), other.economy.data(), economy.size())
        && commands == other.commands && buildQueue == other.buildQueue
        && weapons == other.weapons && attributes == other.attributes;
  }

  bool SAppearance::operator==(const SAppearance& other) const noexcept
  {
    return AppearanceChanges(*this, other) == 0u;
  }

  bool SEntityRecord::operator==(const SEntityRecord& other) const noexcept
  {
    return id == other.id && tickCreated == other.tickCreated && blueprint == other.blueprint && army == other.army && position == other.position
        && farPosition == other.farPosition && SameFloats(farValue.data(), other.farValue.data(), farValue.size())
        && velocity == other.velocity && verticalAcceleration == other.verticalAcceleration
        && anchorBeat == other.anchorBeat && followsGround == other.followsGround
        && orientation == other.orientation && yawOnly == other.yawOnly && yawRate == other.yawRate
        && orientationBeat == other.orientationBeat && Bits(health) == Bits(other.health)
        && Bits(maxHealth) == Bits(other.maxHealth) && Bits(fractionComplete) == Bits(other.fractionComplete)
        && flags == other.flags && isUnit == other.isUnit && (!isUnit || SameUnitFields(unit, other.unit))
        && appearance == other.appearance;
  }

  std::uint64_t HashBlipUpdate(const SEntityRecord& record, const SUnitDetail& detail) noexcept
  {
    // Four lanes in turn, so each value's multiplies wait on the value four before, not the one
    // before: a server hashes every blip update of every view group each beat (plan #118).
    std::uint64_t lanes[4] = {0x9E3779B97F4A7C15ull, 0xC2B2AE3D27D4EB4Full, 0x165667B19E3779F9ull, 0x27D4EB2F165667C5ull};
    const auto add = [&lanes](const std::uint64_t value) {
      const std::uint64_t next = std::rotl(lanes[0] ^ (value * 0xC2B2AE3D27D4EB4Full), 31) * 0x9E3779B185EBCA87ull;
      lanes[0] = lanes[1];
      lanes[1] = lanes[2];
      lanes[2] = lanes[3];
      lanes[3] = next;
    };
    const auto addFloats = [&add](const float* const values, const std::size_t count) {
      for (std::size_t i = 0; i < count; ++i) {
        add(Bits(values[i]));
      }
    };
    const auto addCategories = [&add](const SCategoryBits& bits) {
      add(bits.firstWord);
      add(bits.words.size());
      for (const std::uint32_t word : bits.words) {
        add(word);
      }
    };

    const SAppearance& look = record.appearance;
    add(look.mesh);
    addFloats(look.scale.data(), look.scale.size());
    add(look.attachParent);
    add(look.attachments.size());
    for (const std::uint32_t id : look.attachments) {
      add(id);
    }
    add(Bits(look.impact));
    addFloats(look.scroll.data(), look.scroll.size());
    add(look.visualFlags);
    for (const std::uint32_t value : look.intel) {
      add(value);
    }
    add(look.ambientSound);
    add(look.rumbleSound);
    add(look.underlay);

    for (const auto value : record.position) {
      add(value);
    }
    add(record.farPosition ? 1u : 0u);
    addFloats(record.farValue.data(), record.farValue.size());
    add(record.yawOnly ? 1u : 0u);
    add(record.orientation);
    add(Bits(record.health));
    add(Bits(record.maxHealth));
    add(Bits(record.fractionComplete));
    add(record.flags);

    const SUnitFields& unit = record.unit;
    add(Bits(unit.fuelRatio));
    add(Bits(unit.shieldRatio));
    add(Bits(unit.workProgress));
    add(unit.unitStates);
    add(unit.scriptBits);
    for (const std::uint16_t value : unit.siloCounts) {
      add(value);
    }
    add(unit.unitFlags);

    add(detail.creator);
    add(static_cast<std::uint32_t>(detail.creationTick));
    add(static_cast<std::uint32_t>(detail.stunTicks));
    add(static_cast<std::uint32_t>(detail.jobType));
    add(static_cast<std::uint32_t>(detail.fireState));
    add(static_cast<std::uint32_t>(detail.siloMaxStorage[0]));
    add(static_cast<std::uint32_t>(detail.siloMaxStorage[1]));
    add(detail.selectionInheritor);
    add(detail.customName);
    add(detail.focusUnit);
    add(detail.guardedUnit);
    add(detail.targetBlip);
    add(detail.didRefresh);
    add(static_cast<std::uint32_t>(detail.reconFlags));
    addFloats(detail.economy.data(), detail.economy.size());
    add(detail.commands.size());
    for (const std::int32_t value : detail.commands) {
      add(static_cast<std::uint32_t>(value));
    }
    add(detail.buildQueue.size());
    for (const std::int32_t value : detail.buildQueue) {
      add(static_cast<std::uint32_t>(value));
    }
    add(detail.weapons.size());
    for (const SUnitWeapon& weapon : detail.weapons) {
      addCategories(weapon.targets);
      addCategories(weapon.secondary);
      add(weapon.layer);
      add(Bits(weapon.minRadius));
      add(Bits(weapon.maxRadius));
      add(Bits(weapon.effectiveRadius));
      add(weapon.minRangeVisual);
      add(weapon.maxRangeVisual);
    }
    const SUnitAttributes& attributes = detail.attributes;
    add(attributes.blueprint);
    add(attributes.reserved04);
    addCategories(attributes.restriction);
    addFloats(attributes.scalars.data(), attributes.scalars.size());
    add(attributes.commandCaps);
    add(attributes.toggleCaps);
    for (const std::uint8_t value : attributes.flags) {
      add(value);
    }
    add(attributes.reserved6C);

    std::uint64_t hash = lanes[0];
    for (int lane = 1; lane < 4; ++lane) {
      hash = std::rotl(hash ^ (lanes[lane] * 0xC2B2AE3D27D4EB4Full), 27) * 0x9E3779B185EBCA87ull;
    }
    hash ^= hash >> 32u;
    return hash != 0u ? hash : 1u;
  }

  std::uint64_t HashRecord(const SEntityRecord& record) noexcept
  {
    // A record that isn't a unit keeps an empty unit block, as `operator==` ignores it.
    static const SUnitDetail kNoDetail{};
    std::uint64_t hash = HashBlipUpdate(record, record.isUnit ? *record.unit.detail : kNoDetail);
    const auto add = [&hash](const std::uint64_t value) {
      hash = std::rotl(hash ^ (value * 0xC2B2AE3D27D4EB4Full), 29) * 0x9E3779B185EBCA87ull;
    };
    add(record.id);
    add(record.tickCreated);
    add(record.blueprint);
    add(record.army);
    add(record.isUnit ? 1u : 0u);
    for (const std::int32_t component : record.velocity) {
      add(static_cast<std::uint32_t>(component));
    }
    add(static_cast<std::uint32_t>(record.verticalAcceleration));
    add(record.anchorBeat);
    add(record.followsGround ? 1u : 0u);
    add(static_cast<std::uint32_t>(record.yawRate));
    add(record.orientationBeat);
    return hash ^ (hash >> 29u);
  }

  std::uint32_t CreationFields(const SEntityRecord& record) noexcept
  {
    return kEntityFields | kFieldKind | (record.isUnit ? kUnitFields : 0u)
         | AppearanceChanges(SAppearance{}, record.appearance);
  }

  std::uint32_t ChangedFields(const SEntityRecord& before, const SEntityRecord& after) noexcept
  {
    std::uint32_t fields = AppearanceChanges(before.appearance, after.appearance);
    if (before.position != after.position || before.velocity != after.velocity
        || before.verticalAcceleration != after.verticalAcceleration || before.anchorBeat != after.anchorBeat
        || before.followsGround != after.followsGround
        || before.farPosition != after.farPosition
        || !SameFloats(before.farValue.data(), after.farValue.data(), before.farValue.size())) {
      fields |= kFieldPosition;
    }
    if (before.orientation != after.orientation || before.yawOnly != after.yawOnly || before.yawRate != after.yawRate
        || before.orientationBeat != after.orientationBeat) {
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
      if (!(b.stats == a.stats)) {
        fields |= kFieldUnitStats;
      }
      if (b.buildStateTag != a.buildStateTag || b.fake != a.fake) {
        fields |= kFieldUnitConstants;
      }
      if (!(b.detail == a.detail)) { // shared: one pointer comparison
        const SUnitDetail& bd = *b.detail;
        const SUnitDetail& ad = *a.detail;
        if (!SameDetailScalars(bd, ad)) {
          fields |= kFieldUnitDetail;
        }
        if (!SameFloats(bd.economy.data(), ad.economy.data(), ad.economy.size())) {
          fields |= kFieldUnitEconomy;
        }
        if (bd.commands != ad.commands || bd.buildQueue != ad.buildQueue) {
          fields |= kFieldUnitQueues;
        }
        if (bd.weapons != ad.weapons) {
          fields |= kFieldUnitWeapons;
        }
        if (!(bd.attributes == ad.attributes)) {
          fields |= kFieldUnitAttributes;
        }
      }
    }
    return fields;
  }

  namespace
  {
    /** `numerator / denominator` rounded half up; the denominator is positive. */
    [[nodiscard]] std::int64_t DivideRounded(const std::int64_t numerator, const std::int64_t denominator) noexcept
    {
      const std::int64_t shifted = 2 * numerator + denominator;
      const std::int64_t twice = 2 * denominator;
      return shifted >= 0 ? shifted / twice : -((-shifted + twice - 1) / twice);
    }

    /** Twice the motion's offset, in sub-steps, `t` beats from its anchor. */
    [[nodiscard]] std::int64_t TwiceOffset(const std::int64_t velocity, const std::int64_t acceleration, const std::int64_t t) noexcept
    {
      return 2 * velocity * t + acceleration * t * t;
    }

    struct SAxisMotion
    {
      std::int64_t velocity = 0;
      std::int64_t acceleration = 0;
    };

    /**
     * The motion of one axis that fits the most history: `past[k]` is the position `k` beats
     * ago (`past[0]` now), in whole steps; the result is in `unit` sub-steps per beat. The
     * longest window, a power of two up to `maxWindow`, whose every position lies within a
     * step of the motion wins; a straight fit before a bent one at the same window.
     */
    [[nodiscard]] SAxisMotion FitAxis(
      const std::int64_t* const past, const std::size_t count, const std::uint32_t maxWindow, const std::int64_t unit,
      const bool bend
    ) noexcept
    {
      const auto fits = [&](const SAxisMotion& motion, const std::uint32_t window) {
        for (std::uint32_t k = 1; k < window; ++k) {
          const std::int64_t twiceError =
            2 * (past[0] - past[k]) * unit - TwiceOffset(motion.velocity, -motion.acceleration, static_cast<std::int64_t>(k));
          if (twiceError > 2 * unit || -twiceError > 2 * unit) {
            return false;
          }
        }
        return true;
      };
      std::uint32_t window = 1;
      while (window * 2u <= maxWindow && window * 2u < count) {
        window *= 2u;
      }
      for (; window >= 1u; window /= 2u) {
        if (count <= window) {
          continue;
        }
        const auto w = static_cast<std::int64_t>(window);
        SAxisMotion straight{DivideRounded((past[0] - past[window]) * unit, w), 0};
        if (fits(straight, window)) {
          return straight;
        }
        if (bend && window >= 2u) {
          // Through now, half the window ago and the window's start: p(-t) = p0 - v t + a t^2 / 2.
          SAxisMotion bent{};
          bent.acceleration = DivideRounded(4 * (past[0] - 2 * past[window / 2u] + past[window]) * unit, w * w);
          bent.velocity = DivideRounded(2 * (past[0] - past[window]) * unit + bent.acceleration * w * w, 2 * w);
          if (fits(bent, window)) {
            return bent;
          }
        }
      }
      return {};
    }
  } // namespace

  namespace
  {
    /** The quantised terrain height under a quantised x and z (`codec.ground` set). */
    [[nodiscard]] std::uint32_t GroundStep(const QuantizedPosition& at, const SFrameCodec& codec) noexcept
    {
      return codec.position.y.Encode(
        codec.ground->HeightAt(codec.position.x.Decode(at[0]), codec.position.z.Decode(at[2]))
      );
    }
  } // namespace

  QuantizedPosition PredictPosition(const SEntityRecord& record, const std::uint32_t beat, const SFrameCodec& codec) noexcept
  {
    const std::int64_t elapsed = static_cast<std::int64_t>(beat) - static_cast<std::int64_t>(record.anchorBeat);
    const std::int64_t unit = std::int64_t{1} << codec.velocityFractionBits;
    const std::uint32_t limits[3] = {
      codec.position.x.MaxQuantized(), codec.position.y.MaxQuantized(), codec.position.z.MaxQuantized()
    };
    QuantizedPosition predicted{};
    for (int axis = 0; axis < 3; ++axis) {
      const std::int64_t acceleration = axis == 1 ? record.verticalAcceleration : 0;
      const std::int64_t value = static_cast<std::int64_t>(record.position[axis])
                               + DivideRounded(TwiceOffset(record.velocity[axis], acceleration, elapsed), 2 * unit);
      predicted[axis] = value < 0 ? 0u : (value > limits[axis] ? limits[axis] : static_cast<std::uint32_t>(value));
    }
    if (record.followsGround && codec.ground != nullptr) {
      predicted[1] = GroundStep(predicted, codec);
    }
    return predicted;
  }

  bool ApplyDeadReckoning(
    SEntityRecord& sent, const std::span<const QuantizedPosition> history, const std::uint32_t beat,
    const SReckoningScheme& scheme, const SFrameCodec& codec
  ) noexcept
  {
    if (history.empty()) {
      return false;
    }
    const QuantizedPosition& actual = history.back();
    const QuantizedPosition predicted = PredictPosition(sent, beat, codec);
    bool within = true;
    for (int axis = 0; axis < 3; ++axis) {
      const std::int64_t error = static_cast<std::int64_t>(actual[axis]) - static_cast<std::int64_t>(predicted[axis]);
      if (error > scheme.tolerance || -error > scheme.tolerance) {
        within = false;
      }
    }
    if (within) {
      return false;
    }
    sent.position = actual;
    const std::size_t count = std::min(history.size(), kReckoningHistory);
    const std::int64_t unit = std::int64_t{1} << codec.velocityFractionBits;
    for (int axis = 0; axis < 3; ++axis) {
      std::int64_t past[kReckoningHistory]{};
      for (std::size_t k = 0; k < count; ++k) {
        past[k] = history[history.size() - 1u - k][axis];
      }
      const SAxisMotion motion = FitAxis(past, count, scheme.window, unit, axis == 1 && scheme.verticalAcceleration);
      sent.velocity[axis] = static_cast<std::int32_t>(motion.velocity);
      if (axis == 1) {
        sent.verticalAcceleration = static_cast<std::int32_t>(motion.acceleration);
      }
    }
    // On the terrain for the last beats (within a step): the height follows it, no vertical motion.
    sent.followsGround = false;
    if (scheme.followGround && codec.groundFollowing && codec.ground != nullptr) {
      bool onGround = true;
      for (std::size_t k = 0; k < std::min<std::size_t>(count, 3u) && onGround; ++k) {
        const QuantizedPosition& at = history[history.size() - 1u - k];
        const std::int64_t gap = static_cast<std::int64_t>(at[1]) - static_cast<std::int64_t>(GroundStep(at, codec));
        onGround = gap <= 1 && gap >= -1;
      }
      if (onGround) {
        sent.followsGround = true;
        sent.velocity[1] = 0;
        sent.verticalAcceleration = 0;
      }
    }
    sent.anchorBeat = beat;
    return true;
  }

  std::uint32_t PredictYaw(const SEntityRecord& record, const std::uint32_t beat, const SFrameCodec& codec) noexcept
  {
    if (!codec.orientationReckoning || !record.yawOnly) {
      return record.orientation;
    }
    const std::int64_t elapsed = static_cast<std::int64_t>(beat) - static_cast<std::int64_t>(record.orientationBeat);
    const std::int64_t unit = std::int64_t{1} << codec.velocityFractionBits;
    const std::int64_t turned = DivideRounded(TwiceOffset(record.yawRate, 0, elapsed), 2 * unit);
    return static_cast<std::uint32_t>(static_cast<std::int64_t>(record.orientation) + turned) & 0xFFFFu;
  }

  bool ApplyOrientationReckoning(
    SEntityRecord& sent, const SEntityRecord& actual, const std::span<const std::uint32_t> yawHistory,
    const std::uint32_t beat, const SReckoningScheme& scheme, const SFrameCodec& codec
  ) noexcept
  {
    // The shortest way round between two yaws, in yaw units.
    const auto yawDifference = [](const std::uint32_t a, const std::uint32_t b) -> std::int64_t {
      return static_cast<std::int16_t>(static_cast<std::uint16_t>((a - b) & 0xFFFFu));
    };
    const auto tolerance = static_cast<std::int64_t>(scheme.orientationTolerance);
    bool within = sent.yawOnly == actual.yawOnly;
    if (within && actual.yawOnly) {
      const std::int64_t error = yawDifference(actual.orientation, PredictYaw(sent, beat, codec));
      within = error <= tolerance && -error <= tolerance;
    } else if (within) {
      // Held: the angle between the two rotations, 2 acos |q1 . q2|, against the tolerance.
      const std::array<float, 4> a = UnpackQuaternion(actual.orientation);
      const std::array<float, 4> b = UnpackQuaternion(sent.orientation);
      const double dot = std::fabs(
        static_cast<double>(a[0]) * b[0] + static_cast<double>(a[1]) * b[1] + static_cast<double>(a[2]) * b[2]
        + static_cast<double>(a[3]) * b[3]
      );
      constexpr double kHalfTurnPerUnit = 3.141592653589793 / 65536.0;
      within = sent.orientation == actual.orientation || dot >= std::cos(kHalfTurnPerUnit * static_cast<double>(tolerance));
    }
    if (within) {
      return false;
    }
    sent.yawOnly = actual.yawOnly;
    sent.orientation = actual.orientation;
    sent.yawRate = 0;
    sent.orientationBeat = 0;
    if (actual.yawOnly) {
      // Unwrapped onto the line through this beat's yaw, `past[k]` k beats ago.
      const std::size_t count = std::min(yawHistory.size(), kReckoningHistory);
      std::int64_t past[kReckoningHistory]{};
      for (std::size_t k = 1; k < count; ++k) {
        const std::uint32_t newer = yawHistory[yawHistory.size() - k];
        const std::uint32_t older = yawHistory[yawHistory.size() - 1u - k];
        past[k] = past[k - 1] - yawDifference(newer, older);
      }
      const std::int64_t unit = std::int64_t{1} << codec.velocityFractionBits;
      sent.yawRate = static_cast<std::int32_t>(FitAxis(past, count, scheme.window, unit, false).velocity);
      sent.orientationBeat = beat;
    }
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

  namespace
  {
    /** The frame's header and its removed, created and changed records. */
    void WriteFrameChanges(
      const std::uint32_t frameId, const std::uint32_t baselineId, const std::uint32_t beat, const std::int32_t simRate,
      const std::uint32_t serverMs, const std::span<const std::uint32_t> removed,
      const std::span<const SEntityRecord* const> created, const std::span<const SFrameChange> changed,
      const SFrameCodec& codec, BitWriter& writer
    )
    {
      writer.WriteBits(kLaneVersions[static_cast<std::size_t>(ELane::Entities)], 16);
      writer.WriteBits(frameId, 32);
      writer.WriteBits(baselineId, 32);
      writer.WriteBits(beat, 32);
      writer.WriteVarUint(ZigZag(simRate));
      writer.WriteBits(serverMs, 32);

      bool first = true;
      std::uint32_t previous = 0;
      writer.WriteVarUint(static_cast<std::uint32_t>(removed.size()));
      for (const std::uint32_t id : removed) {
        WriteGap(writer, first, previous, id);
      }

      first = true;
      writer.WriteVarUint(static_cast<std::uint32_t>(created.size()));
      for (const SEntityRecord* const record : created) {
        WriteGap(writer, first, previous, record->id);
        const std::uint32_t fields = CreationFields(*record);
        writer.WriteVarUint(fields);
        writer.WriteVarUint(record->tickCreated);
        WriteFields(writer, *record, fields, codec, beat, nullptr);
      }

      writer.WriteVarUint(static_cast<std::uint32_t>(changed.size()));
      CChangeHeaders headers;
      for (const SFrameChange& change : changed) {
        headers.Write(writer, change.after->id, change.fields);
        WriteFields(writer, *change.after, change.fields, codec, beat, change.before);
      }
    }
  } // namespace

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

    // ComputeFrameDelta's walk, keeping pointers into the two frames instead of copies of the
    // records (a server encodes every view's frame each beat), and each change's baseline record.
    std::vector<std::uint32_t> removed;
    std::vector<const SEntityRecord*> created;
    std::vector<SFrameChange> changed;
    {
      static const std::vector<SEntityRecord> kEmpty;
      const std::vector<SEntityRecord>& before = baseline != nullptr ? baseline->entities : kEmpty;
      const std::vector<SEntityRecord>& after = frame.entities;
      std::size_t b = 0;
      std::size_t a = 0;
      while (b < before.size() || a < after.size()) {
        if (a == after.size() || (b < before.size() && before[b].id < after[a].id)) {
          removed.push_back(before[b].id);
          ++b;
        } else if (b == before.size() || after[a].id < before[b].id) {
          created.push_back(&after[a]);
          ++a;
        } else {
          if (const std::uint32_t fields = ChangedFields(before[b], after[a]); fields != 0u) {
            changed.push_back({fields, &after[a], &before[b]});
          }
          ++a;
          ++b;
        }
      }
    }
    WriteFrameChanges(
      frame.frameId, baseline != nullptr ? baseline->frameId : kNoBaseline, frame.beat, frame.simRate, frame.serverMs, removed,
      created, changed, codec, writer
    );
    return true;
  }

  bool EncodeFrameChanges(const SFrameChanges& changes, const SFrameCodec& codec, BitWriter& writer)
  {
    if (changes.entityCount > codec.maxEntities) {
      return false;
    }
    for (const SEntityRecord* const record : changes.created) {
      if (!FitsCodec(*record, codec, changes.beat)) {
        return false;
      }
    }
    for (const SFrameChange& change : changes.changed) {
      if (!FitsCodec(*change.after, codec, changes.beat)) {
        return false;
      }
    }
    WriteFrameChanges(
      changes.frameId, changes.baselineId, changes.beat, changes.simRate, changes.serverMs, changes.removed, changes.created,
      changes.changed, codec, writer
    );
    return true;
  }

  int PositionFieldBits(const SEntityRecord& record, const SEntityRecord* const before, const SFrameCodec& codec) noexcept
  {
    if (record.farPosition) {
      return 1 + 96;
    }
    if (!PositionMayStep(record, before)) {
      return 1 + PositionWholeBits(codec);
    }
    return 2 + std::min(PositionStepBits(PositionSteps(record, *before)), PositionWholeBits(codec));
  }

  int OrientationFieldBits(const SEntityRecord& record, const SEntityRecord* const before) noexcept
  {
    if (!record.yawOnly) {
      if (!FullMayStep(record, before)) {
        return 1 + 32;
      }
      std::array<std::uint32_t, 3> steps{};
      return 2 + (FullSteps(record.orientation, before->orientation, steps) ? std::min(FullStepBits(steps), 32) : 32);
    }
    if (!YawMayStep(record, before)) {
      return 1 + kYawBits;
    }
    return 2 + std::min(ExpGolombBits(YawStep(record, *before), kStepOrderYaw), kYawBits);
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
    const std::int32_t simRate = UnZigZag(reader.ReadVarUint());
    const std::uint32_t serverMs = reader.ReadBits(32);
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
        record.tickCreated = reader.ReadVarUint();
        if (!ReadFields(reader, record, fields, codec, beat, false)) {
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
      CChangeHeaders headers;
      std::size_t m = 0;
      std::size_t c = 0;
      for (std::uint32_t i = 0; i < changedCount; ++i) {
        std::uint32_t id = 0;
        std::uint32_t fields = 0;
        if (!headers.Read(reader, id, fields)) {
          return false;
        }
        if (fields == 0u || (fields & ~kAllFields) != 0u) {
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
        if (!ReadFields(reader, merged[m], fields, codec, beat, true)) {
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
    out.simRate = simRate;
    out.serverMs = serverMs;
    out.entities = std::move(merged);
    return true;
  }
} // namespace faf::remote::wire
