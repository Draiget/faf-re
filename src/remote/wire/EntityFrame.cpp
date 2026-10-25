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

    /** `beat` is the frame's: a dead-reckoned anchor cannot lie in its future. */
    [[nodiscard]] bool FitsCodec(const SEntityRecord& record, const SFrameCodec& codec, const std::uint32_t beat) noexcept
    {
      const bool turnFits = codec.orientationReckoning && record.yawOnly
                              ? record.orientationBeat <= beat
                              : (record.orientationBeat == 0u && record.yawRate == 0);
      if (!turnFits || (codec.orientationReckoning && !codec.deadReckoning)) {
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

    void WriteCategories(BitWriter& writer, const SCategoryBits& bits)
    {
      writer.WriteVarUint(bits.firstWord);
      writer.WriteVarUint(static_cast<std::uint32_t>(bits.words.size()));
      for (const std::uint32_t word : bits.words) {
        writer.WriteBits(word, 32);
      }
    }

    [[nodiscard]] bool ReadCategories(BitReader& reader, SCategoryBits& bits)
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
        writer.WriteBits(record.position[0], codec.position.x.bits);
        writer.WriteBits(record.position[1], codec.position.y.bits);
        writer.WriteBits(record.position[2], codec.position.z.bits);
        if (codec.deadReckoning) {
          writer.WriteVarUint(beat - record.anchorBeat);
          for (const std::int32_t component : record.velocity) {
            writer.WriteVarUint(ZigZag(component));
          }
          writer.WriteVarUint(ZigZag(record.verticalAcceleration));
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        writer.WriteBool(record.yawOnly);
        writer.WriteBits(record.orientation, record.yawOnly ? kYawBits : 32);
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
          WriteCategories(writer, weapon.targets);
          WriteCategories(writer, weapon.secondary);
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
        WriteCategories(writer, attributes.restriction);
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
        record.verticalAcceleration = 0;
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
          record.verticalAcceleration = UnZigZag(reader.ReadVarUint());
        }
      }
      if ((fields & kFieldOrientation) != 0u) {
        record.yawOnly = reader.ReadBool();
        record.orientation = reader.ReadBits(record.yawOnly ? kYawBits : 32);
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
            if (!ReadCategories(reader, weapon.targets) || !ReadCategories(reader, weapon.secondary)) {
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
          if (!ReadCategories(reader, attributes.restriction)) {
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
        && anchorBeat == other.anchorBeat
        && orientation == other.orientation && yawOnly == other.yawOnly && yawRate == other.yawRate
        && orientationBeat == other.orientationBeat && Bits(health) == Bits(other.health)
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
    if (before.position != after.position || before.velocity != after.velocity
        || before.verticalAcceleration != after.verticalAcceleration || before.anchorBeat != after.anchorBeat
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
      writer.WriteVarUint(record.tickCreated);
      WriteFields(writer, record, fields, codec, frame.beat, nullptr);
    }

    first = true;
    writer.WriteVarUint(static_cast<std::uint32_t>(delta.changed.size()));
    for (const SFrameDelta::SChange& change : delta.changed) {
      WriteGap(writer, first, previous, change.record.id);
      writer.WriteVarUint(change.fields);
      // A change's id is in the baseline (ComputeFrameDelta); both lists are in id order.
      const auto before = std::lower_bound(
        baseline->entities.begin(), baseline->entities.end(), change.record.id,
        [](const SEntityRecord& record, const std::uint32_t id) { return record.id < id; }
      );
      WriteFields(writer, change.record, change.fields, codec, frame.beat, &*before);
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
        record.tickCreated = reader.ReadVarUint();
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
