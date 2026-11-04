#include "remote/wire/ArmyLane.h"

#include <algorithm>

// Engine addition, server mode: see ArmyLane.h.

namespace faf::remote::wire
{
  namespace
  {
    void WriteU64(BitWriter& writer, const std::uint64_t value)
    {
      writer.WriteBits(static_cast<std::uint32_t>(value), 32);
      writer.WriteBits(static_cast<std::uint32_t>(value >> 32u), 32);
    }

    [[nodiscard]] std::uint64_t ReadU64(BitReader& reader) noexcept
    {
      const std::uint64_t low = reader.ReadBits(32);
      const std::uint64_t high = reader.ReadBits(32);
      return low | (high << 32u);
    }

    [[nodiscard]] bool WriteSet(BitWriter& writer, const std::vector<std::uint32_t>& members)
    {
      if (members.size() > SArmyRecord::kMaxSetMembers) {
        return false;
      }
      writer.WriteVarUint(static_cast<std::uint32_t>(members.size()));
      for (const std::uint32_t member : members) {
        writer.WriteVarUint(member);
      }
      return true;
    }

    [[nodiscard]] bool ReadSet(BitReader& reader, std::vector<std::uint32_t>& members)
    {
      const std::uint32_t count = reader.ReadVarUint();
      if (!reader.Ok() || count > SArmyRecord::kMaxSetMembers || count > reader.BitsLeft()) {
        reader.Fail();
        return false;
      }
      members.resize(count);
      for (std::uint32_t& member : members) {
        member = reader.ReadVarUint();
      }
      return reader.Ok();
    }

    [[nodiscard]] bool WriteRecord(BitWriter& writer, const SArmyRecord& record)
    {
      for (const float value : record.economy) {
        writer.WriteFloatExact(value);
      }
      WriteU64(writer, record.maxStorage[0]);
      WriteU64(writer, record.maxStorage[1]);
      writer.WriteBits(record.resourceSharing, 8);
      if (!WriteSet(writer, record.neutrals) || !WriteSet(writer, record.allies) || !WriteSet(writer, record.enemies)
          || !WriteSet(writer, record.validCommandSources)) {
        return false;
      }
      writer.WriteBits(record.isAlly, 8);
      writer.WriteBits(record.playerColor, 32);
      writer.WriteBits(record.armyColor, 32);
      if (record.armyType.size() > SArmyRecord::kMaxTypeLength
          || record.categoryFilter.words.size() > SCategoryBits::kMaxWords) {
        return false;
      }
      writer.WriteVarUint(static_cast<std::uint32_t>(record.armyType.size()));
      for (const char c : record.armyType) {
        writer.WriteBits(static_cast<std::uint8_t>(c), 8);
      }
      writer.WriteBits(static_cast<std::uint32_t>(record.faction), 32);
      writer.WriteBits(record.useWholeMap, 8);
      writer.WriteBits(record.showScore, 8);
      WriteCategoryBits(writer, record.categoryFilter);
      writer.WriteBits(record.isOutOfGame, 8);
      writer.WriteFloatExact(record.armyStart[0]);
      writer.WriteFloatExact(record.armyStart[1]);
      writer.WriteBits(static_cast<std::uint32_t>(record.noRushTimer), 32);
      writer.WriteFloatExact(record.noRushRadius);
      writer.WriteFloatExact(record.noRushOffset[0]);
      writer.WriteFloatExact(record.noRushOffset[1]);
      writer.WriteFloatExact(record.handicapValue);
      writer.WriteFloatExact(record.handicapExtra);
      return true;
    }

    [[nodiscard]] bool ReadRecord(BitReader& reader, SArmyRecord& record)
    {
      for (float& value : record.economy) {
        value = reader.ReadFloatExact();
      }
      record.maxStorage[0] = ReadU64(reader);
      record.maxStorage[1] = ReadU64(reader);
      record.resourceSharing = static_cast<std::uint8_t>(reader.ReadBits(8));
      if (!ReadSet(reader, record.neutrals) || !ReadSet(reader, record.allies) || !ReadSet(reader, record.enemies)
          || !ReadSet(reader, record.validCommandSources)) {
        return false;
      }
      record.isAlly = static_cast<std::uint8_t>(reader.ReadBits(8));
      record.playerColor = reader.ReadBits(32);
      record.armyColor = reader.ReadBits(32);
      const std::uint32_t typeLength = reader.ReadVarUint();
      if (!reader.Ok() || typeLength > SArmyRecord::kMaxTypeLength || typeLength * 8u > reader.BitsLeft()) {
        reader.Fail();
        return false;
      }
      record.armyType.resize(typeLength);
      for (char& c : record.armyType) {
        c = static_cast<char>(reader.ReadBits(8));
      }
      record.faction = static_cast<std::int32_t>(reader.ReadBits(32));
      record.useWholeMap = static_cast<std::uint8_t>(reader.ReadBits(8));
      record.showScore = static_cast<std::uint8_t>(reader.ReadBits(8));
      if (!ReadCategoryBits(reader, record.categoryFilter)) {
        return false;
      }
      record.isOutOfGame = static_cast<std::uint8_t>(reader.ReadBits(8));
      record.armyStart[0] = reader.ReadFloatExact();
      record.armyStart[1] = reader.ReadFloatExact();
      record.noRushTimer = static_cast<std::int32_t>(reader.ReadBits(32));
      record.noRushRadius = reader.ReadFloatExact();
      record.noRushOffset[0] = reader.ReadFloatExact();
      record.noRushOffset[1] = reader.ReadFloatExact();
      record.handicapValue = reader.ReadFloatExact();
      record.handicapExtra = reader.ReadFloatExact();
      return reader.Ok();
    }
  } // namespace

  bool EncodeArmyLane(const std::vector<SArmyRecord>& records, const std::vector<SArmyRecord>* baseline, BitWriter& writer)
  {
    if (records.size() > kMaxArmyRecords) {
      return false;
    }
    writer.WriteVarUint(static_cast<std::uint32_t>(records.size()));
    for (std::size_t index = 0; index < records.size(); ++index) {
      const bool same = baseline != nullptr && index < baseline->size() && (*baseline)[index] == records[index];
      writer.WriteBool(!same);
      if (!same && !WriteRecord(writer, records[index])) {
        return false;
      }
    }
    return true;
  }

  bool DecodeArmyLane(BitReader& reader, const std::vector<SArmyRecord>* baseline, std::vector<SArmyRecord>& out)
  {
    const std::uint32_t count = reader.ReadVarUint();
    if (!reader.Ok() || count > kMaxArmyRecords) {
      reader.Fail();
      return false;
    }
    std::vector<SArmyRecord> records(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      if (reader.ReadBool()) {
        if (!ReadRecord(reader, records[index])) {
          return false;
        }
      } else if (baseline != nullptr && index < baseline->size()) {
        records[index] = (*baseline)[index];
      } else {
        reader.Fail(); // "unchanged" with nothing to be unchanged from
        return false;
      }
    }
    if (!reader.Ok()) {
      return false;
    }
    out = std::move(records);
    return true;
  }

  bool EncodeGridLane(const std::vector<SGridSlot>& grids, const std::vector<SGridSlot>& held, BitWriter& writer)
  {
    if (grids.size() > kMaxGridSlots) {
      return false;
    }
    writer.WriteVarUint(static_cast<std::uint32_t>(grids.size()));
    for (const SGridSlot& slot : grids) {
      const auto found = std::find_if(held.begin(), held.end(), [&slot](const SGridSlot& other) {
        return other.army == slot.army && other.kind == slot.kind;
      });
      if (!EncodeGridSlot(slot, found != held.end() ? &found->bits : nullptr, writer)) {
        return false;
      }
    }
    return true;
  }

  void WriteGridSlotHeader(const SGridSlot& slot, BitWriter& writer)
  {
    writer.WriteBits(slot.army, 8);
    writer.WriteBits(slot.kind, 1);
    writer.WriteVarUint(slot.gridSize);
  }

  bool EncodeGridSlot(const SGridSlot& slot, const SGridBits* const baseline, BitWriter& writer)
  {
    WriteGridSlotHeader(slot, writer);
    return EncodeGridDelta(slot.bits, baseline, writer);
  }

  bool DecodeGridLane(BitReader& reader, std::vector<SGridSlot>& held)
  {
    const std::uint32_t count = reader.ReadVarUint();
    if (!reader.Ok() || count > kMaxGridSlots) {
      reader.Fail();
      return false;
    }
    std::vector<SGridSlot> grids(count);
    for (SGridSlot& slot : grids) {
      slot.army = static_cast<std::uint8_t>(reader.ReadBits(8));
      slot.kind = static_cast<std::uint8_t>(reader.ReadBits(1));
      slot.gridSize = reader.ReadVarUint();
      const auto found = std::find_if(held.begin(), held.end(), [&slot](const SGridSlot& other) {
        return other.army == slot.army && other.kind == slot.kind;
      });
      if (!reader.Ok() || !DecodeGridDelta(reader, found != held.end() ? &found->bits : nullptr, kMaxGridCells, slot.bits)) {
        return false;
      }
    }
    held = std::move(grids);
    return true;
  }
} // namespace faf::remote::wire
