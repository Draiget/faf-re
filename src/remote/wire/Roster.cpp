#include "remote/wire/Roster.h"

#include <bit>

// Engine addition, server mode: see Roster.h.

namespace faf::remote::wire
{
  namespace
  {
    [[nodiscard]] std::uint32_t ZigZag(const std::int32_t value) noexcept
    {
      return (static_cast<std::uint32_t>(value) << 1) ^ static_cast<std::uint32_t>(value >> 31);
    }

    [[nodiscard]] std::int32_t UnZigZag(const std::uint32_t value) noexcept
    {
      return static_cast<std::int32_t>(value >> 1) ^ -static_cast<std::int32_t>(value & 1u);
    }

    void WriteSmallList(BitWriter& writer, const std::vector<std::uint8_t>& values)
    {
      writer.WriteVarUint(static_cast<std::uint32_t>(values.size()));
      for (const std::uint8_t value : values) {
        writer.WriteBits(value, 8);
      }
    }

    [[nodiscard]] bool ReadSmallList(BitReader& reader, std::vector<std::uint8_t>& values, const std::size_t limit)
    {
      const std::uint32_t count = reader.ReadVarUint();
      if (!reader.Ok() || count > limit || static_cast<std::uint64_t>(count) * 8u > reader.BitsLeft()) {
        reader.Fail();
        return false;
      }
      values.resize(count);
      for (std::uint8_t& value : values) {
        value = static_cast<std::uint8_t>(reader.ReadBits(8));
      }
      return reader.Ok();
    }
  } // namespace

  bool SRosterEntry::operator==(const SRosterEntry& other) const noexcept
  {
    return index == other.index && name == other.name && ownerId == other.ownerId && sources == other.sources
        && simRate == other.simRate && std::bit_cast<std::uint32_t>(ping) == std::bit_cast<std::uint32_t>(other.ping)
        && std::bit_cast<std::uint32_t>(quiet) == std::bit_cast<std::uint32_t>(other.quiet)
        && connected == other.connected && ejectedBy == other.ejectedBy;
  }

  bool SRoster::operator==(const SRoster& other) const noexcept
  {
    return localIndex == other.localIndex && entries == other.entries;
  }

  void SRoster::Encode(BitWriter& writer) const
  {
    writer.WriteVarUint(ZigZag(localIndex));
    writer.WriteVarUint(static_cast<std::uint32_t>(entries.size()));
    for (const SRosterEntry& entry : entries) {
      writer.WriteBits(entry.index, 8);
      writer.WriteVarUint(static_cast<std::uint32_t>(entry.name.size()));
      for (const char c : entry.name) {
        writer.WriteBits(static_cast<unsigned char>(c), 8);
      }
      writer.WriteVarUint(ZigZag(entry.ownerId));
      WriteSmallList(writer, entry.sources);
      writer.WriteVarUint(ZigZag(entry.simRate));
      writer.WriteFloatExact(entry.ping);
      writer.WriteFloatExact(entry.quiet);
      writer.WriteBool(entry.connected);
      WriteSmallList(writer, entry.ejectedBy);
    }
  }

  std::optional<SRoster> SRoster::Decode(BitReader& reader)
  {
    SRoster roster{};
    roster.localIndex = UnZigZag(reader.ReadVarUint());
    const std::uint32_t count = reader.ReadVarUint();
    if (!reader.Ok() || count > kMaxEntries) {
      return std::nullopt;
    }
    roster.entries.resize(count);
    for (SRosterEntry& entry : roster.entries) {
      entry.index = static_cast<std::uint8_t>(reader.ReadBits(8));
      const std::uint32_t size = reader.ReadVarUint();
      if (!reader.Ok() || size > SRosterEntry::kMaxNameBytes || static_cast<std::uint64_t>(size) * 8u > reader.BitsLeft()) {
        return std::nullopt;
      }
      entry.name.reserve(size);
      for (std::uint32_t i = 0; i < size; ++i) {
        entry.name.push_back(static_cast<char>(reader.ReadBits(8)));
      }
      entry.ownerId = UnZigZag(reader.ReadVarUint());
      if (!ReadSmallList(reader, entry.sources, SRosterEntry::kMaxSources)) {
        return std::nullopt;
      }
      entry.simRate = UnZigZag(reader.ReadVarUint());
      entry.ping = reader.ReadFloatExact();
      entry.quiet = reader.ReadFloatExact();
      entry.connected = reader.ReadBool();
      if (!ReadSmallList(reader, entry.ejectedBy, kMaxEntries)) {
        return std::nullopt;
      }
    }
    if (!reader.Ok()) {
      return std::nullopt;
    }
    return roster;
  }
} // namespace faf::remote::wire
