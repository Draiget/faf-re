#include "remote/wire/LuaSyncLane.h"

// Engine addition, server mode: see LuaSyncLane.h.

namespace faf::remote::wire
{
  bool EncodeLuaSyncLane(const std::span<const std::uint8_t> table, const std::vector<std::string>& prints, BitWriter& writer)
  {
    if (table.size() > kMaxLuaSyncBytes || prints.size() > kMaxLuaSyncLines) {
      return false;
    }
    writer.WriteVarUint(static_cast<std::uint32_t>(table.size()));
    writer.WriteBytes(table);
    writer.WriteVarUint(static_cast<std::uint32_t>(prints.size()));
    for (const std::string& line : prints) {
      if (line.size() > kMaxLuaSyncLineBytes) {
        return false;
      }
      writer.WriteVarUint(static_cast<std::uint32_t>(line.size()));
      writer.WriteBytes({reinterpret_cast<const std::uint8_t*>(line.data()), line.size()});
    }
    return true;
  }

  bool DecodeLuaSyncLane(BitReader& reader, std::vector<std::uint8_t>& table, std::vector<std::string>& prints)
  {
    const std::uint32_t tableSize = reader.ReadVarUint();
    if (!reader.Ok() || tableSize > kMaxLuaSyncBytes || tableSize > reader.BitsLeft() / 8u) {
      reader.Fail();
      return false;
    }
    table.resize(tableSize);
    for (std::uint8_t& byte : table) {
      byte = static_cast<std::uint8_t>(reader.ReadBits(8));
    }
    const std::uint32_t lines = reader.ReadVarUint();
    if (!reader.Ok() || lines > kMaxLuaSyncLines) {
      reader.Fail();
      return false;
    }
    prints.clear();
    for (std::uint32_t index = 0; index < lines; ++index) {
      const std::uint32_t length = reader.ReadVarUint();
      if (!reader.Ok() || length > kMaxLuaSyncLineBytes || length > reader.BitsLeft() / 8u) {
        reader.Fail();
        return false;
      }
      std::string& line = prints.emplace_back(length, '\0');
      for (char& character : line) {
        character = static_cast<char>(reader.ReadBits(8));
      }
    }
    return reader.Ok();
  }
} // namespace faf::remote::wire
