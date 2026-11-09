#include "remote/wire/NameTable.h"

// Engine addition, server mode: see NameTable.h.

namespace faf::remote::wire
{
  CNameTableWriter::SInterned CNameTableWriter::Intern(const std::string_view name)
  {
    if (const auto it = mIds.find(name); it != mIds.end()) {
      return {it->second, false};
    }
    const auto id = static_cast<std::uint32_t>(mNames.size());
    mIds.emplace(std::string(name), id);
    mNames.emplace_back(name);
    return {id, true};
  }

  void CNameTableWriter::WriteEntry(const std::uint32_t id, BitWriter& writer) const
  {
    const std::string& name = mNames.at(id);
    writer.WriteVarUint(id);
    writer.WriteVarUint(static_cast<std::uint32_t>(name.size()));
    for (const char c : name) {
      writer.WriteBits(static_cast<unsigned char>(c), 8);
    }
  }

  bool CNameTableReader::ReadEntry(BitReader& reader)
  {
    const std::uint32_t id = reader.ReadVarUint();
    const std::uint32_t size = reader.ReadVarUint();
    if (!reader.Ok() || id != mNames.size() || mNames.size() >= kMaxEntries || size > kMaxNameBytes
        || static_cast<std::uint64_t>(size) * 8u > reader.BitsLeft()) {
      reader.Fail();
      return false;
    }
    std::string name;
    name.reserve(size);
    for (std::uint32_t i = 0; i < size; ++i) {
      name.push_back(static_cast<char>(reader.ReadBits(8)));
    }
    if (!reader.Ok()) {
      return false;
    }
    mNames.push_back(std::move(name));
    return true;
  }

  const std::string* CNameTableReader::Find(const std::uint32_t id) const noexcept
  {
    return id < mNames.size() ? &mNames[id] : nullptr;
  }
} // namespace faf::remote::wire
