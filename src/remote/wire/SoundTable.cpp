#include "remote/wire/SoundTable.h"

// Engine addition, server mode: see SoundTable.h.
//
// Entry record: varuint id, then four strings (bank, cue, LOD cutoff, RPC loop variable), each
// a varuint byte length and the bytes.

namespace faf::remote::wire
{
  namespace
  {
    void WriteString(BitWriter& writer, const std::string& text)
    {
      writer.WriteVarUint(static_cast<std::uint32_t>(text.size()));
      for (const char c : text) {
        writer.WriteBits(static_cast<unsigned char>(c), 8);
      }
    }

    [[nodiscard]] bool ReadString(BitReader& reader, std::string& text)
    {
      const std::uint32_t size = reader.ReadVarUint();
      if (!reader.Ok() || size > CSoundTableReader::kMaxNameBytes || size * 8u > reader.BitsLeft()) {
        reader.Fail();
        return false;
      }
      text.clear();
      text.reserve(size);
      for (std::uint32_t i = 0; i < size; ++i) {
        text.push_back(static_cast<char>(reader.ReadBits(8)));
      }
      return reader.Ok();
    }
  } // namespace

  CSoundTableWriter::SInterned CSoundTableWriter::Intern(const SSoundEntry& entry)
  {
    const auto key = std::make_tuple(entry.bank, entry.cue, entry.lodCutoff, entry.rpcLoop);
    if (const auto it = mIds.find(key); it != mIds.end()) {
      return {it->second, false};
    }
    const auto id = static_cast<std::uint32_t>(mEntries.size());
    mIds.emplace(key, id);
    mEntries.push_back(entry);
    return {id, true};
  }

  void CSoundTableWriter::WriteEntry(const std::uint32_t id, BitWriter& writer) const
  {
    const SSoundEntry& entry = mEntries.at(id);
    writer.WriteVarUint(id);
    WriteString(writer, entry.bank);
    WriteString(writer, entry.cue);
    WriteString(writer, entry.lodCutoff);
    WriteString(writer, entry.rpcLoop);
  }

  bool CSoundTableReader::ReadEntry(BitReader& reader)
  {
    const std::uint32_t id = reader.ReadVarUint();
    if (!reader.Ok() || id != mEntries.size() || mEntries.size() >= kMaxEntries) {
      reader.Fail();
      return false;
    }
    SSoundEntry entry;
    if (!ReadString(reader, entry.bank) || !ReadString(reader, entry.cue) || !ReadString(reader, entry.lodCutoff)
        || !ReadString(reader, entry.rpcLoop)) {
      return false;
    }
    mEntries.push_back(std::move(entry));
    return true;
  }

  const SSoundEntry* CSoundTableReader::Find(const std::uint32_t id) const noexcept
  {
    return id < mEntries.size() ? &mEntries[id] : nullptr;
  }
} // namespace faf::remote::wire
