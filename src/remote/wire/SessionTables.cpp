#include "remote/wire/SessionTables.h"

// Engine addition, server mode: see SessionTables.h.

namespace faf::remote::wire
{
  std::uint32_t CSessionTableWriters::Sound(const SSoundEntry& entry)
  {
    const CSoundTableWriter::SInterned interned = mSounds.Intern(entry);
    if (interned.isNew) {
      mNewSounds.push_back(interned.id);
    }
    return interned.id;
  }

  std::uint32_t CSessionTableWriters::Name(const std::string_view name)
  {
    const CNameTableWriter::SInterned interned = mNames.Intern(name);
    if (interned.isNew) {
      mNewNames.push_back(interned.id);
    }
    return interned.id;
  }

  void CSessionTableWriters::WritePending(BitWriter& writer)
  {
    writer.WriteVarUint(static_cast<std::uint32_t>(mNewSounds.size()));
    for (const std::uint32_t id : mNewSounds) {
      mSounds.WriteEntry(id, writer);
    }
    writer.WriteVarUint(static_cast<std::uint32_t>(mNewNames.size()));
    for (const std::uint32_t id : mNewNames) {
      mNames.WriteEntry(id, writer);
    }
    mNewSounds.clear();
    mNewNames.clear();
  }

  bool CSessionTableReaders::Read(BitReader& reader)
  {
    const std::uint32_t sounds = reader.ReadVarUint();
    if (!reader.Ok() || sounds > CSoundTableReader::kMaxEntries) {
      return false;
    }
    for (std::uint32_t i = 0; i < sounds; ++i) {
      if (!mSounds.ReadEntry(reader)) {
        return false;
      }
    }
    const std::uint32_t names = reader.ReadVarUint();
    if (!reader.Ok() || names > CNameTableReader::kMaxEntries) {
      return false;
    }
    for (std::uint32_t i = 0; i < names; ++i) {
      if (!mNames.ReadEntry(reader)) {
        return false;
      }
    }
    return reader.Ok();
  }
} // namespace faf::remote::wire
