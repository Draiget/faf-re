#include "remote/wire/SessionTables.h"

#include <algorithm>

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

  bool CSessionTableWriters::Deposit(const SDeposit& deposit)
  {
    if (mDepositCount >= kMaxDeposits) {
      return false;
    }
    mNewDeposits.push_back(deposit);
    ++mDepositCount;
    return true;
  }

  namespace
  {
    [[nodiscard]] bool CellRectValid(const SCellRect& rect) noexcept
    {
      return rect.x0 <= rect.x1 && rect.z0 <= rect.z1;
    }

    [[nodiscard]] std::uint64_t CellCount(const SCellRect& rect) noexcept
    {
      return CellRectValid(rect) ? (static_cast<std::uint64_t>(static_cast<std::int64_t>(rect.x1) - rect.x0 + 1)
                                    * static_cast<std::uint64_t>(static_cast<std::int64_t>(rect.z1) - rect.z0 + 1))
                                 : 0u;
    }

    [[nodiscard]] std::uint32_t ZigZag(const std::int32_t value) noexcept
    {
      return (static_cast<std::uint32_t>(value) << 1) ^ static_cast<std::uint32_t>(value >> 31);
    }

    [[nodiscard]] std::int32_t UnZigZag(const std::uint32_t value) noexcept
    {
      return static_cast<std::int32_t>(value >> 1) ^ -static_cast<std::int32_t>(value & 1u);
    }
  } // namespace

  bool CSessionTableWriters::TerrainEdit(STerrainEdit edit)
  {
    if (mNewTerrainEdits.size() >= kMaxTerrainEdits || CellCount(edit.cells) > kMaxEditCells
        || edit.heights.size() != CellCount(edit.cells)) {
      return false;
    }
    mNewTerrainEdits.push_back(std::move(edit));
    return true;
  }

  namespace
  {
    void WriteCellRect(const SCellRect& rect, BitWriter& writer)
    {
      writer.WriteVarUint(ZigZag(rect.x0));
      writer.WriteVarUint(ZigZag(rect.z0));
      writer.WriteVarUint(ZigZag(rect.x1));
      writer.WriteVarUint(ZigZag(rect.z1));
    }

    [[nodiscard]] SCellRect ReadCellRect(BitReader& reader)
    {
      SCellRect rect{};
      rect.x0 = UnZigZag(reader.ReadVarUint());
      rect.z0 = UnZigZag(reader.ReadVarUint());
      rect.x1 = UnZigZag(reader.ReadVarUint());
      rect.z1 = UnZigZag(reader.ReadVarUint());
      return rect;
    }
  } // namespace

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
    writer.WriteVarUint(static_cast<std::uint32_t>(mNewDeposits.size()));
    for (const SDeposit& deposit : mNewDeposits) {
      writer.WriteBits(deposit.type, 8);
      writer.WriteVarUint(ZigZag(deposit.x0));
      writer.WriteVarUint(ZigZag(deposit.z0));
      writer.WriteVarUint(ZigZag(deposit.x1));
      writer.WriteVarUint(ZigZag(deposit.z1));
    }
    // Terrain edits: both rectangles, then the heights as the first one and each next one's
    // difference from the one before (flattened ground is one height: a byte a cell).
    writer.WriteVarUint(static_cast<std::uint32_t>(mNewTerrainEdits.size()));
    for (const STerrainEdit& edit : mNewTerrainEdits) {
      WriteCellRect(edit.dirty, writer);
      writer.WriteBool(CellRectValid(edit.cells));
      if (!CellRectValid(edit.cells)) {
        continue;
      }
      WriteCellRect(edit.cells, writer);
      std::uint16_t previous = 0;
      for (const std::uint16_t height : edit.heights) {
        writer.WriteVarUint(ZigZag(static_cast<std::int32_t>(height) - static_cast<std::int32_t>(previous)));
        previous = height;
      }
    }
    mNewSounds.clear();
    mNewNames.clear();
    mNewDeposits.clear();
    mNewTerrainEdits.clear();
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
    const std::uint32_t deposits = reader.ReadVarUint();
    if (!reader.Ok() || deposits > CSessionTableWriters::kMaxDeposits - std::min<std::size_t>(mDeposits.size(), CSessionTableWriters::kMaxDeposits)) {
      return false;
    }
    for (std::uint32_t i = 0; i < deposits; ++i) {
      SDeposit deposit{};
      deposit.type = static_cast<std::uint8_t>(reader.ReadBits(8));
      deposit.x0 = UnZigZag(reader.ReadVarUint());
      deposit.z0 = UnZigZag(reader.ReadVarUint());
      deposit.x1 = UnZigZag(reader.ReadVarUint());
      deposit.z1 = UnZigZag(reader.ReadVarUint());
      if (!reader.Ok()) {
        return false;
      }
      mDeposits.push_back(deposit);
    }
    const std::uint32_t edits = reader.ReadVarUint();
    if (!reader.Ok() || edits > CSessionTableWriters::kMaxTerrainEdits) {
      return false;
    }
    for (std::uint32_t i = 0; i < edits; ++i) {
      STerrainEdit edit{};
      edit.dirty = ReadCellRect(reader);
      if (reader.ReadBool()) {
        edit.cells = ReadCellRect(reader);
        const std::uint64_t cells = CellCount(edit.cells);
        if (!reader.Ok() || cells == 0u || cells > CSessionTableWriters::kMaxEditCells) {
          return false;
        }
        edit.heights.resize(static_cast<std::size_t>(cells));
        std::int32_t previous = 0;
        for (std::uint16_t& height : edit.heights) {
          const std::int32_t value = previous + UnZigZag(reader.ReadVarUint());
          if (!reader.Ok() || value < 0 || value > 0xFFFF) {
            return false;
          }
          height = static_cast<std::uint16_t>(value);
          previous = value;
        }
      } else {
        edit.cells = SCellRect{0, 0, -1, -1};
      }
      if (!reader.Ok()) {
        return false;
      }
      mTerrainEdits.push_back(std::move(edit));
    }
    return reader.Ok();
  }
} // namespace faf::remote::wire
