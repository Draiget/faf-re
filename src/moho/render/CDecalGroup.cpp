#include "moho/render/CDecalGroup.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "moho/render/CWldTerrainDecal.h"

namespace moho
{
  /**
   * Address: 0x00877280 (FUN_00877280, ??0CDecalGroup@Moho@@QAE@@Z)
   * Mangled: ??0CDecalGroup@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one decal-group object with the provided group index, empty
   * display name string, and empty decal-index vector lanes.
   */
  CDecalGroup::CDecalGroup(const std::int32_t index)
    : IDecalGroup()
    , mIndex(index)
    , mName()
    , mDecals()
  {
    mName.mySize = 0u;
    mName.myRes = 15u;
    mName.bx.buf[0] = '\0';

    // msvc8::vector's default constructor already null-initialises all three
    // lanes; the binary's explicit zeroing here IS that constructor inlined.
  }

  /**
   * Address: 0x008772D0 (FUN_008772D0, ??1CDecalGroup@Moho@@QAE@@Z)
   * Deleting thunk: 0x00877670 (FUN_00877670, Moho::CDecalGroup::dtr)
   *
   * What it does:
   * Releases owned decal-index storage and heap-backed name storage, then
   * resets the object into base `IDecalGroup` empty state lanes.
   */
  CDecalGroup::~CDecalGroup()
  {
    // Free the block and null all three lanes: VC8 _Tidy().
    mDecals = msvc8::vector<std::int32_t>{};

    if (mName.myRes >= 0x10u) {
      ::operator delete(mName.bx.ptr);
    }
    mName.mySize = 0u;
    mName.myRes = 15u;
    mName.bx.buf[0] = '\0';
  }

  /**
   * Address: 0x00877320 (FUN_00877320, Moho::CDecalGroup::GetIndex)
   *
   * What it does:
   * Returns the address of the stored group index lane.
   */
  std::int32_t* CDecalGroup::GetIndex()
  {
    return &mIndex;
  }

  /**
   * Address: 0x00877330 (FUN_00877330, Moho::CDecalGroup::GetName2)
   *
   * What it does:
   * Returns mutable access to the group display-name string lane.
   */
  msvc8::string* CDecalGroup::GetName()
  {
    return &mName;
  }

  /**
   * Address: 0x00877340 (FUN_00877340, Moho::CDecalGroup::GetName1)
   *
   * What it does:
   * Duplicate vtable lane for mutable group display-name string access.
   */
  msvc8::string* CDecalGroup::GetNameAlias()
  {
    return &mName;
  }

  /**
   * Address: 0x00877350 (FUN_00877350, Moho::CDecalGroup::GetDecals2)
   *
   * What it does:
   * Returns mutable access to the tracked decal-index vector lane.
   */
  msvc8::vector<std::int32_t>* CDecalGroup::GetDecals()
  {
    return &mDecals;
  }

  /**
   * Address: 0x00877360 (FUN_00877360, Moho::CDecalGroup::GetDecals1)
   *
   * What it does:
   * Duplicate vtable lane for mutable tracked decal-index vector access.
   */
  msvc8::vector<std::int32_t>* CDecalGroup::GetDecalsAlias()
  {
    return &mDecals;
  }

  /**
   * Address: 0x00877410 (FUN_00877410, Moho::CDecalGroup::RemoveFromGroup)
   *
   * What it does:
   * Removes one matching decal-index lane from `mDecals` and compacts the
   * trailing entries.
   */
  void CDecalGroup::RemoveFromGroup(const std::int32_t decalIndex)
  {
    auto* const found = std::find(mDecals.begin(), mDecals.end(), decalIndex);
    if (found == mDecals.end()) {
      return;
    }

    // Shift the tail down over `found` and drop mLast -- erase(pos).
    (void)mDecals.erase(found);
  }

  /**
   * Address: 0x008775C0 (FUN_008775C0, Moho::CDecalGroup::WriteToStream)
   *
   * What it does:
   * Writes group index/name plus every tracked decal index to the binary
   * writer in save-stream order.
   */
  void CDecalGroup::WriteToStream(gpg::BinaryWriter& writer)
  {
    writer.Write(mIndex);
    writer.WriteString(mName);

    writer.Write(static_cast<std::uint32_t>(mDecals.size()));

    for (const std::int32_t decal : mDecals) {
      writer.Write(decal);
    }
  }

  /**
   * Address: 0x008773A0 (FUN_008773A0, Moho::CDecalGroup::Func4)
   * Slot: 6
   *
   * What it does:
   * Reads `decal->mIndex` (`mov edx, [edx+18h]`), overwrites the incoming
   * argument slot with it, and tail-jumps to slot 7 (`jmp [vtbl+0x1C]`).
   * `decal` is dereferenced unconditionally.
   */
  bool CDecalGroup::Contains(CWldTerrainDecal* const decal)
  {
    return Contains(decal->mIndex);
  }

  /**
   * Address: 0x00877370 (FUN_00877370, Moho::CDecalGroup::HasDecal)
   * Slot: 7
   *
   * What it does:
   * Walks `mDecals` from begin (`[this+0x28]`) to end (`[this+0x2C]`) looking
   * for `decalIndex`, then returns `end != cursor` -- true when the walk broke
   * early on a match, false when it ran to the end or the vector was empty.
   */
  bool CDecalGroup::Contains(const std::int32_t decalIndex)
  {
    return std::find(mDecals.begin(), mDecals.end(), decalIndex) != mDecals.end();
  }

  /**
   * Address: 0x008773F0 (FUN_008773F0, Moho::CDecalGroup::Func6)
   * Slot: 8
   *
   * What it does:
   * Reads `decal->mIndex` and tail-jumps to slot 9 (`jmp [vtbl+0x24]`).
   * `decal` is dereferenced unconditionally.
   */
  void CDecalGroup::Add(CWldTerrainDecal* const decal)
  {
    Add(decal->mIndex);
  }

  /**
   * Address: 0x008773C0 (FUN_008773C0, Moho::CDecalGroup::AddToGroup)
   * Slot: 9
   *
   * What it does:
   * Dispatches slot 7 (`call [vtbl+0x1C]`) to test membership and returns when
   * it reports the index is already tracked; otherwise appends it to `mDecals`
   * (`sub_686E80`, the `msvc8::vector<std::int32_t>` push_back emission).
   */
  void CDecalGroup::Add(const std::int32_t decalIndex)
  {
    if (!Contains(decalIndex)) {
      mDecals.push_back(decalIndex);
    }
  }

  /**
   * Address: 0x00877460 (FUN_00877460, Moho::CDecalGroup::Func8)
   * Slot: 10
   *
   * What it does:
   * Reads `decal->mIndex` and tail-jumps to slot 11 (`jmp [vtbl+0x2C]`).
   * `decal` is dereferenced unconditionally.
   */
  void CDecalGroup::RemoveFromGroup(CWldTerrainDecal* const decal)
  {
    RemoveFromGroup(decal->mIndex);
  }

  /**
   * Address: 0x00877480 (FUN_00877480, Moho::CDecalGroup::ReadFromStream)
   *
   * What it does:
   * Inverse of `WriteToStream`: empties the decal-index lane in place, then
   * reads the group index, name, decal count, and that many decal indices from
   * the binary reader in the same field order the save stream wrote.
   */
  void CDecalGroup::ReadFromStream(gpg::BinaryReader& reader, const int version)
  {
    (void)version;

    mDecals.clear();

    reader.Read(reinterpret_cast<char*>(&mIndex), sizeof(mIndex));

    msvc8::string name;
    reader.ReadString(&name);
    mName = name;

    std::int32_t decalCount = 0;
    reader.Read(reinterpret_cast<char*>(&decalCount), sizeof(decalCount));

    for (std::int32_t i = 0; i < decalCount; ++i) {
      std::int32_t decalIndex = 0;
      reader.Read(reinterpret_cast<char*>(&decalIndex), sizeof(decalIndex));
      mDecals.push_back(decalIndex);
    }
  }
} // namespace moho
