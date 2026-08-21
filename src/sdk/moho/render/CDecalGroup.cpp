#include "moho/render/CDecalGroup.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"

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
