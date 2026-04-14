#include "moho/render/CDecalGroup.h"

#include <cstring>

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

    auto& decalView = msvc8::AsVectorRuntimeView(mDecals);
    decalView.begin = nullptr;
    decalView.end = nullptr;
    decalView.capacityEnd = nullptr;
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
    auto& decalView = msvc8::AsVectorRuntimeView(mDecals);
    if (decalView.begin != nullptr) {
      ::operator delete(decalView.begin);
    }
    decalView.begin = nullptr;
    decalView.end = nullptr;
    decalView.capacityEnd = nullptr;

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
    auto& decalView = msvc8::AsVectorRuntimeView(mDecals);

    std::int32_t* found = decalView.begin;
    while (found != decalView.end) {
      if (*found == decalIndex) {
        break;
      }
      ++found;
    }

    if (found == decalView.end) {
      return;
    }

    const std::ptrdiff_t trailingCount = decalView.end - (found + 1);
    if (trailingCount > 0) {
      const std::size_t bytesToMove = static_cast<std::size_t>(trailingCount) * sizeof(std::int32_t);
      (void)::memmove_s(found, bytesToMove, found + 1, bytesToMove);
    }

    --decalView.end;
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

    const auto& decalView = msvc8::AsVectorRuntimeView(mDecals);
    const std::uint32_t decalCount =
      decalView.begin != nullptr ? static_cast<std::uint32_t>(decalView.end - decalView.begin) : 0u;
    writer.Write(decalCount);

    for (std::int32_t* decalIt = decalView.begin; decalIt != decalView.end; ++decalIt) {
      writer.Write(*decalIt);
    }
  }
} // namespace moho
