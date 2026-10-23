#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/render/IDecalGroup.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace moho
{
  class CDecalGroup final : public IDecalGroup
  {
  public:
    /**
     * Address: 0x00877280 (FUN_00877280, ??0CDecalGroup@Moho@@QAE@@Z)
     * Mangled: ??0CDecalGroup@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one decal-group object with the provided group index, empty
     * display name string, and empty decal-index vector lanes.
     */
    explicit CDecalGroup(std::int32_t index);

    /**
     * Address: 0x008772D0 (FUN_008772D0, ??1CDecalGroup@Moho@@QAE@@Z)
     * Deleting thunk: 0x00877670 (FUN_00877670, Moho::CDecalGroup::dtr)
     *
     * What it does:
     * Releases owned decal-index storage and heap-backed name storage, then
     * resets the object into base `IDecalGroup` empty state lanes.
     */
    ~CDecalGroup() override;

    /**
     * Address: 0x00877320 (FUN_00877320, Moho::CDecalGroup::GetIndex)
     *
     * What it does:
     * Returns the address of the stored group index lane.
     */
    [[nodiscard]] std::int32_t* GetIndex() override;

    /**
     * Address: 0x00877330 (FUN_00877330, Moho::CDecalGroup::GetName2)
     *
     * What it does:
     * Returns mutable access to the group display-name string lane.
     */
    [[nodiscard]] msvc8::string* GetName() override;

    /**
     * Address: 0x00877340 (FUN_00877340, Moho::CDecalGroup::GetName1)
     *
     * What it does:
     * Duplicate vtable lane for mutable group display-name string access.
     */
    [[nodiscard]] msvc8::string* GetNameAlias() override;

    /**
     * Address: 0x00877350 (FUN_00877350, Moho::CDecalGroup::GetDecals2)
     *
     * What it does:
     * Returns mutable access to the tracked decal-index vector lane.
     */
    [[nodiscard]] msvc8::vector<std::int32_t>* GetDecals() override;

    /**
     * Address: 0x00877360 (FUN_00877360, Moho::CDecalGroup::GetDecals1)
     *
     * What it does:
     * Duplicate vtable lane for mutable tracked decal-index vector access.
     */
    [[nodiscard]] msvc8::vector<std::int32_t>* GetDecalsAlias() override;

    /**
     * Address: 0x008773A0 (FUN_008773A0, Moho::CDecalGroup::Func4)
     * Slot: 6
     *
     * What it does:
     * Reads `decal->mIndex` and tail-calls the index-taking overload through
     * this same vtable (`jmp [vtbl+0x1C]`). No null check on `decal`.
     */
    [[nodiscard]] bool Contains(CWldTerrainDecal* decal) override;

    /**
     * Address: 0x00877370 (FUN_00877370, Moho::CDecalGroup::HasDecal)
     * Slot: 7
     *
     * What it does:
     * Linear scan of `mDecals` for `decalIndex`, returning whether the scan
     * stopped before the end.
     */
    [[nodiscard]] bool Contains(std::int32_t decalIndex) override;

    /**
     * Address: 0x008773F0 (FUN_008773F0, Moho::CDecalGroup::Func6)
     * Slot: 8
     *
     * What it does:
     * Reads `decal->mIndex` and tail-calls the index-taking overload through
     * this same vtable (`jmp [vtbl+0x24]`). No null check on `decal`.
     */
    void Add(CWldTerrainDecal* decal) override;

    /**
     * Address: 0x008773C0 (FUN_008773C0, Moho::CDecalGroup::AddToGroup)
     * Slot: 9
     *
     * What it does:
     * Appends `decalIndex` to `mDecals` unless the group already tracks it.
     * The membership test is a virtual call to slot 7, not an inlined scan.
     */
    void Add(std::int32_t decalIndex) override;

    /**
     * Address: 0x00877460 (FUN_00877460, Moho::CDecalGroup::Func8)
     * Slot: 10
     *
     * What it does:
     * Reads `decal->mIndex` and tail-calls the index-taking overload through
     * this same vtable (`jmp [vtbl+0x2C]`). No null check on `decal`.
     */
    void RemoveFromGroup(CWldTerrainDecal* decal) override;

    /**
     * Address: 0x00877410 (FUN_00877410, Moho::CDecalGroup::RemoveFromGroup)
     * Slot: 11
     *
     * What it does:
     * Removes one matching decal-index lane from `mDecals` and compacts the
     * trailing entries.
     */
    void RemoveFromGroup(std::int32_t decalIndex) override;

    /**
     * Address: 0x008775C0 (FUN_008775C0, Moho::CDecalGroup::WriteToStream)
     *
     * What it does:
     * Writes group index/name plus every tracked decal index to the binary
     * writer in save-stream order.
     */
    void WriteToStream(gpg::BinaryWriter& writer) override;

    /**
     * Address: 0x00877480 (FUN_00877480, Moho::CDecalGroup::ReadFromStream)
     *
     * IDA signature:
     * gpg::BinaryReader *__thiscall sub_877480(CDecalGroup *this, gpg::BinaryReader *a2, int a3);
     *
     * What it does:
     * Inverse of `WriteToStream`: clears the decal-index lane, then reads the
     * group index, name, decal count, and that many decal indices from the
     * binary reader in the same field order the save stream wrote. The trailing
     * `version` argument is passed through by the load stream but unused here.
     */
    void ReadFromStream(gpg::BinaryReader& reader, int version) override;

  public:
    std::int32_t mIndex = 0;                // +0x04
    msvc8::string mName{};                  // +0x08
    msvc8::vector<std::int32_t> mDecals{};  // +0x24
  };

  static_assert(offsetof(CDecalGroup, mIndex) == 0x04, "CDecalGroup::mIndex offset must be 0x04");
  static_assert(offsetof(CDecalGroup, mName) == 0x08, "CDecalGroup::mName offset must be 0x08");
  static_assert(offsetof(CDecalGroup, mDecals) == 0x24, "CDecalGroup::mDecals offset must be 0x24");
  static_assert(sizeof(CDecalGroup) == 0x34, "CDecalGroup size must be 0x34");
} // namespace moho
