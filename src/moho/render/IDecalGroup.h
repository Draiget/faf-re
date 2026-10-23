#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace moho
{
  class CWldTerrainDecal;

  /**
   * Base interface lane for decal grouping owners.
   *
   * Binary evidence:
   * - constructor lane at 0x00877240
   * - base-vtable reset lane at 0x00877230
   *
   * Its vftable (0x00E49738) has **14 slots, every one `_purecall`**;
   * `CDecalGroup` (vftable 0x00E497F0, `: public IDecalGroup`) supplies all 14.
   *
   * The full slot map, read from the dump and the bodies:
   *
   *   0  0x00877670  scalar deleting destructor (calls ~CDecalGroup)
   *   1  0x00877320  GetIndex        -> `&mIndex`  (+0x04)
   *   2  0x00877340  GetNameAlias    -> `&mName`   (+0x08)
   *   3  0x00877330  GetName         -> `&mName`   (+0x08)
   *   4  0x00877360  GetDecalsAlias  -> `&mDecals` (+0x24)
   *   5  0x00877350  GetDecals       -> `&mDecals` (+0x24)
   *   6  0x008773A0  Contains(obj)   -> tail-calls slot 7 with `[obj+0x18]`
   *   7  0x00877370  Contains(index) -> linear scan of mDecals (+0x28..+0x2C)
   *   8  0x008773F0  Add(obj)        -> tail-calls slot 9 with `[obj+0x18]`
   *   9  0x008773C0  Add(index)      -> slot 7 first, appends to mDecals if absent
   *  10  0x00877460  Remove(obj)     -> tail-calls slot 11 with `[obj+0x18]`
   *  11  0x00877410  RemoveFromGroup(index)
   *  12  0x00877480  ReadFromStream
   *  13  0x008775C0  WriteToStream
   *
   * Slots 6/8/10 are thunks over 7/9/11: each reads an index out of its
   * argument at `+0x18` and tail-jumps to the index-taking overload through
   * this same vtable (`[vtbl+0x1C]`, `[vtbl+0x24]`, `[vtbl+0x2C]` -- slots 7,
   * 9 and 11), so the pairs must keep these relative positions.
   *
   * The argument of those three is a `CWldTerrainDecal*`: that class carries
   * `std::int32_t mIndex` at exactly `+0x18`, and `mDecals` here is a
   * `msvc8::vector<std::int32_t>` of decal indices, so the object overloads
   * are just index-extracting conveniences. `CDecalManager::DestroyDecal`
   * already performs that extraction by hand -- `RemoveFromGroup(decal->mIndex)`
   * in `CWldSplat.cpp` -- which is the same pairing spelled out at the caller.
   *
   * None of slots 6/8/10 or 7/9/11 has a code xref: their only reference is
   * the `??_7CDecalGroup@Moho@@6B@` vtable, so every call is an indirect
   * dispatch the export does not capture, and the object overloads are reached
   * only through an `IDecalGroup*`. `CDecalManager::Load` (0x00877CD0) has no
   * dispatch through them, and `SDecalInfo` is not the argument type -- its
   * constructor leads with three `Wm3::Vec3f`, putting `+0x18` inside the
   * vectors.
   */
  class IDecalGroup
  {
  public:
    /**
     * Address: 0x00877240 (FUN_00877240, ??0IDecalGroup@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one decal-group base object with the `IDecalGroup` vtable.
     */
    IDecalGroup();

    /// Slot 0.
    virtual ~IDecalGroup() = default;

    /// Slot 1. Address of the stored group index lane.
    [[nodiscard]] virtual std::int32_t* GetIndex() = 0;

    /// Slot 2. Duplicate lane for mutable group display-name access.
    [[nodiscard]] virtual msvc8::string* GetNameAlias() = 0;

    /// Slot 3. Mutable access to the group display-name string lane.
    [[nodiscard]] virtual msvc8::string* GetName() = 0;

    /// Slot 4. Duplicate lane for mutable tracked decal-index vector access.
    [[nodiscard]] virtual msvc8::vector<std::int32_t>* GetDecalsAlias() = 0;

    /// Slot 5. Mutable access to the tracked decal-index vector lane.
    [[nodiscard]] virtual msvc8::vector<std::int32_t>* GetDecals() = 0;

    /// Slot 6. Whether `decal`'s index is tracked by this group.
    [[nodiscard]] virtual bool Contains(CWldTerrainDecal* decal) = 0;

    /// Slot 7. Whether `decalIndex` is tracked by this group.
    [[nodiscard]] virtual bool Contains(std::int32_t decalIndex) = 0;

    /// Slot 8. Tracks `decal`'s index, if not already tracked.
    virtual void Add(CWldTerrainDecal* decal) = 0;

    /// Slot 9. Tracks `decalIndex`, if not already tracked.
    virtual void Add(std::int32_t decalIndex) = 0;

    /// Slot 10. Stops tracking `decal`'s index.
    virtual void RemoveFromGroup(CWldTerrainDecal* decal) = 0;

    /// Slot 11. Stops tracking `decalIndex`.
    virtual void RemoveFromGroup(std::int32_t decalIndex) = 0;

    /// Slot 12. Reads group index, name and tracked decal indices.
    virtual void ReadFromStream(gpg::BinaryReader& reader, int version) = 0;

    /// Slot 13. Writes group index, name and tracked decal indices.
    virtual void WriteToStream(gpg::BinaryWriter& writer) = 0;
  };

  static_assert(sizeof(IDecalGroup) == 0x04, "IDecalGroup size must be 0x04");
} // namespace moho
