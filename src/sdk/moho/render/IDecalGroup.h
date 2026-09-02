#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Base interface lane for decal grouping owners.
   *
   * Binary evidence:
   * - constructor lane at 0x00877240
   * - base-vtable reset lane at 0x00877230
   *
   * @warning This interface is under-modelled. Its vftable (0x00E49738) has
   * **14 slots, every one `_purecall`**, but only the destructor is declared
   * here. `CDecalGroup` (vftable 0x00E497F0, `: public IDecalGroup`) supplies
   * all 14, and eight of them already exist in `CDecalGroup.h` under the right
   * names and addresses -- but declared **non-virtual**, so a call through an
   * `IDecalGroup*` cannot reach them.
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
   * this same vtable, so the pairs must keep these relative positions.
   *
   * Completing this means declaring all 13 non-destructor slots pure here, in
   * exactly that order, and marking CDecalGroup's eight `override` while
   * adding the five missing. The one piece still unresolved is the parameter
   * type of the object-taking overloads -- whatever owns an index at `+0x18`.
   * Do not guess it: a wrong signature silently changes the vtable.
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

    virtual ~IDecalGroup() = default;
  };

  static_assert(sizeof(IDecalGroup) == 0x04, "IDecalGroup size must be 0x04");
} // namespace moho
