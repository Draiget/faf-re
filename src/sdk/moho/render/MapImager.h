#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"

struct lua_State;

namespace moho
{
  class MeshInstance;
  class MeshRenderer;

  /**
   * VFTABLE: 0x00E3F07C
   * COL: 0x00E97B0C
   *
   * Owns a vector of MeshInstance pointers used for rendering map border
   * decoration meshes. ClearBorder releases and truncates that vector.
   *
   * Binary evidence:
   *   - ClearBorder (0x007D9F00) accesses [this+0x08] = _Myfirst, [this+0x0C] = _Mylast.
   *   - cfunc_MapBorderClear (0x008483D0) accesses the MapImager embedded at
   *     ren_Viewport+0x32C.
   */
  class MapImager
  {
  public:
    /**
     * Address: 0x007D9BB0 (FUN_007D9BB0, Moho::MapImager::~MapImager)
     *
     * What it does:
     * Clears border mesh instances and releases retained vector storage lanes.
     */
    ~MapImager();

    /**
     * Address: 0x007D9B90 (FUN_007D9B90)
     *
     * What it does:
     * Virtual destructor dispatch slot (slot 0).
     */
    virtual void VirtualDtor();

    /**
     * Address: 0x007D9F00 (FUN_007D9F00)
     *
     * IDA signature:
     * void __usercall Moho::MapImager::ClearBorder(Moho::MapImager *a1@<edi>);
     *
     * What it does:
     * Obtains the MeshRenderer singleton, deletes every MeshInstance in the
     * border mesh list via virtual Release(1), then truncates the vector
     * (sets _Mylast back to _Myfirst, effectively clearing it).
     */
    void ClearBorder();

  public:
    msvc8::vector<MeshInstance*> mMeshInstances;          // +0x04
  };

  static_assert(offsetof(MapImager, mMeshInstances)  == 0x04);

  /**
   * Address: 0x008483D0 (FUN_008483D0)
   *
   * IDA signature:
   * int __cdecl cfunc_MapBorderClear(LuaPlus::LuaState *a1);
   *
   * What it does:
   * Lua C function bound as global "MapBorderClear()". Takes zero arguments.
   * If the global render viewport exists, clears its MapImager border meshes.
   */
  int cfunc_MapBorderClear(struct lua_State* rawState);
} // namespace moho
