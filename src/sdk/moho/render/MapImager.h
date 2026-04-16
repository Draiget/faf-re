#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct lua_State;
namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;
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

    /**
     * Address: 0x007D9C10 (FUN_007D9C10, Moho::MapImager::AddBorder)
     *
     * IDA signature:
     * void __stdcall Moho::MapImager::AddBorder(Moho::MapImager *arg0, std::string *arg4);
     *
     * What it does:
     * Resolves the active terrain blueprint, builds one border mesh instance
     * from the requested mesh blueprint name, and appends it to the border
     * instance vector when creation succeeds.
     */
    void AddBorder(const msvc8::string& meshBlueprintPath);

  public:
    msvc8::vector<MeshInstance*> mMeshInstances;          // +0x04
  };

#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(offsetof(MapImager, mMeshInstances)  == 0x04);
  static_assert(sizeof(MapImager) == 0x10, "MapImager size must be 0x10");
#endif

  /**
   * Address: 0x007F6530 (FUN_007F6530, Moho::REN_ShowSkeletons)
   *
   * What it does:
   * Toggles global skeleton-debug rendering and mirrors that bool lane into
   * the active simulation-driver sync-filter option flag when present.
   */
  void REN_ShowSkeletons();

  /**
   * Address: 0x007FA720 (FUN_007FA720, Moho::REN_RenderShadowDebugOverlay)
   *
   * What it does:
   * No-op shadow debug overlay callback lane retained for binary parity.
   */
  void REN_RenderShadowDebugOverlay();

  /**
   * Address: 0x007F6560 (FUN_007F6560, Moho::REN_MapBorderAdd)
   *
   * What it does:
   * Console callback that expects exactly two tokens and adds the requested
   * border mesh blueprint to the active viewport's MapImager.
   */
  void REN_MapBorderAdd(void* commandArgs);

  /**
   * Address: 0x007F65B0 (FUN_007F65B0, Moho::REN_MapBorderClear)
   *
   * What it does:
   * Console callback that clears the active viewport's MapImager border
   * decoration meshes when a viewport is present.
   */
  void REN_MapBorderClear(void* commandArgs);

  /**
   * Address: 0x007FA1E0 (FUN_007FA1E0, sub_7FA1E0)
   *
   * What it does:
   * Adds one border mesh blueprint to the active viewport map-imager lane
   * when a render viewport exists.
   */
  void REN_AddBorderToActiveViewport(const msvc8::string& meshBlueprintPath);

  /**
   * Address: 0x00848260 (FUN_00848260, cfunc_MapBorderAdd)
   *
   * What it does:
   * Converts raw Lua callback context into `LuaPlus::LuaState` and forwards
   * to `cfunc_MapBorderAddL`.
   */
  int cfunc_MapBorderAdd(lua_State* luaContext);

  /**
   * Address: 0x00848280 (FUN_00848280, func_MapBorderAdd_LuaFuncDef)
   *
   * What it does:
   * Publishes global `MapBorderAdd(blueprintid)` Lua binder metadata into the
   * user init set.
   */
  CScrLuaInitForm* func_MapBorderAdd_LuaFuncDef();

  /**
   * Address: 0x008482E0 (FUN_008482E0, cfunc_MapBorderAddL)
   *
   * What it does:
   * Validates one string argument and asks the active viewport map-imager to
   * add the requested border mesh blueprint.
   */
  int cfunc_MapBorderAddL(LuaPlus::LuaState* state);

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

  /**
   * Address: 0x00848420 (FUN_00848420, func_MapBorderClear_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `MapBorderClear()` into the user
   * init set.
   */
  CScrLuaInitForm* func_MapBorderClear_LuaFuncDef();
} // namespace moho
