// MapImager recovered implementation.

#include "moho/render/MapImager.h"
#include "moho/mesh/Mesh.h"
#include "moho/app/WxRuntimeTypes.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"

namespace moho
{

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
void MapImager::ClearBorder()
{
  // Touch the MeshRenderer singleton to ensure it is initialized.
  MeshRenderer::GetInstance();

  // Release each border mesh instance via its virtual destructor dispatch.
  for (auto* instance : mMeshInstances) {
    instance->Release(1);
  }

  // Truncate the vector (equivalent to clear without deallocation).
  mMeshInstances.clear();
}

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
int cfunc_MapBorderClear(lua_State* rawState)
{
  auto* state = LuaPlus::LuaState::CastState(rawState);

  static constexpr const char* kHelpText = "MapBorderClear()";

  const int argCount = lua_gettop(state->m_state);
  if (argCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kHelpText, 0, argCount);
  }

  // The binary embeds a `MapImager` at `ren_Viewport + 0x32C` and clears it
  // here, but `WRenViewport` (in moho/app/WxRuntimeTypes.h) does not yet
  // expose a `GetMapImager()` accessor — that requires recovering the full
  // 0x350+-byte WRenViewport layout. Re-enable when WRenViewport gains the
  // embedded MapImager and accessor.
  (void)ren_Viewport;

  return 0;
}

} // namespace moho
