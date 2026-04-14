// MapImager recovered implementation.

#include "moho/render/MapImager.h"

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"

namespace
{
  constexpr const char* kMapBorderClearName = "MapBorderClear";
  constexpr const char* kMapBorderClearHelpText = "MapBorderClear()";
  constexpr const char* kGlobalLuaClassName = "<global>";

  struct WRenViewportMapImagerView
  {
    std::uint8_t pad[0x32C];
    moho::MapImager mMapImager;
  };

  static_assert(
    offsetof(WRenViewportMapImagerView, mMapImager) == 0x32C,
    "WRenViewportMapImagerView::mMapImager offset must be 0x32C"
  );

  struct CWldTerrainResRuntimeView
  {
    void* vftable;
    moho::STIMap* mMap;
  };

  static_assert(sizeof(CWldTerrainResRuntimeView) == 0x08, "CWldTerrainResRuntimeView size must be 0x08");
  static_assert(offsetof(CWldTerrainResRuntimeView, mMap) == 0x04, "CWldTerrainResRuntimeView::mMap offset must be 0x04");

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  [[nodiscard]] moho::MapImager* ActiveViewportMapImager() noexcept
  {
    if (moho::ren_Viewport == nullptr) {
      return nullptr;
    }

    auto* const viewportView = reinterpret_cast<WRenViewportMapImagerView*>(moho::ren_Viewport);
    return &viewportView->mMapImager;
  }

  void ClearActiveViewportMapBorder() noexcept
  {
    if (moho::MapImager* const mapImager = ActiveViewportMapImager(); mapImager != nullptr) {
      mapImager->ClearBorder();
    }
  }
} // namespace

namespace moho
{
bool ren_ShowSkeletons = false;

/**
 * Address: 0x007D9BB0 (FUN_007D9BB0, Moho::MapImager::~MapImager)
 */
MapImager::~MapImager()
{
  ClearBorder();
}

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
  MeshRenderer::GetInstance();

  for (auto* instance : mMeshInstances) {
    instance->Release(1);
  }

  mMeshInstances.clear();
}

/**
 * Address: 0x007D9C10 (FUN_007D9C10, Moho::MapImager::AddBorder)
 *
 * IDA signature:
 * void __stdcall Moho::MapImager::AddBorder(Moho::MapImager *arg0, std::string *arg4);
 *
 * What it does:
 * Resolves the active terrain blueprint, builds one border mesh instance from
 * the requested mesh blueprint name, and appends it to the border instance
 * vector when creation succeeds.
 */
void MapImager::AddBorder(const msvc8::string& meshBlueprintPath)
{
  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->mRules == nullptr || session->mWldMap == nullptr || session->mWldMap->mTerrainRes == nullptr) {
    return;
  }

  MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
  if (meshRenderer == nullptr) {
    return;
  }

  const auto* const terrainResView = reinterpret_cast<const CWldTerrainResRuntimeView*>(session->mWldMap->mTerrainRes);
  const STIMap* const terrainMap = terrainResView->mMap;
  if (terrainMap == nullptr || terrainMap->mHeightField.get() == nullptr) {
    return;
  }

  const Wm3::AxisAlignedBox3f terrainBounds = terrainMap->mHeightField->GetBounds3D();
  const float elevationOffset = 0.0f;

  const Wm3::Vec3f borderPosition{
    (terrainBounds.Min.x + terrainBounds.Max.x) * 0.5f,
    ((terrainBounds.Min.y + terrainBounds.Max.y) * 0.5f) + elevationOffset,
    (terrainBounds.Min.z + terrainBounds.Max.z) * 0.5f,
  };
  const Wm3::Quaternionf borderOrientation = Wm3::Quaternionf::Identity();
  const VTransform borderTransform(borderPosition, borderOrientation);

  msvc8::string normalizedBlueprintPath{};
  gpg::STR_CopyFilename(&normalizedBlueprintPath, &meshBlueprintPath);

  RResId meshBlueprintId{};
  meshBlueprintId.name = normalizedBlueprintPath;

  RMeshBlueprint* const meshBlueprint = session->mRules->GetMeshBlueprint(meshBlueprintId);
  if (meshBlueprint == nullptr) {
    return;
  }

  const float borderScale = (terrainBounds.Max.x - terrainBounds.Min.x) * meshBlueprint->mUniformScale;
  const Wm3::Vec3f borderScaleVec{borderScale, borderScale, borderScale};

  MeshInstance* const instance =
    meshRenderer->CreateMeshInstance(0, -1, meshBlueprint, borderScaleVec, false, boost::shared_ptr<MeshMaterial>{});
  if (instance == nullptr) {
    return;
  }

  instance->SetStance(borderTransform, borderTransform);
  mMeshInstances.push_back(instance);
}

/**
 * Address: 0x007F6530 (FUN_007F6530, Moho::REN_ShowSkeletons)
 *
 * What it does:
 * Toggles global skeleton-debug rendering and mirrors that bool lane into the
 * active simulation-driver sync-filter option flag when present.
 */
void REN_ShowSkeletons()
{
  const bool showSkeletons = !moho::ren_ShowSkeletons;
  moho::ren_ShowSkeletons = showSkeletons;

  if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
    activeDriver->SetSyncFilterOptionFlag(showSkeletons);
  }
}

/**
 * Address: 0x007F6560 (FUN_007F6560, Moho::REN_MapBorderAdd)
 *
 * What it does:
 * Console callback that expects exactly two tokens and adds the requested
 * border mesh blueprint to the active viewport's MapImager.
 */
void REN_MapBorderAdd(void* const commandArgs)
{
  const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
  if (args.Count() != 2u) {
    return;
  }

  if (moho::ren_Viewport == nullptr) {
    return;
  }

  ActiveViewportMapImager()->AddBorder(*args.At(1));
}

/**
 * Address: 0x007F65B0 (FUN_007F65B0, Moho::REN_MapBorderClear)
 *
 * What it does:
 * Console callback that clears the active viewport's MapImager border
 * decoration meshes when a viewport is present.
 */
void REN_MapBorderClear(void* const commandArgs)
{
  (void)commandArgs;
  ClearActiveViewportMapBorder();
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

  ClearActiveViewportMapBorder();
  return 0;
}

/**
 * Address: 0x00848420 (FUN_00848420, func_MapBorderClear_LuaFuncDef)
 *
 * What it does:
 * Publishes global Lua binder metadata for `MapBorderClear()` into the user
 * init set.
 */
CScrLuaInitForm* func_MapBorderClear_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kMapBorderClearName,
    &moho::cfunc_MapBorderClear,
    nullptr,
    kGlobalLuaClassName,
    kMapBorderClearHelpText
  );
  return &binder;
}

} // namespace moho
