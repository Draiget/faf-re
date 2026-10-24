// FAF FA-Binary-Patches (section/DrawFunc.cpp, hooks/HDraw.cpp, hooks/GetFPS.cpp).
// Not in the shipped binary; see UiWorldShapes.h.

#include "moho/ui/UiWorldShapes.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/RenderProfiler.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/SCR_Color.h"
#include "moho/render/WorldShapeGpuRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace
{
  constexpr const char* kGlobalLuaClassName = "<global>";
  constexpr const char* kUnknownColorFmt = "Unknown color: %s";
  constexpr lua_Number kDefaultThickness = 0.15f;
  /// The patch's lower bound on a shape's thickness, in LOD units (`std::max(thickness / lod, 2.f)`).
  constexpr float kMinimumThicknessLodUnits = 2.0f;

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  /**
   * The patch's globals around one `OnRenderWorld` call.
   *
   * `mViewPending` is DrawFunc.cpp's `_worldview`: set as soon as any world
   * view reaches the hook, cleared only by a pass that ran the callback to the
   * end. Outside a callback the Lua functions return silently while it is clear
   * and raise "Attempt to call ... outside of OnRenderWorld" while it is set -
   * which, as in the patched exe, is whenever the last view drawn had no
   * callback to run.
   */
  struct RenderWorldPass
  {
    bool mViewPending = false;               // `_worldview != nullptr`
    bool mInRenderWorld = false;             // `is_in_render_world`
    moho::CD3DPrimBatcher* mBatcher = nullptr;
    const moho::GeomCamera3* mCamera = nullptr;
    bool mGpu = false;                       // collect records for WorldShapeGpuRenderer
    std::vector<moho::WorldShapeRecord> mRecords;
  };

  RenderWorldPass sPass;
  float sRenderWorldFrameSeconds = 0.0f; // `delta_frame`

  /** The patch's `ToVector` (include/utility.h): `{t[1], t[2], t[3]}`, zero for a non-table. */
  [[nodiscard]] moho::Vector3f ReadLuaVector(lua_State* const L, const int index)
  {
    moho::Vector3f result{0.0f, 0.0f, 0.0f};
    if (!lua_istable(L, index)) {
      return result;
    }
    lua_pushvalue(L, index);
    lua_rawgeti(L, -1, 1);
    result.x = static_cast<float>(lua_tonumber(L, -1));
    lua_rawgeti(L, -2, 2);
    result.y = static_cast<float>(lua_tonumber(L, -1));
    lua_rawgeti(L, -3, 3);
    result.z = static_cast<float>(lua_tonumber(L, -1));
    lua_pop(L, 4);
    return result;
  }

  /** The head every draw function shares: false means `return 0`. */
  [[nodiscard]] bool EnterShapeCall(lua_State* const L, const char* const outsideMessage)
  {
    if (sPass.mBatcher == nullptr || !sPass.mViewPending) {
      return false;
    }
    if (!sPass.mInRenderWorld) {
      luaL_error(L, outsideMessage);
      return false;
    }
    return true;
  }

  /** `Moho::TryConvertToColor` (0x004B2B90) on argument `index`, or the engine's "Unknown color" error. */
  [[nodiscard]] std::uint32_t ParseColorArgument(lua_State* const L, const char* const text)
  {
    std::uint32_t color = 0U;
    if (!moho::SCR_ParseColor(text, &color)) {
      luaL_error(L, kUnknownColorFmt, text);
    }
    return color;
  }

  /**
   * The patch's `GetLODMetric`: row 2 of the view camera's viewport matrix
   * dotted with `point` (`camera[169..172]`, i.e. `GeomCamera3::viewport` at
   * +0x284, row 2 at +0x2A4) - world units per pixel at that point.
   */
  [[nodiscard]] float LodMetric(const moho::Vector3f& point)
  {
    return sPass.mCamera->viewport.ProjectViewportWidthRow2(point);
  }

  /** At least two LOD units: the patch's `std::max(thickness / lod, 2.f)`. */
  [[nodiscard]] float ThicknessInLodUnits(const float thickness, const float lod)
  {
    return std::max(thickness / lod, kMinimumThicknessLodUnits);
  }

  void StorePoint(moho::WorldShapeRecord& record, const std::size_t index, const moho::Vector3f& point)
  {
    record.mPoints[index][0] = point.x;
    record.mPoints[index][1] = point.y;
    record.mPoints[index][2] = point.z;
  }

  /** Draws through the batcher now, as the patch does, or keeps the record for the GPU path. */
  void SubmitShape(const moho::WorldShapeRecord& record)
  {
    if (sPass.mGpu) {
      sPass.mRecords.push_back(record);
    } else {
      moho::DrawWorldShape(*sPass.mBatcher, record);
    }
  }

  /** The patch's `Vector3f::normalized` (include/Maths.h): unchanged when the length is not positive. */
  [[nodiscard]] moho::Vector3f NormalizedOrSame(const moho::Vector3f& v)
  {
    const float length = std::sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    if (length > 0.0f) {
      return {v.x / length, v.y / length, v.z / length};
    }
    return v;
  }
} // namespace

void moho::UI_SetRenderWorldFrameSeconds(const float frameSeconds) noexcept
{
  sRenderWorldFrameSeconds = frameSeconds;
}

/**
 * FAF FA-Binary-Patches (section/DrawFunc.cpp, CustomDraw; hooks/HDraw.cpp
 * jumps there from 0x0086EF2B, the end of `CUIWorldView::Render`, 0x0086EE00).
 *
 * What it does:
 * When custom rendering is on and the view's script object has an
 * `OnRenderWorld` function, sets the batcher up for world-space solid shapes
 * (primbatcher TAlphaBlendLinearSampleNoDepth, the view camera's matrices, a
 * solid white texture), calls `OnRenderWorld(self, frameSeconds)` with the
 * UI_Draw* functions enabled, warns with the message if it fails, and flushes.
 */
void moho::CUIWorldView::RenderWorldShapes(CD3DPrimBatcher* const batcher)
{
  sPass.mViewPending = true;
  sPass.mBatcher = batcher;

  if (!GetCustomRender()) {
    return;
  }

  LuaPlus::LuaState* const state = mLuaObj.GetActiveState();
  if (state == nullptr || batcher == nullptr) {
    return;
  }
  lua_State* const L = state->GetCState();
  const int savedTop = lua_gettop(L);
  mLuaObj.PushStack(L);
  lua_pushstring(L, "OnRenderWorld");
  lua_gettable(L, -2);
  if (!lua_isfunction(L, -1)) {
    lua_settop(L, savedTop);
    return;
  }

  const gpg::gal::RenderProfileScope profileShapes("WorldShapes"); // FAF instrumentation

  // `CD3DPrimBatcher::Setup` (0x00438560), which the patch spells out as
  // `SetupDevice` + `ResetBatcher`.
  (void)batcher->Setup("TAlphaBlendLinearSampleNoDepth");
  const GeomCamera3& camera = mCamera->CameraGetView();
  batcher->SetViewProjMatrix(camera);
  batcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFU));

  sPass.mCamera = &camera;
  sPass.mGpu = WorldShapeGpuRenderer::Get().IsActive();
  sPass.mRecords.clear();

  sPass.mInRenderWorld = true;
  lua_pushvalue(L, -2);
  lua_pushnumber(L, static_cast<lua_Number>(sRenderWorldFrameSeconds));
  if (LuaCallProtected(L, 2, 0) != 0) {
    gpg::Warnf("%s", lua_tostring(L, -1));
  }
  lua_settop(L, savedTop);
  sPass.mInRenderWorld = false;

  {
    const gpg::gal::RenderProfileScope profileDraw("WorldShapesDraw"); // FAF instrumentation
    if (sPass.mGpu && !WorldShapeGpuRenderer::Get().Draw(*batcher, this, sPass.mRecords)) {
      for (const WorldShapeRecord& record : sPass.mRecords) {
        DrawWorldShape(*batcher, record);
      }
    }
    sPass.mRecords.clear();
    batcher->Flush();
  }

  sPass.mCamera = nullptr;
  sPass.mViewPending = false;
}

/**
 * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawRect).
 *
 * What it does:
 * Draws a square outline through `DRAW_Rect` (0x00455480) without a height
 * field: corner `pos`, sides `size` along +Z and +X, border `thickness` world
 * units but at least two LOD units at `pos`.
 */
int moho::cfunc_UI_DrawRect(lua_State* const L)
{
  if (!EnterShapeCall(L, "Attempt to call DrawRect outside of OnRenderWorld")) {
    return 0;
  }

  const Vector3f pos = ReadLuaVector(L, 1);
  const float size = static_cast<float>(luaL_checknumber(L, 2));
  const char* const colorText = luaL_checklstring(L, 3, nullptr);
  const float thickness = static_cast<float>(luaL_optnumber(L, 4, kDefaultThickness));
  const std::uint32_t color = ParseColorArgument(L, colorText);

  const float lod = LodMetric(pos);
  const float lodThickness = ThicknessInLodUnits(thickness, lod);
  const Vector3f heightAxis{0.0f, 0.0f, size};
  const Vector3f widthAxis{size, 0.0f, 0.0f};
  const DrawRectRing ring = DRAW_RectRing(lodThickness * lod, heightAxis, widthAxis, pos);

  WorldShapeRecord record{};
  record.mKind = WorldShapeKind::Rect;
  record.mColor = color;
  for (std::size_t corner = 0; corner < 4U; ++corner) {
    StorePoint(record, corner, ring.outer[corner]);
    StorePoint(record, corner + 4U, ring.inner[corner]);
  }
  SubmitShape(record);
  return 0;
}

moho::CScrLuaInitForm* moho::func_UI_DrawRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UI_DrawRect",
    &moho::cfunc_UI_DrawRect,
    nullptr,
    kGlobalLuaClassName,
    "UI_DrawRect(pos:vector, size:float, color:string, thickness?=0.15:float)"
  );
  return &binder;
}

/**
 * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawCircle).
 *
 * What it does:
 * Draws a horizontal ring through `DRAW_Circle` (0x00456200, normal +Y),
 * `thickness` world units either side of `radius` but at least two LOD units
 * at `pos`.
 */
int moho::cfunc_UI_DrawCircle(lua_State* const L)
{
  if (!EnterShapeCall(L, "Attempt to call DrawCircle outside of OnRenderWorld")) {
    return 0;
  }

  const Vector3f pos = ReadLuaVector(L, 1);
  const float radius = static_cast<float>(luaL_checknumber(L, 2));
  const char* const colorText = luaL_checklstring(L, 3, nullptr);
  const float thickness = static_cast<float>(luaL_optnumber(L, 4, kDefaultThickness));
  const std::uint32_t color = ParseColorArgument(L, colorText);

  const Vector3f normal{0.0f, 1.0f, 0.0f};
  const float lod = LodMetric(pos);
  const float lodThickness = ThicknessInLodUnits(thickness, lod);
  const DrawOvalAxes axes = DRAW_CircleAxes(normal, radius, lod * lodThickness);

  WorldShapeRecord record{};
  record.mKind = WorldShapeKind::Circle;
  record.mColor = color;
  StorePoint(record, 0U, pos);
  StorePoint(record, 1U, axes.innerSin);
  StorePoint(record, 2U, axes.outerCos);
  StorePoint(record, 3U, axes.outerSin);
  StorePoint(record, 4U, axes.innerCos);
  SubmitShape(record);
  return 0;
}

moho::CScrLuaInitForm* moho::func_UI_DrawCircle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UI_DrawCircle",
    &moho::cfunc_UI_DrawCircle,
    nullptr,
    kGlobalLuaClassName,
    "UI_DrawCircle(pos:vector, radius:float, color:string, thickness?=0.15:float)"
  );
  return &binder;
}

/**
 * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawLine).
 *
 * What it does:
 * Draws one `CD3DPrimBatcher::DrawQuad` (0x00438DA0) from `pos1` to `pos2`,
 * offset either way along the horizontal normal of the segment by half the
 * thickness; the thickness is at least two LOD units at the farther end.
 */
int moho::cfunc_UI_DrawLine(lua_State* const L)
{
  if (!EnterShapeCall(L, "Attempt to call DrawLine outside of OnRenderWorld")) {
    return 0;
  }

  const Vector3f pos1 = ReadLuaVector(L, 1);
  const Vector3f pos2 = ReadLuaVector(L, 2);
  const char* const colorText = luaL_checklstring(L, 3, nullptr);
  const float thickness = static_cast<float>(luaL_optnumber(L, 4, kDefaultThickness));
  const std::uint32_t color = ParseColorArgument(L, colorText);

  const float lod = std::max(LodMetric(pos1), LodMetric(pos2));
  const float halfThickness = ThicknessInLodUnits(thickness, lod) * lod * 0.5f;

  // FindNormalVector: the segment's horizontal normal.
  const Vector3f normal = NormalizedOrSame({-(pos2.z - pos1.z), 0.0f, pos2.x - pos1.x});
  const Vector3f offset{normal.x * halfThickness, normal.y * halfThickness, normal.z * halfThickness};

  const Vector3f pos1Plus{pos1.x + offset.x, pos1.y + offset.y, pos1.z + offset.z};
  const Vector3f pos1Minus{pos1.x - offset.x, pos1.y - offset.y, pos1.z - offset.z};
  const Vector3f pos2Plus{pos2.x + offset.x, pos2.y + offset.y, pos2.z + offset.z};
  const Vector3f pos2Minus{pos2.x - offset.x, pos2.y - offset.y, pos2.z - offset.z};

  // The patch's `_DrawQuad(color, edx=v1, ecx=v2, esi=v3, batcher, v4)` is
  // `DrawQuad(v4, v2, v1, v3, color)`: 0x00438DA0 takes its top-left corner on
  // the stack, top-right in ecx, bottom-right in edx and bottom-left in esi.
  WorldShapeRecord record{};
  record.mKind = WorldShapeKind::Line;
  record.mColor = color;
  StorePoint(record, 0U, pos2Minus);
  StorePoint(record, 1U, pos1Minus);
  StorePoint(record, 2U, pos1Plus);
  StorePoint(record, 3U, pos2Plus);
  SubmitShape(record);
  return 0;
}

moho::CScrLuaInitForm* moho::func_UI_DrawLine_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "UI_DrawLine",
    &moho::cfunc_UI_DrawLine,
    nullptr,
    kGlobalLuaClassName,
    "UI_DrawLine(pos1:vector, pos2:vector, color:string, thickness?=0.15:float)"
  );
  return &binder;
}

namespace
{
  /**
   * Drives this file's Lua binder definitions (see MapImager.cpp's bootstrap
   * for why a source line has to name them).
   */
  struct UiWorldShapesLuaFuncDefBootstrap
  {
    UiWorldShapesLuaFuncDefBootstrap()
    {
      (void)::moho::func_UI_DrawRect_LuaFuncDef();
      (void)::moho::func_UI_DrawCircle_LuaFuncDef();
      (void)::moho::func_UI_DrawLine_LuaFuncDef();
    }
  };

  const UiWorldShapesLuaFuncDefBootstrap gUiWorldShapesLuaFuncDefBootstrap{};
} // namespace
