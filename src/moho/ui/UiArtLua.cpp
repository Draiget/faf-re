// Engine addition (in-game launcher, WP5): the UI Lua's way to the pictures moho/ui/UiArt.h draws. Each call draws
// once per distinct request, keeps the PNG in memory under /fafengine-mem/ and returns that path for
// Bitmap:SetTexture.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <string>
#include <string_view>

#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/ui/UiArt.h"

namespace
{
  using namespace moho::uiart;

  /** FNV-1a over the request, as the picture's name: the same request finds the same picture. */
  std::string NameFor(
    const std::string_view kind,
    const std::string_view request
  )
  {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char c : request) {
      hash = (hash ^ static_cast<unsigned char>(c)) * 1099511628211ULL;
    }
    char text[24];
    std::snprintf(text, sizeof(text), "%016llx", static_cast<unsigned long long>(hash));
    return std::string(kMemoryPrefix) + std::string(kind) + "/" + text + ".png";
  }

  const char* StringArg(
    lua_State* const L,
    const int index
  )
  {
    return lua_isstring(L, index) ? lua_tostring(L, index) : nullptr;
  }

  double NumberArg(
    lua_State* const L,
    const int index,
    const double fallback
  )
  {
    return lua_isnumber(L, index) ? static_cast<double>(lua_tonumber(L, index)) : fallback;
  }

  Rgba ColorArg(
    lua_State* const L,
    const int index,
    const Rgba fallback
  )
  {
    Rgba color = fallback;
    if (const char* const text = StringArg(L, index)) {
      (void)ParseColor(text, color);
    }
    return color;
  }

  int PushPicture(
    lua_State* const L,
    const std::string& path,
    const auto& draw
  )
  {
    if (FindImage(path) == nullptr) {
      const auto image = draw();
      if (!image) {
        lua_pushnil(L);
        lua_pushstring(L, image.error().c_str());
        return 2;
      }
      RegisterImage(path, EncodePng(*image));
    }
    lua_pushstring(L, path.c_str());
    return 1;
  }

  /** string|nil, why = FafUi_Icon(svgElements, sizePixels, color[, strokeWidth=2[, viewBox=24]]) */
  int IconBody(
    lua_State* const L
  )
  {
    const char* const svg = StringArg(L, 1);
    const int size = static_cast<int>(NumberArg(L, 2, 0));
    const char* const colorText = StringArg(L, 3);
    const double stroke = NumberArg(L, 4, 2.0);
    const double viewBox = NumberArg(L, 5, 24.0);
    if (svg == nullptr || size <= 0) {
      lua_pushnil(L);
      lua_pushstring(L, "FafUi_Icon(svgElements, sizePixels, color[, strokeWidth[, viewBox]])");
      return 2;
    }
    const Rgba color = ColorArg(L, 3, Rgba{});
    char spec[96];
    std::snprintf(spec, sizeof(spec), "|%d|%s|%g|%g", size, colorText != nullptr ? colorText : "", stroke, viewBox);
    return PushPicture(L, NameFor("icon", std::string(svg) + spec), [&] {
      return DrawIcon(svg, size, color, static_cast<float>(stroke), static_cast<float>(viewBox));
    });
  }

  /** string = FafUi_Corner(corner 0-3, radiusPixels, fill[, border[, borderWidth=0]]) */
  int CornerBody(
    lua_State* const L
  )
  {
    const int corner = static_cast<int>(NumberArg(L, 1, 0)) & 3;
    const int radius = std::max(1, static_cast<int>(NumberArg(L, 2, 1)));
    const Rgba fill = ColorArg(L, 3, Rgba{0, 0, 0, 0});
    const Rgba border = ColorArg(L, 4, Rgba{0, 0, 0, 0});
    const double width = NumberArg(L, 5, 0.0);
    char spec[128];
    std::snprintf(
      spec,
      sizeof(spec),
      "%d|%d|%02x%02x%02x%02x|%02x%02x%02x%02x|%g",
      corner,
      radius,
      fill.a,
      fill.r,
      fill.g,
      fill.b,
      border.a,
      border.r,
      border.g,
      border.b,
      width
    );
    return PushPicture(L, NameFor("corner", spec), [&] {
      return std::expected<Image, std::string>(DrawCorner(corner, radius, fill, border, static_cast<float>(width)));
    });
  }

  /** string = FafUi_Box(widthPixels, heightPixels, radiusPixels, fill[, border[, borderWidth=0]]) */
  int BoxBody(
    lua_State* const L
  )
  {
    const int width = std::clamp(static_cast<int>(NumberArg(L, 1, 1)), 1, 4096);
    const int height = std::clamp(static_cast<int>(NumberArg(L, 2, 1)), 1, 4096);
    const double radius = NumberArg(L, 3, 0.0);
    const Rgba fill = ColorArg(L, 4, Rgba{0, 0, 0, 0});
    const Rgba border = ColorArg(L, 5, Rgba{0, 0, 0, 0});
    const double borderWidth = NumberArg(L, 6, 0.0);
    char spec[160];
    std::snprintf(
      spec,
      sizeof(spec),
      "%d|%d|%g|%02x%02x%02x%02x|%02x%02x%02x%02x|%g",
      width,
      height,
      radius,
      fill.a,
      fill.r,
      fill.g,
      fill.b,
      border.a,
      border.r,
      border.g,
      border.b,
      borderWidth
    );
    return PushPicture(L, NameFor("box", spec), [&] {
      return std::expected<Image, std::string>(
        DrawRoundedRect(width, height, static_cast<float>(radius), fill, border, static_cast<float>(borderWidth))
      );
    });
  }

  template <int (*Body)(lua_State*)>
  int Binding(
    lua_State* const luaContext
  )
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    return state != nullptr && state->m_state != nullptr ? Body(state->m_state) : 0;
  }

  void RegisterUiArtBindings()
  {
    using moho::CScrLuaBinder;
    static CScrLuaBinder icon(
      moho::SCR_UserLuaInitSet(),
      "FafUi_Icon",
      &Binding<&IconBody>,
      nullptr,
      "<global>",
      "string FafUi_Icon(svgElements, sizePixels, color, [strokeWidth], [viewBox]) - an icon drawn from SVG elements, "
      "as a texture path."
    );
    static CScrLuaBinder corner(
      moho::SCR_UserLuaInitSet(),
      "FafUi_Corner",
      &Binding<&CornerBody>,
      nullptr,
      "<global>",
      "string FafUi_Corner(corner, radiusPixels, fill, [border], [borderWidth]) - one rounded corner (0 top left, "
      "clockwise), as a texture path."
    );
    static CScrLuaBinder box(
      moho::SCR_UserLuaInitSet(),
      "FafUi_Box",
      &Binding<&BoxBody>,
      nullptr,
      "<global>",
      "string FafUi_Box(widthPixels, heightPixels, radiusPixels, fill, [border], [borderWidth]) - a rounded box, as a "
      "texture path."
    );
  }

  struct UiArtLuaFuncDefBootstrap
  {
    UiArtLuaFuncDefBootstrap()
    {
      RegisterUiArtBindings();
    }
  };

  UiArtLuaFuncDefBootstrap gUiArtLuaFuncDefBootstrap;
} // namespace
