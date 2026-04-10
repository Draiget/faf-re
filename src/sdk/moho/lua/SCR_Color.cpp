#include "moho/lua/SCR_Color.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <map>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/XDataError.h"

namespace
{
  struct NamedColorEntry
  {
    const char* name;
    std::uint32_t argb;
  };

  constexpr std::array<NamedColorEntry, 141> kNamedColors = {
    { { "AliceBlue", 0xFFF0F8FFu },
      { "AntiqueWhite", 0xFFFAEBD7u },
      { "Aqua", 0xFF00FFFFu },
      { "Aquamarine", 0xFF7FFFD4u },
      { "Azure", 0xFFF0FFFFu },
      { "Beige", 0xFFF5F5DCu },
      { "Bisque", 0xFFFFE4C4u },
      { "Black", 0xFF000000u },
      { "BlanchedAlmond", 0xFFFFEBCDu },
      { "Blue", 0xFF0000FFu },
      { "BlueViolet", 0xFF8A2BE2u },
      { "Brown", 0xFFA52A2Au },
      { "BurlyWood", 0xFFDEB887u },
      { "CadetBlue", 0xFF5F9EA0u },
      { "Chartreuse", 0xFF7FFF00u },
      { "Chocolate", 0xFFD2691Eu },
      { "Coral", 0xFFFF7F50u },
      { "CornflowerBlue", 0xFF6495EDu },
      { "Cornsilk", 0xFFFFF8DCu },
      { "Crimson", 0xFFDC143Cu },
      { "Cyan", 0xFF00FFFFu },
      { "DarkBlue", 0xFF00008Bu },
      { "DarkCyan", 0xFF008B8Bu },
      { "DarkGoldenrod", 0xFFB8860Bu },
      { "DarkGray", 0xFFA9A9A9u },
      { "DarkGreen", 0xFF006400u },
      { "DarkKhaki", 0xFFBDB76Bu },
      { "DarkMagenta", 0xFF8B008Bu },
      { "DarkOliveGreen", 0xFF556B2Fu },
      { "DarkOrange", 0xFFFF8C00u },
      { "DarkOrchid", 0xFF9932CCu },
      { "DarkRed", 0xFF8B0000u },
      { "DarkSalmon", 0xFFE9967Au },
      { "DarkSeaGreen", 0xFF8FBC8Bu },
      { "DarkSlateBlue", 0xFF483D8Bu },
      { "DarkSlateGray", 0xFF2F4F4Fu },
      { "DarkTurquoise", 0xFF00CED1u },
      { "DarkViolet", 0xFF9400D3u },
      { "DeepPink", 0xFFFF1493u },
      { "DeepSkyBlue", 0xFF00BFFFu },
      { "DimGray", 0xFF696969u },
      { "DodgerBlue", 0xFF1E90FFu },
      { "Firebrick", 0xFFB22222u },
      { "FloralWhite", 0xFFFFFAF0u },
      { "ForestGreen", 0xFF228B22u },
      { "Fuchsia", 0xFFFF00FFu },
      { "Gainsboro", 0xFFDCDCDCu },
      { "GhostWhite", 0xFFF8F8FFu },
      { "Gold", 0xFFFFD700u },
      { "Goldenrod", 0xFFDAA520u },
      { "Gray", 0xFF808080u },
      { "Green", 0xFF008000u },
      { "GreenYellow", 0xFFADFF2Fu },
      { "Honeydew", 0xFFF0FFF0u },
      { "HotPink", 0xFFFF69B4u },
      { "IndianRed", 0xFFCD5C5Cu },
      { "Indigo", 0xFF4B0082u },
      { "Ivory", 0xFFFFFFF0u },
      { "Khaki", 0xFFF0E68Cu },
      { "Lavender", 0xFFE6E6FAu },
      { "LavenderBlush", 0xFFFFF0F5u },
      { "LawnGreen", 0xFF7CFC00u },
      { "LemonChiffon", 0xFFFFFACDu },
      { "LightBlue", 0xFFADD8E6u },
      { "LightCoral", 0xFFF08080u },
      { "LightCyan", 0xFFE0FFFFu },
      { "LightGoldenrodYellow", 0xFFFAFAD2u },
      { "LightGray", 0xFFD3D3D3u },
      { "LightGreen", 0xFF90EE90u },
      { "LightPink", 0xFFFFB6C1u },
      { "LightSalmon", 0xFFFFA07Au },
      { "LightSeaGreen", 0xFF20B2AAu },
      { "LightSkyBlue", 0xFF87CEFAu },
      { "LightSlateGray", 0xFF778899u },
      { "LightSteelBlue", 0xFFB0C4DEu },
      { "LightYellow", 0xFFFFFFE0u },
      { "Lime", 0xFF00FF00u },
      { "LimeGreen", 0xFF32CD32u },
      { "Linen", 0xFFFAF0E6u },
      { "Magenta", 0xFFFF00FFu },
      { "Maroon", 0xFF800000u },
      { "MediumAquamarine", 0xFF66CDAAu },
      { "MediumBlue", 0xFF0000CDu },
      { "MediumOrchid", 0xFFBA55D3u },
      { "MediumPurple", 0xFF9370DBu },
      { "MediumSeaGreen", 0xFF3CB371u },
      { "MediumSlateBlue", 0xFF7B68EEu },
      { "MediumSpringGreen", 0xFF00FA9Au },
      { "MediumTurquoise", 0xFF48D1CCu },
      { "MediumVioletRed", 0xFFC71585u },
      { "MidnightBlue", 0xFF191970u },
      { "MintCream", 0xFFF5FFFAu },
      { "MistyRose", 0xFFFFE4E1u },
      { "Moccasin", 0xFFFFE4B5u },
      { "NavajoWhite", 0xFFFFDEADu },
      { "Navy", 0xFF000080u },
      { "OldLace", 0xFFFDF5E6u },
      { "Olive", 0xFF808000u },
      { "OliveDrab", 0xFF6B8E23u },
      { "Orange", 0xFFFFA500u },
      { "OrangeRed", 0xFFFF4500u },
      { "Orchid", 0xFFDA70D6u },
      { "PaleGoldenrod", 0xFFEEE8AAu },
      { "PaleGreen", 0xFF98FB98u },
      { "PaleTurquoise", 0xFFAFEEEEu },
      { "PaleVioletRed", 0xFFDB7093u },
      { "PapayaWhip", 0xFFFFEFD5u },
      { "PeachPuff", 0xFFFFDAB9u },
      { "Peru", 0xFFCD853Fu },
      { "Pink", 0xFFFFC0CBu },
      { "Plum", 0xFFDDA0DDu },
      { "PowderBlue", 0xFFB0E0E6u },
      { "Purple", 0xFF800080u },
      { "Red", 0xFFFF0000u },
      { "RosyBrown", 0xFFBC8F8Fu },
      { "RoyalBlue", 0xFF4169E1u },
      { "SaddleBrown", 0xFF8B4513u },
      { "Salmon", 0xFFFA8072u },
      { "SandyBrown", 0xFFF4A460u },
      { "SeaGreen", 0xFF2E8B57u },
      { "SeaShell", 0xFFFFF5EEu },
      { "Sienna", 0xFFA0522Du },
      { "Silver", 0xFFC0C0C0u },
      { "SkyBlue", 0xFF87CEEBu },
      { "SlateBlue", 0xFF6A5ACDu },
      { "SlateGray", 0xFF708090u },
      { "Snow", 0xFFFFFAFAu },
      { "SpringGreen", 0xFF00FF7Fu },
      { "SteelBlue", 0xFF4682B4u },
      { "Tan", 0xFFD2B48Cu },
      { "Teal", 0xFF008080u },
      { "Thistle", 0xFFD8BFD8u },
      { "Tomato", 0xFFFF6347u },
      { "Turquoise", 0xFF40E0D0u },
      { "Violet", 0xFFEE82EEu },
      { "Wheat", 0xFFF5DEB3u },
      { "White", 0xFFFFFFFFu },
      { "WhiteSmoke", 0xFFF5F5F5u },
      { "Yellow", 0xFFFFFF00u },
      { "YellowGreen", 0xFF9ACD32u },
      { "transparent", 0x00000000u } }
  };

  struct Msvc8StringLess
  {
    [[nodiscard]] bool operator()(const msvc8::string& lhs, const msvc8::string& rhs) const noexcept
    {
      return std::strcmp(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  using ColorNameMap = std::map<msvc8::string, std::uint32_t, Msvc8StringLess>;

  constexpr const char* kUnknownColorFmt = "Unknown color: %s";
  constexpr const char* kInvalidColorTypeText = "Invalid color, must be a string.";
  constexpr const char* kEnumColorNamesHelpText =
    "table EnumColorNames() - returns a table containing strings of all the color names";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] const ColorNameMap& GetColorNameMap()
  {
    static const ColorNameMap sColorMap = [] {
      ColorNameMap colorMap{};
      for (const NamedColorEntry& entry : kNamedColors) {
        colorMap[gpg::STR_ToLower(entry.name)] = entry.argb;
      }
      return colorMap;
    }();
    return sColorMap;
  }

  [[nodiscard]] bool DecodeHexNibble(const char value, std::uint32_t& outNibble)
  {
    if (value >= '0' && value <= '9') {
      outNibble = static_cast<std::uint32_t>(value - '0');
      return true;
    }
    if (value >= 'a' && value <= 'f') {
      outNibble = static_cast<std::uint32_t>(value - 'W');
      return true;
    }
    if (value >= 'A' && value <= 'F') {
      outNibble = static_cast<std::uint32_t>(value - '7');
      return true;
    }
    return false;
  }

  /**
   * Address: 0x004B2B90 (FUN_004B2B90, func_ParseColor)
   *
   * What it does:
   * Resolves one color token as named-color lookup or 6/8-digit hex payload.
   */
  [[nodiscard]] bool TryParseColor(const char* const colorText, std::uint32_t* const outColor)
  {
    const msvc8::string loweredColor = gpg::STR_ToLower(colorText);
    const ColorNameMap& colorMap = GetColorNameMap();
    const auto foundIt = colorMap.find(loweredColor);
    if (foundIt != colorMap.end()) {
      *outColor = foundIt->second;
      return true;
    }

    const std::size_t textLength = std::strlen(colorText);
    if (textLength != 6 && textLength != 8) {
      return false;
    }

    std::uint32_t accum = *outColor;
    for (std::size_t index = 0; index < textLength; ++index) {
      std::uint32_t nibble = 0;
      if (!DecodeHexNibble(colorText[index], nibble)) {
        return false;
      }
      accum = nibble | (accum << 4);
    }

    if (textLength == 6) {
      accum |= 0xFF000000u;
    }

    *outColor = accum;
    return true;
  }
} // namespace

/**
 * Address: 0x004B2D20 (FUN_004B2D20, Moho::SCR_DecodeColor)
 *
 * What it does:
 * Decodes one Lua string color token into packed ARGB, reporting Lua errors
 * on type mismatch or unknown names.
 */
std::uint32_t moho::SCR_DecodeColor(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& colorObject)
{
  if (!colorObject.IsString()) {
    LuaPlus::LuaState::Error(state, kInvalidColorTypeText);
    return 0;
  }

  std::uint32_t decodedColor = 0;
  const char* const colorText = colorObject.GetString();
  if (TryParseColor(colorText, &decodedColor)) {
    return decodedColor;
  }

  LuaPlus::LuaState::Error(state, kUnknownColorFmt, colorObject.GetString());
  return 0;
}

/**
 * Address: 0x004B2D80 (FUN_004B2D80, Moho::SCR_DecodeColor)
 *
 * What it does:
 * Decodes one color string into packed ARGB and throws `XDataError` on
 * unknown color names/hex payloads.
 */
std::uint32_t moho::SCR_DecodeColor(const msvc8::string& colorText)
{
  std::uint32_t decodedColor = 0;
  if (!TryParseColor(colorText.c_str(), &decodedColor)) {
    const msvc8::string errorMessage = gpg::STR_Printf(kUnknownColorFmt, colorText.c_str());
    throw XDataError(errorMessage.c_str());
  }

  return decodedColor;
}

/**
 * Address: 0x004B2E60 (FUN_004B2E60, Moho::SCR_EncodeColor)
 *
 * What it does:
 * Encodes one packed ARGB value as lowercase 8-digit hex Lua string object.
 */
LuaPlus::LuaObject moho::SCR_EncodeColor(LuaPlus::LuaState* const state, const std::uint32_t colorValue)
{
  LuaPlus::LuaObject encodedColor;
  char colorText[12]{};
  std::snprintf(colorText, sizeof(colorText), "%08x", colorValue);
  encodedColor.AssignString(state, colorText);
  return encodedColor;
}

/**
 * Address: 0x004B2EE0 (FUN_004B2EE0, cfunc_EnumColorNames)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to `cfunc_EnumColorNamesL`.
 */
int moho::cfunc_EnumColorNames(lua_State* const luaContext)
{
  return cfunc_EnumColorNamesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x004B2F60 (FUN_004B2F60, cfunc_EnumColorNamesL)
 *
 * What it does:
 * Returns a Lua table listing every registered named color.
 */
int moho::cfunc_EnumColorNamesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kEnumColorNamesHelpText, 0, argumentCount);
  }

  LuaPlus::LuaObject colorNamesTable;
  colorNamesTable.AssignNewTable(state, 0, 0);

  int index = 1;
  for (const NamedColorEntry& entry : kNamedColors) {
    colorNamesTable.SetString(index++, entry.name);
  }

  colorNamesTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x004B2F00 (FUN_004B2F00, func_EnumColorNames_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EnumColorNames`.
 */
moho::CScrLuaInitForm* moho::func_EnumColorNames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "EnumColorNames",
    &moho::cfunc_EnumColorNames,
    nullptr,
    "<global>",
    kEnumColorNamesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC5CD0 (FUN_00BC5CD0, register_EnumColorNames_LuaFuncDef)
 *
 * What it does:
 * Startup thunk forwarding to `func_EnumColorNames_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_EnumColorNames_LuaFuncDef()
{
  return func_EnumColorNames_LuaFuncDef();
}
