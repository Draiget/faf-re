#include "editor/ui/EdTheme.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/LuaTableIterator.h"
#include "lua/luaplus/include/lauxlib.h"
#include "lua/luaplus/include/lua.h"

namespace faf::editor
{
  namespace
  {
    // The editor's look before themes (EdApp.cpp, SetUpImGui): dark panels, an orange accent.
    constexpr std::string_view kEditorDark = R"lua(-- The editor's own dark look.
Theme = {
    name = 'Editor Dark',
    base = 'dark',
    accent = '#e39442',
    rounding = 3,
    colors = {
        WindowBg = '#1c1f25f7',
        PopupBg = '#171a1f',
        TitleBg = '#24282f',
        TitleBgActive = '#2e333d',
        MenuBarBg = '#24282f',
    },
}
)lua";

    // The mockup's look (issue #388): near-black panels, a blue accent, rounder corners.
    constexpr std::string_view kFafBlue =
      R"lua(-- FAF Blue: the consolidated editor mockup's look. Copy this file into the themes folder to make your own.
Theme = {
    name = 'FAF Blue',
    base = 'dark',
    accent = '#4ea1ff',
    rounding = 5,
    colors = {
        Text = '#e9edf2',
        TextDisabled = '#7f8a97',
        WindowBg = '#1b2028',
        ChildBg = '#1b202800',
        PopupBg = '#1b2028',
        Border = '#2a313b',
        FrameBg = '#14181e',
        FrameBgHovered = '#1e242c',
        FrameBgActive = '#242b35',
        TitleBg = '#14181e',
        TitleBgActive = '#14181e',
        MenuBarBg = '#14181e',
        ScrollbarBg = '#1b202800',
        Button = '#242b35',
        ButtonHovered = '#2e3743',
        Separator = '#2a313b',
        Tab = '#14181e00',
        TabHovered = '#1b2028',
        TabSelected = '#1b2028',
        TabDimmed = '#14181e00',
        TabDimmedSelected = '#1b2028',
        TableBorderStrong = '#2a313b',
        TableBorderLight = '#20262e',
        DockingEmptyBg = '#0d1014',
    },
}
)lua";

    constexpr std::string_view kLight = R"lua(-- A light look.
Theme = {
    name = 'Light',
    base = 'light',
    accent = '#1f6fe0',
    rounding = 5,
    colors = {
        Text = '#141a21',
        TextDisabled = '#66717d',
        WindowBg = '#f6f7f9',
        PopupBg = '#ffffff',
        Border = '#d5dbe2',
        FrameBg = '#ffffff',
        FrameBgHovered = '#eef1f5',
        FrameBgActive = '#e1e6ec',
        TitleBg = '#e9ecf0',
        TitleBgActive = '#e9ecf0',
        MenuBarBg = '#e9ecf0',
        Button = '#eef1f5',
        ButtonHovered = '#e1e6ec',
        Tab = '#e9ecf0',
        TabSelected = '#ffffff',
        TabDimmed = '#e9ecf0',
        TabDimmedSelected = '#f6f7f9',
    },
}
)lua";

    [[nodiscard]] int HexDigit(
      const char c
    )
    {
      if (c >= '0' && c <= '9') {
        return c - '0';
      }
      const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      return lower >= 'a' && lower <= 'f' ? lower - 'a' + 10 : -1;
    }

    /** A colour as the file gives it: a string or a table of numbers. */
    [[nodiscard]] bool ColorOf(
      const LuaPlus::LuaObject& value,
      float rgba[4]
    )
    {
      if (value.IsString()) {
        return ParseThemeColor(value.GetString(), rgba);
      }
      if (!value.IsTable()) {
        return false;
      }
      float parts[4] = {0.0f, 0.0f, 0.0f, 1.0f};
      bool over1 = false;
      int count = 0;
      for (int i = 0; i < 4; ++i) {
        const LuaPlus::LuaObject part = value.GetByIndex(i + 1);
        if (!part.IsNumber()) {
          break;
        }
        parts[i] = static_cast<float>(part.GetNumber());
        over1 = over1 || parts[i] > 1.0f;
        ++count;
      }
      if (count < 3) {
        return false;
      }
      for (int i = 0; i < 4; ++i) {
        // Numbers over 1 mean 0..255 (alpha left alone when it wasn't given).
        const float v = over1 && (i < count) ? parts[i] / 255.0f : parts[i];
        rgba[i] = std::clamp(v, 0.0f, 1.0f);
      }
      return true;
    }
  } // namespace

  bool ParseThemeColor(
    std::string_view text,
    float rgba[4]
  )
  {
    if (!text.empty() && text.front() == '#') {
      text.remove_prefix(1);
    }
    if (text.size() != 3 && text.size() != 6 && text.size() != 8) {
      return false;
    }
    int values[8] = {};
    for (std::size_t i = 0; i < text.size(); ++i) {
      values[i] = HexDigit(text[i]);
      if (values[i] < 0) {
        return false;
      }
    }
    if (text.size() == 3) {
      for (int i = 0; i < 3; ++i) {
        rgba[i] = static_cast<float>(values[i] * 17) / 255.0f;
      }
      rgba[3] = 1.0f;
      return true;
    }
    for (std::size_t i = 0; i < text.size() / 2; ++i) {
      rgba[i] = static_cast<float>(values[i * 2] * 16 + values[i * 2 + 1]) / 255.0f;
    }
    if (text.size() == 6) {
      rgba[3] = 1.0f;
    }
    return true;
  }

  EdTheme ReadTheme(
    const std::string& text,
    const std::string& chunk
  )
  {
    EdTheme theme;
    LuaPlus::LuaState state(LuaPlus::LuaState::LIB_BASE);
    lua_State* const L = state.GetCState();
    const std::string name = "=" + chunk;
    // LuaCallProtected: this Lua's only protected call (it has no lua_pcall; errors are C++ throws).
    if (luaL_loadbuffer(L, text.data(), text.size(), name.c_str()) != 0 || LuaCallProtected(L, 0, 0) != 0) {
      const char* const message = lua_tostring(L, -1);
      theme.problems.emplace_back(message != nullptr ? message : "the file doesn't run");
      lua_settop(L, 0);
      return theme;
    }
    const LuaPlus::LuaObject table = state.GetGlobal("Theme");
    if (!table.IsTable()) {
      theme.problems.emplace_back("the file sets no Theme table");
      return theme;
    }
    if (const LuaPlus::LuaObject value = table["name"]; value.IsString()) {
      theme.name = value.GetString();
    }
    if (const LuaPlus::LuaObject value = table["base"]; value.IsString()) {
      const std::string base = value.GetString();
      if (base == "light") {
        theme.light = true;
      } else if (base != "dark") {
        theme.problems.push_back("base '" + base + "' is neither 'dark' nor 'light'");
      }
    }
    if (const LuaPlus::LuaObject value = table["accent"]; !value.IsNil()) {
      theme.hasAccent = ColorOf(value, theme.accent);
      if (!theme.hasAccent) {
        theme.problems.emplace_back("accent isn't a colour");
      }
    }
    if (const LuaPlus::LuaObject value = table["rounding"]; value.IsNumber()) {
      theme.rounding = std::clamp(static_cast<float>(value.GetNumber()), 0.0f, 16.0f);
    }
    if (const LuaPlus::LuaObject colors = table["colors"]; colors.IsTable()) {
      for (LuaPlus::LuaTableIterator it(colors, 1); it.IsValid(); it.Next()) {
        if (!it.GetKey().IsString()) {
          continue;
        }
        EdThemeColor color;
        color.name = it.GetKey().GetString();
        if (ColorOf(it.GetValue(), color.rgba)) {
          theme.colors.push_back(color);
        } else {
          theme.problems.push_back("colors." + color.name + " isn't a colour");
        }
      }
      // Lua's table order isn't the file's: by name, so a theme applies the same way each time.
      std::sort(theme.colors.begin(), theme.colors.end(), [](const EdThemeColor& a, const EdThemeColor& b) {
        return a.name < b.name;
      });
    }
    return theme;
  }

  const std::vector<std::string_view>& BuiltInThemeSources()
  {
    // FAF Blue first: the mockup's look is the default.
    static const std::vector<std::string_view> sources = {kFafBlue, kEditorDark, kLight};
    return sources;
  }

  std::vector<EdTheme> LoadThemes(
    const std::filesystem::path& folder
  )
  {
    std::vector<EdTheme> themes;
    for (const std::string_view source : BuiltInThemeSources()) {
      themes.push_back(ReadTheme(std::string(source), "built-in theme"));
    }
    std::error_code error;
    if (folder.empty() || !std::filesystem::is_directory(folder, error)) {
      return themes;
    }
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(folder, error)) {
      if (entry.is_regular_file(error) && entry.path().extension() == ".lua") {
        files.push_back(entry.path());
      }
    }
    std::sort(files.begin(), files.end());
    for (const std::filesystem::path& file : files) {
      std::ifstream in(file, std::ios::binary);
      std::stringstream text;
      text << in.rdbuf();
      EdTheme theme = ReadTheme(text.str(), file.filename().string());
      theme.file = file.string();
      if (theme.name.empty()) {
        theme.name = file.stem().string();
      }
      const auto same = std::find_if(themes.begin(), themes.end(), [&theme](const EdTheme& t) {
        return t.name == theme.name;
      });
      if (same != themes.end()) {
        *same = std::move(theme);
      } else {
        themes.push_back(std::move(theme));
      }
    }
    return themes;
  }
} // namespace faf::editor
