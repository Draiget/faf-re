#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /** One colour a theme sets: an ImGui colour's name without its prefix (`WindowBg`) and its red, green, blue, alpha.
   */
  struct EdThemeColor
  {
    std::string name;
    float rgba[4] = {0.0f, 0.0f, 0.0f, 1.0f};
  };

  /**
   * The editor's look, read from a Lua file (design §3: themes, as the user asked: "based on lua"). The file sets a
   * table `Theme`:
   *
   *     Theme = {
   *         name = 'FAF Blue',
   *         base = 'dark',          -- 'dark' or 'light': ImGui's own colours under the theme's
   *         accent = '#4ea1ff',     -- ticks, sliders, selection, the active tab, the title row's mark
   *         rounding = 5,           -- corners of windows, frames, tabs, popups, in pixels at 100 %
   *         colors = { WindowBg = '#14181e', Text = '#e9edf2', ... },  -- any ImGui colour by name
   *     }
   *
   * Colours are `#rgb`, `#rrggbb`, `#rrggbbaa`, or `{r, g, b[, a]}` from 0 to 1 (or to 255). The file runs with Lua's
   * base library only.
   */
  struct EdTheme
  {
    std::string name;
    std::string file; // where it was read from; empty for a built-in
    bool light = false;
    bool hasAccent = false;
    float accent[4] = {0.0f, 0.0f, 0.0f, 1.0f};
    float rounding = -1.0f; // -1: the editor's own
    std::vector<EdThemeColor> colors;
    /** What the file got wrong (a Lua error, a colour it can't read); the theme still applies what it could read. */
    std::vector<std::string> problems;
  };

  /** `#rgb`, `#rrggbb` or `#rrggbbaa` (the `#` optional) into 0..1 values; false when it isn't one. */
  [[nodiscard]] bool ParseThemeColor(std::string_view text, float rgba[4]);

  /** The theme a Lua text sets; `chunk` names it in Lua's errors. */
  [[nodiscard]] EdTheme ReadTheme(const std::string& text, const std::string& chunk);

  /** The themes the editor carries (Editor Dark, FAF Blue, Light), as Lua texts, the first the default. */
  [[nodiscard]] const std::vector<std::string_view>& BuiltInThemeSources();

  /**
   * The built-in themes, then each `*.lua` in `folder` by file name; a file whose theme has a built-in's name replaces
   * it. A file that names no theme is listed by its file name.
   */
  [[nodiscard]] std::vector<EdTheme> LoadThemes(const std::filesystem::path& folder);
} // namespace faf::editor
