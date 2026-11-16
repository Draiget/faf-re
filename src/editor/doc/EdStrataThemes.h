#pragma once

// Strata themes (FAF Studio's envlib.lua Themes and data/envlib_themes.lua): the textures and tile sizes of a map's
// layers, by slot (0 the base, 1..8 the painted layers, 9 the Upper layer), from the shipped maps, hand picked, or the
// user's own (saved from a map or imported from another map's file).

#include <map>
#include <expected>
#include <string>
#include <vector>

namespace faf::editor
{
  struct StrataThemeLayer
  {
    std::string albedo;
    std::string normal;
    float size = 4.0f;
    float nsize = 4.0f;
  };

  struct StrataTheme
  {
    std::string id;
    std::string name;
    std::string group; // "Curated", "Campaign", ... or "My themes"
    std::string desc;
    std::map<int, StrataThemeLayer> layers;
    bool user = false;
  };

  /** The themes of a `Themes = { ... }` (or `UserThemes = { ... }`) table; the error otherwise. */
  [[nodiscard]] std::expected<void, std::string>
  ParseStrataThemes(const std::string& text, const char* tableName, std::vector<StrataTheme>& out);
  /** The user's themes as a `UserThemes = { ... }` table that ParseStrataThemes reads back. */
  [[nodiscard]] std::string WriteStrataThemes(const std::vector<StrataTheme>& themes);
  /** An id from a name: `user_` and its letters and digits, lower case, others as `_`. */
  [[nodiscard]] std::string StrataThemeId(const std::string& name);
} // namespace faf::editor
