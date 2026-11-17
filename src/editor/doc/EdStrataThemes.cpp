#include "editor/doc/EdStrataThemes.h"

#include "editor/doc/EdJsonTree.h"
#include "editor/doc/EdLuaTable.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  std::expected<void, std::string> ParseStrataThemes(
    const std::string& text,
    const char* const tableName,
    std::vector<StrataTheme>& out
  )
  {
    JsonTree root;
    if (const auto read = ParseLuaAssignments(text, root); !read) {
      return std::unexpected(read.error());
    }
    const JsonTree* const list = root.Get(tableName);
    if (list == nullptr) {
      return std::unexpected(std::string("no ") + tableName + " table");
    }
    for (const JsonTree& entry : list->items) {
      StrataTheme theme;
      theme.id = entry.Str("id", "");
      theme.name = entry.Str("name", theme.id);
      theme.group = entry.Str("group", "");
      theme.desc = entry.Str("desc", "");
      if (const JsonTree* const layers = entry.Get("layers"); layers != nullptr) {
        // `[0] = { ... }` keys, and positional entries (1, 2, ...) when the table had no keys.
        const auto take = [&theme](const int slot, const JsonTree& layer) {
          if (slot < 0 || slot > 9 || layer.kind != JsonTree::Kind::Object) {
            return;
          }
          StrataThemeLayer l;
          l.albedo = layer.Str("albedo", "");
          l.normal = layer.Str("normal", "");
          l.size = layer.Float("size", 4.0f);
          l.nsize = layer.Float("nsize", l.size);
          if (!l.albedo.empty()) {
            theme.layers[slot] = l;
          }
        };
        for (const auto& [key, layer] : layers->fields) {
          if (!key.empty() && std::isdigit(static_cast<unsigned char>(key[0])) != 0) {
            take(std::atoi(key.c_str()), layer);
          }
        }
        if (layers->fields.empty()) {
          for (std::size_t i = 0; i < layers->items.size(); ++i) {
            take(static_cast<int>(i) + 1, layers->items[i]);
          }
        }
      }
      if (!theme.id.empty() && !theme.layers.empty()) {
        out.push_back(std::move(theme));
      }
    }
    return {};
  }

  std::string WriteStrataThemes(
    const std::vector<StrataTheme>& themes
  )
  {
    const auto quoted = [](const std::string& text) {
      std::string out = "\"";
      for (const char c : text) {
        if (c == '"' || c == '\\') {
          out += '\\';
        }
        out += c == '\n' ? ' ' : c;
      }
      return out + "\"";
    };
    std::string text =
      "-- The editor's own strata themes (Layers > Theme library), as FAF Studio keeps them.\nUserThemes = {\n";
    for (const StrataTheme& theme : themes) {
      text += "    {\n";
      text += "        id = " + quoted(theme.id) + ",\n";
      text += "        name = " + quoted(theme.name) + ",\n";
      text += "        desc = " + quoted(theme.desc) + ",\n";
      text += "        layers = {\n";
      for (const auto& [slot, layer] : theme.layers) {
        char sizes[96];
        (void)std::snprintf(
          sizes,
          sizeof(sizes),
          "size = %g, nsize = %g",
          static_cast<double>(layer.size),
          static_cast<double>(layer.nsize)
        );
        text += "            [" + std::to_string(slot) + "] = { albedo = " + quoted(layer.albedo) +
          (layer.normal.empty() ? std::string() : ", normal = " + quoted(layer.normal)) + ", " + sizes + " },\n";
      }
      text += "        },\n    },\n";
    }
    return text + "}\n";
  }

  std::string StrataThemeId(
    const std::string& name
  )
  {
    std::string id = "user_";
    for (const char c : name) {
      id += std::isalnum(static_cast<unsigned char>(c)) != 0
        ? static_cast<char>(std::tolower(static_cast<unsigned char>(c)))
        : '_';
    }
    return id;
  }
} // namespace faf::editor
