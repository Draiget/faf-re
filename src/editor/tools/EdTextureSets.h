#pragma once

#include "editor/tools/EdGroundKind.h"

#include <array>
#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Texture sets (FAF Studio's texsets.lua): ready-made choices of terrain textures by kind of ground, so a map gets a
   * look in one step. A set names, for the base layer, the Upper layer and each of the eight kinds, candidate paths in
   * the game data (the first that exists is used).
   */
  struct TextureTheme
  {
    const char* id;
    const char* label;
    float size; // the tile when a texture can't be read
    std::vector<const char*> base;
    std::vector<const char*> upper;
    std::array<std::vector<const char*>, 9> kinds; // by GroundKind
  };
  [[nodiscard]] const std::vector<TextureTheme>& TextureThemes();

  /**
   * The painted layer of every kind for a shader (0: the shader has no layer for it): the standard 8 layers (grass 1,
   * rock 2, sand 3, dirt 4, wet 5, high rock 6, dark rock 7, snow 8); 7 layers without dark rock, snow on 7; the
   * biplanar ones put rock and high rock on 3 and 4 (drawn from the side); 4 layers (TTerrain): rock, sand, dirt, snow
   * (grass is the base).
   */
  [[nodiscard]] std::array<int, 9> ThemeLayout(int painted, bool biplanar);

  struct ThemeSlot
  {
    int slot = 0; // 0 base, 1..8 painted, 9 Upper
    GroundKind kind = GroundKind::Unknown;
    std::string albedo;
    float size = 0.0f;
  };

  /**
   * What a theme gives the layers: the base, each kind's layer in the layout, and the Upper layer when the shader draws
   * it as an overlay (`upperOverlay`). `exists(path)` says whether the game data has a file; `pixels(path)` its width
   * (0: unreadable). Tile sizes are optimal for each texture (the theme's size when it can't be read; the base twice
   * it); the Upper layer's is the base's MacroTile.
   */
  [[nodiscard]] std::vector<ThemeSlot> ThemeSlots(
    const TextureTheme& theme,
    int painted,
    bool biplanar,
    bool upperOverlay,
    const std::function<bool(const std::string&)>& exists,
    const std::function<int(const std::string&)>& pixels
  );
} // namespace faf::editor
