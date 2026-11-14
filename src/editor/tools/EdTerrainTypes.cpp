#include "editor/tools/EdTerrainTypes.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <regex>

namespace faf::editor
{
  std::vector<TerrainTypeInfo> ParseTerrainTypes(
    const std::string& lua
  )
  {
    std::vector<TerrainTypeInfo> types;
    const std::regex head(R"(Name\s*=\s*'([^']*)'\s*,\s*TypeCode\s*=\s*(\d+))");
    std::vector<std::pair<std::size_t, std::smatch>> heads;
    for (auto it = std::sregex_iterator(lua.begin(), lua.end(), head); it != std::sregex_iterator(); ++it) {
      heads.emplace_back(static_cast<std::size_t>(it->position(0)), *it);
    }
    for (std::size_t i = 0; i < heads.size(); ++i) {
      const std::smatch& match = heads[i].second;
      const std::size_t start = heads[i].first;
      const std::size_t end = i + 1 < heads.size() ? heads[i + 1].first : lua.size();
      const std::string entry = lua.substr(start, end - start);
      TerrainTypeInfo type;
      type.name = match[1].str();
      type.code = std::atoi(match[2].str().c_str());
      std::smatch field;
      if (std::regex_search(entry, field, std::regex(R"(\bColor\s*=\s*'([0-9A-Fa-f]{8})')"))) {
        type.color = static_cast<std::uint32_t>(std::strtoul(field[1].str().c_str(), nullptr, 16));
      }
      if (std::regex_search(entry, field, std::regex(R"(\bDescription\s*=\s*'([^'\n]*)')"))) {
        type.description = field[1].str();
      }
      if (std::regex_search(entry, field, std::regex(R"(\bStyle\s*=\s*'([^']*)')"))) {
        type.style = field[1].str();
      }
      type.blocking = std::regex_search(entry, std::regex(R"(\bBlocking\s*=\s*true\b)"));
      if (type.code >= 0 && type.code <= 255) {
        types.push_back(std::move(type));
      }
    }
    return types;
  }

  std::vector<TerrainTypeRun> TerrainTypeRuns(
    const std::uint8_t* const grid,
    const int width,
    const int height,
    const std::uint8_t skip
  )
  {
    std::vector<TerrainTypeRun> runs;
    if (grid == nullptr) {
      return runs;
    }
    for (int z = 0; z < height; ++z) {
      const std::uint8_t* const row = grid + static_cast<std::size_t>(z) * static_cast<std::size_t>(width);
      int x = 0;
      while (x < width) {
        const std::uint8_t code = row[x];
        int end = x + 1;
        while (end < width && row[end] == code) {
          ++end;
        }
        if (code != skip) {
          runs.push_back({x, end, z, code});
        }
        x = end;
      }
    }
    return runs;
  }

  int PaintTerrainType(
    std::uint8_t* const grid,
    const int width,
    const int height,
    const float x,
    const float z,
    const float radius,
    const std::uint8_t code
  )
  {
    if (grid == nullptr || radius <= 0.0f) {
      return 0;
    }
    int changed = 0;
    const int x0 = std::max(0, static_cast<int>(std::floor(x - radius)));
    const int x1 = std::min(width - 1, static_cast<int>(std::ceil(x + radius)));
    const int z0 = std::max(0, static_cast<int>(std::floor(z - radius)));
    const int z1 = std::min(height - 1, static_cast<int>(std::ceil(z + radius)));
    for (int cz = z0; cz <= z1; ++cz) {
      for (int cx = x0; cx <= x1; ++cx) {
        const float dx = static_cast<float>(cx) + 0.5f - x;
        const float dz = static_cast<float>(cz) + 0.5f - z;
        if (dx * dx + dz * dz > radius * radius) {
          continue;
        }
        std::uint8_t& cell =
          grid[static_cast<std::size_t>(cz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(cx)];
        if (cell != code) {
          cell = code;
          ++changed;
        }
      }
    }
    return changed;
  }
  int DefaultTerrainTypeFor(
    const std::string& albedo,
    const std::vector<TerrainTypeInfo>& types
  )
  {
    // FAF Studio's terraintype.lua RULES, first match wins (lower case file names).
    static constexpr std::pair<const char*, int> kRules[] = {
      {"lav_lava", 230}, {"lavalt", 230},   {"lavamd", 230},      {"lavadk", 230},   {"lava0", 230},
      {"lavarock", 152}, {"lav_rock", 152}, {"lav_cracked", 153}, {"lav_gravel", 5}, {"lav_ribbon", 154},
      {"snow", 200},     {"ice", 201},      {"macroice", 201},    {"sandwet", 41},   {"reef_sand", 41},
      {"sand", 40},      {"tarmac", 151},   {"concrete", 151},    {"road", 151},     {"tech_wiers", 151},
      {"grid", 151},     {"grass", 80},     {"hostas", 81},       {"jung", 82},      {"farm", 84},
      {"veg", 83},       {"crystal", 156},  {"cryst", 156},       {"coral", 160},    {"rock", 150},
      {"cliff", 158},    {"stone", 150},    {"ashley", 6},        {"gravel", 4},     {"dirt", 2},
      {"mud", 3},        {"soil", 2},       {"trans", 2},
    };
    std::string name =
      albedo.substr(albedo.find_last_of("/\\") == std::string::npos ? 0 : albedo.find_last_of("/\\") + 1);
    for (char& c : name) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    for (const auto& [word, code] : kRules) {
      if (name.find(word) != std::string::npos) {
        if (std::any_of(types.begin(), types.end(), [code = code](const TerrainTypeInfo& t) {
          return t.code == code;
        })) {
          return code;
        }
      }
    }
    return 1;
  }

  std::size_t TerrainTypesFromLayers(
    const std::uint64_t* const texels,
    const int maskWidth,
    const int maskHeight,
    const std::uint8_t remapped,
    const std::array<bool, 9>& textured,
    const std::array<int, 9>& types,
    std::uint8_t* const grid,
    const int gridWidth,
    const int gridHeight,
    const bool onlyDefault
  )
  {
    if (texels == nullptr || grid == nullptr || maskWidth < 1 || maskHeight < 1 || gridWidth < 1 || gridHeight < 1) {
      return 0;
    }
    std::size_t changed = 0;
    for (int z = 0; z < gridHeight; ++z) {
      const int mz = std::min(
        maskHeight - 1,
        static_cast<int>(
          (static_cast<float>(z) + 0.5f) * static_cast<float>(maskHeight) / static_cast<float>(gridHeight)
        )
      );
      for (int x = 0; x < gridWidth; ++x) {
        const int mx = std::min(
          maskWidth - 1,
          static_cast<int>(
            (static_cast<float>(x) + 0.5f) * static_cast<float>(maskWidth) / static_cast<float>(gridWidth)
          )
        );
        const std::uint64_t texel =
          texels[static_cast<std::size_t>(mz) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(mx)];
        // The layer seen most: from the top down, each takes its weight of what is left.
        float remaining = 1.0f;
        int bestLayer = 0;
        float bestShare = -1.0f;
        for (int layer = 8; layer >= 1; --layer) {
          if (!textured[static_cast<std::size_t>(layer)]) {
            continue;
          }
          const int byte = layer - 1;
          const int stored = static_cast<int>((texel >> (8 * byte)) & 0xFFu);
          const float weight = (remapped & (1U << byte)) != 0
            ? std::max(0.0f, 2.0f * static_cast<float>(stored) / 255.0f - 1.0f)
            : static_cast<float>(stored) / 255.0f;
          if (weight <= 0.0f) {
            continue;
          }
          const float share = weight * remaining;
          if (share > bestShare) {
            bestShare = share;
            bestLayer = layer;
          }
          remaining *= 1.0f - weight;
        }
        if (remaining >= bestShare) {
          bestLayer = 0;
        }
        std::uint8_t& cell =
          grid[static_cast<std::size_t>(z) * static_cast<std::size_t>(gridWidth) + static_cast<std::size_t>(x)];
        if (onlyDefault && cell > 1) {
          continue;
        }
        const auto code = static_cast<std::uint8_t>(std::clamp(types[static_cast<std::size_t>(bestLayer)], 0, 255));
        if (cell != code) {
          cell = code;
          ++changed;
        }
      }
    }
    return changed;
  }
} // namespace faf::editor
