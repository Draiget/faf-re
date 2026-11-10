#include "editor/tools/EdTerrainTypes.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <regex>

namespace faf::editor
{
  std::vector<TerrainTypeInfo> ParseTerrainTypes(const std::string& lua)
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

  std::vector<TerrainTypeRun> TerrainTypeRuns(const std::uint8_t* const grid, const int width, const int height, const std::uint8_t skip)
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

  int PaintTerrainType(std::uint8_t* const grid, const int width, const int height, const float x, const float z, const float radius,
                       const std::uint8_t code)
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
        std::uint8_t& cell = grid[static_cast<std::size_t>(cz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(cx)];
        if (cell != code) {
          cell = code;
          ++changed;
        }
      }
    }
    return changed;
  }
} // namespace faf::editor
