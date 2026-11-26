// The growth of a river's water over the pits beside it: see WaterBanks.h. Pure arithmetic on arrays, no engine
// types, so the host tests compile it on its own.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "moho/terrain/water/WaterBanks.h"

namespace moho::water
{
  std::size_t GrowBanks(
    const int width,
    const int height,
    const float* const terrain,
    const std::uint8_t* const body,
    const bool (&grows)[256],
    const float seaLevel,
    const int rings,
    const BankLevelFn levelAt,
    const void* const context,
    std::uint8_t* const grownBody,
    float* const grownLevel
  )
  {
    if (width <= 0 || height <= 0) {
      return 0;
    }
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    std::fill(grownBody, grownBody + count, std::uint8_t{0});
    std::fill(grownLevel, grownLevel + count, 0.0f);
    if (rings <= 0 || levelAt == nullptr) {
      return 0;
    }

    // the first ring grows from every wet vertex of a growing body
    std::vector<std::size_t> frontier;
    for (std::size_t i = 0; i < count; ++i) {
      if (body[i] != 0u && grows[body[i]]) {
        frontier.push_back(i);
      }
    }

    // a vertex's claim in the ring being made: the lowest body wins, of one body's levels the lowest
    std::vector<std::uint8_t> claimBody(count, 0u);
    std::vector<float> claimLevel(count, 0.0f);
    std::vector<std::size_t> claimed;
    std::size_t total = 0;
    for (int ring = 0; ring < rings && !frontier.empty(); ++ring) {
      claimed.clear();
      for (const std::size_t from : frontier) {
        const std::uint8_t fromBody = grownBody[from] != 0u ? grownBody[from] : body[from];
        const int x = static_cast<int>(from % static_cast<std::size_t>(width));
        const int z = static_cast<int>(from / static_cast<std::size_t>(width));
        const int steps[4][2] = {{-1, 0}, {1, 0}, {0, -1}, {0, 1}};
        for (const auto& step : steps) {
          const int nx = x + step[0];
          const int nz = z + step[1];
          if (nx < 0 || nz < 0 || nx >= width || nz >= height) {
            continue;
          }
          const std::size_t to =
            static_cast<std::size_t>(nz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(nx);
          if (body[to] != 0u || grownBody[to] != 0u) {
            continue;
          }
          float level = 0.0f;
          if (!levelAt(context, fromBody, nx, nz, ring, level)) {
            continue;
          }
          const float ground = terrain[to];
          if (!(ground < level) || ground < seaLevel) {
            continue;
          }
          if (claimBody[to] == 0u) {
            claimed.push_back(to);
            claimBody[to] = fromBody;
            claimLevel[to] = level;
          } else if (fromBody < claimBody[to] || (fromBody == claimBody[to] && level < claimLevel[to])) {
            claimBody[to] = fromBody;
            claimLevel[to] = level;
          }
        }
      }
      frontier.clear();
      for (const std::size_t to : claimed) {
        grownBody[to] = claimBody[to];
        grownLevel[to] = claimLevel[to];
        claimBody[to] = 0u;
        frontier.push_back(to);
      }
      total += claimed.size();
    }
    return total;
  }
} // namespace moho::water
