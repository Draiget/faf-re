// Host test of the banks of water bodies (src/moho/terrain/water/WaterBanks.h, docs/WATER_SIMULATION.md, "Banks"): the
// growth of a river's water over the pits beside it (up to the ground, never past the rings, the river's own reach, the
// sea or another body) and the source patch of water2.fx (it must refuse text it does not recognise and leave it
// untouched; with FAF_STOCK_FX_DIR naming a folder with FAF's stock water2.fx it must patch it completely, once, leave
// the other techniques alone and apply to the text the river patch makes of it as well). Pure C++, no engine objects.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "moho/terrain/water/RiverFlow.h"
#include "moho/terrain/water/WaterBanks.h"

namespace
{
  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    ++gChecks;                                                                                                         \
    if (!(cond)) {                                                                                                     \
      ++gFailures;                                                                                                     \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  using namespace moho::water;

  // The river's field as the engine's callback gives it: the level at a vertex is `level[body] - slope * x`, and a
  // vertex further than `half + reach` from the row `centre` is out of the river's reach.
  struct Field
  {
    float level[3] = {0.0f, 10.0f, 9.0f};
    float slope = 0.0f;
    float centre = 17.5f;
    float half = 3.0f;
    float reach = 100.0f;
    // a lake: its level whatever the vertex, and no further than `lakeRings` rings
    bool lake = false;
    int lakeRings = 3;
  };

  bool FieldLevel(
    const void* const context,
    const std::uint8_t body,
    const int x,
    const int z,
    const int ring,
    float& level
  )
  {
    const Field& field = *static_cast<const Field*>(context);
    if (field.lake) {
      level = field.level[body];
      return ring < field.lakeRings;
    }
    const float dz = static_cast<float>(z) - field.centre;
    const float distance = dz < 0.0f ? -dz : dz;
    if (body > 2u || distance > field.half + field.reach) {
      return false;
    }
    level = field.level[body] - field.slope * static_cast<float>(x);
    return true;
  }

  struct Grid
  {
    int width;
    int height;
    std::vector<float> terrain;
    std::vector<std::uint8_t> body;
    std::vector<std::uint8_t> grownBody;
    std::vector<float> grownLevel;
    bool grows[256] = {};
    Field field;

    Grid(
      const int w,
      const int h,
      const float ground
    )
      : width(w)
      , height(h)
      , terrain(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), ground)
      , body(terrain.size(), 0u)
      , grownBody(terrain.size(), 0u)
      , grownLevel(terrain.size(), 0.0f)
    {}

    std::size_t At(
      const int x,
      const int z
    ) const
    {
      return static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x);
    }

    std::size_t Grow(
      const float sea,
      const int rings
    )
    {
      return GrowBanks(
        width,
        height,
        terrain.data(),
        body.data(),
        grows,
        sea,
        rings,
        &FieldLevel,
        &field,
        grownBody.data(),
        grownLevel.data()
      );
    }
  };

  // A channel across the grid along x: wet rows z in [z0, z1] at level 10 (bed 5), a pit of ground 6 on both sides
  // (below the level) as far as `pit` rows, then ground 20 (a bank).
  Grid Channel(
    const int z0,
    const int z1,
    const int pit
  )
  {
    Grid grid(24, 40, 20.0f);
    for (int z = 0; z < grid.height; ++z) {
      for (int x = 0; x < grid.width; ++x) {
        const bool wet = z >= z0 && z <= z1;
        const bool inPit = (z < z0 && z0 - z <= pit) || (z > z1 && z - z1 <= pit);
        if (wet) {
          grid.terrain[grid.At(x, z)] = 5.0f;
          grid.body[grid.At(x, z)] = 1u;
        } else if (inPit) {
          grid.terrain[grid.At(x, z)] = 6.0f;
        }
      }
    }
    grid.grows[1] = true;
    grid.field.centre = 0.5f * static_cast<float>(z0 + z1);
    grid.field.half = 0.5f * static_cast<float>(z1 - z0);
    return grid;
  }

  void TestGrowth()
  {
    std::printf("growth: the pit beside a river joins its water up to the ground\n");
    {
      Grid grid = Channel(15, 20, 4);
      const std::size_t grown = grid.Grow(-10000.0f, 8);
      // 4 rows each side over the width
      CHECK(grown == static_cast<std::size_t>(8 * grid.width));
      for (int x = 0; x < grid.width; ++x) {
        for (int z = 0; z < grid.height; ++z) {
          const bool pit = (z >= 11 && z <= 14) || (z >= 21 && z <= 24);
          CHECK(grid.grownBody[grid.At(x, z)] == (pit ? 1u : 0u));
          if (pit) {
            CHECK(grid.grownLevel[grid.At(x, z)] == 10.0f);
          }
        }
      }
      // the ground above the level stops it: row 10 and row 25 are 20 high
      CHECK(grid.grownBody[grid.At(3, 10)] == 0u && grid.grownBody[grid.At(3, 25)] == 0u);
      // the inputs are not touched
      CHECK(grid.body[grid.At(3, 12)] == 0u && grid.body[grid.At(3, 17)] == 1u);
    }
    std::printf("growth: the rings cap a pit that goes on, and so does the river's own reach\n");
    {
      Grid grid = Channel(15, 20, 30);
      const std::size_t grown = grid.Grow(-10000.0f, 3);
      CHECK(grown == static_cast<std::size_t>(6 * grid.width));
      CHECK(grid.grownBody[grid.At(5, 12)] == 1u && grid.grownBody[grid.At(5, 11)] == 0u);
      CHECK(grid.grownBody[grid.At(5, 23)] == 1u && grid.grownBody[grid.At(5, 24)] == 0u);
      Grid none = Channel(15, 20, 30);
      CHECK(none.Grow(-10000.0f, 0) == 0);
      // the field says nothing further than 4 past the half width of 2.5 from the middle row 17.5: rows 11 to 24
      Grid reach = Channel(15, 20, 30);
      reach.field.reach = 4.0f;
      CHECK(reach.Grow(-10000.0f, 30) == static_cast<std::size_t>(8 * reach.width));
      CHECK(reach.grownBody[reach.At(5, 11)] == 1u && reach.grownBody[reach.At(5, 10)] == 0u);
      CHECK(reach.grownBody[reach.At(5, 24)] == 1u && reach.grownBody[reach.At(5, 25)] == 0u);
    }
    std::printf("growth: not below the sea, not into another body, a body that does not grow stays\n");
    {
      // every pit vertex (6) is below the sea level 7: the sea has it
      Grid grid = Channel(15, 20, 4);
      CHECK(grid.Grow(7.0f, 8) == 0);
      Grid lake = Channel(15, 20, 4);
      for (int x = 0; x < lake.width; ++x) {
        for (int z = 21; z <= 24; ++z) {
          lake.body[lake.At(x, z)] = 2u;
        }
      }
      CHECK(lake.Grow(-10000.0f, 8) == static_cast<std::size_t>(4 * lake.width));
      CHECK(lake.grownBody[lake.At(2, 23)] == 0u); // the lake's own vertices are not grown over
      Grid noGrow = Channel(15, 20, 4);
      noGrow.grows[1] = false;
      CHECK(noGrow.Grow(-10000.0f, 8) == 0);
    }
    std::printf(
      "growth: a sloped river's banks take the river's level there, not the level of the water they grow from\n"
    );
    {
      Grid grid = Channel(15, 20, 6);
      grid.field.slope = 0.25f;
      (void)grid.Grow(-10000.0f, 8);
      // the pit ground is 6: it joins where the level of its column (10 - x / 4) is above it, x up to 15, and every
      // vertex has the level of its own column whatever column the water came from
      for (int x = 0; x < grid.width; ++x) {
        const float want = 10.0f - 0.25f * static_cast<float>(x);
        const bool joins = want > 6.0f;
        for (const int z : {12, 13, 14, 21, 22, 23}) {
          CHECK((grid.grownBody[grid.At(x, z)] == 1u) == joins);
          if (joins) {
            CHECK(grid.grownLevel[grid.At(x, z)] == want);
          }
        }
      }
    }
    std::printf("growth: a lake grows as many rings as its reach, at its level\n");
    {
      Grid grid = Channel(15, 20, 30);
      grid.field.lake = true;
      grid.field.lakeRings = 3;
      CHECK(grid.Grow(-10000.0f, 30) == static_cast<std::size_t>(6 * grid.width));
      CHECK(grid.grownBody[grid.At(5, 12)] == 1u && grid.grownBody[grid.At(5, 11)] == 0u);
      CHECK(grid.grownLevel[grid.At(5, 12)] == 10.0f);
      // a dry body does not grow
      Grid dry = Channel(15, 20, 30);
      dry.field.lake = true;
      dry.grows[1] = false;
      CHECK(dry.Grow(-10000.0f, 30) == 0);
    }
    std::printf("growth: two rivers meeting over one vertex, the lower number wins; the result is repeatable\n");
    {
      Grid grid(12, 12, 6.0f);
      grid.grows[1] = grid.grows[2] = true;
      grid.body[grid.At(2, 6)] = 2u;
      grid.body[grid.At(8, 6)] = 1u;
      grid.terrain[grid.At(2, 6)] = grid.terrain[grid.At(8, 6)] = 3.0f;
      grid.field.centre = 6.0f;
      (void)grid.Grow(-10000.0f, 3);
      // vertex (5, 6) is three steps from both: body 1 gets it with its level
      CHECK(grid.grownBody[grid.At(5, 6)] == 1u && grid.grownLevel[grid.At(5, 6)] == 10.0f);
      Grid again = grid;
      (void)again.Grow(-10000.0f, 3);
      CHECK(again.grownBody == grid.grownBody && again.grownLevel == grid.grownLevel);
    }
    std::printf("growth: the map's edge, an empty map\n");
    {
      Grid grid = Channel(0, 3, 4);
      CHECK(grid.Grow(-10000.0f, 8) == static_cast<std::size_t>(4 * grid.width));
      Grid none(8, 8, 6.0f);
      CHECK(none.Grow(-10000.0f, 8) == 0);
      CHECK(GrowBanks(0, 0, nullptr, nullptr, none.grows, 0.0f, 8, &FieldLevel, &none.field, nullptr, nullptr) == 0);
      CHECK(none.Grow(-10000.0f, 8) == 0);
    }
  }

  std::size_t Count(
    const std::string& text,
    const std::string& needle
  )
  {
    std::size_t n = 0;
    for (std::size_t p = text.find(needle); p != std::string::npos; p = text.find(needle, p + needle.size())) {
      ++n;
    }
    return n;
  }

  bool ReadFile(
    const std::string& path,
    std::string& out
  )
  {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
  }

  void TestRefusesUnknownText()
  {
    std::printf("patch: text without the anchors is left alone\n");
    std::string empty;
    CHECK(!PatchWaterBanks(empty).patched && empty.empty());
    std::string other = "float4 HighFidelityPS() { return 0; }\n";
    const std::string copy = other;
    const BankPatchResult result = PatchWaterBanks(other);
    CHECK(!result.patched && !result.error.empty() && other == copy);
    // the mask shader twice
    std::string twice = "struct MASK_OUTPUT { float4 p; };\nfloat4 WaterLayAlphaMaskPS(MASK_OUTPUT i)\n{\n return "
                        "float4(0,0,0,output.b);\n"
                        "}\nfloat4 WaterLayAlphaMaskPS(MASK_OUTPUT i)\n{\n return float4(0,0,0,output.b);\n}\n";
    const std::string twiceCopy = twice;
    CHECK(!PatchWaterBanks(twice).patched && twice == twiceCopy);
    // the anchors out of order
    std::string order = "float4 WaterLayAlphaMaskPS(MASK_OUTPUT i)\n{\n return float4(0,0,0,output.b);\n}\nstruct "
                        "MASK_OUTPUT { float4 p; };\n";
    const std::string orderCopy = order;
    CHECK(!PatchWaterBanks(order).patched && order == orderCopy);
    // a minimal text: patched once
    std::string minimal =
      "texture A;\nstruct MASK_OUTPUT { float4 p; };\nfloat4 WaterLayAlphaMaskPS(MASK_OUTPUT i)\n{\n"
      "  float4 output = 0;\n  return float4(0,0,0,output.b);\n}\n";
    CHECK(PatchWaterBanks(minimal).patched);
    CHECK(Count(minimal, "float4 waterBankParams;") == 1);
    CHECK(Count(minimal, "return float4(0,0,0,waterBankParams.x > 0.5 ? 0.0 : output.b);") == 1);
    CHECK(Count(minimal, "return float4(0,0,0,output.b);") == 0);
    CHECK(minimal.find("float4 waterBankParams;") < minimal.find("struct MASK_OUTPUT"));
    std::string again = minimal;
    CHECK(!PatchWaterBanks(again).patched && again == minimal);
  }

  void TestPatch(
    const std::string& base,
    const char* const label
  )
  {
    std::printf("patch: the %s water2.fx\n", label);
    std::string text = base;
    const BankPatchResult result = PatchWaterBanks(text);
    CHECK(result.patched);
    if (!result.patched) {
      std::printf("  %s\n", result.error.c_str());
      return;
    }
    CHECK(Count(text, "float4 waterBankParams;") == 1);
    CHECK(Count(text, "waterBankParams.x > 0.5 ? 0.0 : output.b") == 1);
    // the declaration precedes the mask vertex shader's structure and the pixel shader that reads it
    CHECK(text.find("float4 waterBankParams;") < text.find("struct MASK_OUTPUT"));
    CHECK(text.find("struct MASK_OUTPUT") < text.find("float4 WaterLayAlphaMaskPS("));
    // the pass states of the mask technique and everything around the patched lines are the shipped ones
    CHECK(Count(text, "technique TWaterLayAlphaMask") == 1);
    CHECK(Count(text, "AlphaFunc = Equal;") == Count(base, "AlphaFunc = Equal;"));
    CHECK(text.size() > base.size());
    // exactly the two edits: taking them out gives the shipped text back
    std::string undone = text;
    const std::size_t declAt = undone.find("// ---- FAF banks of water bodies");
    const std::size_t structAt = undone.find("struct MASK_OUTPUT");
    CHECK(declAt != std::string::npos && structAt != std::string::npos && declAt < structAt);
    if (declAt != std::string::npos && structAt != std::string::npos && declAt < structAt) {
      undone.erase(declAt, structAt - declAt);
      const std::string patched = "return float4(0,0,0,waterBankParams.x > 0.5 ? 0.0 : output.b);";
      const std::size_t at = undone.find(patched);
      CHECK(at != std::string::npos);
      if (at != std::string::npos) {
        undone.replace(at, patched.size(), "return float4(0,0,0,output.b);");
      }
      CHECK(undone == base);
    }
    std::string again = text;
    CHECK(!PatchWaterBanks(again).patched && again == text);
    // the river patch and this one do not touch each other's lines, in either order
    std::string rivered = base;
    const bool riverPatched = PatchWaterRivers(rivered).patched;
    CHECK(riverPatched);
    if (riverPatched) {
      std::string both = rivered;
      CHECK(PatchWaterBanks(both).patched);
      std::string other = text;
      CHECK(PatchWaterRivers(other).patched);
      CHECK(Count(both, "float4 waterBankParams;") == 1 && Count(both, "float4 waterRiverParams;") == 1);
      CHECK(Count(other, "float4 waterBankParams;") == 1 && Count(other, "float4 waterRiverParams;") == 1);
      CHECK(both.size() == other.size());
    }
  }
} // namespace

int main()
{
  TestGrowth();
  TestRefusesUnknownText();
  if (const char* const directory = std::getenv("FAF_STOCK_FX_DIR"); directory != nullptr && *directory != '\0') {
    std::string stock;
    if (ReadFile(std::string(directory) + "/water2.fx", stock)) {
      TestPatch(stock, "stock");
    } else {
      std::printf("water2.fx not found in %s\n", directory);
      ++gFailures;
    }
  } else {
    std::printf("FAF_STOCK_FX_DIR not set: the stock water2.fx checks are skipped\n");
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures == 0 ? 0 : 1;
}
