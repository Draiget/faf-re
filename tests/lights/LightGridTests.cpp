// Host test of the light texture images (src/moho/render/lights/LightGrid): layout of the data texture, cell
// membership, the 8-entry cell limit, strongest-first order, clamping at the map edges and the lookup the shader will
// do. Called from main() in LightCollectorTests.cpp.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

#include "moho/render/lights/LightGrid.h"

namespace
{
  using namespace moho::lights;

  int gGridFailures = 0;
  int gGridChecks = 0;

#define GCHECK(cond)                                                                                                   \
  do {                                                                                                                 \
    ++gGridChecks;                                                                                                     \
    if (!(cond)) {                                                                                                     \
      ++gGridFailures;                                                                                                 \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  Light MakeLight(
    const float x,
    const float y,
    const float z,
    const float radius,
    const float power = 10.0f
  )
  {
    Light l{};
    l.pos[0] = x;
    l.pos[1] = y;
    l.pos[2] = z;
    l.radius = radius;
    l.rgb[0] = 1.0f;
    l.rgb[1] = 0.5f;
    l.rgb[2] = 0.25f;
    l.kind = Kind::Flash;
    l.power = power;
    return l;
  }

  void TestLayout()
  {
    // 1024 x 1024 map (a 20 km map): 128 cells of 8
    GridLayout a = GridLayout::ForMap(1024.0f, 1024.0f);
    GCHECK(a.cellsX == 128 && a.cellsZ == 128 && a.cellSize == 8.0f);
    // 4096 map (81 km): 128 cells of 32
    GridLayout b = GridLayout::ForMap(4096.0f, 4096.0f);
    GCHECK(b.cellsX == 128 && b.cellsZ == 128 && b.cellSize == 32.0f);
    // 256 map (5 km): the cell does not go below 4, so 64 cells
    GridLayout c = GridLayout::ForMap(256.0f, 256.0f);
    GCHECK(c.cellsX == 64 && c.cellsZ == 64 && c.cellSize == 4.0f);
    // 512 map (10 km): 128 cells of 4
    GridLayout c2 = GridLayout::ForMap(512.0f, 512.0f);
    GCHECK(c2.cellsX == 128 && c2.cellsZ == 128 && c2.cellSize == 4.0f);
    // non-square: the longer side sets the cell size
    GridLayout d = GridLayout::ForMap(1024.0f, 512.0f);
    GCHECK(d.cellsX == 128 && d.cellsZ == 64 && d.cellSize == 8.0f);
    // everything is covered
    GCHECK(static_cast<float>(b.cellsX) * b.cellSize >= 4096.0f);
    GCHECK(static_cast<float>(d.cellsZ) * d.cellSize >= 512.0f);
    // garbage maps still give a valid 1-cell grid
    GridLayout e = GridLayout::ForMap(std::numeric_limits<float>::quiet_NaN(), -5.0f);
    GCHECK(e.cellsX >= 1 && e.cellsZ >= 1 && e.cellSize >= kMinCellSize);
  }

  void TestDataTextureLayout()
  {
    GCHECK(LightGridImage::DataRows(0) == 1);
    GCHECK(LightGridImage::DataRows(1) == 1);
    GCHECK(LightGridImage::DataRows(341) == 1); // 1023 texels
    GCHECK(LightGridImage::DataRows(342) == 2); // 1026 texels

    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    std::vector<Light> lights;
    lights.push_back(MakeLight(100.0f, 7.0f, 200.0f, 30.0f));
    Light second = MakeLight(500.0f, 3.0f, 600.0f, 12.0f);
    second.rgb[0] = 2.0f;
    second.kind = Kind::Glow;
    lights.push_back(second);

    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.lightCount == 2);
    GCHECK(image.data.size() == static_cast<std::size_t>(kDataWidth) * 4);
    // light 0: A, B, C
    GCHECK(image.data[0] == 100.0f && image.data[1] == 7.0f && image.data[2] == 200.0f && image.data[3] == 30.0f);
    GCHECK(
      image.data[4] == 1.0f && image.data[5] == 0.5f && image.data[6] == 0.25f &&
      image.data[7] == static_cast<float>(Kind::Flash)
    );
    GCHECK(image.data[8] == 100.0f && image.data[9] == 7.0f && image.data[10] == 200.0f && image.data[11] == 0.0f);
    // light 1 starts at texel 3
    const std::size_t o = 3 * 4;
    GCHECK(image.data[o + 0] == 500.0f && image.data[o + 3] == 12.0f);
    GCHECK(image.data[o + 4] == 2.0f && image.data[o + 7] == static_cast<float>(Kind::Glow));
    GCHECK(
      image.grid.size() == static_cast<std::size_t>(image.GridRows()) * kGridTexelWidth * 4 && image.GridRows() >= 1
    );
  }

  void TestMembership()
  {
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f); // cells of 16
    std::vector<Light> lights{MakeLight(100.0f, 0.0f, 100.0f, 20.0f)};
    LightGridImage image;
    BuildLightGrid(lights, layout, image);

    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(100.0f, 100.0f, idx) == 1 && idx[0] == 0); // at the centre
    GCHECK(image.CellLights(115.0f, 100.0f, idx) == 1);                // in the cell next door, within the radius
    GCHECK(image.CellLights(85.0f, 100.0f, idx) == 1);
    GCHECK(image.CellLights(100.0f, 400.0f, idx) == 0); // far away
    // The cell test is by rectangle: a cell whose nearest point is further than the radius does not list the light
    // Light at (100,100) r=20: x in [80,120]; cell x index 7 covers [112,128) -> nearest 12 < 20 yes; index 8 [128,144)
    // -> 28 > 20 no
    GCHECK(image.CellLights(130.0f, 100.0f, idx) == 0);
    // corners of the bounding square outside the circle are not listed: cell (7,7) covers [112,128): nearest corner
    // (112,112) is sqrt(12^2+12^2)=16.97 < 20 -> listed; cell (8,8)=[128,144): sqrt(28^2*2)=39 -> not
    GCHECK(image.CellLights(135.0f, 135.0f, idx) == 0);
    GCHECK(image.cellsLit > 4);

    // CellCount agrees with CellLights
    GCHECK(image.CellCount(12, 12) == 1); // cell [96,104) x [96,104) holds (100,100)
    GCHECK(image.CellCount(127, 127) == 0);
    GCHECK(image.CellCount(128, 0) == 0); // out of range
  }

  void TestOrderAndOverflow()
  {
    // more lights on one spot than a cell lists: the safety limit holds, the strongest come first, nothing else is lost
    const GridLayout layout = GridLayout::ForMap(256.0f, 256.0f);
    std::vector<Light> lights;
    for (std::uint32_t i = 0; i < kMaxLightsPerCell + 16; ++i) {
      lights.push_back(MakeLight(128.0f, 0.0f, 128.0f, 10.0f, 100.0f - static_cast<float>(i)));
    }
    LightGridImage image;
    BuildLightGrid(lights, layout, image);

    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(128.0f, 128.0f, idx) == kMaxLightsPerCell);
    for (std::uint32_t i = 0; i < kMaxLightsPerCell; ++i) {
      GCHECK(idx[i] == i); // equal at the middle of the cell: the ranking order of the lights
    }
    GCHECK(image.overflow > 0);
    GCHECK(
      image.lightCount == kMaxLightsPerCell + 16
    ); // all lights are in the data texture, only the cell list is limited
  }

  void TestCrowdedCellRejectsWholeLights()
  {
    // A cell full of lights must not cut its own list: a weaker light that reaches the full cell and an empty one is
    // left out of both (otherwise the two cells disagree about it and the lighting steps at their border: the lit
    // squares of a big fight).
    const GridLayout layout = GridLayout::ForMap(256.0f, 256.0f); // cells of 4
    std::vector<Light> lights;
    for (std::uint32_t i = 0; i < kMaxLightsPerCell; ++i) {
      lights.push_back(MakeLight(130.0f, 0.0f, 130.0f, 1.0f, 1000.0f - static_cast<float>(i)));
    }
    lights.push_back(MakeLight(134.0f, 0.0f, 130.0f, 10.0f, 1.0f)); // the weak one, index kMaxLightsPerCell
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    std::uint32_t idx[kMaxLightsPerCell];
    const std::uint32_t full = image.CellLights(130.0f, 130.0f, idx);
    GCHECK(full == kMaxLightsPerCell);
    bool weakInFull = false;
    for (std::uint32_t i = 0; i < full; ++i) {
      weakInFull = weakInFull || idx[i] == kMaxLightsPerCell;
    }
    GCHECK(!weakInFull);
    const std::uint32_t near = image.CellLights(140.0f, 130.0f, idx);
    for (std::uint32_t i = 0; i < near; ++i) {
      GCHECK(idx[i] != kMaxLightsPerCell); // left out of the neighbour too
    }
    GCHECK(image.overflow > 0);
  }

  void TestCellListsAreComplete()
  {
    // Twenty lights reach the same cells (more than the 8 and 16 entries of the earlier layouts): every one of them is
    // listed in every cell it reaches, so two neighbouring cells never disagree about a light that reaches both (that
    // disagreement was the lit square).
    const GridLayout layout = GridLayout::ForMap(256.0f, 256.0f); // cells of 4
    std::vector<Light> lights;
    for (std::uint32_t i = 0; i < 20; ++i) {
      lights.push_back(
        MakeLight(130.0f + 0.5f * static_cast<float>(i), 0.0f, 130.0f, 12.0f, 100.0f - static_cast<float>(i))
      );
    }
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.overflow == 0);
    std::uint32_t idx[kMaxLightsPerCell];
    for (float x = 120.0f; x < 150.0f; x += 4.0f) {
      GCHECK(image.CellLights(x + 2.0f, 130.0f, idx) >= 1);
    }
    // a point close to every light's centre sees all 20 on both sides of a cell border
    GCHECK(image.CellLights(135.9f, 130.0f, idx) == 20);
    GCHECK(image.CellLights(136.1f, 130.0f, idx) == 20);
    GCHECK(image.CellLights(135.9f, 133.9f, idx) == 20);
    GCHECK(image.CellLights(135.9f, 134.1f, idx) == 20);
  }

  void TestStrongestAtTheMiddleFirst()
  {
    // Three strong lights that only graze the cell at (134, 134) are first in the ranking; a weak one right on top of
    // the cell comes last. The list is ordered by what each adds at the middle of the cell, so the weak one leads.
    const GridLayout layout =
      GridLayout::ForMap(256.0f, 256.0f); // 4 unit cells: the cell [132,136) has its middle at 134
    std::vector<Light> lights;
    for (std::uint32_t i = 0; i < 3; ++i) {
      lights.push_back(MakeLight(143.5f, 0.0f, 134.0f, 10.0f, 100.0f - static_cast<float>(i)));
    }
    Light weak = MakeLight(134.0f, 0.0f, 134.0f, 10.0f, 1.0f);
    weak.rgb[0] = 0.3f;
    weak.rgb[1] = 0.15f;
    weak.rgb[2] = 0.07f;
    lights.push_back(weak);
    LightGridImage image;
    BuildLightGrid(lights, layout, image);

    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(134.0f, 134.0f, idx) == 4);
    GCHECK(idx[0] == 3); // the weak one on top of the cell
    GCHECK(idx[1] == 0 && idx[2] == 1 && idx[3] == 2);
  }

  Occluder BoxAt(
    const float x,
    const float y,
    const float z,
    const float hx,
    const float hy,
    const float hz
  )
  {
    Occluder o;
    o.center[0] = x;
    o.center[1] = y;
    o.center[2] = z;
    o.axis[0][0] = hx;
    o.axis[1][1] = hy;
    o.axis[2][2] = hz;
    return o;
  }

  void TestWithoutCells()
  {
    // The irradiance field reads the light data and the casters only: a build without the cells makes the same data and
    // the same casters, an empty table and no lists.
    const GridLayout layout = GridLayout::ForMap(256.0f, 256.0f);
    std::vector<Light> lights;
    for (std::uint32_t i = 0; i < 12; ++i) {
      lights.push_back(
        MakeLight(100.0f + 3.0f * static_cast<float>(i), 3.0f, 100.0f, 14.0f, 50.0f - static_cast<float>(i))
      );
    }
    lights.push_back(MakeLight(std::numeric_limits<float>::quiet_NaN(), 0.0f, 0.0f, 5.0f)); // skipped in both
    std::vector<Occluder> boxes{
      BoxAt(104.0f, 1.0f, 100.0f, 2.0f, 1.0f, 2.0f), BoxAt(10.0f, 1.0f, 10.0f, 2.0f, 1.0f, 2.0f)
    };
    LightGridImage full;
    LightGridImage field;
    BuildLightGrid(lights, layout, full, &boxes);
    BuildLightGrid(lights, layout, field, &boxes, false);
    GCHECK(field.lightCount == full.lightCount && field.lightCount == 12);
    GCHECK(field.data == full.data);
    GCHECK(field.occluderCount == full.occluderCount && field.occluderCount >= 1);
    GCHECK(field.occluders == full.occluders);
    GCHECK(field.grid.empty() && field.gridTexels == 0 && field.GridRows() == 0);
    GCHECK(field.entries == 0 && field.cellsLit == 0 && field.occluderEntries == 0);
    GCHECK(!full.grid.empty() && full.entries > 0);
    // the full build after a build without cells is the full build again (the same image object is reused every frame)
    BuildLightGrid(lights, layout, field, &boxes);
    GCHECK(field.grid == full.grid && field.entries == full.entries && field.occluderEntries == full.occluderEntries);
  }

  void TestOccluders()
  {
    const GridLayout layout = GridLayout::ForMap(256.0f, 256.0f); // cells of 4
    std::vector<Light> lights{MakeLight(100.0f, 3.0f, 100.0f, 12.0f)};
    // one box beside the light, one far away, one big and beside it
    std::vector<Occluder> boxes{
      BoxAt(106.0f, 1.0f, 100.0f, 1.0f, 1.0f, 2.0f),
      BoxAt(200.0f, 1.0f, 200.0f, 1.0f, 1.0f, 1.0f),
      BoxAt(94.0f, 2.0f, 103.0f, 3.0f, 2.0f, 3.0f)
    };
    LightGridImage image;
    BuildLightGrid(lights, layout, image, &boxes);
    // the far box does not touch a light: not in the data texture; the other two are, the larger first
    GCHECK(image.occluderCount == 2);
    GCHECK(image.OccluderRows() == 1);
    GCHECK(
      image.occluders[0] == 94.0f && image.occluders[1] == 2.0f && image.occluders[2] == 103.0f
    ); // the larger box has index 0
    // texel 1 is the first half-extent vector with 1 / length squared in w
    GCHECK(
      image.occluders[4] == 3.0f && image.occluders[5] == 0.0f && image.occluders[7] > 0.1f &&
      image.occluders[7] < 0.12f
    );
    GCHECK(image.occluders[8 + 1] == 2.0f && image.occluders[12 + 2] == 3.0f);
    // the box next to the light is listed in the cell of the light and in the cells behind it, up to the reach
    std::uint32_t idx[kMaxOccludersPerCell];
    GCHECK(image.CellOccluders(100.0f, 100.0f, idx) == 2);
    GCHECK(image.CellOccluders(120.0f, 100.0f, idx) >= 1); // 14 behind the small box (reach 16 + its radius)
    GCHECK(image.CellOccluders(200.0f, 200.0f, idx) == 0); // nothing near
    GCHECK(image.occluderEntries > 4);
    // the light lists did not change
    std::uint32_t lightIdx[kMaxLightsPerCell];
    GCHECK(image.CellLights(100.0f, 100.0f, lightIdx) == 1 && lightIdx[0] == 0);

    // a light that lights a screen casts no shadows: the same box is not listed
    std::vector<Light> big{MakeLight(100.0f, 3.0f, 100.0f, 100.0f)};
    BuildLightGrid(big, layout, image, &boxes);
    GCHECK(image.occluderCount == 0 && image.CellOccluders(100.0f, 100.0f, idx) == 0);

    // no occluders given: no change in the lists, an empty occluder texture
    BuildLightGrid(lights, layout, image);
    GCHECK(image.occluderCount == 0 && image.occluders.empty() && image.CellLights(100.0f, 100.0f, lightIdx) == 1);

    // more than kMaxOccludersPerCell around one light: the cell lists the first (largest) ones
    boxes.clear();
    for (int i = 0; i < 40; ++i) {
      boxes.push_back(BoxAt(
        100.0f + 0.1f * static_cast<float>(i), 1.0f, 100.0f, 1.0f + 0.01f * static_cast<float>(40 - i), 1.0f, 1.0f
      ));
    }
    BuildLightGrid(lights, layout, image, &boxes);
    GCHECK(image.CellOccluders(100.0f, 100.0f, idx) == kMaxOccludersPerCell);
    GCHECK(idx[0] == 0);
  }

  void TestHugeLightAndEdges()
  {
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    // a nuke flash: radius 520 covers most of the map and must not run off the grid
    std::vector<Light> lights{MakeLight(512.0f, 0.0f, 512.0f, 520.0f)};
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.cellsLit > 2500);
    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(
      image.CellLights(0.5f, 0.5f, idx) == 0
    ); // corner of the map: 701 from the nearest point of its cell -> outside the circle
    GCHECK(image.CellLights(200.0f, 200.0f, idx) == 1); // 441 away: inside
    GCHECK(image.CellLights(512.0f, 512.0f, idx) == 1);
    GCHECK(image.CellLights(1023.0f, 512.0f, idx) == 1); // 511 away: inside

    // light on the edge and off the map
    lights.assign(1, MakeLight(-10.0f, 0.0f, 500.0f, 30.0f));
    BuildLightGrid(lights, layout, image);
    GCHECK(image.CellLights(5.0f, 500.0f, idx) == 1);
    lights.assign(1, MakeLight(-500.0f, 0.0f, 500.0f, 30.0f));
    BuildLightGrid(lights, layout, image);
    GCHECK(image.outsideMap == 1 && image.cellsLit == 0 && image.lightCount == 1);
    lights.assign(1, MakeLight(1.0e30f, 0.0f, -1.0e30f, 30.0f));
    BuildLightGrid(lights, layout, image);
    GCHECK(image.outsideMap == 1 && image.cellsLit == 0);
    lights.assign(1, MakeLight(512.0f, 0.0f, 512.0f, 1.0e30f)); // absurd radius: every cell, no overflow of the loops
    BuildLightGrid(lights, layout, image);
    GCHECK(image.cellsLit == 128u * 128u);

    // outside the map the lookup is empty
    GCHECK(image.CellLights(-1.0f, 10.0f, idx) == 0);
    GCHECK(image.CellLights(10.0f, 2000.0f, idx) == 0);
    GCHECK(image.CellLights(std::numeric_limits<float>::quiet_NaN(), 10.0f, idx) == 0);
  }

  void TestInvalidLights()
  {
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    const float nan = std::numeric_limits<float>::quiet_NaN();
    std::vector<Light> lights;
    lights.push_back(MakeLight(nan, 0.0f, 0.0f, 10.0f));
    lights.push_back(MakeLight(100.0f, 0.0f, 100.0f, 0.0f));  // no radius
    lights.push_back(MakeLight(100.0f, 0.0f, 100.0f, -5.0f)); // negative radius
    Light bad = MakeLight(100.0f, 0.0f, 100.0f, 10.0f);
    bad.rgb[1] = std::numeric_limits<float>::infinity();
    lights.push_back(bad);
    lights.push_back(MakeLight(100.0f, 0.0f, 100.0f, 10.0f)); // the only good one: index 0

    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.skipped == 4);
    GCHECK(image.lightCount == 1);
    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(100.0f, 100.0f, idx) == 1 && idx[0] == 0);
  }

  void TestCapAndEmpty()
  {
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    std::vector<Light> lights;
    for (std::size_t i = 0; i < kMaxGridLights + 40; ++i) {
      lights.push_back(MakeLight(static_cast<float>(i % 1000), 0.0f, static_cast<float>((i * 7) % 1000), 8.0f));
    }
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.lightCount == kMaxGridLights);
    GCHECK(image.data.size() == static_cast<std::size_t>(LightGridImage::DataRows(kMaxGridLights)) * kDataWidth * 4);

    lights.clear();
    BuildLightGrid(lights, layout, image);
    GCHECK(image.lightCount == 0 && image.cellsLit == 0);
    GCHECK(image.data.size() == static_cast<std::size_t>(kDataWidth) * 4); // the texture stays valid with no lights
    for (const float v : image.grid) {
      GCHECK(v == 0.0f);
      if (v != 0.0f) {
        break;
      }
    }

    // a rebuild into the same image leaves nothing of the previous frame behind
    lights.assign(1, MakeLight(100.0f, 0.0f, 100.0f, 20.0f));
    BuildLightGrid(lights, layout, image);
    GCHECK(image.cellsLit > 0);
    lights.clear();
    BuildLightGrid(lights, layout, image);
    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(100.0f, 100.0f, idx) == 0);
  }

  void TestManyLights()
  {
    // the first patch carried 16 lights on units and 28 on the ground; all 4096 are in the data texture now
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    std::vector<Light> lights;
    for (std::size_t i = 0; i < kMaxGridLights; ++i) {
      lights.push_back(MakeLight(
        8.0f + static_cast<float>((i * 13) % 1000),
        1.0f,
        8.0f + static_cast<float>((i * 29) % 1000),
        12.0f,
        5000.0f - static_cast<float>(i)
      ));
    }
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.lightCount == kMaxGridLights);
    GCHECK(image.DataRows() == 12);
    // the last light's texels are where the shader looks for them
    const std::size_t last = (kMaxGridLights - 1) * kTexelsPerLight;
    const std::size_t row = last / kDataWidth;
    const std::size_t col = last % kDataWidth;
    const float* a = &image.data[(row * kDataWidth + col) * 4];
    GCHECK(a[0] == lights.back().pos[0] && a[2] == lights.back().pos[2] && a[3] == 12.0f);
    std::uint32_t idx[kMaxLightsPerCell];
    const std::uint32_t n = image.CellLights(lights.back().pos[0], lights.back().pos[2], idx);
    GCHECK(n >= 1 && n <= kMaxLightsPerCell);
  }

  void TestCapsuleAndSpot()
  {
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f); // cells of 16
    // a beam along x from 100 to 300 at z = 500, radius 10
    Light beam = MakeLight(100.0f, 3.0f, 500.0f, 10.0f);
    beam.kind = Kind::Beam;
    beam.end[0] = 300.0f;
    beam.end[1] = 3.0f;
    beam.end[2] = 500.0f;
    std::vector<Light> lights{beam};
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    std::uint32_t idx[kMaxLightsPerCell];
    GCHECK(image.CellLights(100.0f, 500.0f, idx) == 1);
    GCHECK(image.CellLights(200.0f, 500.0f, idx) == 1); // the middle of the segment
    GCHECK(image.CellLights(299.0f, 505.0f, idx) == 1); // the far end
    GCHECK(image.CellLights(200.0f, 540.0f, idx) == 0); // 40 beside the beam, radius 10
    GCHECK(image.CellLights(400.0f, 500.0f, idx) == 0); // beyond the end
    const float* c = &image.data[2 * 4];
    GCHECK(c[0] == 300.0f && c[2] == 500.0f && c[3] == 0.0f); // the capsule end is in texel C
    GCHECK(image.cellsLit > 12);

    // a spotlight: direction and cone in texel C
    Light spot = MakeLight(600.0f, 4.0f, 600.0f, 30.0f);
    spot.kind = Kind::Spot;
    spot.end[0] = 1.0f;
    spot.end[1] = 0.0f;
    spot.end[2] = 0.0f;
    spot.cone = 0.8f;
    lights.assign(1, spot);
    BuildLightGrid(lights, layout, image);
    const float* d = &image.data[2 * 4];
    GCHECK(d[0] == 1.0f && d[1] == 0.0f && d[2] == 0.0f && d[3] == 0.8f);
    const float* b = &image.data[1 * 4];
    GCHECK(b[3] == static_cast<float>(Kind::Spot));
    GCHECK(image.CellLights(600.0f, 600.0f, idx) == 1);

    // a beam with a broken end point is skipped and leaves no hole in the indices
    Light bad = beam;
    bad.end[0] = std::numeric_limits<float>::quiet_NaN();
    lights.assign(2, MakeLight(100.0f, 0.0f, 100.0f, 10.0f));
    lights[0] = bad;
    BuildLightGrid(lights, layout, image);
    GCHECK(image.skipped == 1 && image.lightCount == 1);
    GCHECK(image.CellLights(100.0f, 100.0f, idx) == 1 && idx[0] == 0);
  }

  void TestEntriesAreExactIntegers()
  {
    // "index + 1" entries stay exact floats at the largest index we use
    const GridLayout layout = GridLayout::ForMap(1024.0f, 1024.0f);
    std::vector<Light> lights;
    for (std::size_t i = 0; i < kMaxGridLights; ++i) {
      lights.push_back(
        MakeLight(300.0f + static_cast<float>(i) * 0.01f, 0.0f, 300.0f, 2.0f, 1000.0f - static_cast<float>(i))
      );
    }
    LightGridImage image;
    BuildLightGrid(lights, layout, image);
    std::uint32_t idx[kMaxLightsPerCell];
    const std::uint32_t n = image.CellLights(300.0f, 300.0f, idx);
    GCHECK(n == kMaxLightsPerCell);
    for (std::uint32_t i = 0; i < n; ++i) {
      GCHECK(idx[i] == i);
    }
  }
} // namespace

int RunGridTests(
  int& checks
)
{
  TestLayout();
  TestDataTextureLayout();
  TestMembership();
  TestOrderAndOverflow();
  TestCrowdedCellRejectsWholeLights();
  TestCellListsAreComplete();
  TestStrongestAtTheMiddleFirst();
  TestWithoutCells();
  TestOccluders();
  TestHugeLightAndEdges();
  TestInvalidLights();
  TestCapAndEmpty();
  TestEntriesAreExactIntegers();
  TestManyLights();
  TestCapsuleAndSpot();
  checks += gGridChecks;
  return gGridFailures;
}
