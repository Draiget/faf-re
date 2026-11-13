// The Erosion window's library (src/editor/tools/EdErosionSuite.cpp): solvers, presets, the coarse run's scaling, and
// the solvers run on height words.

#include "editor/tools/EdErosionSuite.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace
{
  using faf::editor::ErodeHeights;
  using faf::editor::ErosionDefaults;
  using faf::editor::ErosionOpValues;
  using faf::editor::ErosionPresets;
  using faf::editor::ErosionPresetValues;
  using faf::editor::ErosionPreviewStep;
  using faf::editor::ErosionSolvers;
  using faf::editor::FindErosionSolver;

  constexpr float kScale = 1.0f / 128.0f;

  /** A 65 x 65 map: a cone 40 units high with a ripple, in height words. */
  std::vector<std::uint16_t> Cone()
  {
    std::vector<std::uint16_t> words(65 * 65);
    for (int z = 0; z < 65; ++z) {
      for (int x = 0; x < 65; ++x) {
        const float d = std::hypot(static_cast<float>(x) - 32.0f, static_cast<float>(z) - 32.0f);
        const float h = std::max(2.0f, 42.0f - d * 1.2f) + std::sin(static_cast<float>(x) * 0.7f) * 0.8f;
        words[static_cast<std::size_t>(z * 65 + x)] = static_cast<std::uint16_t>(std::lround(h / kScale));
      }
    }
    return words;
  }

  std::size_t Changed(
    const std::vector<std::uint16_t>& a,
    const std::vector<std::uint16_t>& b
  )
  {
    std::size_t n = 0;
    for (std::size_t k = 0; k < a.size(); ++k) {
      n += a[k] != b[k] ? 1u : 0u;
    }
    return n;
  }

  TEST(
    ErosionSuite,
    SolversAndPresetsHaveTheirSettings
  )
  {
    ASSERT_EQ(ErosionSolvers().size(), 3U);
    for (const auto& solver : ErosionSolvers()) {
      const auto values = ErosionDefaults(solver);
      EXPECT_EQ(values.size(), solver.params.size()) << solver.id << ": every setting has a default";
      EXPECT_EQ(values.count("protect"), 1U) << solver.id << ": the shared settings are there";
      for (const auto& p : solver.params) {
        EXPECT_GE(p.fallback, p.min) << solver.id << " " << p.key;
        EXPECT_LE(p.fallback, p.max) << solver.id << " " << p.key;
      }
    }
    ASSERT_EQ(ErosionPresets().size(), 6U);
    for (const auto& preset : ErosionPresets()) {
      const auto* const solver = FindErosionSolver(preset.solver);
      ASSERT_NE(solver, nullptr) << preset.id;
      const auto values = ErosionPresetValues(preset);
      for (const auto& [key, value] : preset.values) {
        ASSERT_EQ(values.count(key), 1U) << preset.id << " sets " << key << ", which its solver has";
        EXPECT_DOUBLE_EQ(values.at(key), value);
      }
    }
    EXPECT_DOUBLE_EQ(ErosionPresetValues(ErosionPresets()[1]).at("iterations"), 100.0) << "Hills";
  }

  TEST(
    ErosionSuite,
    CoarseRunsAreScaled
  )
  {
    const auto& hydraulic = *FindErosionSolver("hydraulic");
    auto v = ErosionDefaults(hydraulic);
    v["iterations"] = 100;
    const auto coarse = ErosionOpValues(hydraulic, v, 4);
    EXPECT_DOUBLE_EQ(coarse.at("iterations"), 25.0);
    EXPECT_DOUBLE_EQ(coarse.at("rain"), 0.016);
    EXPECT_DOUBLE_EQ(coarse.at("smooth_passes"), 0.0) << "step 4 and up: no filter passes";
    EXPECT_DOUBLE_EQ(coarse.at("masks"), 0.0) << "a preview makes no masks";
    EXPECT_EQ(ErosionOpValues(hydraulic, v, 1).count("masks"), 0U) << "a full run is untouched";
    const auto& droplet = *FindErosionSolver("droplet");
    const auto drops = ErosionOpValues(droplet, ErosionDefaults(droplet), 2);
    EXPECT_DOUBLE_EQ(drops.at("lifetime"), 20.0);
    EXPECT_NEAR(drops.at("density"), 2.0 / 3.0, 1e-9);
    // The preview's step keeps the grid within 257 samples and prefers one dividing the map.
    EXPECT_EQ(ErosionPreviewStep(1025, 1025), 4);
    EXPECT_EQ(ErosionPreviewStep(257, 257), 1);
    EXPECT_EQ(ErosionPreviewStep(513, 1025), 4);
  }

  TEST(
    ErosionSuite,
    EverySolverErodesTheHeights
  )
  {
    for (const auto& solver : ErosionSolvers()) {
      auto values = ErosionDefaults(solver);
      if (values.count("iterations") != 0u) {
        values["iterations"] = std::min(values["iterations"], 20.0);
      }
      if (values.count("rounds") != 0u) {
        values["rounds"] = 4;
      }
      const auto before = Cone();
      auto after = before;
      std::string error;
      ASSERT_TRUE(ErodeHeights(after.data(), 65, 65, kScale, solver, values, 1, error)) << solver.id << ": " << error;
      EXPECT_GT(Changed(before, after), 100U) << solver.id << " changed the ground";
      // Keep height range (on by default): the top and bottom stay near the input's.
      const auto [lo, hi] = std::minmax_element(after.begin(), after.end());
      const auto [lo0, hi0] = std::minmax_element(before.begin(), before.end());
      EXPECT_NEAR(*hi * kScale, *hi0 * kScale, 2.0) << solver.id;
      EXPECT_NEAR(*lo * kScale, *lo0 * kScale, 2.0) << solver.id;
    }
  }

  TEST(
    ErosionSuite,
    APreviewKeepsTheFineDetail
  )
  {
    const auto& hydraulic = *FindErosionSolver("hydraulic");
    auto values = ErosionDefaults(hydraulic);
    values["iterations"] = 40;
    const auto before = Cone();
    auto preview = before;
    std::string error;
    ASSERT_TRUE(ErodeHeights(preview.data(), 65, 65, kScale, hydraulic, values, 4, error)) << error;
    EXPECT_GT(Changed(before, preview), 100U) << "the coarse run's change reaches the full heights";
    // The ripple (0.8 units every ~9 samples) is finer than the 4-sample grid: it is still there.
    int ripples = 0;
    for (int x = 1; x < 64; ++x) {
      const int a = preview[static_cast<std::size_t>(5 * 65 + x - 1)];
      const int b = preview[static_cast<std::size_t>(5 * 65 + x)];
      const int c = preview[static_cast<std::size_t>(5 * 65 + x + 1)];
      ripples += (b > a && b > c) ? 1 : 0;
    }
    EXPECT_GE(ripples, 4) << "the fine ripple survives a coarse preview";
  }
} // namespace
