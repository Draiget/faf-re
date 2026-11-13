// SC tools (src/editor/tools/EdScTools.cpp): pads under the markers with rings and clusters, applied and taken off
// exactly, re-applied in place; the slope limit with blocked shares; the grade along a route.

#include "editor/tools/EdScTools.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <vector>

namespace
{
  using faf::editor::ApplyPads;
  using faf::editor::BlockedShares;
  using faf::editor::CollectPads;
  using faf::editor::LimitSlopes;
  using faf::editor::Pad;
  using faf::editor::PadMarker;
  using faf::editor::PadResult;
  using faf::editor::PadSettings;
  using faf::editor::PadSignature;
  using faf::editor::RampProfile;
  using faf::editor::RemovePads;
  using faf::editor::SlopeLimitSettings;

  constexpr float kScale = 1.0f / 128.0f;
  constexpr int kSide = 129;

  /** Rolling ground: a few units of hills, in words. */
  std::vector<std::uint16_t> Rolling()
  {
    std::vector<std::uint16_t> words(kSide * kSide);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        const float h =
          20.0f + 3.0f * std::sin(static_cast<float>(x) * 0.11f) + 2.0f * std::cos(static_cast<float>(z) * 0.07f);
        words[static_cast<std::size_t>(z * kSide + x)] = static_cast<std::uint16_t>(std::lround(h / kScale));
      }
    }
    return words;
  }

  TEST(
    ScTools,
    PadsGroupIntoRingsAndClusters
  )
  {
    const std::vector<PadMarker> markers = {
      {"ARMY_1", "Blank Marker", 30.0f, 30.0f},
      {"Mass 01", "Mass", 40.0f, 30.0f},   // in ARMY_1's ring
      {"Mass 02", "Mass", 100.0f, 100.0f}, // a cluster with Mass 03
      {"Mass 03", "Mass", 108.0f, 100.0f},
      {"Mass 04", "Mass", 20.0f, 110.0f}, // alone
      {"Hydrocarbon 01", "Hydrocarbon", 35.0f, 45.0f},
      {"Rally", "Rally Point", 60.0f, 60.0f}, // no pad
    };
    PadSettings settings;
    const auto pads = CollectPads(markers, settings);
    ASSERT_EQ(pads.size(), 6U);
    EXPECT_EQ(pads[0].name, "ARMY_1") << "starts first";
    EXPECT_EQ(pads[1].kind, Pad::Kind::Hydro) << "then hydrocarbons, then mass";
    const auto find = [&](const char* name) {
      for (const Pad& p : pads) {
        if (p.name == name) {
          return p;
        }
      }
      return Pad{};
    };
    EXPECT_GT(find("ARMY_1").group, 0);
    EXPECT_EQ(find("Mass 01").group, find("ARMY_1").group) << "the ring shares the start's height";
    EXPECT_EQ(find("Hydrocarbon 01").group, find("ARMY_1").group);
    EXPECT_GT(find("Mass 02").group, 0);
    EXPECT_EQ(find("Mass 02").group, find("Mass 03").group) << "a cluster";
    EXPECT_NE(find("Mass 02").group, find("ARMY_1").group);
    EXPECT_EQ(find("Mass 04").group, 0) << "alone: its own height";
    EXPECT_FLOAT_EQ(find("Mass 01").half, settings.massHalf);
    // The signature follows a marker's move, not the ground.
    auto moved = markers;
    moved[1].x += 1.0f;
    EXPECT_NE(PadSignature(CollectPads(moved, settings), settings), PadSignature(pads, settings));
    settings.massPads = false;
    EXPECT_EQ(CollectPads(markers, settings).size(), 2U) << "the start and the hydrocarbon";
  }

  TEST(
    ScTools,
    PadsApplyRemoveAndReplaceExactly
  )
  {
    const auto original = Rolling();
    auto words = original;
    PadSettings settings;
    std::vector<PadMarker> markers = {{"ARMY_1", "Blank Marker", 40.0f, 40.0f}, {"Mass 01", "Mass", 52.0f, 40.0f}};
    PadResult first;
    std::string error;
    const int changed =
      ApplyPads(words.data(), kSide, kSide, kScale, CollectPads(markers, settings), settings, {}, first, error);
    ASSERT_GT(changed, 100) << error;
    // The start's core is flat: its samples share one height.
    const std::uint16_t middle = words[static_cast<std::size_t>(40 * kSide + 40)];
    EXPECT_EQ(words[static_cast<std::size_t>(36 * kSide + 44)], middle);
    EXPECT_EQ(words[static_cast<std::size_t>(40 * kSide + 52)], middle)
      << "the mass in the ring is at the start's height";
    // Move the start and apply again: the old pad is taken off first, then the new one made.
    markers[0].x = 70.0f;
    PadResult second;
    ASSERT_GT(
      ApplyPads(words.data(), kSide, kSide, kScale, CollectPads(markers, settings), settings, first, second, error), 0
    );
    EXPECT_NE(first.signature, second.signature);
    // Taking the second off gives the original ground back, word for word.
    (void)RemovePads(words.data(), kSide, kSide, kScale, second);
    std::size_t differ = 0;
    for (std::size_t k = 0; k < words.size(); ++k) {
      differ += words[k] != original[k] ? 1u : 0u;
    }
    EXPECT_EQ(differ, 0U) << "pads off: the ground as it was";
    PadResult none;
    EXPECT_EQ(ApplyPads(words.data(), kSide, kSide, kScale, {}, settings, {}, none, error), -1);
  }

  TEST(
    ScTools,
    SlopeLimitUnblocksGround
  )
  {
    // A cliff: 0 to 30 units over two samples.
    std::vector<std::uint16_t> words(kSide * kSide);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        const float h = x < 64 ? 5.0f : (x < 66 ? 5.0f + 15.0f * static_cast<float>(x - 63) : 35.0f);
        words[static_cast<std::size_t>(z * kSide + x)] = static_cast<std::uint16_t>(std::lround(h / kScale));
      }
    }
    const auto before = BlockedShares(words.data(), kSide, kSide, kScale, 0.75f);
    ASSERT_EQ(before.size(), 4U);
    EXPECT_GT(before[0], 0.0f) << "the cliff blocks land units";
    std::string error;
    SlopeLimitSettings settings;
    ASSERT_GT(LimitSlopes(words.data(), kSide, kSide, kScale, settings, error), 0) << error;
    const auto after = BlockedShares(words.data(), kSide, kSide, kScale, 0.75f);
    EXPECT_LT(after[0], before[0]) << "less ground blocked for small land units";
  }

  TEST(
    ScTools,
    RampGradeAlongARoute
  )
  {
    // A slope of 0.5 along x.
    std::vector<std::uint16_t> words(kSide * kSide);
    for (int z = 0; z < kSide; ++z) {
      for (int x = 0; x < kSide; ++x) {
        words[static_cast<std::size_t>(z * kSide + x)] =
          static_cast<std::uint16_t>(std::lround((10.0f + 0.5f * x) / kScale));
      }
    }
    const auto along = RampProfile(words.data(), kSide, kSide, kScale, {{10.0f, 60.0f}, {110.0f, 60.0f}});
    EXPECT_NEAR(along.length, 100.0f, 1e-3f);
    EXPECT_NEAR(along.maxGrade, 0.5f, 0.01f);
    EXPECT_NEAR(along.meanGrade, 0.5f, 0.01f);
    EXPECT_FLOAT_EQ(along.over, 0.0f) << "0.5 is under 0.75";
    EXPECT_TRUE(along.runs.empty());
    const auto steep =
      RampProfile(words.data(), kSide, kSide, kScale, {{10.0f, 60.0f}, {110.0f, 60.0f}}, 1.0f, 3.0f, 0.4f);
    EXPECT_GT(steep.over, 0.9f) << "over a 0.4 limit nearly all the way";
    ASSERT_EQ(steep.runs.size(), 1U);
    const auto across = RampProfile(words.data(), kSide, kSide, kScale, {{60.0f, 10.0f}, {60.0f, 110.0f}});
    EXPECT_NEAR(across.maxGrade, 0.0f, 0.01f) << "across the slope it is level";
  }
} // namespace
