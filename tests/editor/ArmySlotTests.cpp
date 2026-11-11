// The map editor's army slot helpers (src/editor/tools/EdArmySlots.cpp): mirror partners, the paired slot order and the
// next free army name.

#include "editor/tools/EdArmySlots.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::Symmetry;
  using Start = std::optional<std::array<float, 2>>;

  // SCMP_009's eight starts (its _save.lua), slot order as the map has it; the map is half turn symmetric, 1025
  // samples.
  const std::vector<Start> kSeton = {
    std::array<float, 2>{672.0f, 346.0f},
    std::array<float, 2>{358.0f, 674.0f},
    std::array<float, 2>{856.0f, 434.0f},
    std::array<float, 2>{172.0f, 600.0f},
    std::array<float, 2>{662.0f, 168.0f},
    std::array<float, 2>{366.0f, 864.0f},
    std::array<float, 2>{926.0f, 102.0f},
    std::array<float, 2>{100.0f, 914.0f},
  };

  TEST(
    ArmySlots,
    HalfTurnPartnersAreTheOppositeStarts
  )
  {
    const std::vector<int> partners = faf::editor::MirrorPartners(kSeton, 1025, 1025, Symmetry::HalfTurn, 2);
    EXPECT_EQ(partners, (std::vector<int>{1, 0, 3, 2, 5, 4, 7, 6}));
  }

  TEST(
    ArmySlots,
    PairingPutsEachStartBesideItsMirror
  )
  {
    // The same starts shuffled: slots 1, 3, 5, 7 on one side, then the other side.
    const std::vector<Start> shuffled = {
      kSeton[0], kSeton[2], kSeton[4], kSeton[6], kSeton[1], kSeton[3], kSeton[5], kSeton[7]
    };
    const std::vector<int> partners = faf::editor::MirrorPartners(shuffled, 1025, 1025, Symmetry::HalfTurn, 2);
    const std::vector<int> order = faf::editor::PairMirroredSlots(partners);
    EXPECT_EQ(order, (std::vector<int>{0, 4, 1, 5, 2, 6, 3, 7}));
  }

  TEST(
    ArmySlots,
    NoSymmetryOrAMissingStartKeepsTheSlot
  )
  {
    std::vector<Start> starts = kSeton;
    starts[2] = std::nullopt;
    const std::vector<int> none = faf::editor::MirrorPartners(starts, 1025, 1025, Symmetry::None, 2);
    EXPECT_EQ(none, (std::vector<int>(8, -1)));
    EXPECT_EQ(faf::editor::PairMirroredSlots(none), (std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7}));
    // ARMY_3 has no start: its partner ARMY_4 finds the nearest other start, which is already taken in a pair or not;
    // ARMY_3 itself goes after the pairs.
    const std::vector<int> partners = faf::editor::MirrorPartners(starts, 1025, 1025, Symmetry::HalfTurn, 2);
    EXPECT_EQ(partners[2], -1);
    const std::vector<int> order = faf::editor::PairMirroredSlots(partners);
    ASSERT_EQ(order.size(), 8U);
    EXPECT_EQ(order[0], 0);
    EXPECT_EQ(order[1], 1);
    EXPECT_EQ(order.back() == 2 || order[order.size() - 2] == 2, true);
  }

  TEST(
    ArmySlots,
    LeftRightMirror
  )
  {
    const std::vector<Start> starts = {
      std::array<float, 2>{100.0f, 200.0f},
      std::array<float, 2>{150.0f, 400.0f},
      std::array<float, 2>{412.0f, 200.0f},
      std::array<float, 2>{362.0f, 400.0f}
    };
    const std::vector<int> partners = faf::editor::MirrorPartners(starts, 513, 513, Symmetry::LeftRight, 2);
    EXPECT_EQ(partners, (std::vector<int>{2, 3, 0, 1}));
    EXPECT_EQ(faf::editor::PairMirroredSlots(partners), (std::vector<int>{0, 2, 1, 3}));
  }

  TEST(
    ArmySlots,
    NextArmyName
  )
  {
    EXPECT_EQ(faf::editor::NextArmyName({}), "ARMY_1");
    EXPECT_EQ(faf::editor::NextArmyName({"ARMY_1", "ARMY_8", "NEUTRAL_CIVILIAN", "ARMY_17"}), "ARMY_18");
    EXPECT_EQ(faf::editor::NextArmyName({"ARMY_2", "ARMY_X", "ARMY_"}), "ARMY_3");
  }
} // namespace
