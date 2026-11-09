// The map editor's height undo (src/editor/undo/EdHeightHistory.cpp): undo gives back the same bytes, redo
// the stroke's, as the plan's stage 3 asks.

#include "editor/tools/EdHeightBrush.h"
#include "editor/undo/EdHeightHistory.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <vector>

namespace
{
  using faf::editor::ApplyHeightBrush;
  using faf::editor::HeightBrush;
  using faf::editor::HeightBrushMode;
  using faf::editor::HeightBrushRects;
  using faf::editor::HeightHistory;
  using faf::editor::SampleRect;
  using faf::editor::Symmetry;

  constexpr int kSize = 129;

  std::vector<std::uint16_t> RandomField(const unsigned seed)
  {
    std::mt19937 random(seed);
    std::vector<std::uint16_t> words(static_cast<std::size_t>(kSize) * kSize);
    for (std::uint16_t& word : words) {
      word = static_cast<std::uint16_t>(random() & 0x7FFF);
    }
    return words;
  }

  /** One stroke of `steps` brush steps along a line, recorded in `history` as the editor records one. */
  void Stroke(std::vector<std::uint16_t>& words, HeightHistory& history, const HeightBrush& brush, const float x0, const float z0,
              const float x1, const float z1, const int steps)
  {
    history.BeginStroke();
    for (int i = 0; i < steps; ++i) {
      const float t = static_cast<float>(i) / static_cast<float>(steps - 1);
      const float x = x0 + (x1 - x0) * t;
      const float z = z0 + (z1 - z0) * t;
      for (const SampleRect& rect : HeightBrushRects(kSize, kSize, x, z, brush)) {
        history.BeforeWrite(words.data(), rect);
      }
      (void)ApplyHeightBrush(words.data(), kSize, kSize, x, z, brush, 0.03f);
    }
    history.EndStroke(words.data());
  }

  TEST(HeightHistory, UndoGivesBackTheSameBytesAndRedoTheStrokes)
  {
    std::vector<std::uint16_t> words = RandomField(7u);
    const std::vector<std::uint16_t> original = words;
    HeightHistory history;
    history.Reset(kSize, kSize);

    HeightBrush brush;
    brush.radius = 9.0f;
    brush.strength = 1.0f;
    brush.symmetry = Symmetry::BothAxes;
    brush.mode = HeightBrushMode::Raise;
    Stroke(words, history, brush, 10.0f, 10.0f, 60.0f, 40.0f, 20);
    const std::vector<std::uint16_t> afterFirst = words;
    brush.mode = HeightBrushMode::Smooth;
    Stroke(words, history, brush, 30.0f, 90.0f, 100.0f, 20.0f, 30);
    const std::vector<std::uint16_t> afterSecond = words;
    ASSERT_NE(afterFirst, original);
    ASSERT_NE(afterSecond, afterFirst);
    EXPECT_EQ(history.UndoCount(), 2u);

    std::vector<SampleRect> changed;
    ASSERT_TRUE(history.Undo(words.data(), changed));
    EXPECT_EQ(words, afterFirst);
    EXPECT_FALSE(changed.empty());
    ASSERT_TRUE(history.Undo(words.data(), changed));
    EXPECT_EQ(words, original);
    EXPECT_FALSE(history.Undo(words.data(), changed));

    ASSERT_TRUE(history.Redo(words.data(), changed));
    EXPECT_EQ(words, afterFirst);
    ASSERT_TRUE(history.Redo(words.data(), changed));
    EXPECT_EQ(words, afterSecond);
    EXPECT_FALSE(history.Redo(words.data(), changed));
  }

  TEST(HeightHistory, ANewStrokeClearsRedo)
  {
    std::vector<std::uint16_t> words = RandomField(11u);
    HeightHistory history;
    history.Reset(kSize, kSize);
    HeightBrush brush;
    Stroke(words, history, brush, 20.0f, 20.0f, 40.0f, 40.0f, 5);
    std::vector<SampleRect> changed;
    ASSERT_TRUE(history.Undo(words.data(), changed));
    EXPECT_EQ(history.RedoCount(), 1u);
    Stroke(words, history, brush, 80.0f, 80.0f, 90.0f, 90.0f, 5);
    EXPECT_EQ(history.RedoCount(), 0u);
    EXPECT_EQ(history.UndoCount(), 1u);
  }

  TEST(HeightHistory, TheBudgetDropsTheOldestStrokes)
  {
    std::vector<std::uint16_t> words = RandomField(13u);
    HeightHistory history;
    // About three single-tile strokes' worth (a 32 x 32 tile before and after: 4 KB).
    history.Reset(kSize, kSize, 3u * 4096u);
    HeightBrush brush;
    brush.radius = 3.0f;
    for (int i = 0; i < 6; ++i) {
      Stroke(words, history, brush, 16.0f, 16.0f, 16.0f, 16.0f, 2);
    }
    EXPECT_EQ(history.UndoCount(), 3u);
  }
} // namespace
