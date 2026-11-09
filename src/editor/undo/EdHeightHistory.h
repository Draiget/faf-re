#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "editor/tools/EdHeightBrush.h"

namespace faf::editor
{
  /**
   * Undo and redo for the height field (board task WPE.6), by tiles: during a stroke, the first write to a
   * 32 x 32 tile saves that tile's heights from before; the stroke's end saves the same tiles' heights
   * after. Undo writes the befores back, redo the afters. Byte-exact, and only the tiles a stroke touched
   * are kept. The oldest strokes go when the history passes its memory budget.
   */
  class HeightHistory
  {
  public:
    static constexpr int kTile = 32;

    /** Forgets everything; the field is `width` x `height` samples. */
    void Reset(int width, int height, std::size_t budgetBytes = std::size_t{256} << 20);

    /** A stroke starts. */
    void BeginStroke();

    /** Before the stroke writes `rect` of `heights`: keeps the tiles it covers as they are, once each. */
    void BeforeWrite(const std::uint16_t* heights, const SampleRect& rect);

    /** The stroke ended: keeps its tiles' new heights and makes it the newest undo step (redo is cleared). */
    void EndStroke(const std::uint16_t* heights);

    /** Writes the newest stroke's old heights back; the rectangles it wrote go to `changed`. */
    bool Undo(std::uint16_t* heights, std::vector<SampleRect>& changed);

    /** Writes the newest undone stroke's new heights back. */
    bool Redo(std::uint16_t* heights, std::vector<SampleRect>& changed);

    [[nodiscard]] std::size_t UndoCount() const noexcept { return mUndo.size(); }
    [[nodiscard]] std::size_t RedoCount() const noexcept { return mRedo.size(); }
    [[nodiscard]] bool Stroking() const noexcept { return mStroking; }

  private:
    struct Tile
    {
      int index = 0;
      std::vector<std::uint16_t> before;
      std::vector<std::uint16_t> after;
    };
    struct Step
    {
      std::vector<Tile> tiles;
      [[nodiscard]] std::size_t Bytes() const;
    };

    [[nodiscard]] SampleRect TileRect(int index) const;
    void Copy(const std::uint16_t* heights, const SampleRect& rect, std::vector<std::uint16_t>& out) const;
    void Paste(std::uint16_t* heights, const SampleRect& rect, const std::vector<std::uint16_t>& in) const;
    void Trim();

    int mWidth = 0;
    int mHeight = 0;
    int mTilesX = 0;
    std::size_t mBudget = 0;
    bool mStroking = false;
    Step mCurrent;
    std::vector<int> mTileInCurrent; // per tile: its slot in mCurrent.tiles + 1, or 0
    std::deque<Step> mUndo;
    std::vector<Step> mRedo;
  };
} // namespace faf::editor
