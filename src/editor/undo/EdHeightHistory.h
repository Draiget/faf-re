#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "editor/tools/EdHeightBrush.h"

namespace faf::editor
{
  /**
   * Undo and redo for a grid of `T` (the height field's words, WPE.6; the stratum masks' texels, WPE.7), by
   * tiles: during a stroke, the first write to a 32 x 32 tile saves that tile from before; the stroke's end
   * saves the same tiles after. Undo writes the befores back, redo the afters. Byte-exact, and only the
   * tiles a stroke touched are kept. The oldest strokes go when the history passes its memory budget.
   */
  template <typename T>
  class TileHistory
  {
  public:
    static constexpr int kTile = 32;

    /** Forgets everything; the field is `width` x `height` samples. */
    void Reset(int width, int height, std::size_t budgetBytes = std::size_t{256} << 20);

    /** A stroke starts. */
    void BeginStroke();

    /** Before the stroke writes `rect` of `heights`: keeps the tiles it covers as they are, once each. */
    void BeforeWrite(const T* heights, const SampleRect& rect);

    /** The stroke ended: keeps its tiles' new heights and makes it the newest undo step (redo is cleared). */
    void EndStroke(const T* heights);

    /** Writes the newest stroke's old heights back; the rectangles it wrote go to `changed`. */
    bool Undo(T* heights, std::vector<SampleRect>& changed);

    /** Writes the newest undone stroke's new heights back. */
    bool Redo(T* heights, std::vector<SampleRect>& changed);

    [[nodiscard]] std::size_t UndoCount() const noexcept { return mUndo.size(); }
    [[nodiscard]] std::size_t RedoCount() const noexcept { return mRedo.size(); }
    [[nodiscard]] bool Stroking() const noexcept { return mStroking; }
    /** Forgets the undone strokes (another kind of edit came after them). */
    void ClearRedo() { mRedo.clear(); }

  private:
    struct Tile
    {
      int index = 0;
      std::vector<T> before;
      std::vector<T> after;
    };
    struct Step
    {
      std::vector<Tile> tiles;
      [[nodiscard]] std::size_t Bytes() const;
    };

    [[nodiscard]] SampleRect TileRect(int index) const;
    void Copy(const T* heights, const SampleRect& rect, std::vector<T>& out) const;
    void Paste(T* heights, const SampleRect& rect, const std::vector<T>& in) const;
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

  extern template class TileHistory<std::uint16_t>;
  extern template class TileHistory<std::uint64_t>;
  /** The height field's history: its 16-bit words. */
  using HeightHistory = TileHistory<std::uint16_t>;
  /** The stratum masks' history: one texel's eight layer weights as one 64-bit word (byte k is stratum k). */
  using MaskHistory = TileHistory<std::uint64_t>;
} // namespace faf::editor
