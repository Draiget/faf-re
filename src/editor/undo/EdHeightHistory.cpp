#include "editor/undo/EdHeightHistory.h"

#include <algorithm>

namespace faf::editor
{
  template <typename T>
  std::size_t TileHistory<T>::Step::Bytes() const
  {
    std::size_t bytes = 0;
    for (const Tile& tile : tiles) {
      bytes += (tile.before.size() + tile.after.size()) * sizeof(T);
    }
    return bytes;
  }

  template <typename T>
  void TileHistory<T>::Reset(const int width, const int height, const std::size_t budgetBytes)
  {
    mWidth = width;
    mHeight = height;
    mTilesX = (width + kTile - 1) / kTile;
    const int tilesZ = (height + kTile - 1) / kTile;
    mBudget = budgetBytes;
    mStroking = false;
    mCurrent = {};
    mTileInCurrent.assign(static_cast<std::size_t>(mTilesX) * static_cast<std::size_t>(tilesZ), 0);
    mUndo.clear();
    mRedo.clear();
  }

  template <typename T>
  SampleRect TileHistory<T>::TileRect(const int index) const
  {
    const int tx = index % mTilesX;
    const int tz = index / mTilesX;
    return {tx * kTile, tz * kTile, std::min(mWidth - 1, tx * kTile + kTile - 1), std::min(mHeight - 1, tz * kTile + kTile - 1)};
  }

  template <typename T>
  void TileHistory<T>::Copy(const T* const heights, const SampleRect& rect, std::vector<T>& out) const
  {
    out.clear();
    for (int z = rect.z0; z <= rect.z1; ++z) {
      const T* const row = heights + static_cast<std::size_t>(z) * static_cast<std::size_t>(mWidth);
      out.insert(out.end(), row + rect.x0, row + rect.x1 + 1);
    }
  }

  template <typename T>
  void TileHistory<T>::Paste(T* const heights, const SampleRect& rect, const std::vector<T>& in) const
  {
    const std::size_t rowLength = static_cast<std::size_t>(rect.x1 - rect.x0 + 1);
    for (int z = rect.z0; z <= rect.z1; ++z) {
      std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(static_cast<std::size_t>(z - rect.z0) * rowLength), rowLength,
                  heights + static_cast<std::size_t>(z) * static_cast<std::size_t>(mWidth) + static_cast<std::size_t>(rect.x0));
    }
  }

  template <typename T>
  void TileHistory<T>::BeginStroke()
  {
    mStroking = true;
    mCurrent = {};
    std::fill(mTileInCurrent.begin(), mTileInCurrent.end(), 0);
  }

  template <typename T>
  void TileHistory<T>::BeforeWrite(const T* const heights, const SampleRect& rect)
  {
    if (!mStroking || mWidth == 0) {
      return;
    }
    const int tx0 = std::max(0, rect.x0) / kTile;
    const int tz0 = std::max(0, rect.z0) / kTile;
    const int tx1 = std::min(mWidth - 1, rect.x1) / kTile;
    const int tz1 = std::min(mHeight - 1, rect.z1) / kTile;
    for (int tz = tz0; tz <= tz1; ++tz) {
      for (int tx = tx0; tx <= tx1; ++tx) {
        const int index = tz * mTilesX + tx;
        int& slot = mTileInCurrent[static_cast<std::size_t>(index)];
        if (slot != 0) {
          continue;
        }
        Tile tile;
        tile.index = index;
        Copy(heights, TileRect(index), tile.before);
        mCurrent.tiles.push_back(std::move(tile));
        slot = static_cast<int>(mCurrent.tiles.size());
      }
    }
  }

  template <typename T>
  void TileHistory<T>::EndStroke(const T* const heights)
  {
    if (!mStroking) {
      return;
    }
    mStroking = false;
    if (mCurrent.tiles.empty()) {
      return;
    }
    for (Tile& tile : mCurrent.tiles) {
      Copy(heights, TileRect(tile.index), tile.after);
    }
    mUndo.push_back(std::move(mCurrent));
    mCurrent = {};
    mRedo.clear();
    Trim();
  }

  template <typename T>
  void TileHistory<T>::Trim()
  {
    std::size_t bytes = 0;
    for (const Step& step : mUndo) {
      bytes += step.Bytes();
    }
    // Keep the newest step whatever its size.
    while (bytes > mBudget && mUndo.size() > 1) {
      bytes -= mUndo.front().Bytes();
      mUndo.pop_front();
    }
  }

  template <typename T>
  bool TileHistory<T>::Undo(T* const heights, std::vector<SampleRect>& changed)
  {
    if (mStroking || mUndo.empty()) {
      return false;
    }
    Step step = std::move(mUndo.back());
    mUndo.pop_back();
    for (const Tile& tile : step.tiles) {
      const SampleRect rect = TileRect(tile.index);
      Paste(heights, rect, tile.before);
      changed.push_back(rect);
    }
    mRedo.push_back(std::move(step));
    return true;
  }

  template <typename T>
  bool TileHistory<T>::Redo(T* const heights, std::vector<SampleRect>& changed)
  {
    if (mStroking || mRedo.empty()) {
      return false;
    }
    Step step = std::move(mRedo.back());
    mRedo.pop_back();
    for (const Tile& tile : step.tiles) {
      const SampleRect rect = TileRect(tile.index);
      Paste(heights, rect, tile.after);
      changed.push_back(rect);
    }
    mUndo.push_back(std::move(step));
    return true;
  }
  template class TileHistory<std::uint16_t>;
  template class TileHistory<std::uint64_t>;
} // namespace faf::editor
