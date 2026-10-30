#include "remote/wire/IntelGridDelta.h"

#include <utility>

// Engine addition, server mode: see IntelGridDelta.h.

namespace faf::remote::wire
{
  namespace
  {
    [[nodiscard]] bool SameShape(const SGridBits& grid, const SGridBits* const baseline) noexcept
    {
      return baseline != nullptr && baseline->width == grid.width && baseline->height == grid.height
          && baseline->cells.size() == grid.cells.size();
    }
  } // namespace

  bool EncodeGridDelta(const SGridBits& current, const SGridBits* const baseline, BitWriter& writer)
  {
    const std::uint64_t cellCount = static_cast<std::uint64_t>(current.width) * current.height;
    if (cellCount != current.cells.size()) {
      return false;
    }
    const SGridBits* const base = SameShape(current, baseline) ? baseline : nullptr;

    writer.WriteVarUint(current.width);
    writer.WriteVarUint(current.height);
    bool flipped = false; // the kind of the run being counted: unchanged first
    std::uint32_t run = 0;
    for (std::size_t i = 0; i < current.cells.size(); ++i) {
      const std::uint8_t before = base != nullptr ? base->cells[i] : 0u;
      const bool cellFlipped = (current.cells[i] != 0u) != (before != 0u);
      if (cellFlipped != flipped) {
        writer.WriteVarUint(run);
        flipped = cellFlipped;
        run = 0;
      }
      ++run;
    }
    if (run > 0u) {
      writer.WriteVarUint(run);
    }
    return true;
  }

  bool DecodeGridDelta(BitReader& reader, const SGridBits* const baseline, const std::uint32_t maxCells, SGridBits& out)
  {
    const std::uint32_t width = reader.ReadVarUint();
    const std::uint32_t height = reader.ReadVarUint();
    if (!reader.Ok()) {
      return false;
    }
    const std::uint64_t cellCount = static_cast<std::uint64_t>(width) * height;
    if (cellCount > maxCells) {
      reader.Fail();
      return false;
    }

    SGridBits grid;
    grid.width = width;
    grid.height = height;
    grid.cells.assign(static_cast<std::size_t>(cellCount), 0u);
    const bool sameShape = baseline != nullptr && baseline->width == width && baseline->height == height
                        && baseline->cells.size() == cellCount;
    if (sameShape) {
      for (std::size_t i = 0; i < grid.cells.size(); ++i) {
        grid.cells[i] = baseline->cells[i] != 0u ? 1u : 0u;
      }
    }

    std::uint64_t done = 0;
    bool flipped = false;
    while (done < cellCount) {
      const std::uint32_t run = reader.ReadVarUint();
      if (!reader.Ok() || run > cellCount - done) {
        reader.Fail();
        return false;
      }
      if (flipped) {
        for (std::uint64_t i = done; i < done + run; ++i) {
          grid.cells[static_cast<std::size_t>(i)] ^= 1u;
        }
      }
      done += run;
      flipped = !flipped;
    }
    out = std::move(grid);
    return true;
  }
} // namespace faf::remote::wire
