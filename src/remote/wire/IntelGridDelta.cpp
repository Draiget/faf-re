#include "remote/wire/IntelGridDelta.h"

#include <bit>
#include <cstring>
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
    const std::uint8_t* const cells = current.cells.data();
    const std::uint8_t* const before = base != nullptr ? base->cells.data() : nullptr;
    const std::size_t count = current.cells.size();
    std::size_t i = 0;
    while (i < count) {
      // Most of a grid is unchanged between beats: while counting unchanged cells, take eight at
      // a time when their bytes are equal (equal bytes are unchanged cells, so the runs are the same).
      if (!flipped && i + 8u <= count) {
        std::uint64_t now = 0;
        std::uint64_t was = 0;
        std::memcpy(&now, cells + i, 8u);
        if (before != nullptr) {
          std::memcpy(&was, before + i, 8u);
        }
        if (now == was) {
          run += 8u;
          i += 8u;
          continue;
        }
      }
      const std::uint8_t old = before != nullptr ? before[i] : 0u;
      const bool cellFlipped = (cells[i] != 0u) != (old != 0u);
      if (cellFlipped != flipped) {
        writer.WriteVarUint(run);
        flipped = cellFlipped;
        run = 0;
      }
      ++run;
      ++i;
    }
    if (run > 0u) {
      writer.WriteVarUint(run);
    }
    return true;
  }

  void EncodeGridDeltaInPlace(
    const std::uint32_t width, const std::uint32_t height, const std::int8_t* const now, std::uint64_t* const seen, BitWriter& writer
  )
  {
    EncodeGridDeltaInPlace(width, height, now, seen, writer, nullptr, 0u, true);
  }

  void EncodeGridDeltaInPlace(
    const std::uint32_t width, const std::uint32_t height, const std::int8_t* const now, std::uint64_t* const seen, BitWriter& writer,
    std::uint8_t* const changed, const std::uint32_t chunkCells, const bool readAll
  )
  {
    writer.WriteVarUint(width);
    writer.WriteVarUint(height);
    constexpr std::uint64_t kLow7 = 0x7F7F7F7F7F7F7F7Full;
    constexpr std::uint64_t kLowBits = 0x0101010101010101ull;
    // Eight cells to eight bits, cell k to bit k: the top bit of each byte says the cell is non-zero,
    // and the multiply gathers those bits into the top byte.
    const auto seenOf8 = [](const std::int8_t* const cells) noexcept {
      std::uint64_t bytes = 0;
      std::memcpy(&bytes, cells, 8u);
      const std::uint64_t top = (((bytes & kLow7) + kLow7) | bytes) >> 7u & kLowBits;
      return (top * 0x0102040810204080ull) >> 56u;
    };
    const std::size_t count = static_cast<std::size_t>(width) * height;
    const std::size_t wordsPerChunk = changed != nullptr && chunkCells >= 64u ? chunkCells / 64u : 0u;
    bool flipped = false; // the kind of the run being counted: unchanged first
    std::uint32_t run = 0;
    for (std::size_t word = 0, first = 0; first < count; ++word, first += 64u) {
      if (wordsPerChunk != 0u && word % wordsPerChunk == 0u) {
        // A chunk the sim hasn't touched since it was last read: every cell as it was.
        std::uint8_t& flag = changed[word / wordsPerChunk];
        const bool untouched = flag == 0u && !readAll;
        flag = 0u;
        if (untouched) {
          const std::size_t chunk = count - first < chunkCells ? count - first : chunkCells;
          if (flipped) {
            writer.WriteVarUint(run);
            flipped = false;
            run = 0;
          }
          run += static_cast<std::uint32_t>(chunk);
          word += wordsPerChunk - 1u;
          first += chunk - 64u;
          continue;
        }
      }
      const std::size_t cells = count - first < 64u ? count - first : 64u;
      std::uint64_t bits = 0;
      if (cells == 64u) {
        for (std::size_t k = 0; k < 8u; ++k) {
          bits |= seenOf8(now + first + 8u * k) << (8u * k);
        }
      } else {
        for (std::size_t k = 0; k < cells; ++k) {
          bits |= std::uint64_t{now[first + k] != 0 ? 1u : 0u} << k;
        }
      }
      const std::uint64_t changed = bits ^ seen[word];
      seen[word] = bits;
      const std::uint64_t all = cells == 64u ? ~std::uint64_t{0} : (std::uint64_t{1} << cells) - 1u;
      if (changed == (flipped ? all : 0u)) {
        run += static_cast<std::uint32_t>(cells); // the whole word continues the run
        continue;
      }
      // Runs inside the word: the length of each stretch of equal bits from `at`.
      std::size_t at = 0;
      while (at < cells) {
        const std::uint64_t rest = changed >> at;
        const auto stretch = static_cast<std::size_t>(flipped ? std::countr_one(rest) : std::countr_zero(rest));
        const std::size_t length = stretch < cells - at ? stretch : cells - at;
        run += static_cast<std::uint32_t>(length);
        at += length;
        if (at < cells) {
          writer.WriteVarUint(run);
          flipped = !flipped;
          run = 0;
        }
      }
    }
    if (run > 0u) {
      writer.WriteVarUint(run);
    }
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
