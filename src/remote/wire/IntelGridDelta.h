#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP5.4): the view army's intel grids on the wire. A remote
// client needs the vision and water grids of its own army and of every army allied with it
// (research/WP11.3: the user code reads only those two kinds, through the focus army and its
// allies, and treats a missing grid as "sees everything"). The user code only ever tests a
// cell for non-zero (`CIntelGrid::IsVisible`), so a grid travels as one bit per cell.
//
// A grid goes as a run-length delta against the copy the client holds: width and height, then
// alternating run lengths of unchanged and flipped cells in row order, starting with an
// unchanged run (which may be empty), until every cell is covered. Fog moves at its edges, so a
// beat's delta is a few short runs. A baseline of another size, or none, counts as all hidden.

namespace faf::remote::wire
{
  /** A grid as the client tests it: row-major, one byte per cell, 1 where it is visible. */
  struct SGridBits
  {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> cells;

    [[nodiscard]] bool operator==(const SGridBits& other) const noexcept = default;
  };

  /** Writes `current` as a delta against `baseline` (null: all hidden). False on a malformed grid. */
  [[nodiscard]] bool EncodeGridDelta(const SGridBits& current, const SGridBits* baseline, BitWriter& writer);
  /** The words `EncodeGridDeltaInPlace` keeps a grid of this many cells in. */
  [[nodiscard]] constexpr std::size_t GridSeenWords(const std::size_t cells) noexcept { return (cells + 63u) / 64u; }
  /**
   * `EncodeGridDelta` straight from the sim's cells, any value but 0 being a set cell, against what
   * was set last time in `seen` (bit `i % 64` of word `i / 64` for cell `i`, `GridSeenWords` words),
   * which then holds `now`'s: one pass over the sim's cells, 64 at a time, and an eighth of that
   * for what the client holds. The same bits.
   */
  void EncodeGridDeltaInPlace(std::uint32_t width, std::uint32_t height, const std::int8_t* now, std::uint64_t* seen, BitWriter& writer);
  /**
   * The same, reading only the chunks of `chunkCells` cells (a multiple of 64) whose byte in
   * `changed` is set, and clearing them: the sim sets them where it may have changed a cell
   * (`moho::CIntelGrid::ChangedChunks`). `readAll` reads every chunk (a `seen` just reset).
   */
  void EncodeGridDeltaInPlace(
    std::uint32_t width, std::uint32_t height, const std::int8_t* now, std::uint64_t* seen, BitWriter& writer, std::uint8_t* changed,
    std::uint32_t chunkCells, bool readAll
  );

  /**
   * Reads one grid against `baseline` (the copy the encoder used, or null). Refuses a grid larger
   * than `maxCells` and runs that overshoot it, without allocating more than `maxCells` bytes.
   */
  [[nodiscard]] bool DecodeGridDelta(BitReader& reader, const SGridBits* baseline, std::uint32_t maxCells, SGridBits& out);
} // namespace faf::remote::wire
