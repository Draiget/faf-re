#pragma once

#include <cstdint>

namespace faf::editor::memtrace
{
  /**
   * `/memtrace`: finds what a play leaves behind (board task WPE.16). Installs the engine's memory
   * hook (`gpg::SetMemHook`, which `malloc_0` and `free_0` call for every block), and records each
   * live block's size, call stack and the play it was made in. Its own records live on a private
   * Win32 heap, so recording never re-enters the hook. Slow; for diagnosis only.
   */
  void Start();

  /** Whether `Start` ran. */
  [[nodiscard]] bool Running() noexcept;

  /** A play starts: blocks from now on belong to it. Returns its number (1 for the first play). */
  std::uint32_t NextPlay();

  /**
   * Logs the call stacks whose blocks made during play `play` are still alive, the largest first
   * (`count` of them, each with up to six frames past the allocator).
   */
  void Report(std::uint32_t play, int count);
} // namespace faf::editor::memtrace
