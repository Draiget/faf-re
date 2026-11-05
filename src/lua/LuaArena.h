#pragma once

#include <cstddef>
#include <cstdint>

/**
 * Where a Lua state's memory lives on 64-bit builds (not in the binary).
 *
 * A Lua value is 8 bytes in the 2007 binary, a tag and a 32-bit pointer, which is what keeps tables
 * small. `LuaPlus::ValuePointer` keeps it 8 bytes on x64: every Lua object comes from this one range
 * below 4 GB, so its pointer fits 32 bits and reads back with a zero extend. `nblocks` keeps counting
 * x86 sizes (LuaMemAccounting.h), so the layout doesn't change how often Lua collects.
 *
 * 32-bit builds keep the binary's allocator and none of this exists.
 */
#if INTPTR_MAX != INT32_MAX
namespace lua
{
  /** Reserves the range, once. Allocating does it too; FAF_HIGHMEM has to do it before it takes the rest. */
  void ArenaReserve() noexcept;

  /** A block of at least `bytes`, 8-byte aligned, from the range. Null when the range is full. */
  [[nodiscard]] void* ArenaAllocate(std::size_t bytes) noexcept;

  /** The block resized, keeping its bytes; `block` may be null. Null when the range is full. */
  [[nodiscard]] void* ArenaReallocate(void* block, std::size_t oldBytes, std::size_t bytes) noexcept;

  /** Frees a block of the range; `block` may be null. */
  void ArenaFree(void* block) noexcept;

  /**
   * A light userdata's pointer as a 32-bit value: a cell in the range holding the pointer. Light
   * userdata can name anything, an image's address or a module handle, so it does not fit 32 bits.
   * The same pointer always gets the same cell, so it compares and hashes as itself. Cells are never
   * freed: the engine pushes a handful of pointers.
   */
  [[nodiscard]] void* const* ArenaLightCell(void* pointer) noexcept;
} // namespace lua
#endif
