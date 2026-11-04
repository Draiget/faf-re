#pragma once

#if defined(_M_X64) || defined(__x86_64__)

#include <cstddef>
#include <new>
#include <utility>
#include <vector>

#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimThreadRole.h"

namespace moho
{
  /**
   * x64 only: the free list on the sim thread that formations and projectiles return to and that 11-bone pose arrays
   * also allocate from, the last freed block handed out first.
   *
   * Units keep a raw formation pointer (`SInfoCache::mFormationLayer`), and `IsSameFormationLayerWith` (0x006A8D40)
   * compares pointers, so a stale pointer can equal a new formation at a reused address. In the binary these objects
   * come from the sim thread's lane of the 896-byte class of its allocator (`malloc_0`, 0x00958B20), so a projectile
   * or a pose update between two formations takes the block the next formation would have reused. x86 runs that
   * allocator and doesn't need this list.
   *
   * Tested in the x86 allocator: with cache trims off and every other object of the class moved out, 26901494 and
   * 26906026 still pass; without pose arrays they fail at the same beat and hash as a list of formations and
   * projectiles, and without projectiles too 26916583 fails at beat 4900.
   *
   * A pose array takes a block here but doesn't return one (`CAniPoseBoneArray::FreeHeapBones`). The binary freed no
   * pose array on any thread in the ticks logged for 27064121 (7378 to 7381). When ours freed them here, they lay on
   * top of a freed formation and the next formation missed its old address.
   *
   * Other threads never touch the list, as a block they free goes to their own lane in the binary.
   */
  class SimBlockLane
  {
  public:
    static constexpr std::size_t kBlockBytes = 2048u;

    [[nodiscard]] static void* Allocate() noexcept
    {
      if (IsSimThread() && !gSimKeyframeRestoring.load(std::memory_order_relaxed)) {
        std::vector<void*>& blocks = Blocks();
        if (!blocks.empty()) {
          void* const block = blocks.back();
          blocks.pop_back();
          return block;
        }
      }
      return ::operator new(kBlockBytes, std::nothrow);
    }

    static void Free(void* const block) noexcept
    {
      if (IsSimThread() && !gSimKeyframeRestoring.load(std::memory_order_relaxed)) {
        try {
          Blocks().push_back(block);
          return;
        } catch (...) {
        }
      }
      ::operator delete(block);
    }

    /**
     * Engine addition (replay keyframes): the free list is game state, as the next object of any of the three kinds
     * takes its last block. While a keyframe loads the list stands still (`gSimKeyframeRestoring`), so what the load
     * creates doesn't use up the blocks the saved game had free.
     */
    [[nodiscard]] static const std::vector<void*>& FreeBlocks() noexcept
    {
      return Blocks();
    }

    /** Replaces the free list. Only while no sim runs. */
    static void SetFreeBlocks(std::vector<void*> blocks) noexcept
    {
      for (void* const block : Blocks()) {
        ::operator delete(block);
      }
      Blocks() = std::move(blocks);
    }

  private:
    [[nodiscard]] static std::vector<void*>& Blocks() noexcept
    {
      static std::vector<void*> sBlocks;
      return sBlocks;
    }
  };
} // namespace moho

#endif
