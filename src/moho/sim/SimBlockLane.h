#pragma once

#if defined(_M_X64) || defined(__x86_64__)

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <utility>
#include <vector>

#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimThreadRole.h"

namespace moho
{
  /**
   * x64 only: the free list formations and projectiles share on the sim thread, the last freed block handed out
   * first. 11-bone pose arrays, `unsigned int` storage and visible decal storage take blocks from it too.
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
   * Other threads never touch the list, as a block they free goes to their own lane in the binary.
   *
   * It follows retail's log of that class. The sim thread frees no pose array there (27064121, ticks 7378 to 7381), so
   * pose arrays take blocks and don't return them. `IdPool`'s `BVIntSet` words and `mVisibleDecals` take blocks as well
   * (26992801, tick 4139), and hold them while they live. Still an approximation: expired decals go highest id first
   * where retail goes by address, and a block trim past 2 MB isn't modelled.
   */
  class SimBlockLane
  {
  public:
    static constexpr std::size_t kBlockBytes = 2048u;
    static constexpr std::size_t kParkedBlocks = 4096u;

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
     * For an object that takes a block of this class in the binary but lives elsewhere here: the block it would have
     * taken leaves the list, so the next object gets the one under it, as in the binary. It isn't freed at once: the
     * heap would hand the address straight back to the next formation (26910291 at tick 68593), where the binary's
     * block is still occupied. The oldest of `kParkedBlocks` goes back to the heap instead.
     */
    static void PassTopBlock() noexcept
    {
      if (IsSimThread() && !gSimKeyframeRestoring.load(std::memory_order_relaxed)) {
        std::vector<void*>& blocks = Blocks();
        if (!blocks.empty()) {
          static void* sParked[kParkedBlocks] = {};
          static std::size_t sNextParked = 0;
          ::operator delete(sParked[sNextParked]);
          sParked[sNextParked] = blocks.back();
          sNextParked = (sNextParked + 1u) % kParkedBlocks;
          blocks.pop_back();
        }
      }
    }

    /**
     * Storage whose bytes land in the binary's class holds a block for as long as it lives. While a keyframe loads
     * the list stands still, so it only notes the storage: `AdoptHeldBlocks` gives it the saved block.
     */
    static void NoteStorageAllocated(const void* const storage, const std::size_t bytes) noexcept
    {
      if (bytes <= 768u || bytes > 896u || !IsSimThread()) {
        return;
      }
      const bool restoring = gSimKeyframeRestoring.load(std::memory_order_relaxed);
      try {
        AddHeld(HeldBlock{storage, bytes, restoring ? nullptr : Allocate()});
      } catch (...) {
      }
    }

    static void NoteStorageFreed(const void* const storage) noexcept
    {
      // This runs for every free of `unsigned int` storage, and nearly none of it holds a block.
      if (!IsSimThread() || HeldFilterSlot(storage) == 0u) {
        return;
      }
      std::vector<HeldBlock>& held = Held();
      for (std::size_t i = held.size(); i != 0u; --i) {
        if (held[i - 1u].storage == storage) {
          --HeldFilterSlot(storage);
          void* const block = held[i - 1u].block;
          held[i - 1u] = held.back();
          held.pop_back();
          Free(block);
          return;
        }
      }
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

    /** Replaces the free list and drops the held blocks. Only while no sim runs. */
    static void SetFreeBlocks(std::vector<void*> blocks) noexcept
    {
      for (void* const block : Blocks()) {
        ::operator delete(block);
      }
      Blocks() = std::move(blocks);
      for (const HeldBlock& held : Held()) {
        ::operator delete(held.block);
      }
      Held().clear();
      std::memset(HeldFilterSlots(), 0, kHeldFilterSlots * sizeof(std::uint32_t));
    }

    struct HeldBlock
    {
      const void* storage;
      std::size_t bytes;
      void* block;
    };

    [[nodiscard]] static const std::vector<HeldBlock>& HeldBlocks() noexcept
    {
      return Held();
    }

    /**
     * After a keyframe's load: each storage it noted gets a saved block of its size. Which one is by order, as the
     * storage has no name in the save. Saved blocks left over stay held, as a unit's stale pointer can name them.
     */
    static void AdoptHeldBlocks(std::vector<HeldBlock> saved) noexcept
    {
      for (HeldBlock& held : Held()) {
        if (held.block != nullptr) {
          continue;
        }
        for (HeldBlock& candidate : saved) {
          if (candidate.block != nullptr && candidate.bytes == held.bytes) {
            held.block = candidate.block;
            candidate.block = nullptr;
            break;
          }
        }
        if (held.block == nullptr) {
          held.block = ::operator new(kBlockBytes, std::nothrow);
        }
      }
      for (const HeldBlock& candidate : saved) {
        if (candidate.block != nullptr) {
          try {
            AddHeld(HeldBlock{nullptr, candidate.bytes, candidate.block});
          } catch (...) {
          }
        }
      }
    }

  private:
    static constexpr std::size_t kHeldFilterSlots = std::size_t{1} << 16u;

    /** Held entries per hash of their storage: zero means no entry has it, and a shared slot only costs a walk. Static, as a heap allocation here would move what the sim gets next. */
    [[nodiscard]] static std::uint32_t* HeldFilterSlots() noexcept
    {
      static std::uint32_t sSlots[kHeldFilterSlots] = {};
      return sSlots;
    }

    [[nodiscard]] static std::uint32_t& HeldFilterSlot(const void* const storage) noexcept
    {
      const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(storage);
      return HeldFilterSlots()[((address >> 4u) ^ (address >> 20u)) & (kHeldFilterSlots - 1u)];
    }

    static void AddHeld(const HeldBlock& entry)
    {
      Held().push_back(entry);
      ++HeldFilterSlot(entry.storage);
    }

    [[nodiscard]] static std::vector<HeldBlock>& Held() noexcept
    {
      static std::vector<HeldBlock> sHeld;
      return sHeld;
    }

    [[nodiscard]] static std::vector<void*>& Blocks() noexcept
    {
      static std::vector<void*> sBlocks;
      return sBlocks;
    }
  };
} // namespace moho

#endif
