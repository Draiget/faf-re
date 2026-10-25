#pragma once

#include <cstddef>
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace moho
{
  struct FreeNode
  {
    FreeNode* next;
  };

  class FixedSlabPool;

  struct SlabHeader
  {
    std::uint32_t magic;           // 0x534C4142 ('SLAB')
    FixedSlabPool* ownerPool;      // Owning pool
    SlabHeader* nextSlab;          // Intrusive slab list links
    SlabHeader* prevSlab;
    std::uint32_t allocatedBlocks; // Currently allocated blocks in this slab
    std::uint32_t totalBlocks;     // Total slots capacity in this slab
    FreeNode* freeList;            // Head of free block list
  };

  /**
   * Thread-safe fixed-size slab allocator managing 64-KB virtual memory blocks.
   * Derives slab headers via pointer masking: ptr & ~0xFFFF.
   * Reclaims completely empty slabs to the OS via VirtualFree when cache limit is exceeded.
   */
  class FixedSlabPool
  {
  public:
    static constexpr std::size_t kSlabBytes = 64u * 1024u;
    static constexpr std::uint32_t kSlabMagic = 0x534C4142u; // 'SLAB'
    static constexpr std::uint32_t kMaxCachedEmptySlabs = 2u;

    explicit FixedSlabPool(std::size_t blockSize, std::size_t alignment = 16u);
    ~FixedSlabPool();

    FixedSlabPool(const FixedSlabPool&) = delete;
    FixedSlabPool& operator=(const FixedSlabPool&) = delete;

    [[nodiscard]] void* Allocate();
    void Deallocate(void* ptr) noexcept;
    void Clear() noexcept;

    [[nodiscard]] std::size_t GetBlockSize() const noexcept;
    [[nodiscard]] std::size_t GetAllocatedCount() const noexcept;
    [[nodiscard]] std::size_t GetActiveSlabCount() const noexcept;
    [[nodiscard]] std::size_t GetCachedEmptySlabCount() const noexcept;

  private:
    [[nodiscard]] SlabHeader* CreateNewSlab();
    void FreeSlabToOs(SlabHeader* slab) noexcept;

    void LinkSlab(SlabHeader*& listHead, SlabHeader* slab) noexcept;
    void UnlinkSlab(SlabHeader*& listHead, SlabHeader* slab) noexcept;

    std::size_t mBlockSize{0};
    std::size_t mAlignedBlockSize{0};
    std::size_t mBlocksPerSlab{0};

    SRWLOCK mLock = SRWLOCK_INIT;

    SlabHeader* mActiveSlab{nullptr};       // Slabs with available free slots
    SlabHeader* mFullSlabs{nullptr};        // Slabs where all slots are allocated
    SlabHeader* mCachedEmptySlabs{nullptr}; // Empty slabs kept in reserve

    std::size_t mAllocatedCount{0};
    std::size_t mActiveSlabCount{0};
    std::size_t mCachedEmptySlabCount{0};
  };

} // namespace moho
