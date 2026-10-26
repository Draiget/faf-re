#include "moho/entity/FixedSlabPool.h"

#include <cassert>
#include <new>
#include <vector>

namespace moho
{
  namespace
  {
    constexpr std::size_t AlignUp(const std::size_t value, const std::size_t alignment) noexcept
    {
      return (value + (alignment - 1u)) & ~(alignment - 1u);
    }
  } // namespace

  namespace slab_region
  {
    static std::uintptr_t gBase = 0;
    static INIT_ONCE gInitOnce = INIT_ONCE_STATIC_INIT;
    static SRWLOCK gLock = SRWLOCK_INIT;
    static std::vector<std::size_t> gFreeSlabOffsets;
    static std::size_t gNextOffset = 0;

    static BOOL CALLBACK InitReserve(PINIT_ONCE, PVOID, PVOID*) noexcept
    {
      void* const base = ::VirtualAlloc(nullptr, kReserveBytes, MEM_RESERVE, PAGE_NOACCESS);
      gBase = reinterpret_cast<std::uintptr_t>(base);
      return TRUE;
    }

    static void EnsureInit() noexcept
    {
      (void)::InitOnceExecuteOnce(&gInitOnce, &InitReserve, nullptr, nullptr);
    }

    bool Owns(const void* const ptr) noexcept
    {
      EnsureInit();
      const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(ptr);
      return gBase != 0 && (address - gBase) < kReserveBytes;
    }

    void* AllocateSlab() noexcept
    {
      EnsureInit();
      if (gBase == 0) {
        return nullptr;
      }

      std::size_t offset = 0;
      ::AcquireSRWLockExclusive(&gLock);
      if (!gFreeSlabOffsets.empty()) {
        offset = gFreeSlabOffsets.back();
        gFreeSlabOffsets.pop_back();
      } else if (gNextOffset + kSlabBytes <= kReserveBytes) {
        offset = gNextOffset;
        gNextOffset += kSlabBytes;
      } else {
        ::ReleaseSRWLockExclusive(&gLock);
        return nullptr;
      }
      ::ReleaseSRWLockExclusive(&gLock);

      void* const slabPtr = reinterpret_cast<void*>(gBase + offset);
      void* const committed = ::VirtualAlloc(slabPtr, kSlabBytes, MEM_COMMIT, PAGE_READWRITE);
      return committed;
    }

    void FreeSlab(void* const slab) noexcept
    {
      if (slab == nullptr) {
        return;
      }

      const std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(slab);
      assert(Owns(slab));
      assert((addr & (kSlabBytes - 1u)) == 0);

      const std::size_t offset = addr - gBase;
      ::VirtualFree(slab, kSlabBytes, MEM_DECOMMIT);

      ::AcquireSRWLockExclusive(&gLock);
      gFreeSlabOffsets.push_back(offset);
      ::ReleaseSRWLockExclusive(&gLock);
    }
  } // namespace slab_region

  FixedSlabPool::FixedSlabPool(const std::size_t blockSize, const std::size_t alignment)
    : mBlockSize(blockSize)
  {
    const std::size_t reqAlign = (alignment < 16u) ? 16u : alignment;
    mAlignedBlockSize = AlignUp((blockSize < sizeof(FreeNode)) ? sizeof(FreeNode) : blockSize, reqAlign);

    const std::size_t headerBytes = AlignUp(sizeof(SlabHeader), reqAlign);
    assert(headerBytes < kSlabBytes);

    mBlocksPerSlab = (kSlabBytes - headerBytes) / mAlignedBlockSize;
    assert(mBlocksPerSlab > 0);
  }

  FixedSlabPool::~FixedSlabPool()
  {
    Clear();
  }

  void FixedSlabPool::Clear() noexcept
  {
    ::AcquireSRWLockExclusive(&mLock);

    auto freeList = [this](SlabHeader*& head) {
      while (head != nullptr) {
        SlabHeader* const next = head->nextSlab;
        FreeSlabToOs(head);
        head = next;
      }
    };

    // Cached empty slabs hold 0 live blocks, safe to free to OS
    freeList(mCachedEmptySlabs);
    mCachedEmptySlabCount = 0;

    // Free active and full slabs only when no live allocated blocks remain
    if (mAllocatedCount == 0) {
      freeList(mActiveSlab);
      mActiveSlabCount = 0;

      freeList(mFullSlabs);
    }

    ::ReleaseSRWLockExclusive(&mLock);
  }

  void* FixedSlabPool::Allocate()
  {
    ::AcquireSRWLockExclusive(&mLock);

    SlabHeader* slab = mActiveSlab;
    if (slab == nullptr || slab->freeList == nullptr) {
      if (mCachedEmptySlabs != nullptr) {
        slab = mCachedEmptySlabs;
        UnlinkSlab(mCachedEmptySlabs, slab);
        --mCachedEmptySlabCount;
        LinkSlab(mActiveSlab, slab);
        ++mActiveSlabCount;
      } else {
        slab = CreateNewSlab();
        if (slab == nullptr) {
          ::ReleaseSRWLockExclusive(&mLock);
          throw std::bad_alloc();
        }
        LinkSlab(mActiveSlab, slab);
        ++mActiveSlabCount;
      }
    }

    assert(slab->freeList != nullptr);
    FreeNode* const node = slab->freeList;
    slab->freeList = node->next;
    ++slab->allocatedBlocks;
    ++mAllocatedCount;

    // If slab became completely full, move it to full list
    if (slab->freeList == nullptr) {
      UnlinkSlab(mActiveSlab, slab);
      LinkSlab(mFullSlabs, slab);
    }

    ::ReleaseSRWLockExclusive(&mLock);
    return static_cast<void*>(node);
  }

  void FixedSlabPool::Deallocate(void* const ptr) noexcept
  {
    if (ptr == nullptr) {
      return;
    }

    SlabHeader* const slab = reinterpret_cast<SlabHeader*>(
      reinterpret_cast<std::uintptr_t>(ptr) & ~std::uintptr_t(kSlabBytes - 1u)
    );

    assert(slab->magic == kSlabMagic);
    assert(slab->ownerPool == this);

    ::AcquireSRWLockExclusive(&mLock);

    const bool wasFull = (slab->freeList == nullptr);

    FreeNode* const node = static_cast<FreeNode*>(ptr);
    node->next = slab->freeList;
    slab->freeList = node;

    assert(slab->allocatedBlocks > 0);
    --slab->allocatedBlocks;
    --mAllocatedCount;

    if (wasFull) {
      // Slab was full, now has a free slot -> move back to active list
      UnlinkSlab(mFullSlabs, slab);
      LinkSlab(mActiveSlab, slab);
    }

    if (slab->allocatedBlocks == 0) {
      // Slab is completely empty
      UnlinkSlab(mActiveSlab, slab);
      --mActiveSlabCount;

      if (mCachedEmptySlabCount >= kMaxCachedEmptySlabs) {
        FreeSlabToOs(slab);
      } else {
        LinkSlab(mCachedEmptySlabs, slab);
        ++mCachedEmptySlabCount;
      }
    }

    ::ReleaseSRWLockExclusive(&mLock);
  }

  SlabHeader* FixedSlabPool::CreateNewSlab()
  {
    void* const rawMemory = slab_region::AllocateSlab();
    if (rawMemory == nullptr) {
      return nullptr;
    }

    assert((reinterpret_cast<std::uintptr_t>(rawMemory) & (kSlabBytes - 1u)) == 0);

    SlabHeader* const header = static_cast<SlabHeader*>(rawMemory);
    header->magic = kSlabMagic;
    header->ownerPool = this;
    header->nextSlab = nullptr;
    header->prevSlab = nullptr;
    header->allocatedBlocks = 0;
    header->totalBlocks = static_cast<std::uint32_t>(mBlocksPerSlab);

    const std::size_t headerBytes = AlignUp(sizeof(SlabHeader), (mAlignedBlockSize < 16u) ? 16u : 16u);
    std::uint8_t* cursor = static_cast<std::uint8_t*>(rawMemory) + headerBytes;

    FreeNode* prevNode = nullptr;
    for (std::size_t i = 0; i < mBlocksPerSlab; ++i) {
      FreeNode* const current = reinterpret_cast<FreeNode*>(cursor);
      if (prevNode != nullptr) {
        prevNode->next = current;
      } else {
        header->freeList = current;
      }
      prevNode = current;
      cursor += mAlignedBlockSize;
    }

    if (prevNode != nullptr) {
      prevNode->next = nullptr;
    }

    return header;
  }

  void FixedSlabPool::FreeSlabToOs(SlabHeader* const slab) noexcept
  {
    if (slab != nullptr) {
      slab->magic = 0;
      slab->ownerPool = nullptr;
      slab_region::FreeSlab(slab);
    }
  }

  void FixedSlabPool::LinkSlab(SlabHeader*& listHead, SlabHeader* const slab) noexcept
  {
    slab->nextSlab = listHead;
    slab->prevSlab = nullptr;
    if (listHead != nullptr) {
      listHead->prevSlab = slab;
    }
    listHead = slab;
  }

  void FixedSlabPool::UnlinkSlab(SlabHeader*& listHead, SlabHeader* const slab) noexcept
  {
    if (slab->prevSlab != nullptr) {
      slab->prevSlab->nextSlab = slab->nextSlab;
    } else if (listHead == slab) {
      listHead = slab->nextSlab;
    }

    if (slab->nextSlab != nullptr) {
      slab->nextSlab->prevSlab = slab->prevSlab;
    }

    slab->nextSlab = nullptr;
    slab->prevSlab = nullptr;
  }

  std::size_t FixedSlabPool::GetBlockSize() const noexcept
  {
    return mBlockSize;
  }

  std::size_t FixedSlabPool::GetAllocatedCount() const noexcept
  {
    return mAllocatedCount;
  }

  std::size_t FixedSlabPool::GetActiveSlabCount() const noexcept
  {
    return mActiveSlabCount;
  }

  std::size_t FixedSlabPool::GetCachedEmptySlabCount() const noexcept
  {
    return mCachedEmptySlabCount;
  }

} // namespace moho
