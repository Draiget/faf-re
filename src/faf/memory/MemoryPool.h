#pragma once
#include <memory>
#include <vector>

namespace faf
{
  class MemoryPool
  {
  public:
    MemoryPool() = delete;
    ~MemoryPool();

    MemoryPool(std::size_t blockSize, std::size_t nextCapacity);

    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    MemoryPool(MemoryPool&& other) noexcept;
    MemoryPool& operator=(MemoryPool&& other) noexcept;

    size_t GetBlockSize() const;

    void* Allocate();
    void Deallocate(void* ptr) noexcept;

    bool Owns(
      const void* ptr
    ) const noexcept
    {
      if (!ptr)
        return false;
      const char* p = static_cast<const char*>(ptr);
      for (const void* chunk : m_chunks) {
        const char* start = static_cast<const char*>(chunk);
        const char* end = start + (m_blockSize * m_nextCapacity);

        if (p >= start && p < end) {
            return true;
        }
      }
      return false;
    }

  private:
    void* AllocateChunk(size_t capacity);

  private:
    struct FreeNode
    {
      FreeNode* next;
    };

    std::size_t m_blockSize;
    std::size_t m_nextCapacity;
    FreeNode* m_freeList;
    std::vector<void*> m_chunks;
  };

  class MultiMemoryPool
  {
  public:
    MultiMemoryPool() = default;
    MultiMemoryPool(std::size_t intialCapacity);

    MultiMemoryPool(MultiMemoryPool&&) = default;
    MultiMemoryPool& operator=(MultiMemoryPool&&) = default;
    MultiMemoryPool(const MultiMemoryPool&) = delete;
    MultiMemoryPool& operator=(const MultiMemoryPool&) = delete;

    void AddPool(
      std::size_t blockSize,
      std::size_t nextCapacity
    )
    {
      m_pools.emplace_back(blockSize, nextCapacity);
    }

    void* Allocate(
      std::size_t size
    )
    {
      for (auto& pool : m_pools) {
        if (pool.GetBlockSize() == size) {
          return pool.Allocate();
        }
      }
      throw std::bad_alloc();
    }

    void Deallocate(
      void* ptr,
      std::size_t size
    )
    {
      if (ptr == nullptr) {
        return;
      }

      for (auto& pool : m_pools) {
        if (pool.GetBlockSize() == size) {
          pool.Deallocate(ptr);
          return;
        }
      }

      std::abort();
    }

    void Deallocate(
      void* ptr
    )
    {
      if (ptr == nullptr) {
        return;
      }

      for (auto& pool : m_pools) {
        if (pool.Owns(ptr)) {
          pool.Deallocate(ptr);
          return;
        }
      }

      std::abort();
    }

  private:
    std::vector<MemoryPool> m_pools;
  };

} // namespace faf