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
    MemoryPool(std::size_t blockSize, std::size_t nextCapacity, std::size_t initialCapacity);

    MemoryPool(const MemoryPool&) = delete;
    MemoryPool& operator=(const MemoryPool&) = delete;
    MemoryPool(MemoryPool&& other) noexcept;
    MemoryPool& operator=(MemoryPool&& other) noexcept;

    size_t GetBlockSize() const;

    void* Allocate();
    void Deallocate(void* ptr);

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

    MultiMemoryPool(MultiMemoryPool&&) = default;
    MultiMemoryPool& operator=(MultiMemoryPool&&) = default;
    MultiMemoryPool(const MultiMemoryPool&) = delete;
    MultiMemoryPool& operator=(const MultiMemoryPool&) = delete;

    void AddPool(
      std::size_t blockSize,
      std::size_t nextCapacity,
      std::size_t initialCapacity = 0
    )
    {
      m_pools.emplace_back(blockSize, nextCapacity, initialCapacity);
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
    ) noexcept
    {
      if (ptr == nullptr) {
        return;
      }

      for (auto& pool : m_pools) {
        if (pool.GetBlockSize() >= size) {
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