
#include "MemoryPool.h"

namespace faf
{
  faf::MemoryPool::MemoryPool(
    std::size_t blockSize,
    std::size_t nextCapacity
  )
    : MemoryPool{blockSize, nextCapacity, 0}
  {}

  faf::MemoryPool::MemoryPool(
    std::size_t blockSize,
    std::size_t nextCapacity,
    std::size_t initialCapacity
  )
    : m_blockSize{blockSize}
    , m_nextCapacity{nextCapacity}
    , m_freeList{nullptr}
  {
    if (initialCapacity != 0) {
      AllocateChunk(initialCapacity);
    }
  }

  MemoryPool::MemoryPool(
    MemoryPool&& other
  ) noexcept
    : m_blockSize(other.m_blockSize)
    , m_nextCapacity(other.m_nextCapacity)
    , m_freeList(other.m_freeList)
    , m_chunks(std::move(other.m_chunks))
  {
    other.m_freeList = nullptr;
    other.m_blockSize = 0;
    other.m_nextCapacity = 0;
  }

  MemoryPool& MemoryPool::operator=(
    MemoryPool&& other
  ) noexcept
  {
    if (this != &other) {
      for (void* chunk : m_chunks) {
        std::free(chunk);
      }
      m_blockSize = other.m_blockSize;
      m_nextCapacity = other.m_nextCapacity;
      m_freeList = other.m_freeList;
      m_chunks = std::move(other.m_chunks);

      other.m_freeList = nullptr;
      other.m_blockSize = 0;
      other.m_nextCapacity = 0;
    }
    return *this;
  }

  MemoryPool::~MemoryPool()
  {
    for (void* p : m_chunks) {
      std::free(p);
    }
  }
  size_t MemoryPool::GetBlockSize() const
  {
    return m_blockSize;
  }
  void* MemoryPool::Allocate()
  {
    if (m_freeList == nullptr) {
      if (AllocateChunk(m_nextCapacity) == nullptr) {
        return nullptr;
      }
    }
    FreeNode* node = m_freeList;
    m_freeList = node->next;
    return static_cast<void*>(node);
  }
  void MemoryPool::Deallocate(
    void* ptr
  )
  {
    if (ptr == nullptr) {
      return;
    }
    FreeNode* node = static_cast<FreeNode*>(ptr);
    node->next = m_freeList;
    m_freeList = node;
  }
  void* MemoryPool::AllocateChunk(
    size_t capacity
  )
  {
    void* chunk = std::malloc(m_blockSize * capacity);
    if (chunk == nullptr) {
      return nullptr;
    }
    m_chunks.push_back(chunk);

    char* current_block = static_cast<char*>(chunk);
    for (std::size_t i = 0; i < capacity; ++i) {
      FreeNode* node = reinterpret_cast<FreeNode*>(current_block);
      node->next = m_freeList;
      m_freeList = node;
      current_block += m_blockSize;
    }

    return chunk;
  }

  MultiMemoryPool::MultiMemoryPool(
    std::size_t intialCapacity
  )
  {
    m_pools.reserve(intialCapacity);
  }
} // namespace faf