#pragma once
#include "faf/memory/MemoryPool.h"

namespace moho
{
  class EntityPool
  {
  public:
    static EntityPool* sInstance;

  public:
    EntityPool();

    void* Allocate(std::size_t size);
    void Dellocate(void* ptr, std::size_t size);

  private:
    faf::MultiMemoryPool mPool;
  };
} // namespace moho