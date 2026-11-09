#pragma once
#include <cstddef>
#include <mutex>

#include "faf/memory/MemoryPool.h"

namespace moho
{
  /// Engine addition (sim_EntityPool, startup only): the switch's value when the first entity is allocated.
  extern bool sim_EntityPool;

  /**
   * Engine addition: Entity and its subclasses come from one free list per object size, so entities of a type sit
   * together in memory. `sim_EntityPool` is read once, at the first allocation, so every block is freed the way it was
   * allocated. A size with no pool, and every size with the switch off, uses the global allocator. Projectiles never
   * come here: they keep their own allocator (see Projectile::operator new).
   */
  class EntityPool
  {
  public:
    static EntityPool* sInstance;

  public:
    EntityPool();

    void* Allocate(std::size_t size);
    void* TryAllocate(std::size_t size) noexcept;
    void Dellocate(void* ptr, std::size_t size) noexcept;

  private:
    [[nodiscard]] static bool Active() noexcept;

    faf::MultiMemoryPool mPool;
    std::mutex mLock;
  };
} // namespace moho
