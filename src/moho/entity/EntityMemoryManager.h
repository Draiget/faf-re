#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace moho
{
  class FixedSlabPool;

  extern bool sim_EntityPools;

  /**
   * High-level manager coordinating FixedSlabPool instances for each Entity size class.
   * Dispatches Allocate/Deallocate with slab_region range checks and fallback to global new/delete.
   */
  class EntityMemoryManager
  {
  public:
    static EntityMemoryManager& Instance();

    void Clear() noexcept;

    [[nodiscard]] void* Allocate(std::size_t size);
    // A slab block, or nullptr when sim_EntityPools is off, no slab pool has this size or the slab region is full.
    [[nodiscard]] void* TryAllocateSlab(std::size_t size);
    // True when ptr lies in the slab reservation, so Deallocate must take it.
    [[nodiscard]] static bool OwnsBlock(const void* ptr) noexcept;
    void Deallocate(void* ptr, std::size_t size) noexcept;

    [[nodiscard]] FixedSlabPool* FindPoolForSize(std::size_t size) noexcept;

    // Diagnostic accessors
    [[nodiscard]] std::size_t GetTotalAllocatedCount() const noexcept;
    [[nodiscard]] std::size_t GetTotalActiveSlabs() const noexcept;
    [[nodiscard]] std::size_t GetTotalCachedEmptySlabs() const noexcept;

  private:
    EntityMemoryManager();
    ~EntityMemoryManager();

    EntityMemoryManager(const EntityMemoryManager&) = delete;
    EntityMemoryManager& operator=(const EntityMemoryManager&) = delete;

    void RegisterSize(std::size_t size);

    std::vector<std::unique_ptr<FixedSlabPool>> mPools;
  };

} // namespace moho
