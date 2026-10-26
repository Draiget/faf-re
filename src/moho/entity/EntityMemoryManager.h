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
