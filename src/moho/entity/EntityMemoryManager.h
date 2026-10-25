#pragma once

#include <cstddef>
#include <cstdint>
#include "moho/entity/FixedSlabPool.h"

namespace moho
{
  extern bool sim_EntityPools;

  /**
   * High-level manager coordinating FixedSlabPool instances for each Entity size class.
   * Dispatches Allocate/Deallocate and provides fallback to global new/delete.
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

    // Known Entity class sizes:
    // 0x6A8 (1704) - Unit
    // 0x380 (896)  - Projectile
    // 0x2A0 (672)  - CollisionBeamEntity
    // 0x288 (648)  - Prop
    // 0x280 (640)  - ReconBlip
    // 0x270 (624)  - Shield / Entity
    FixedSlabPool mPoolUnit;
    FixedSlabPool mPoolProjectile;
    FixedSlabPool mPoolCollisionBeam;
    FixedSlabPool mPoolProp;
    FixedSlabPool mPoolReconBlip;
    FixedSlabPool mPoolEntityShield;
  };

} // namespace moho
