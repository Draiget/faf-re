#include "moho/entity/EntityMemoryManager.h"

#include <new>
#include "moho/console/CConCommand.h"
#include "moho/entity/FixedSlabPool.h"

#include "moho/unit/core/Unit.h"
#include "moho/projectile/Projectile.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/Prop.h"
#include "moho/sim/ReconBlip.h"
#include "moho/entity/Shield.h"
#include "moho/entity/Entity.h"

namespace moho
{
  bool sim_EntityPools = false;

  TConVar<bool> gTConVar_sim_EntityPools(
    "sim_EntityPools",
    "Use 64-KB slab memory pools for Unit, Projectile, and all Entity-derived instances.",
    &sim_EntityPools
  );

  EntityMemoryManager::EntityMemoryManager()
  {
    // Register size classes dynamically via sizeof on the current architecture (x86 or x64)
    RegisterSize(sizeof(Unit));
    RegisterSize(sizeof(ReconBlip));
    RegisterSize(sizeof(Projectile));
    RegisterSize(sizeof(CollisionBeamEntity));
    RegisterSize(sizeof(Prop));
    RegisterSize(sizeof(Shield));
    RegisterSize(sizeof(Entity));
  }

  EntityMemoryManager::~EntityMemoryManager()
  {
    Clear();
  }

  void EntityMemoryManager::RegisterSize(const std::size_t size)
  {
    for (const auto& pool : mPools) {
      if (pool->GetBlockSize() == size) {
        return; // Already registered
      }
    }
    mPools.push_back(std::make_unique<FixedSlabPool>(size, 16));
  }

  EntityMemoryManager& EntityMemoryManager::Instance()
  {
    static EntityMemoryManager sInstance;
    return sInstance;
  }

  void EntityMemoryManager::Clear() noexcept
  {
    for (auto& pool : mPools) {
      pool->Clear();
    }
  }

  FixedSlabPool* EntityMemoryManager::FindPoolForSize(const std::size_t size) noexcept
  {
    for (const auto& pool : mPools) {
      if (pool->GetBlockSize() == size) {
        return pool.get();
      }
    }
    return nullptr;
  }

  void* EntityMemoryManager::Allocate(const std::size_t size)
  {
    if (sim_EntityPools) {
      FixedSlabPool* const pool = FindPoolForSize(size);
      if (pool != nullptr) {
        return pool->Allocate();
      }
    }

    return ::operator new(size);
  }

  void EntityMemoryManager::Deallocate(void* const ptr, const std::size_t size) noexcept
  {
    if (ptr == nullptr) {
      return;
    }

    // 1. Range check: does the pointer belong to our reserved slab region?
    if (!slab_region::Owns(ptr)) {
      ::operator delete(ptr);
      return;
    }

    // 2. Safe to resolve slab header
    const SlabHeader* const slab = reinterpret_cast<const SlabHeader*>(
      reinterpret_cast<std::uintptr_t>(ptr) & ~std::uintptr_t(FixedSlabPool::kSlabBytes - 1u)
    );

    if (slab->magic == FixedSlabPool::kSlabMagic && slab->ownerPool != nullptr) {
      slab->ownerPool->Deallocate(ptr);
      return;
    }

    ::operator delete(ptr);
  }

  std::size_t EntityMemoryManager::GetTotalAllocatedCount() const noexcept
  {
    std::size_t total = 0;
    for (const auto& pool : mPools) {
      total += pool->GetAllocatedCount();
    }
    return total;
  }

  std::size_t EntityMemoryManager::GetTotalActiveSlabs() const noexcept
  {
    std::size_t total = 0;
    for (const auto& pool : mPools) {
      total += pool->GetActiveSlabCount();
    }
    return total;
  }

  std::size_t EntityMemoryManager::GetTotalCachedEmptySlabs() const noexcept
  {
    std::size_t total = 0;
    for (const auto& pool : mPools) {
      total += pool->GetCachedEmptySlabCount();
    }
    return total;
  }

} // namespace moho
