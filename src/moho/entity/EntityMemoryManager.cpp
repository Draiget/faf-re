#include "moho/entity/EntityMemoryManager.h"

#include <new>
#include "moho/console/CConCommand.h"

namespace moho
{
  bool sim_EntityPools = true;

  TConVar<bool> gTConVar_sim_EntityPools(
    "sim_EntityPools",
    "Use 64-KB slab memory pools for Unit, Projectile, and all Entity-derived instances.",
    &sim_EntityPools
  );

  EntityMemoryManager::EntityMemoryManager()
    : mPoolUnit(0x6A8, 16)
    , mPoolProjectile(0x380, 16)
    , mPoolCollisionBeam(0x2A0, 16)
    , mPoolProp(0x288, 16)
    , mPoolReconBlip(0x280, 16)
    , mPoolEntityShield(0x270, 16)
  {
  }

  EntityMemoryManager::~EntityMemoryManager()
  {
    Clear();
  }

  EntityMemoryManager& EntityMemoryManager::Instance()
  {
    static EntityMemoryManager sInstance;
    return sInstance;
  }

  void EntityMemoryManager::Clear() noexcept
  {
    mPoolUnit.Clear();
    mPoolProjectile.Clear();
    mPoolCollisionBeam.Clear();
    mPoolProp.Clear();
    mPoolReconBlip.Clear();
    mPoolEntityShield.Clear();
  }

  FixedSlabPool* EntityMemoryManager::FindPoolForSize(const std::size_t size) noexcept
  {
    switch (size) {
      case 0x6A8:
        return &mPoolUnit;
      case 0x380:
        return &mPoolProjectile;
      case 0x2A0:
        return &mPoolCollisionBeam;
      case 0x288:
        return &mPoolProp;
      case 0x280:
        return &mPoolReconBlip;
      case 0x270:
        return &mPoolEntityShield;
      default:
        return nullptr;
    }
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

    const SlabHeader* const slab = reinterpret_cast<const SlabHeader*>(
      reinterpret_cast<std::uintptr_t>(ptr) & ~std::uintptr_t(FixedSlabPool::kSlabBytes - 1u)
    );

    // Hybrid check: verify if pointer originated from one of our valid slabs
    if (slab->magic == FixedSlabPool::kSlabMagic && slab->ownerPool != nullptr) {
      slab->ownerPool->Deallocate(ptr);
      return;
    }

    // Otherwise, it was allocated via global operator new
    ::operator delete(ptr);
  }

  std::size_t EntityMemoryManager::GetTotalAllocatedCount() const noexcept
  {
    return mPoolUnit.GetAllocatedCount() +
           mPoolProjectile.GetAllocatedCount() +
           mPoolCollisionBeam.GetAllocatedCount() +
           mPoolProp.GetAllocatedCount() +
           mPoolReconBlip.GetAllocatedCount() +
           mPoolEntityShield.GetAllocatedCount();
  }

  std::size_t EntityMemoryManager::GetTotalActiveSlabs() const noexcept
  {
    return mPoolUnit.GetActiveSlabCount() +
           mPoolProjectile.GetActiveSlabCount() +
           mPoolCollisionBeam.GetActiveSlabCount() +
           mPoolProp.GetActiveSlabCount() +
           mPoolReconBlip.GetActiveSlabCount() +
           mPoolEntityShield.GetActiveSlabCount();
  }

  std::size_t EntityMemoryManager::GetTotalCachedEmptySlabs() const noexcept
  {
    return mPoolUnit.GetCachedEmptySlabCount() +
           mPoolProjectile.GetCachedEmptySlabCount() +
           mPoolCollisionBeam.GetCachedEmptySlabCount() +
           mPoolProp.GetCachedEmptySlabCount() +
           mPoolReconBlip.GetCachedEmptySlabCount() +
           mPoolEntityShield.GetCachedEmptySlabCount();
  }

} // namespace moho
