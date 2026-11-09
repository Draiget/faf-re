#include "EntityPool.h"

#include <new>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/Prop.h"
#include "moho/entity/Shield.h"
#include "moho/sim/ReconBlip.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  bool sim_EntityPool = true;
  TConVar<bool> gTConVar_sim_EntityPool(
    "sim_EntityPool",
    "Allocate entities from one free list per object size (same results). Read at the first entity allocation.",
    &sim_EntityPool
  );

  EntityPool::EntityPool()
    : mPool{6}
  {
    // One pool per size: on x86 Shield and Entity are both 0x270 bytes and share one.
    const auto add = [this](const std::size_t size, const std::size_t chunk) {
      if (!mPool.Has(size)) {
        mPool.AddPool(size, chunk);
      }
    };
    add(sizeof(moho::Unit), 1024);
    add(sizeof(moho::Prop), 1024);
    add(sizeof(moho::ReconBlip), 1024);
    add(sizeof(moho::CollisionBeamEntity), 128);
    add(sizeof(moho::Shield), 128);
    add(sizeof(moho::Entity), 128);
  }

  bool EntityPool::Active() noexcept
  {
    static const bool active = [] {
      gpg::Logf("sim_EntityPool: %s (read at the first entity allocation)", sim_EntityPool ? "on" : "off");
      return sim_EntityPool;
    }();
    return active;
  }

  void* EntityPool::Allocate(
    std::size_t size
  )
  {
    if (Active() && mPool.Has(size)) {
      void* block = nullptr;
      {
        const std::lock_guard<std::mutex> lock(mLock);
        block = mPool.Allocate(size);
      }
      if (block == nullptr) {
        throw std::bad_alloc();
      }
      return block;
    }
    return ::operator new(size);
  }

  void* EntityPool::TryAllocate(
    std::size_t size
  ) noexcept
  {
    try {
      return Allocate(size);
    } catch (...) {
      return nullptr;
    }
  }

  void EntityPool::Dellocate(
    void* ptr,
    std::size_t size
  ) noexcept
  {
    if (ptr == nullptr) {
      return;
    }
    if (Active() && mPool.Has(size)) {
      const std::lock_guard<std::mutex> lock(mLock);
      mPool.Deallocate(ptr, size);
      return;
    }
    ::operator delete(ptr);
  }

  EntityPool* EntityPool::sInstance = new EntityPool();
} // namespace moho
