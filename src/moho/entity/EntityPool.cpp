#include "EntityPool.h"

#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/Prop.h"
#include "moho/entity/Shield.h"
#include "moho/projectile/Projectile.h"
#include "moho/sim/ReconBlip.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  EntityPool::EntityPool()
    : mPool{7}
  {
    mPool.AddPool(sizeof(moho::Unit), 1024);
    mPool.AddPool(sizeof(moho::Projectile), 1024);
    mPool.AddPool(sizeof(moho::Prop), 1024);
    mPool.AddPool(sizeof(moho::ReconBlip), 1024);
    mPool.AddPool(sizeof(moho::CollisionBeamEntity), 128);
    mPool.AddPool(sizeof(moho::Shield), 128);
    mPool.AddPool(sizeof(moho::Entity), 128);
  }

  void* EntityPool::Allocate(
    std::size_t size
  )
  {
    return mPool.Allocate(size);
  }

  void EntityPool::Dellocate(
    void* ptr,
    std::size_t size
  )
  {
    mPool.Deallocate(ptr, size);
  }

  EntityPool* EntityPool::sInstance = new EntityPool();
} // namespace moho