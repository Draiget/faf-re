#pragma once

#include "moho/entity/EntityCollisionUpdater.h"

namespace moho
{
  // Owning binary-facing layout is in moho/entity/EntityCollisionUpdater.h.
  using CColPrimitiveBase = EntityCollisionUpdater;
  using CColPairResult = CollisionPairResult;
  using CColLineResult = CollisionLineResult;

  template <class T>
  struct CColPrimitiveType;

  template <>
  struct CColPrimitiveType<Wm3::Box3f>
  {
    using type = BoxCollisionPrimitive;
  };

  template <>
  struct CColPrimitiveType<Wm3::Sphere3f>
  {
    using type = SphereCollisionPrimitive;
  };

  template <class T>
  using CColPrimitive = typename CColPrimitiveType<T>::type;
} // namespace moho
