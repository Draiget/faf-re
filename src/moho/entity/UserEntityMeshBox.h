#pragma once

// The box a selection command uses for a user entity: its mesh's, or the invalid box.

#include "Wm3Box3.h"
#include "moho/collision/CColPrimitiveBox3f.h"
#include "moho/entity/UserEntity.h"
#include "moho/math/Vector3f.h"
#include "moho/mesh/Mesh.h"

namespace moho
{
  [[nodiscard]] inline const Wm3::Box3f* SelectionEntityMeshBox(moho::UserEntity* const entity)
  {
    moho::MeshInstance* const meshInstance = (entity != nullptr) ? entity->mMeshInstance : nullptr;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      return &meshInstance->box;
    }
    return &moho::Invalid<Wm3::Box3f>();
  }
} // namespace moho
