#pragma once

#include "moho/mesh/Mesh.h"

namespace moho
{
  /**
   * Engine addition, not in the binary.
   *
   * Whether the LOD a batch key names is one the instance's mesh holds now. `MeshRenderer::Batch` keeps the pointer
   * from the moment the batch was built; a mesh that has since been reloaded or released leaves a LOD the batch still
   * names (seen as reads through 0x0101010101010101 and 0xA5A5A5A5A5A5A5A5 in the feeds of the water and the lights on
   * a replay seek, where units come and go many times a frame). A feed that reads through the LOD (its material, its
   * blueprint copy) asks first. The instance holds its mesh, so the mesh's own list is safe to read.
   */
  [[nodiscard]] inline bool BatchLodIsLive(
    const MeshInstance* const instance,
    const MeshLOD* const lod
  )
  {
    const Mesh* const mesh = instance != nullptr ? instance->mesh.get() : nullptr;
    if (mesh == nullptr) {
      return false;
    }
    for (MeshLOD* const* it = mesh->lods.begin(); it != mesh->lods.end(); ++it) {
      if (*it == lod) {
        return true;
      }
    }
    return false;
  }
} // namespace moho
