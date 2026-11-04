#pragma once

#include <cstddef>

#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"

namespace moho
{
  /**
   * Engine addition: a pose's bone by index, or null for an index it doesn't have.
   */
  [[nodiscard]] inline CAniPoseBone* ResolvePoseBone(CAniPose* const pose, const int boneIndex)
  {
    if (pose == nullptr || boneIndex < 0) {
      return nullptr;
    }

    CAniPoseBone* const bonesBegin = pose->mBones.begin();
    CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesBegin >= bonesEnd) {
      return nullptr;
    }

    const std::ptrdiff_t boneCount = bonesEnd - bonesBegin;
    if (boneIndex >= boneCount) {
      return nullptr;
    }

    return &bonesBegin[boneIndex];
  }

  /**
   * Engine addition: as above, through an actor's pose.
   */
  [[nodiscard]] inline CAniPoseBone* ResolvePoseBone(CAniActor* const actor, const int boneIndex)
  {
    return actor != nullptr ? ResolvePoseBone(actor->mPose.get(), boneIndex) : nullptr;
  }
} // namespace moho
