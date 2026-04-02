#include "CAniSkel.h"

#include <cstring>

#include "CAniDefaultSkel.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/resource/SScmFile.h"
#include "wm3/Vector3.h"

namespace
{
  struct NoDeleteAniSkel
  {
    void operator()(const moho::CAniSkel*) const noexcept {}
  };
} // namespace

namespace moho
{
  gpg::RType* CAniSkel::sType = nullptr;

  /**
   * Address: 0x0054A370 (FUN_0054A370, scalar deleting destructor thunk)
   * Mangled: ??_GCAniSkel@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Tears down bone containers/shared state and optionally deletes `this`.
   */
  CAniSkel::~CAniSkel() = default;

  /**
   * Address: 0x00549E20 (FUN_00549E20)
   *
   * unsigned int
   *
   * IDA signature:
   * int __userpurge FUN_00549e20@<eax>(int this@<esi>, uint index@<edi>);
   *
   * What it does:
   * Returns a bone pointer for a valid index, otherwise null.
   */
  const SAniSkelBone* CAniSkel::GetBone(const std::uint32_t boneIndex) const
  {
    const SAniSkelBone* const begin = mBones.begin();
    if (!begin) {
      return nullptr;
    }

    if (boneIndex >= static_cast<std::uint32_t>(mBones.size())) {
      return nullptr;
    }

    return begin + boneIndex;
  }

  /**
   * Address: 0x0054A7B0 (FUN_0054A7B0)
   *
   * char const *
   *
   * IDA signature:
   * int __thiscall FUN_0054a7b0(void *this, byte *name);
   *
   * What it does:
   * Binary-searches the sorted bone-name table and returns index or `-1`.
   */
  std::int32_t CAniSkel::FindBoneIndex(const char* const boneName) const
  {
    if (!boneName) {
      return -1;
    }

    const SAniSkelBoneNameIndex* const begin = mBoneNameToIndex.begin();
    if (!begin) {
      return -1;
    }

    std::int32_t low = 0;
    std::int32_t high = static_cast<std::int32_t>(mBoneNameToIndex.size());
    while (low < high) {
      const std::int32_t middle = (low + high) >> 1;
      const char* const middleName = begin[middle].mBoneName ? begin[middle].mBoneName : "";
      const std::int32_t compareResult = std::strcmp(boneName, middleName);
      if (compareResult < 0) {
        high = middle;
        continue;
      }

      if (compareResult > 0) {
        low = middle + 1;
        continue;
      }

      return begin[middle].mBoneIndex;
    }

    return -1;
  }

  /**
   * Address: 0x0054AC90 (FUN_0054AC90)
   *
   * What it does:
   * Returns a shared pointer to process-global default skeleton storage.
   */
  boost::shared_ptr<const CAniSkel> CAniSkel::GetDefaultSkeleton()
  {
    static CAniDefaultSkel defaultSkeleton{};
    return boost::shared_ptr<const CAniSkel>(static_cast<const CAniSkel*>(&defaultSkeleton), NoDeleteAniSkel{});
  }

  /**
   * Address: 0x0054A540 (FUN_0054A540)
   * Mangled: ?UpdateBoneBounds@CAniSkel@Moho@@AAEXXZ
   *
   * What it does:
   * Rebuilds per-bone min/max bounds from SCM sample mapping data.
   */
  void CAniSkel::UpdateBoneBounds()
  {
    SAniSkelBone* const boneStart = mBones.begin();
    SAniSkelBone* const boneFinish = mBones.end();
    for (SAniSkelBone* bone = boneStart; bone && bone != boneFinish; ++bone) {
      bone->mBoundsMinX = 0.0f;
      bone->mBoundsMinY = 0.0f;
      bone->mBoundsMinZ = 0.0f;
      bone->mBoundsMaxX = 0.0f;
      bone->mBoundsMaxY = 0.0f;
      bone->mBoundsMaxZ = 0.0f;
    }

    const SScmFile* const sourceFile = mFile.get();
    if (sourceFile == nullptr || boneStart == nullptr) {
      return;
    }

    const std::uint32_t boneCount = static_cast<std::uint32_t>(mBones.size());
    const std::uint32_t sampleCount = sourceFile->mBoneBoundsSampleCount;
    if (sampleCount == 0u) {
      return;
    }

    const SScmBoneBoundsSample* const samples = scm_file::GetBoneBoundsSamples(*sourceFile);
    if (samples == nullptr) {
      return;
    }

    for (std::uint32_t sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex) {
      const SScmBoneBoundsSample& sample = samples[sampleIndex];
      const std::uint32_t boneIndex = sample.mBoneIndex;
      if (boneIndex >= boneCount) {
        gpg::Warnf("Encoutered bad SCM file. Dumping out data");
        for (std::uint32_t dumpIndex = 0; dumpIndex < boneCount; ++dumpIndex) {
          const char* const boneName = boneStart[dumpIndex].mBoneName ? boneStart[dumpIndex].mBoneName : "";
          gpg::Warnf(" dumping bone %d name = %s", dumpIndex, boneName);
        }

        GPG_ASSERT(!"Invalid bone index in SCM bounds sample");
        return;
      }

      SAniSkelBone& bone = boneStart[boneIndex];
      const Wm3::Vec3f localPosition{sample.mLocalPositionX, sample.mLocalPositionY, sample.mLocalPositionZ};
      Wm3::Vec3f rotatedPosition{};
      Wm3::MultiplyQuaternionVector(&rotatedPosition, localPosition, bone.mBoneTransform.orient_);

      const float mappedX = bone.mBoneTransform.pos_.x + rotatedPosition.x;
      const float mappedY = bone.mBoneTransform.pos_.y + rotatedPosition.y;
      const float mappedZ = bone.mBoneTransform.pos_.z + rotatedPosition.z;

      if (mappedX < bone.mBoundsMinX) {
        bone.mBoundsMinX = mappedX;
      }
      if (mappedY < bone.mBoundsMinY) {
        bone.mBoundsMinY = mappedY;
      }
      if (mappedZ < bone.mBoundsMinZ) {
        bone.mBoundsMinZ = mappedZ;
      }

      if (mappedX > bone.mBoundsMaxX) {
        bone.mBoundsMaxX = mappedX;
      }
      if (mappedY > bone.mBoundsMaxY) {
        bone.mBoundsMaxY = mappedY;
      }
      if (mappedZ > bone.mBoundsMaxZ) {
        bone.mBoundsMaxZ = mappedZ;
      }
    }
  }
} // namespace moho
