#include "CAniSkel.h"

#include <cstring>

#include "CAniDefaultSkel.h"

namespace
{
  struct NoDeleteAniSkel
  {
    void operator()(const moho::CAniSkel*) const noexcept {}
  };

  void InitializeDefaultSkeletonStorage(moho::CAniDefaultSkel& skeleton)
  {
    // 0x0054A390 seeds a single default bone/name entry and parent index -1.
    static constexpr const char* kDefaultBoneName = "";

    skeleton.mSourceSkeleton.reset();
    skeleton.mBones = msvc8::vector<moho::SAniSkelBone>{};
    skeleton.mBoneNameToIndex = msvc8::vector<moho::SAniSkelBoneNameIndex>{};

    moho::SAniSkelBone defaultBone{};
    defaultBone.mBoneName = kDefaultBoneName;
    defaultBone.mParentBoneIndex = -1;
    skeleton.mBones.push_back(defaultBone);

    moho::SAniSkelBoneNameIndex nameIndex{};
    nameIndex.mBoneName = kDefaultBoneName;
    nameIndex.mBoneIndex = 0;
    skeleton.mBoneNameToIndex.push_back(nameIndex);

    skeleton.RebuildBoneBounds();
  }
} // namespace

namespace moho
{
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
    static const bool initialized = [] {
      InitializeDefaultSkeletonStorage(defaultSkeleton);
      return true;
    }();

    (void)initialized;
    return boost::shared_ptr<const CAniSkel>(static_cast<const CAniSkel*>(&defaultSkeleton), NoDeleteAniSkel{});
  }

  /**
   * Address: 0x0054A540 (FUN_0054A540)
   *
   * What it does:
   * Rebuilds per-bone min/max bounds from source mapping data.
   */
  void CAniSkel::RebuildBoneBounds()
  {
    for (SAniSkelBone* bone = mBones.begin(); bone && bone != mBones.end(); ++bone) {
      bone->mBoundsMinX = 0.0f;
      bone->mBoundsMinY = 0.0f;
      bone->mBoundsMinZ = 0.0f;
      bone->mBoundsMaxX = 0.0f;
      bone->mBoundsMaxY = 0.0f;
      bone->mBoundsMaxZ = 0.0f;
    }

    // Full mapping walk depends on CAniResourceSkel internals (+0x10/+0x18 and
    // 0x44-byte entries) which are recovered in a follow-up pass.
  }
} // namespace moho
