#include "CAniDefaultSkel.h"

namespace moho
{
  /**
   * Address: 0x0054A390 (FUN_0054A390, Moho::CAniDefaultSkel::CAniDefaultSkel)
   * Mangled: ??0CAniDefaultSkel@Moho@@IAE@XZ
   *
   * What it does:
   * Initializes the process-default skeleton with one `Root` bone and one
   * matching bone-name index entry, then rebuilds bounds.
   */
  CAniDefaultSkel::CAniDefaultSkel()
  {
    mFile.reset();
    mBones = msvc8::vector<SAniSkelBone>{};
    mBoneNameToIndex = msvc8::vector<SAniSkelBoneNameIndex>{};

    SAniSkelBone rootBone{};
    rootBone.mBoneName = "Root";
    rootBone.mParentBoneIndex = -1;
    rootBone.mLocalOffsetX = 1.0f;
    rootBone.mBoneTransform.orient_.w = 1.0f;
    mBones.push_back(rootBone);

    SAniSkelBoneNameIndex rootNameIndex{};
    rootNameIndex.mBoneName = "Root";
    rootNameIndex.mBoneIndex = 0;
    mBoneNameToIndex.push_back(rootNameIndex);

    UpdateBoneBounds();
  }

  /**
   * Address: 0x0054AD50 (FUN_0054AD50, scalar deleting destructor thunk)
   * Mangled: ??_GCAniDefaultSkel@Moho@@UAEPAXI@Z
   *
   * What it does:
   * Runs base skeleton teardown and conditionally deletes `this`.
   */
  CAniDefaultSkel::~CAniDefaultSkel() = default;
} // namespace moho
