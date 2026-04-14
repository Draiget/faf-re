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
   * Address: 0x0054A4C0 (FUN_0054A4C0, Moho::CAniDefaultSkel::~CAniDefaultSkel)
   * Mangled: ??1CAniDefaultSkel@Moho@@QAE@XZ
   * Deleting thunk: 0x0054AD50 (FUN_0054AD50, ??_GCAniDefaultSkel@Moho@@UAEPAXI@Z)
   *
   * What it does:
   * Resets vftable to `CAniSkel`, releases skeleton vectors/shared SCM file,
   * then returns to scalar deleting destructor thunk for optional delete.
   */
  CAniDefaultSkel::~CAniDefaultSkel() = default;
} // namespace moho
