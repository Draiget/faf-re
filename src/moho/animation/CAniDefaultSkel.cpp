#include "CAniDefaultSkel.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* CAniDefaultSkel::sType = nullptr;

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
    rootBone.mLocalTransform.orient_.w = 1.0f;
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

namespace moho
{
  void CAniDefaultSkel::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetShared(CAniSkel::GetDefaultSkeleton(), 1u);
  }

  void CAniDefaultSkel::MemberSaveConstructArgs(
    gpg::WriteArchive&, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    result.SetOwned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CAniDefaultSkel>`, vtable 0x00E173D4.
   *
   * Address: 0x00BC98D0 (FUN_00BC98D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4540 (FUN_00BF4540 -- the global's destructor.)
   * Address: 0x0054C4D0 (FUN_0054C4D0 -- `Init`.)
   * Address: 0x0054AAA0 (FUN_0054AAA0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct CAniDefaultSkelSaveConstruct : gpg::SerSaveConstructHelper<CAniDefaultSkel>
  {};

  /**
   * `gpg::SerConstructHelper<CAniDefaultSkel>`, vtable 0x00E173E4.
   *
   * Address: 0x00BC9900 (FUN_00BC9900 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4570 (FUN_00BF4570 -- the global's destructor.)
   * Address: 0x0054C550 (FUN_0054C550 -- `Init`.)
   * Address: 0x0054ABB0 (FUN_0054ABB0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x0054DE50 (FUN_0054DE50 -- `Delete`.)
   */
  struct CAniDefaultSkelConstruct : gpg::SerConstructHelper<CAniDefaultSkel>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AC334 -- process-global `CAniDefaultSkelSaveConstruct` singleton.
  moho::CAniDefaultSkelSaveConstruct gCAniDefaultSkelSaveConstruct;

  // Address: 0x010AC254 -- process-global `CAniDefaultSkelConstruct` singleton.
  moho::CAniDefaultSkelConstruct gCAniDefaultSkelConstruct;
} // namespace
