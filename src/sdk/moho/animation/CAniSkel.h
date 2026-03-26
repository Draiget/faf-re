#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/render/camera/VTransform.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CAniDefaultSkel;
  struct SScmFile;

  struct SAniSkelBoneNameIndex
  {
    const char* mBoneName;   // +0x00
    std::int32_t mBoneIndex; // +0x04
  };

  static_assert(
    offsetof(SAniSkelBoneNameIndex, mBoneName) == 0x00, "SAniSkelBoneNameIndex::mBoneName offset must be 0x00"
  );
  static_assert(
    offsetof(SAniSkelBoneNameIndex, mBoneIndex) == 0x04, "SAniSkelBoneNameIndex::mBoneIndex offset must be 0x04"
  );
  static_assert(sizeof(SAniSkelBoneNameIndex) == 0x08, "SAniSkelBoneNameIndex size must be 0x08");

  struct SAniSkelBone
  {
    const char* mBoneName;         // +0x00
    std::int32_t mParentBoneIndex; // +0x04
    float mLocalOffsetX;           // +0x08
    float mLocalOffsetY;           // +0x0C
    float mLocalOffsetZ;           // +0x10
    float mLocalScale;             // +0x14
    std::int32_t mChildStartIndex; // +0x18
    std::int32_t mChildCount;      // +0x1C
    std::int32_t mFlags;           // +0x20
    VTransform mBoneTransform;     // +0x24
    float mBoundsMinX;             // +0x40
    float mBoundsMinY;             // +0x44
    float mBoundsMinZ;             // +0x48
    float mBoundsMaxX;             // +0x4C
    float mBoundsMaxY;             // +0x50
    float mBoundsMaxZ;             // +0x54
  };

  static_assert(offsetof(SAniSkelBone, mBoneName) == 0x00, "SAniSkelBone::mBoneName offset must be 0x00");
  static_assert(offsetof(SAniSkelBone, mParentBoneIndex) == 0x04, "SAniSkelBone::mParentBoneIndex offset must be 0x04");
  static_assert(offsetof(SAniSkelBone, mLocalOffsetX) == 0x08, "SAniSkelBone::mLocalOffsetX offset must be 0x08");
  static_assert(offsetof(SAniSkelBone, mLocalOffsetY) == 0x0C, "SAniSkelBone::mLocalOffsetY offset must be 0x0C");
  static_assert(offsetof(SAniSkelBone, mLocalOffsetZ) == 0x10, "SAniSkelBone::mLocalOffsetZ offset must be 0x10");
  static_assert(offsetof(SAniSkelBone, mLocalScale) == 0x14, "SAniSkelBone::mLocalScale offset must be 0x14");
  static_assert(offsetof(SAniSkelBone, mChildStartIndex) == 0x18, "SAniSkelBone::mChildStartIndex offset must be 0x18");
  static_assert(offsetof(SAniSkelBone, mChildCount) == 0x1C, "SAniSkelBone::mChildCount offset must be 0x1C");
  static_assert(offsetof(SAniSkelBone, mFlags) == 0x20, "SAniSkelBone::mFlags offset must be 0x20");
  static_assert(offsetof(SAniSkelBone, mBoneTransform) == 0x24, "SAniSkelBone::mBoneTransform offset must be 0x24");
  static_assert(offsetof(SAniSkelBone, mBoundsMinX) == 0x40, "SAniSkelBone::mBoundsMinX offset must be 0x40");
  static_assert(offsetof(SAniSkelBone, mBoundsMinY) == 0x44, "SAniSkelBone::mBoundsMinY offset must be 0x44");
  static_assert(offsetof(SAniSkelBone, mBoundsMinZ) == 0x48, "SAniSkelBone::mBoundsMinZ offset must be 0x48");
  static_assert(offsetof(SAniSkelBone, mBoundsMaxX) == 0x4C, "SAniSkelBone::mBoundsMaxX offset must be 0x4C");
  static_assert(offsetof(SAniSkelBone, mBoundsMaxY) == 0x50, "SAniSkelBone::mBoundsMaxY offset must be 0x50");
  static_assert(offsetof(SAniSkelBone, mBoundsMaxZ) == 0x54, "SAniSkelBone::mBoundsMaxZ offset must be 0x54");
  static_assert(sizeof(SAniSkelBone) == 0x58, "SAniSkelBone size must be 0x58");

  class CAniSkel
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0054A370 (FUN_0054A370, scalar deleting destructor thunk)
     * Mangled: ??_GCAniSkel@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Tears down bone containers/shared state and optionally deletes `this`.
     */
    virtual ~CAniSkel();

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
    [[nodiscard]] const SAniSkelBone* GetBone(std::uint32_t boneIndex) const;

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
    [[nodiscard]] std::int32_t FindBoneIndex(const char* boneName) const;

    /**
     * Address: 0x0054AC90 (FUN_0054AC90)
     *
     * What it does:
     * Returns a shared pointer to process-global default skeleton storage.
     */
    [[nodiscard]] static boost::shared_ptr<const CAniSkel> GetDefaultSkeleton();

    /**
     * Address: 0x0054A540 (FUN_0054A540)
     * Mangled: ?UpdateBoneBounds@CAniSkel@Moho@@AAEXXZ
     *
     * What it does:
     * Rebuilds per-bone min/max bounds from SCM sample mapping data.
     */
    void UpdateBoneBounds();

  public:
    boost::shared_ptr<const SScmFile> mFile;               // +0x04
    msvc8::vector<SAniSkelBone> mBones;                    // +0x0C
    msvc8::vector<SAniSkelBoneNameIndex> mBoneNameToIndex; // +0x1C

  protected:
    CAniSkel() = default;
  };

  static_assert(offsetof(CAniSkel, mFile) == 0x04, "CAniSkel::mFile offset must be 0x04");
  static_assert(offsetof(CAniSkel, mBones) == 0x0C, "CAniSkel::mBones offset must be 0x0C");
  static_assert(offsetof(CAniSkel, mBoneNameToIndex) == 0x1C, "CAniSkel::mBoneNameToIndex offset must be 0x1C");
  static_assert(sizeof(CAniSkel) == 0x2C, "CAniSkel size must be 0x2C");
} // namespace moho
