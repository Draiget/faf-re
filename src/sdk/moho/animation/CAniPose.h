#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/camera/VTransform.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAniSkel;
  class CAniPose;
  struct SAniSkelBone;

  /**
   * Address: 0x0063D210 (FUN_0063D210, boost::shared_ptr_CAniPose::shared_ptr_CAniPose)
   *
   * What it does:
   * Constructs one `shared_ptr<CAniPose>` from one raw pose pointer lane.
   */
  boost::shared_ptr<CAniPose>* ConstructSharedAniPoseFromRaw(
    boost::shared_ptr<CAniPose>* outPose,
    CAniPose* pose
  );

  class CAniPoseBone
  {
  public:
    static gpg::RType* sType;

    CAniPoseBone() = default;

    /**
     * Address: 0x0054C9C0 (FUN_0054C9C0, Moho::CAniPoseBone::CAniPoseBone)
     *
     * What it does:
     * Copy-constructs one pose-bone lane including transform, parent/pose links,
     * and visibility/interpolation flags.
     */
    CAniPoseBone(const CAniPoseBone& copy);

    /**
     * Address: 0x0054BE30 (FUN_0054BE30, Moho::CAniPoseBone::SetVisibleRecur)
     *
     * What it does:
     * Recursively applies one visibility state to this bone and all direct/indirect
     * children in the owning pose's packed bone array.
     */
    [[nodiscard]] std::uint32_t SetVisibleRecur(bool visible);

    /**
     * Address: 0x0054BC00 (FUN_0054BC00, Moho::CAniPoseBone::Rotate)
     *
     * What it does:
     * Applies one local quaternion delta to this bone and invalidates cached
     * composite transform lanes for recomputation.
     */
    void Rotate(const Wm3::Quaternionf& rotation);

    /**
     * Address: 0x0054BDD0 (FUN_0054BDD0)
     *
     * What it does:
     * Replaces this bone's local transform with `transform` and marks the
     * owning pose bone lane dirty for composite rebuild.
     */
    void SetLocalTransform(const VTransform& transform);

    /**
     * Address: 0x0054BEC0 (FUN_0054BEC0, Moho::CAniPoseBone::GetCompositeTransform)
     *
     * What it does:
     * Returns this bone composite transform, recomputing it from parent/local
     * lanes when dirty.
     */
    [[nodiscard]] const VTransform& GetCompositeTransform() const;

    /**
     * Address: 0x0063EE30 (FUN_0063EE30, sub_63EE30)
     *
     * What it does:
     * Resolves this pose bone's corresponding skeleton-bone lane from the
     * owning pose skeleton and returns null when the index is out of range.
     */
    [[nodiscard]] const SAniSkelBone* ResolveSkeletonBone() const;

    /**
     * Address: 0x0054F630 (FUN_0054F630, Moho::CAniPoseBone::MemberSerialize)
     *
     * What it does:
     * Stores per-bone pose serialization lanes (local-space flag, local
     * transform, visibility, interpolation-skip flag).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0054F5C0 (FUN_0054F5C0, Moho::CAniPoseBone::MemberDeserialize)
     *
     * What it does:
     * Loads per-bone pose serialization lanes (local-transform + visibility
     * flags) and marks composite transform dirty for lazy recompute.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    VTransform mCompositeTransform;        // +0x00
    std::uint8_t mCompositeDirty;          // +0x1C
    std::uint8_t mCompositeIsLocal;        // +0x1D
    std::uint8_t pad_1E_1F[0x02]{};
    VTransform mLocalTransform;            // +0x20
    std::int32_t mIdx;                     // +0x3C
    CAniPose* mPose;                       // +0x40
    CAniPoseBone* mParent;                 // +0x44
    std::uint8_t mVisible;                 // +0x48
    std::uint8_t mSkipNextInterp;          // +0x49
    std::uint8_t pad_4A_4B[0x02]{};
  };

  struct CAniPoseBoneArray
  {
  public:
    [[nodiscard]] CAniPoseBone* begin() noexcept
    {
      return mBegin;
    }

    [[nodiscard]] const CAniPoseBone* begin() const noexcept
    {
      return mBegin;
    }

    [[nodiscard]] CAniPoseBone* end() noexcept
    {
      return mEnd;
    }

    [[nodiscard]] const CAniPoseBone* end() const noexcept
    {
      return mEnd;
    }

  public:
    CAniPoseBone* mBegin;         // +0x00
    CAniPoseBone* mEnd;           // +0x04
    CAniPoseBone* mCapacity;      // +0x08
    CAniPoseBone* mOriginal;      // +0x0C
    CAniPoseBone mInlineStorage;  // +0x10
  };

  class CAniPose
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
     *
     * What it does:
     * Initializes animation-pose state from skeleton + scalar pose factor.
     */
    CAniPose(boost::shared_ptr<const CAniSkel> skeleton, float scale);

    /**
     * Address: 0x0054B290 (FUN_0054B290, ??0CAniPose@Moho@@QAE@ABV01@@Z)
     *
     * What it does:
     * Initializes one pose with default storage lanes, then overwrites it from
     * another pose.
     */
    CAniPose(const CAniPose& copy);

    ~CAniPose() = default;

    /**
     * Address: 0x0054B330 (FUN_0054B330, ?OverwritePose@CAniPose@Moho@@QAEXABV12@@Z)
     *
     * What it does:
     * Copies skeleton/transform/max-offset state and rebuilds per-bone parent
     * links from this pose's skeleton hierarchy.
     */
    void OverwritePose(const CAniPose& copy);

    /**
     * Address: 0x0054B5F0 (FUN_0054B5F0, ?UpdateBones@CAniPose@Moho@@QAEXXZ)
     *
     * What it does:
     * Seeds per-bone local transforms from the skeleton bind lanes, applying
     * pose scale to local position and resetting composite dirty flags.
     */
    void UpdateBones();

    /**
     * Address: 0x0054B6D0 (FUN_0054B6D0, ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z)
     * Mangled: ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z
     *
     * What it does:
     * Copies local pose transform and per-bone local lanes from one source
     * pose into this pose while marking destination composite lanes dirty.
     */
    void CopyPose(const CAniPose* sourcePose, bool preserveSourceLane);

    /**
     * Address: 0x0054B550 (FUN_0054B550, ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z)
     * Mangled: ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z
     *
     * What it does:
     * Updates pose world transform when orientation/position lanes differ and
     * marks affected non-local bone composite lanes dirty.
     */
    void SetWorldTransform(const VTransform& transform);

    /**
     * Address: 0x0054B770 (FUN_0054B770, ?InterpolatePose@CAniPose@Moho@@QAEXMPBV12@0H@Z)
     *
     * What it does:
     * Interpolates pose transforms and bone lanes from two source poses using
     * the requested blend factor.
     */
    void InterpolatePose(float interp, const CAniPose* sourcePose, const CAniPose* targetPose, int bones);

    /**
     * Address: 0x005E3B10 (FUN_005E3B10, ?GetSkeleton@CAniPose@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns a retained copy of this pose's skeleton shared handle.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

    /**
     * Address: 0x0054F380 (FUN_0054F380, Moho::CAniPose::MemberDeserialize)
     *
     * What it does:
     * Deserializes skeleton/shared lanes, local transform, and pose-bone
     * payload, then rebuilds per-bone pose/parent links from skeleton data.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0054F4F0 (FUN_0054F4F0, Moho::CAniPose::MemberSerialize)
     *
     * What it does:
     * Serializes skeleton pointer, scalar/local transform lanes, bone array
     * payload, and max-offset cache value.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    friend class CAniPoseBone;

  private:
    /**
     * Address: 0x0054B990 (FUN_0054B990, ?MarkBoneDirty@CAniPose@Moho@@AAEXH@Z)
     *
     * What it does:
     * Marks one bone as composite-dirty, then propagates that dirty state to
     * downstream bones whose parent is already dirty.
     */
    void MarkBoneDirty(int idx);

    /**
     * Address: 0x0054BD80 (FUN_0054BD80)
     *
     * What it does:
     * Composes one pose-bone local transform with an incoming transform and
     * marks that bone dirty through its pose/index ownership lanes.
     */
    static void ApplyBoneLocalTransform(CAniPoseBone* bone, const VTransform& transform);

  public:
    boost::shared_ptr<const CAniSkel> mSkeleton; // +0x00
    float mScale;                                // +0x08
    VTransform mLocalTransform;                  // +0x0C
    CAniPoseBoneArray mBones;                    // +0x28
    std::uint8_t pad_84_87[0x04]{};
    float mMaxOffset;                            // +0x88
    std::uint8_t pad_8C_8F[0x04]{};
  };

  static_assert(offsetof(CAniPoseBone, mCompositeDirty) == 0x1C, "CAniPoseBone::mCompositeDirty offset must be 0x1C");
  static_assert(offsetof(CAniPoseBone, mCompositeIsLocal) == 0x1D, "CAniPoseBone::mCompositeIsLocal offset must be 0x1D");
  static_assert(offsetof(CAniPoseBone, mLocalTransform) == 0x20, "CAniPoseBone::mLocalTransform offset must be 0x20");
  static_assert(offsetof(CAniPoseBone, mIdx) == 0x3C, "CAniPoseBone::mIdx offset must be 0x3C");
  static_assert(offsetof(CAniPoseBone, mPose) == 0x40, "CAniPoseBone::mPose offset must be 0x40");
  static_assert(offsetof(CAniPoseBone, mParent) == 0x44, "CAniPoseBone::mParent offset must be 0x44");
  static_assert(offsetof(CAniPoseBone, mVisible) == 0x48, "CAniPoseBone::mVisible offset must be 0x48");
  static_assert(offsetof(CAniPoseBone, mSkipNextInterp) == 0x49, "CAniPoseBone::mSkipNextInterp offset must be 0x49");
  static_assert(sizeof(CAniPoseBone) == 0x4C, "CAniPoseBone size must be 0x4C");
  static_assert(offsetof(CAniPoseBoneArray, mBegin) == 0x00, "CAniPoseBoneArray::mBegin offset must be 0x00");
  static_assert(offsetof(CAniPoseBoneArray, mInlineStorage) == 0x10, "CAniPoseBoneArray::mInlineStorage offset must be 0x10");
  static_assert(sizeof(CAniPoseBoneArray) == 0x5C, "CAniPoseBoneArray size must be 0x5C");
  static_assert(offsetof(CAniPose, mSkeleton) == 0x00, "CAniPose::mSkeleton offset must be 0x00");
  static_assert(offsetof(CAniPose, mScale) == 0x08, "CAniPose::mScale offset must be 0x08");
  static_assert(offsetof(CAniPose, mLocalTransform) == 0x0C, "CAniPose::mLocalTransform offset must be 0x0C");
  static_assert(offsetof(CAniPose, mBones) == 0x28, "CAniPose::mBones offset must be 0x28");
  static_assert(offsetof(CAniPose, mMaxOffset) == 0x88, "CAniPose::mMaxOffset offset must be 0x88");
  static_assert(sizeof(CAniPose) == 0x90, "CAniPose size must be 0x90");
} // namespace moho
