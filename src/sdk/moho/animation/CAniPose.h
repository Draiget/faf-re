#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/camera/VTransform.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAniSkel;
  class CAniPose;

  class CAniPoseBone
  {
  public:
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
     * Address: 0x0054BEC0 (FUN_0054BEC0, Moho::CAniPoseBone::GetCompositeTransform)
     *
     * What it does:
     * Returns this bone composite transform, recomputing it from parent/local
     * lanes when dirty.
     */
    [[nodiscard]] const VTransform& GetCompositeTransform() const;

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
    /**
     * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
     *
     * What it does:
     * Initializes animation-pose state from skeleton + scalar pose factor.
     */
    CAniPose(boost::shared_ptr<const CAniSkel> skeleton, float scale);

    ~CAniPose() = default;

    /**
     * Address: 0x005E3B10 (FUN_005E3B10, ?GetSkeleton@CAniPose@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns a retained copy of this pose's skeleton shared handle.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

    /**
     * Address: 0x0054F4F0 (FUN_0054F4F0, Moho::CAniPose::MemberSerialize)
     *
     * What it does:
     * Serializes skeleton pointer, scalar/local transform lanes, bone array
     * payload, and max-offset cache value.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

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
