#include "CAniPose.h"

#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniSkel.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/math/QuaternionMath.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedVTransformType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::VTransform));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorCAniPoseBoneType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(gpg::fastvector<moho::CAniPoseBone>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedCAniSkelType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::CAniSkel));
    }
    return sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (object == nullptr) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    if (dynamicType != nullptr && staticType != nullptr && dynamicType->IsDerivedFrom(staticType, &baseOffset)) {
      out.mObj =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
      out.mType = dynamicType;
      return out;
    }

    out.mObj = object;
    out.mType = dynamicType ? dynamicType : staticType;
    return out;
  }

  [[nodiscard]] moho::VTransform MakeIdentityPoseTransform() noexcept
  {
    moho::VTransform transform{};
    transform.orient_.w = 1.0f;
    transform.orient_.x = 0.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
    return transform;
  }

  void InitializePoseBonesInlineStorage(moho::CAniPose& pose)
  {
    pose.mBones.mBegin = &pose.mBones.mInlineStorage;
    pose.mBones.mEnd = &pose.mBones.mInlineStorage;
    pose.mBones.mCapacity = reinterpret_cast<moho::CAniPoseBone*>(reinterpret_cast<std::uint8_t*>(&pose) + 0x84);
    pose.mBones.mOriginal = &pose.mBones.mInlineStorage;
  }

  [[nodiscard]] gpg::fastvector_runtime_view<moho::CAniPoseBone>&
  PoseBoneRuntimeView(moho::CAniPoseBoneArray& storage) noexcept
  {
    return gpg::AsFastVectorRuntimeView<moho::CAniPoseBone>(&storage);
  }

  void ResizePoseBoneStorage(
    moho::CAniPoseBoneArray& storage,
    const std::uint32_t count,
    const moho::CAniPoseBone& fillValue
  )
  {
    auto& runtimeView = PoseBoneRuntimeView(storage);
    gpg::FastVectorRuntimeResizeFill(&fillValue, count, runtimeView);
  }

  [[nodiscard]] bool PoseTransformDiffers(const moho::VTransform& lhs, const moho::VTransform& rhs) noexcept
  {
    const moho::EntityTransformPayload lhsPayload = moho::ReadEntityTransformPayload(lhs);
    const moho::EntityTransformPayload rhsPayload = moho::ReadEntityTransformPayload(rhs);
    return moho::EntityTransformPositionDiffers(lhsPayload, rhsPayload)
      || moho::EntityTransformOrientationDiffers(lhsPayload, rhsPayload);
  }

  struct SAniSkelBindPoseLaneView
  {
    const char* mBoneName;               // +0x00
    std::int32_t mParentBoneIndex;       // +0x04
    float mLocalOrientationX;            // +0x08
    float mLocalOrientationY;            // +0x0C
    float mLocalOrientationZ;            // +0x10
    float mLocalOrientationW;            // +0x14
    float mLocalPositionX;               // +0x18
    float mLocalPositionY;               // +0x1C
    float mLocalPositionZ;               // +0x20
    std::uint8_t mReserved24_57[0x34]{}; // +0x24
  };

  static_assert(sizeof(SAniSkelBindPoseLaneView) == sizeof(moho::SAniSkelBone), "SAniSkelBindPoseLaneView size must match SAniSkelBone");
  static_assert(
    offsetof(SAniSkelBindPoseLaneView, mLocalOrientationX) == 0x08,
    "SAniSkelBindPoseLaneView::mLocalOrientationX offset must be 0x08"
  );
  static_assert(
    offsetof(SAniSkelBindPoseLaneView, mLocalPositionX) == 0x18,
    "SAniSkelBindPoseLaneView::mLocalPositionX offset must be 0x18"
  );

  [[nodiscard]] const SAniSkelBindPoseLaneView& BindPoseLaneView(const moho::SAniSkelBone& bone) noexcept
  {
    return reinterpret_cast<const SAniSkelBindPoseLaneView&>(bone);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0054C9C0 (FUN_0054C9C0, Moho::CAniPoseBone::CAniPoseBone)
   *
   * What it does:
   * Copy-constructs one pose-bone lane including transform payload, owning pose
   * link, parent link, and visibility flags.
   */
  CAniPoseBone::CAniPoseBone(const CAniPoseBone& copy)
    : mCompositeTransform(copy.mCompositeTransform)
    , mCompositeDirty(copy.mCompositeDirty)
    , mCompositeIsLocal(copy.mCompositeIsLocal)
    , mLocalTransform(copy.mLocalTransform)
    , mIdx(copy.mIdx)
    , mPose(copy.mPose)
    , mParent(copy.mParent)
    , mVisible(copy.mVisible)
    , mSkipNextInterp(copy.mSkipNextInterp)
  {
    pad_1E_1F[0] = copy.pad_1E_1F[0];
    pad_1E_1F[1] = copy.pad_1E_1F[1];
    pad_4A_4B[0] = copy.pad_4A_4B[0];
    pad_4A_4B[1] = copy.pad_4A_4B[1];
  }

  /**
   * Address: 0x0054BE30 (FUN_0054BE30, Moho::CAniPoseBone::SetVisibleRecur)
   */
  std::uint32_t CAniPoseBone::SetVisibleRecur(const bool visible)
  {
    std::uint32_t boneCount = 0;
    if (mPose != nullptr) {
      CAniPoseBone* const bonesBegin = mPose->mBones.begin();
      CAniPoseBone* const bonesEnd = mPose->mBones.end();
      if (bonesBegin != nullptr && bonesEnd != nullptr && bonesBegin <= bonesEnd) {
        boneCount = static_cast<std::uint32_t>(bonesEnd - bonesBegin);
        for (std::uint32_t index = 0; index < boneCount; ++index) {
          CAniPoseBone& candidate = bonesBegin[static_cast<std::size_t>(index)];
          if (candidate.mParent == this) {
            candidate.SetVisibleRecur(visible);
          }
        }
      }
    }

    mVisible = visible ? 1u : 0u;
    return boneCount;
  }

  /**
   * Address: 0x0054F630 (FUN_0054F630, Moho::CAniPoseBone::MemberSerialize)
   *
   * What it does:
   * Writes one bone's local-space flag, local transform lane, visibility, and
   * skip-interpolation flag in archive order.
   */
  void CAniPoseBone::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteBool(mCompositeIsLocal);

    const gpg::RRef nullOwner{};
    archive->Write(CachedVTransformType(), &mLocalTransform, nullOwner);

    archive->WriteBool(mVisible);
    archive->WriteBool(mSkipNextInterp);
  }

  /**
   * Address: 0x0054F5C0 (FUN_0054F5C0, Moho::CAniPoseBone::MemberDeserialize)
   */
  void CAniPoseBone::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    mCompositeDirty = 1u;

    bool compositeIsLocal = false;
    archive->ReadBool(&compositeIsLocal);
    mCompositeIsLocal = compositeIsLocal ? 1u : 0u;

    const gpg::RRef nullOwner{};
    archive->Read(CachedVTransformType(), &mLocalTransform, nullOwner);

    bool visible = false;
    archive->ReadBool(&visible);
    mVisible = visible ? 1u : 0u;

    bool skipNextInterp = false;
    archive->ReadBool(&skipNextInterp);
    mSkipNextInterp = skipNextInterp ? 1u : 0u;
  }

  /**
   * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
   *
   * What it does:
   * Stores pose skeleton handle + source scale and zeros trailing runtime bytes.
   */
  CAniPose::CAniPose(const boost::shared_ptr<const CAniSkel> skeleton, const float scale)
    : mSkeleton(skeleton)
    , mScale(scale)
    , mLocalTransform()
    , mBones()
    , mMaxOffset(-std::numeric_limits<float>::infinity())
  {
    mLocalTransform.orient_.w = 1.0f;
    mLocalTransform.orient_.x = 0.0f;
    mLocalTransform.orient_.y = 0.0f;
    mLocalTransform.orient_.z = 0.0f;
    mLocalTransform.pos_.x = 0.0f;
    mLocalTransform.pos_.y = 0.0f;
    mLocalTransform.pos_.z = 0.0f;

    InitializePoseBonesInlineStorage(*this);
  }

  /**
   * Address: 0x0054B290 (FUN_0054B290, ??0CAniPose@Moho@@QAE@ABV01@@Z)
   *
   * What it does:
   * Initializes one pose to default storage/layout lanes and then overwrites
   * that state from `copy`.
   */
  CAniPose::CAniPose(const CAniPose& copy)
    : mSkeleton()
    , mScale(0.0f)
    , mLocalTransform(MakeIdentityPoseTransform())
    , mBones()
    , mMaxOffset(0.0f)
  {
    InitializePoseBonesInlineStorage(*this);
    OverwritePose(copy);
  }

  /**
   * Address: 0x0054B330 (FUN_0054B330, ?OverwritePose@CAniPose@Moho@@QAEXABV12@@Z)
   *
   * What it does:
   * Copies pose-level state and rebuilds destination per-bone parent pointers
   * from the destination skeleton bone hierarchy.
   */
  void CAniPose::OverwritePose(const CAniPose& copy)
  {
    mSkeleton = copy.mSkeleton;
    mScale = copy.mScale;
    mLocalTransform = copy.mLocalTransform;
    mMaxOffset = copy.mMaxOffset;

    CAniPoseBone fillBone{};
    fillBone.mCompositeTransform = MakeIdentityPoseTransform();
    fillBone.mCompositeDirty = 1u;
    fillBone.mCompositeIsLocal = 0u;
    fillBone.mLocalTransform = MakeIdentityPoseTransform();
    fillBone.mIdx = 0;
    fillBone.mPose = nullptr;
    fillBone.mParent = nullptr;
    fillBone.mVisible = 0u;
    fillBone.mSkipNextInterp = 0u;

    const CAniPoseBone* const sourceBegin = copy.mBones.begin();
    const CAniPoseBone* const sourceEnd = copy.mBones.end();
    const std::uint32_t boneCount = (sourceBegin && sourceEnd && sourceEnd >= sourceBegin)
      ? static_cast<std::uint32_t>(sourceEnd - sourceBegin)
      : 0u;
    ResizePoseBoneStorage(mBones, boneCount, fillBone);

    if (boneCount == 0u || sourceBegin == nullptr) {
      return;
    }

    CAniPoseBone* const destinationBegin = mBones.begin();
    if (destinationBegin == nullptr) {
      return;
    }

    for (std::uint32_t index = 0; index < boneCount; ++index) {
      CAniPoseBone& destinationBone = destinationBegin[index];
      const CAniPoseBone& sourceBone = sourceBegin[index];

      destinationBone.mPose = this;
      destinationBone.mIdx = static_cast<std::int32_t>(index);
      destinationBone.mVisible = sourceBone.mVisible;
      destinationBone.mSkipNextInterp = sourceBone.mSkipNextInterp;

      std::int32_t parentIndex = -1;
      if (mSkeleton) {
        const SAniSkelBone* const skeletonBone = mSkeleton->GetBone(index);
        if (skeletonBone) {
          parentIndex = skeletonBone->mParentBoneIndex;
        }
      }

      if (parentIndex >= 0 && parentIndex < static_cast<std::int32_t>(boneCount)) {
        destinationBone.mParent = &destinationBegin[parentIndex];
      } else {
        destinationBone.mParent = nullptr;
      }

      destinationBone.mLocalTransform = sourceBone.mLocalTransform;
      destinationBone.mCompositeDirty = 1u;
      destinationBone.mCompositeIsLocal = sourceBone.mCompositeIsLocal;
    }
  }

  /**
   * Address: 0x0054B5F0 (FUN_0054B5F0, ?UpdateBones@CAniPose@Moho@@QAEXXZ)
   *
   * What it does:
   * Seeds destination pose-bone local transforms from skeleton bind lanes and
   * resets per-bone composite invalidation flags.
   */
  void CAniPose::UpdateBones()
  {
    CAniPoseBone* const destinationBegin = mBones.begin();
    CAniPoseBone* const destinationEnd = mBones.end();
    if (destinationBegin == nullptr || destinationEnd == nullptr || destinationEnd <= destinationBegin) {
      return;
    }

    const CAniSkel* const skeleton = mSkeleton.get();
    if (skeleton == nullptr) {
      return;
    }

    const std::int32_t destinationBoneCount = static_cast<std::int32_t>(destinationEnd - destinationBegin);
    const float scale = mScale;
    for (std::int32_t index = 0; index < destinationBoneCount; ++index) {
      const SAniSkelBone* const skeletonBone = skeleton->GetBone(static_cast<std::uint32_t>(index));
      if (skeletonBone == nullptr) {
        continue;
      }

      const SAniSkelBindPoseLaneView& bindLane = BindPoseLaneView(*skeletonBone);
      CAniPoseBone& destinationBone = destinationBegin[index];

      destinationBone.mLocalTransform.pos_.x = bindLane.mLocalPositionX * scale;
      destinationBone.mLocalTransform.pos_.y = bindLane.mLocalPositionY * scale;
      destinationBone.mLocalTransform.pos_.z = bindLane.mLocalPositionZ * scale;

      destinationBone.mLocalTransform.orient_.x = bindLane.mLocalOrientationX;
      destinationBone.mLocalTransform.orient_.y = bindLane.mLocalOrientationY;
      destinationBone.mLocalTransform.orient_.z = bindLane.mLocalOrientationZ;
      destinationBone.mLocalTransform.orient_.w = bindLane.mLocalOrientationW;

      destinationBone.mCompositeDirty = 1u;
      destinationBone.mSkipNextInterp = 0u;
      destinationBone.mCompositeIsLocal = 0u;
    }
  }

  /**
   * Address: 0x0054B6D0 (FUN_0054B6D0, ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z)
   * Mangled: ?CopyPose@CAniPose@Moho@@QAEXPBV12@_N@Z
   *
   * What it does:
   * Copies one source pose's local transform and bone-local lanes into this
   * pose and marks copied destination lanes composite-dirty.
   */
  void CAniPose::CopyPose(const CAniPose* const sourcePose, const bool preserveSourceLane)
  {
    (void)preserveSourceLane;
    if (sourcePose == nullptr) {
      return;
    }

    mLocalTransform = sourcePose->mLocalTransform;

    const CAniPoseBone* const sourceBegin = sourcePose->mBones.begin();
    const CAniPoseBone* const sourceEnd = sourcePose->mBones.end();
    CAniPoseBone* const destinationBegin = mBones.begin();
    CAniPoseBone* const destinationEnd = mBones.end();
    if (sourceBegin == nullptr || sourceEnd == nullptr || destinationBegin == nullptr || destinationEnd == nullptr) {
      return;
    }

    std::int32_t boneCount = static_cast<std::int32_t>(destinationEnd - destinationBegin);
    const std::int32_t sourceBoneCount = static_cast<std::int32_t>(sourceEnd - sourceBegin);
    if (sourceBoneCount < boneCount) {
      boneCount = sourceBoneCount;
    }

    const CAniSkel* const skeleton = mSkeleton.get();
    if (skeleton != nullptr) {
      const SAniSkelBone* const skeletonBegin = skeleton->mBones.begin();
      const SAniSkelBone* const skeletonEnd = skeleton->mBones.end();
      if (skeletonBegin != nullptr && skeletonEnd != nullptr && skeletonEnd >= skeletonBegin) {
        const std::int32_t skeletonBoneCount = static_cast<std::int32_t>(skeletonEnd - skeletonBegin);
        if (skeletonBoneCount < boneCount) {
          boneCount = skeletonBoneCount;
        }
      }
    }

    if (boneCount <= 0) {
      return;
    }

    for (std::int32_t index = 0; index < boneCount; ++index) {
      const CAniPoseBone& sourceBone = sourceBegin[index];
      CAniPoseBone& destinationBone = destinationBegin[index];

      destinationBone.mLocalTransform = sourceBone.mLocalTransform;
      destinationBone.mCompositeDirty = 1u;
      destinationBone.mCompositeIsLocal = sourceBone.mCompositeIsLocal;
      destinationBone.mVisible = sourceBone.mVisible;
      destinationBone.mSkipNextInterp = sourceBone.mSkipNextInterp;
    }
  }

  /**
   * Address: 0x0054B550 (FUN_0054B550, ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z)
   * Mangled: ?SetWorldTransform@CAniPose@Moho@@QAEXABVVTransform@2@@Z
   *
   * What it does:
   * Applies one new pose-world transform and invalidates composite caches for
   * non-local bones whose parent lane is root or already dirty.
   */
  void CAniPose::SetWorldTransform(const VTransform& transform)
  {
    if (!PoseTransformDiffers(mLocalTransform, transform)) {
      return;
    }

    mLocalTransform = transform;

    CAniPoseBone* const bonesBegin = mBones.begin();
    CAniPoseBone* const bonesEnd = mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesEnd <= bonesBegin) {
      return;
    }

    for (CAniPoseBone* bone = bonesBegin; bone != bonesEnd; ++bone) {
      if (bone->mCompositeIsLocal != 0u) {
        continue;
      }

      CAniPoseBone* const parent = bone->mParent;
      if (parent == nullptr || parent->mCompositeDirty != 0u) {
        bone->mCompositeDirty = 1u;
      }
    }
  }

  /**
   * Address: 0x0054B770 (FUN_0054B770, ?InterpolatePose@CAniPose@Moho@@QAEXMPBV12@0H@Z)
   *
   * What it does:
   * Interpolates pose transforms and bone lanes from two source poses using
   * the requested blend factor.
   */
  void CAniPose::InterpolatePose(
    const float interp,
    const CAniPose* const sourcePose,
    const CAniPose* const targetPose,
    const int bones
  )
  {
    const float sourcePosX = sourcePose->mLocalTransform.pos_.x;
    const float sourcePosY = sourcePose->mLocalTransform.pos_.y;
    const float sourcePosZ = sourcePose->mLocalTransform.pos_.z;
    const float targetPosX = targetPose->mLocalTransform.pos_.x;
    const float targetPosY = targetPose->mLocalTransform.pos_.y;
    const float targetPosZ = targetPose->mLocalTransform.pos_.z;

    mLocalTransform.pos_.x = sourcePosX + ((targetPosX - sourcePosX) * interp);
    mLocalTransform.pos_.y = sourcePosY + ((targetPosY - sourcePosY) * interp);
    mLocalTransform.pos_.z = sourcePosZ + ((targetPosZ - sourcePosZ) * interp);

    Wm3::Quaternionf blendedOrientation{};
    QuatLERP(&targetPose->mLocalTransform.orient_, &sourcePose->mLocalTransform.orient_, &blendedOrientation, interp);
    mLocalTransform.orient_ = blendedOrientation;

    CAniPoseBone* const destinationBegin = mBones.begin();
    CAniPoseBone* const destinationEnd = mBones.end();
    const int destinationBoneCount = static_cast<int>(destinationEnd - destinationBegin);
    int boneCount = destinationBoneCount;
    if (boneCount >= bones) {
      boneCount = bones;
    }

    if (boneCount > 0) {
      float poseInterp = interp;
      float boneInterp = poseInterp;
      int remainingBones = boneCount;
      int index = 0;
      do {
        const CAniPoseBone* const sourceBone = &sourcePose->mBones.begin()[index];
        CAniPoseBone* const destinationBone = &destinationBegin[index];
        const CAniPoseBone* const targetBone = &targetPose->mBones.begin()[index];

        destinationBone->mCompositeDirty = 1u;
        destinationBone->mCompositeIsLocal = targetBone->mCompositeIsLocal;
        destinationBone->mVisible = targetBone->mVisible;
        destinationBone->mSkipNextInterp = targetBone->mSkipNextInterp;

        if (targetBone->mSkipNextInterp != 0u) {
          poseInterp = 1.0f;
          boneInterp = 1.0f;
        }

        if (sourceBone->mCompositeIsLocal == targetBone->mCompositeIsLocal) {
          const float sourceBonePosX = sourceBone->mLocalTransform.pos_.x;
          const float sourceBonePosY = sourceBone->mLocalTransform.pos_.y;
          const float sourceBonePosZ = sourceBone->mLocalTransform.pos_.z;
          const float targetBonePosX = targetBone->mLocalTransform.pos_.x;
          const float targetBonePosY = targetBone->mLocalTransform.pos_.y;
          const float targetBonePosZ = targetBone->mLocalTransform.pos_.z;

          destinationBone->mLocalTransform.pos_.x = sourceBonePosX + ((targetBonePosX - sourceBonePosX) * boneInterp);
          destinationBone->mLocalTransform.pos_.y = sourceBonePosY + ((targetBonePosY - sourceBonePosY) * boneInterp);
          destinationBone->mLocalTransform.pos_.z = sourceBonePosZ + ((targetBonePosZ - sourceBonePosZ) * boneInterp);

          QuatLERP(
            &targetBone->mLocalTransform.orient_,
            &sourceBone->mLocalTransform.orient_,
            &destinationBone->mLocalTransform.orient_,
            boneInterp
          );
        } else {
          destinationBone->mLocalTransform.orient_ = targetBone->mLocalTransform.orient_;
          destinationBone->mLocalTransform.pos_ = targetBone->mLocalTransform.pos_;
        }

        boneInterp = poseInterp;
        ++index;
        --remainingBones;
      } while (remainingBones != 0);
    }

    const float sourceMaxOffset = sourcePose->mMaxOffset;
    const float targetMaxOffset = targetPose->mMaxOffset;
    if (targetMaxOffset <= sourceMaxOffset) {
      mMaxOffset = sourceMaxOffset;
    } else {
      mMaxOffset = targetMaxOffset;
    }
  }

  /**
   * Address: 0x005E3B10 (FUN_005E3B10, ?GetSkeleton@CAniPose@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<const CAniSkel> CAniPose::GetSkeleton() const
  {
    return mSkeleton;
  }

  /**
   * Address: 0x0054B990 (FUN_0054B990, ?MarkBoneDirty@CAniPose@Moho@@AAEXH@Z)
   */
  void CAniPose::MarkBoneDirty(const int idx)
  {
    CAniPoseBone* const bonesBegin = mBones.begin();
    CAniPoseBone* const bonesEnd = mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesEnd < bonesBegin || idx < 0) {
      return;
    }

    const int boneCount = static_cast<int>(bonesEnd - bonesBegin);
    if (idx >= boneCount) {
      return;
    }

    CAniPoseBone& baseBone = bonesBegin[idx];
    if (baseBone.mCompositeDirty != 0u) {
      return;
    }

    baseBone.mCompositeDirty = 1u;
    for (int boneIndex = idx + 1; boneIndex < boneCount; ++boneIndex) {
      CAniPoseBone& candidate = bonesBegin[boneIndex];
      if (candidate.mParent != nullptr && candidate.mParent->mCompositeDirty != 0u) {
        candidate.mCompositeDirty = 1u;
      }
    }
  }

  /**
   * Address: 0x0054F4F0 (FUN_0054F4F0, Moho::CAniPose::MemberSerialize)
   */
  void CAniPose::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef nullOwner{};
    const gpg::RRef skeletonRef =
      MakeDerivedRef(const_cast<CAniSkel*>(mSkeleton.get()), CachedCAniSkelType());
    gpg::WriteRawPointer(archive, skeletonRef, gpg::TrackedPointerState::Shared, nullOwner);

    archive->WriteFloat(mScale);
    archive->Write(CachedVTransformType(), &mLocalTransform, nullOwner);
    archive->Write(CachedFastVectorCAniPoseBoneType(), &mBones, nullOwner);
    archive->WriteFloat(mMaxOffset);
  }
} // namespace moho
