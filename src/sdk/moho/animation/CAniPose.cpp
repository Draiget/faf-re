#include "CAniPose.h"

#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/animation/CAniSkel.h"

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
} // namespace

namespace moho
{
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
