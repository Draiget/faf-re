#include "CAnimationManipulator.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <typeinfo>

namespace
{
  struct AnimationClipHeaderView
  {
    std::uint8_t mReserved00[0x08];
    std::uint32_t mFrameCount;     // +0x08
    float mDurationSeconds;        // +0x0C
    std::uint32_t mBoneTrackCount; // +0x10
  };

  struct AnimationResourceView
  {
    std::uint8_t mReserved00[0x2C];
    AnimationClipHeaderView* mClipHeader; // +0x2C
  };

  [[nodiscard]] const AnimationClipHeaderView*
  GetAnimationClipHeader(const moho::CAnimationManipulator::AnimationResourceRef& ref)
  {
    if (!ref.px) {
      return nullptr;
    }

    auto* const resource = static_cast<const AnimationResourceView*>(ref.px);
    return resource->mClipHeader;
  }

  void ReleaseAnimationRef(moho::CAnimationManipulator::AnimationResourceRef& ref) noexcept
  {
    if (ref.pi != nullptr) {
      ref.pi->release();
    }
    ref.px = nullptr;
    ref.pi = nullptr;
  }

  void AssignAnimationRef(
    moho::CAnimationManipulator::AnimationResourceRef& destination,
    const moho::CAnimationManipulator::AnimationResourceRef& source
  )
  {
    if (source.pi != nullptr) {
      source.pi->add_ref_copy();
    }
    ReleaseAnimationRef(destination);
    destination = source;
  }

  void FreeBoneMaskStorage(moho::SAniManipBitStorage& mask)
  {
    if (mask.mWords != nullptr) {
      delete[] mask.mWords;
    }
    mask.mBitCount = 0;
    mask.mReservedWordBase = 0;
    mask.mWords = nullptr;
    mask.mWordsEnd = nullptr;
    mask.mWordsCapacityEnd = nullptr;
  }

  [[nodiscard]] std::uint32_t WordCountForBits(const std::uint32_t bitCount)
  {
    return (bitCount + 31u) >> 5u;
  }

  void InitializeBoneMaskStorage(moho::SAniManipBitStorage& mask, const std::uint32_t bitCount)
  {
    const std::uint32_t requiredWords = WordCountForBits(bitCount);
    if (requiredWords == 0) {
      FreeBoneMaskStorage(mask);
      return;
    }

    const std::uint32_t existingCapacity =
      mask.mWords && mask.mWordsCapacityEnd ? static_cast<std::uint32_t>(mask.mWordsCapacityEnd - mask.mWords) : 0u;
    if (existingCapacity < requiredWords) {
      if (mask.mWords != nullptr) {
        delete[] mask.mWords;
      }
      mask.mWords = new std::uint32_t[requiredWords];
      mask.mWordsCapacityEnd = mask.mWords + requiredWords;
    }

    mask.mBitCount = bitCount;
    mask.mReservedWordBase = 0;
    mask.mWordsEnd = mask.mWords + requiredWords;
    for (std::uint32_t* word = mask.mWords; word != mask.mWordsEnd; ++word) {
      *word = 0xFFFFFFFFu;
    }

    const std::uint32_t trailingBits = bitCount & 31u;
    if (trailingBits != 0u) {
      mask.mWordsEnd[-1] &= ((1u << trailingBits) - 1u);
    }
  }

  [[nodiscard]] bool IsBoneMaskBitSet(const moho::SAniManipBitStorage& mask, const std::uint32_t bitIndex)
  {
    if (!mask.mWords || bitIndex >= mask.mBitCount) {
      return false;
    }

    const std::uint32_t wordIndex = bitIndex >> 5u;
    const std::uint32_t bitInWord = bitIndex & 31u;
    const std::uint32_t* const word = mask.mWords + wordIndex;
    return ((*word & (1u << bitInWord)) != 0u);
  }

  void SetBoneMaskBit(moho::SAniManipBitStorage& mask, const std::uint32_t bitIndex, const bool enabled)
  {
    if (!mask.mWords || bitIndex >= mask.mBitCount) {
      return;
    }

    const std::uint32_t wordIndex = bitIndex >> 5u;
    const std::uint32_t bitInWord = bitIndex & 31u;
    std::uint32_t* const word = mask.mWords + wordIndex;
    const std::uint32_t bit = (1u << bitInWord);
    if (enabled) {
      *word |= bit;
    } else {
      *word &= ~bit;
    }
  }

  [[nodiscard]] float WrapToRange(const float value, const float range)
  {
    if (range == 0.0f) {
      return 0.0f;
    }

    float wrapped = std::fmod(value, range);
    if (wrapped < 0.0f) {
      wrapped += range;
    }
    return wrapped;
  }

  void UnlinkOwnerNode(moho::SAniManipOwnerLink& node)
  {
    if (node.mPrevSlot == nullptr) {
      return;
    }

    auto** cursor = node.mPrevSlot;
    while (*cursor != &node) {
      cursor = &((*cursor)->mNext);
    }
    *cursor = node.mNext;
    node.mPrevSlot = nullptr;
    node.mNext = nullptr;
  }

  gpg::RType* CachedCAnimationManipulatorType()
  {
    if (!moho::CAnimationManipulator::sType) {
      moho::CAnimationManipulator::sType = gpg::LookupRType(typeid(moho::CAnimationManipulator));
    }
    return moho::CAnimationManipulator::sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  void AddIAniManipulatorBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(moho::IAniManipulator));
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

namespace moho
{
  gpg::RType* CAnimationManipulator::sType = nullptr;

  /**
   * Address: 0x0063F380 (FUN_0063F380, ??0CAnimationManipulator@Moho@@QAE@XZ)
   */
  CAnimationManipulator::CAnimationManipulator()
    : mRate(1.0f)
    , mAnimationTime(0.0f)
    , mLastFramePosition(-1.0f)
    , mLooping(false)
    , mFrameChanged(false)
    , mIgnoreMotionScaling(false)
    , mOverwriteMode(false)
    , mDisableOnSignal(false)
    , mDirectionalAnim(false)
  {
    mOwnerLink.mPrevSlot = nullptr;
    mOwnerLink.mNext = nullptr;
    mBoneMask = {};
    mAnimationRef = {};
  }

  /**
   * Address: 0x0063F8D0 (FUN_0063F8D0, ??1CAnimationManipulator@Moho@@UAE@XZ)
   */
  CAnimationManipulator::~CAnimationManipulator()
  {
    ReleaseAnimationRef(mAnimationRef);
    FreeBoneMaskStorage(mBoneMask);
    UnlinkOwnerNode(mOwnerLink);
  }

  /**
   * Address: 0x0063EEE0 (FUN_0063EEE0, ?GetClass@CAnimationManipulator@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* CAnimationManipulator::GetClass() const
  {
    return CachedCAnimationManipulatorType();
  }

  /**
   * Address: 0x0063EF00 (FUN_0063EF00, ?GetDerivedObjectRef@CAnimationManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef CAnimationManipulator::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, CachedCAnimationManipulatorType());
  }

  /**
   * Address: 0x0063FDD0 (FUN_0063FDD0, CAnimationManipulator::ManipulatorUpdate)
   */
  bool CAnimationManipulator::ManipulatorUpdate()
  {
    const AnimationClipHeaderView* const clip = GetAnimationClipHeader(mAnimationRef);
    if (!clip || clip->mFrameCount == 0) {
      return false;
    }

    if (!mIgnoreMotionScaling) {
      mAnimationTime += mRate * 0.1f;
    }

    const float duration = clip->mDurationSeconds;
    if (mLooping) {
      mAnimationTime = WrapToRange(mAnimationTime, duration);
    } else {
      mAnimationTime = std::clamp(mAnimationTime, 0.0f, std::max(duration, 0.0f));
    }

    const bool signaled = UpdateTriggeredState();
    if (!(signaled && mDisableOnSignal)) {
      float framePosition = 0.0f;
      if (duration > 0.0f && clip->mFrameCount > 1u) {
        framePosition = (static_cast<float>(clip->mFrameCount - 1u) / duration) * mAnimationTime;
      }

      mFrameChanged = (framePosition != mLastFramePosition);
      mLastFramePosition = framePosition;
    }

    return mFrameChanged;
  }

  /**
   * Address: 0x0063F9E0 (FUN_0063F9E0)
   */
  void CAnimationManipulator::SetAnimationFraction(const float fraction)
  {
    const AnimationClipHeaderView* const clip = GetAnimationClipHeader(mAnimationRef);
    if (!clip) {
      return;
    }

    float normalized = fraction;
    if (mLooping) {
      normalized = normalized - std::floor(normalized);
    } else {
      normalized = std::clamp(normalized, 0.0f, 1.0f);
    }

    mAnimationTime = clip->mDurationSeconds * normalized;
    UpdateTriggeredState();
  }

  /**
   * Address: 0x0063FA90 (FUN_0063FA90)
   */
  void CAnimationManipulator::SetAnimationTime(const float timeSeconds)
  {
    const AnimationClipHeaderView* const clip = GetAnimationClipHeader(mAnimationRef);
    if (!clip) {
      return;
    }

    const float duration = clip->mDurationSeconds;
    if (mLooping) {
      mAnimationTime = WrapToRange(timeSeconds, duration);
    } else {
      mAnimationTime = std::clamp(timeSeconds, 0.0f, std::max(duration, 0.0f));
    }

    UpdateTriggeredState();
  }

  /**
   * Address: 0x0063FB10 (FUN_0063FB10)
   */
  bool CAnimationManipulator::UpdateTriggeredState()
  {
    const float duration = GetAnimationDuration();
    const bool missingAnimation = (mAnimationRef.px == nullptr);
    const bool zeroRate = (mRate == 0.0f);
    const bool reachedStart = (mRate < 0.0f) && (mAnimationTime == 0.0f);
    const bool reachedEnd = (mRate > 0.0f) && (mAnimationTime == duration);
    const bool shouldSignal = missingAnimation || zeroRate || (!mLooping && (reachedStart || reachedEnd));

    mTriggered = shouldSignal;
    return shouldSignal;
  }

  /**
   * Address: 0x0063FBA0 (FUN_0063FBA0)
   */
  void CAnimationManipulator::SetAnimationResource(const AnimationResourceRef& resource, const bool looping)
  {
    if (!resource.px) {
      ResetWatchBoneStorage();
    }

    AssignAnimationRef(mAnimationRef, resource);
    mAnimationTime = 0.0f;
    mLastFramePosition = -1.0f;
    mLooping = looping;
    UpdateTriggeredState();
  }

  /**
   * Address: 0x006412C0 (FUN_006412C0)
   */
  void CAnimationManipulator::SetBoneEnabled(
    const std::int32_t boneIndex, const bool /*includeDescendants*/, const bool enabled
  )
  {
    if (boneIndex < 0) {
      return;
    }

    SetBoneMaskBit(mBoneMask, static_cast<std::uint32_t>(boneIndex), enabled);
  }

  float CAnimationManipulator::GetRate() const noexcept
  {
    return mRate;
  }

  void CAnimationManipulator::SetRate(const float rate)
  {
    mRate = rate;
    UpdateTriggeredState();
  }

  float CAnimationManipulator::GetAnimationFraction() const
  {
    const float duration = GetAnimationDuration();
    if (duration <= 0.0f) {
      return 0.0f;
    }
    return mAnimationTime / duration;
  }

  float CAnimationManipulator::GetAnimationTime() const noexcept
  {
    return mAnimationTime;
  }

  float CAnimationManipulator::GetAnimationDuration() const
  {
    const AnimationClipHeaderView* const clip = GetAnimationClipHeader(mAnimationRef);
    if (!clip) {
      return 0.0f;
    }
    return clip->mDurationSeconds;
  }

  void CAnimationManipulator::SetOverwriteMode(const bool enabled) noexcept
  {
    mOverwriteMode = enabled;
  }

  void CAnimationManipulator::SetDisableOnSignal(const bool enabled) noexcept
  {
    mDisableOnSignal = enabled;
  }

  void CAnimationManipulator::SetDirectionalAnim(const bool enabled) noexcept
  {
    mDirectionalAnim = enabled;
  }

  void CAnimationManipulator::InitializeBoneMask(const std::uint32_t boneCount)
  {
    InitializeBoneMaskStorage(mBoneMask, boneCount);
  }

  /**
   * Address: 0x00641E70 (FUN_00641E70, sub_641E70)
   */
  void CAnimationManipulatorConstruct::RegisterConstructFunctions()
  {
    gpg::RType* const type = CachedCAnimationManipulatorType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x00641EF0 (FUN_00641EF0, sub_641EF0)
   */
  void CAnimationManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCAnimationManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x0063F0E0 (FUN_0063F0E0, scalar deleting destructor thunk)
   */
  CAnimationManipulatorTypeInfo::~CAnimationManipulatorTypeInfo() = default;

  /**
   * Address: 0x0063F0D0 (FUN_0063F0D0, ?GetName@CAnimationManipulatorTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* CAnimationManipulatorTypeInfo::GetName() const
  {
    return "CAnimationManipulator";
  }

  /**
   * Address: 0x0063F0A0 (FUN_0063F0A0, ?Init@CAnimationManipulatorTypeInfo@Moho@@UAEXXZ)
   */
  void CAnimationManipulatorTypeInfo::Init()
  {
    size_ = sizeof(CAnimationManipulator);
    gpg::RType::Init();
    AddIAniManipulatorBase(this);
    Finish();
  }
} // namespace moho
