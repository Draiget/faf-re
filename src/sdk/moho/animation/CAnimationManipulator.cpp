#include "CAnimationManipulator.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

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

  using TypeInfo = moho::CAnimationManipulatorTypeInfo;

  alignas(TypeInfo) unsigned char gCAnimationManipulatorTypeInfoStorage[sizeof(TypeInfo)] = {};
  bool gCAnimationManipulatorTypeInfoConstructed = false;
  moho::CAnimationManipulatorConstruct gCAnimationManipulatorConstruct;
  moho::CAnimationManipulatorSerializer gCAnimationManipulatorSerializer;
  gpg::RType* gWeakPtrUnitType = nullptr;
  gpg::RType* gVectorBoolType = nullptr;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mNext != nullptr && helper.mPrev != nullptr) {
      static_cast<gpg::SerHelperBase*>(helper.mNext)->mPrev = static_cast<gpg::SerHelperBase*>(helper.mPrev);
      static_cast<gpg::SerHelperBase*>(helper.mPrev)->mNext = static_cast<gpg::SerHelperBase*>(helper.mNext);
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  [[nodiscard]] TypeInfo& GetCAnimationManipulatorTypeInfo() noexcept
  {
    if (!gCAnimationManipulatorTypeInfoConstructed) {
      auto* const typeInfo = new (gCAnimationManipulatorTypeInfoStorage) TypeInfo();
      gpg::PreRegisterRType(typeid(moho::CAnimationManipulator), typeInfo);
      gCAnimationManipulatorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCAnimationManipulatorTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorTypeForSerializer()
  {
    if (!moho::IAniManipulator::sType) {
      moho::IAniManipulator::sType = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return moho::IAniManipulator::sType;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    if (!gWeakPtrUnitType) {
      gWeakPtrUnitType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return gWeakPtrUnitType;
  }

  [[nodiscard]] gpg::RType* CachedVectorBoolType()
  {
    if (!gVectorBoolType) {
      gVectorBoolType = gpg::LookupRType(typeid(std::vector<bool>));
    }
    return gVectorBoolType;
  }

  [[nodiscard]] moho::WeakPtr<moho::Unit>* AnimationGoalWeakPtr(moho::CAnimationManipulator* const object)
  {
    return reinterpret_cast<moho::WeakPtr<moho::Unit>*>(&object->mOwnerLink);
  }

  [[nodiscard]] const moho::WeakPtr<moho::Unit>* AnimationGoalWeakPtr(const moho::CAnimationManipulator* const object)
  {
    return reinterpret_cast<const moho::WeakPtr<moho::Unit>*>(&object->mOwnerLink);
  }

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  void PromoteTrackedPointerToShared(gpg::TrackedPointerInfo& tracked)
  {
    GPG_ASSERT(tracked.type != nullptr && tracked.type->deleteFunc_ != nullptr);
    if (!tracked.type || !tracked.type->deleteFunc_) {
      return;
    }

    auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
      tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
    );
    tracked.sharedObject = tracked.object;
    tracked.sharedControl = control;
    tracked.state = gpg::TrackedPointerState::Shared;
  }

  void ReadSharedAnimationResourcePointer(
    moho::CAnimationManipulator::AnimationResourceRef& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      outPointer.release();
      return;
    }

    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      PromoteTrackedPointerToShared(tracked);
    }

    GPG_ASSERT(tracked.state == gpg::TrackedPointerState::Shared);
    GPG_ASSERT(tracked.sharedObject != nullptr && tracked.sharedControl != nullptr);

    if (tracked.state != gpg::TrackedPointerState::Shared || !tracked.sharedObject || !tracked.sharedControl) {
      outPointer.release();
      return;
    }

    moho::CAnimationManipulator::AnimationResourceRef source{};
    source.px = tracked.sharedObject;
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }

  void WriteSharedAnimationResourcePointer(
    const moho::CAnimationManipulator::AnimationResourceRef& pointer,
    gpg::WriteArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef objectRef{};
    objectRef.mObj = pointer.px;
    if (pointer.px != nullptr) {
      objectRef.mType = static_cast<gpg::RObject*>(pointer.px)->GetClass();
      GPG_ASSERT(objectRef.mType != nullptr);
    } else {
      objectRef.mType = nullptr;
    }

    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Shared, ownerRef);
  }

  /**
   * Address: 0x00642A50 (FUN_00642A50, DeserializeCAnimationManipulatorState)
   *
   * What it does:
   * Loads CAnimationManipulator-specific serialization fields after
   * IAniManipulator base payload.
   */
  void DeserializeCAnimationManipulatorState(moho::CAnimationManipulator* const object, gpg::ReadArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedIAniManipulatorTypeForSerializer(), static_cast<moho::IAniManipulator*>(object), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), AnimationGoalWeakPtr(object), nullOwner);
    archive->Read(CachedVectorBoolType(), &object->mBoneMask, nullOwner);
    ReadSharedAnimationResourcePointer(object->mAnimationRef, archive, nullOwner);
    archive->ReadFloat(&object->mRate);
    archive->ReadFloat(&object->mAnimationTime);
    archive->ReadFloat(&object->mLastFramePosition);
    archive->ReadBool(&object->mLooping);
    archive->ReadBool(&object->mFrameChanged);
    archive->ReadBool(&object->mIgnoreMotionScaling);
    archive->ReadBool(&object->mOverwriteMode);
    archive->ReadBool(&object->mDisableOnSignal);
    archive->ReadBool(&object->mDirectionalAnim);
  }

  /**
   * Address: 0x00642BB0 (FUN_00642BB0, SerializeCAnimationManipulatorState)
   *
   * What it does:
   * Saves CAnimationManipulator-specific serialization fields after
   * IAniManipulator base payload.
   */
  void SerializeCAnimationManipulatorState(
    const moho::CAnimationManipulator* const object, gpg::WriteArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedIAniManipulatorTypeForSerializer(), const_cast<moho::IAniManipulator*>(static_cast<const moho::IAniManipulator*>(object)), nullOwner);
    archive->Write(CachedWeakPtrUnitType(), const_cast<moho::WeakPtr<moho::Unit>*>(AnimationGoalWeakPtr(object)), nullOwner);
    archive->Write(CachedVectorBoolType(), const_cast<moho::SAniManipBitStorage*>(&object->mBoneMask), nullOwner);
    WriteSharedAnimationResourcePointer(object->mAnimationRef, archive, nullOwner);
    archive->WriteFloat(object->mRate);
    archive->WriteFloat(object->mAnimationTime);
    archive->WriteFloat(object->mLastFramePosition);
    archive->WriteBool(object->mLooping);
    archive->WriteBool(object->mFrameChanged);
    archive->WriteBool(object->mIgnoreMotionScaling);
    archive->WriteBool(object->mOverwriteMode);
    archive->WriteBool(object->mDisableOnSignal);
    archive->WriteBool(object->mDirectionalAnim);
  }

  gpg::SerHelperBase* cleanup_CAnimationManipulatorConstructImpl()
  {
    return UnlinkHelperNode(gCAnimationManipulatorConstruct);
  }

  gpg::SerHelperBase* cleanup_CAnimationManipulatorSerializerImpl()
  {
    return UnlinkHelperNode(gCAnimationManipulatorSerializer);
  }

  void cleanup_CAnimationManipulatorTypeInfoImpl()
  {
    if (!gCAnimationManipulatorTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(&GetCAnimationManipulatorTypeInfo())->~RType();
    gCAnimationManipulatorTypeInfoConstructed = false;
  }

  void CleanupCAnimationManipulatorConstructAtexit()
  {
    (void)cleanup_CAnimationManipulatorConstructImpl();
  }

  void CleanupCAnimationManipulatorSerializerAtexit()
  {
    (void)cleanup_CAnimationManipulatorSerializerImpl();
  }

  void CleanupCAnimationManipulatorTypeInfoAtexit()
  {
    cleanup_CAnimationManipulatorTypeInfoImpl();
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
    mAnimationRef.release();
    mBoneMask.Reset();
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

    mAnimationRef.assign_retain(resource);
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

    mBoneMask.SetBit(static_cast<std::uint32_t>(boneIndex), enabled);
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
    mBoneMask.Resize(boneCount, true);
  }

  /**
   * Address: 0x0063F220 (FUN_0063F220, Moho::CAnimationManipulatorConstruct::Construct)
   */
  void CAnimationManipulatorConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    CAnimationManipulator* const object = new (std::nothrow) CAnimationManipulator();
    if (result == nullptr) {
      delete object;
      return;
    }

    const gpg::RRef objectRef = MakeTypedRef(object, CachedCAnimationManipulatorType());
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x00642340 (FUN_00642340, Moho::CAnimationManipulatorConstruct::Deconstruct)
   */
  void CAnimationManipulatorConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const object = static_cast<CAnimationManipulator*>(objectPtr);
    if (object != nullptr) {
      delete object;
    }
  }

  /**
   * Address: 0x00641E70 (FUN_00641E70, Moho::CAnimationManipulatorConstruct::RegisterConstructFunctions)
   */
  void CAnimationManipulatorConstruct::RegisterConstructFunctions()
  {
    gpg::RType* const type = CachedCAnimationManipulatorType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x0063F2C0 (FUN_0063F2C0, Moho::CAnimationManipulatorSerializer::Deserialize)
   */
  void CAnimationManipulatorSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    DeserializeCAnimationManipulatorState(reinterpret_cast<CAnimationManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x0063F2D0 (FUN_0063F2D0, Moho::CAnimationManipulatorSerializer::Serialize)
   */
  void CAnimationManipulatorSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    SerializeCAnimationManipulatorState(reinterpret_cast<const CAnimationManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x00641EF0 (FUN_00641EF0, Moho::CAnimationManipulatorSerializer::RegisterSerializeFunctions)
   */
  void CAnimationManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCAnimationManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
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

  /**
   * Address: 0x00BFAFF0 (FUN_00BFAFF0, Moho::CAnimationManipulatorConstruct::~CAnimationManipulatorConstruct)
   *
   * What it does:
   * Unlinks the global construct helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CAnimationManipulatorConstruct()
  {
    return cleanup_CAnimationManipulatorConstructImpl();
  }

  /**
   * Address: 0x00BFAF90 (FUN_00BFAF90, Moho::CAnimationManipulatorTypeInfo::~CAnimationManipulatorTypeInfo)
   *
   * What it does:
   * Releases startup-owned `CAnimationManipulatorTypeInfo` reflection storage.
   */
  void cleanup_CAnimationManipulatorTypeInfo()
  {
    cleanup_CAnimationManipulatorTypeInfoImpl();
  }

  /**
   * Address: 0x00BFB020 (FUN_00BFB020, Moho::CAnimationManipulatorSerializer::~CAnimationManipulatorSerializer)
   *
   * What it does:
   * Unlinks the global serializer helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CAnimationManipulatorSerializer()
  {
    return cleanup_CAnimationManipulatorSerializerImpl();
  }

  /**
   * Address: 0x00BD2DF0 (FUN_00BD2DF0, register_CAnimationManipulatorSerializer)
   *
   * What it does:
   * Initializes the global serializer helper callbacks and installs process-exit cleanup.
   */
  int register_CAnimationManipulatorSerializer()
  {
    InitializeHelperNode(gCAnimationManipulatorSerializer);
    gCAnimationManipulatorSerializer.mSerLoadFunc = &CAnimationManipulatorSerializer::Deserialize;
    gCAnimationManipulatorSerializer.mSerSaveFunc = &CAnimationManipulatorSerializer::Serialize;
    gCAnimationManipulatorSerializer.RegisterSerializeFunctions();
    return std::atexit(&CleanupCAnimationManipulatorSerializerAtexit);
  }

  /**
   * Address: 0x00BD2DB0 (FUN_00BD2DB0, register_CAnimationManipulatorConstruct)
   *
   * What it does:
   * Initializes the global construct helper callbacks and registers process-exit cleanup.
   */
  void register_CAnimationManipulatorConstruct()
  {
    InitializeHelperNode(gCAnimationManipulatorConstruct);
    gCAnimationManipulatorConstruct.mSerConstructFunc =
      reinterpret_cast<gpg::RType::construct_func_t>(&CAnimationManipulatorConstruct::Construct);
    gCAnimationManipulatorConstruct.mDeleteFunc = &CAnimationManipulatorConstruct::Deconstruct;
    gCAnimationManipulatorConstruct.RegisterConstructFunctions();
    (void)std::atexit(&CleanupCAnimationManipulatorConstructAtexit);
  }

  /**
   * Address: 0x00BD2D90 (FUN_00BD2D90, register_CAnimationManipulatorTypeInfo)
   *
   * What it does:
   * Forces startup construction/preregistration for `CAnimationManipulator` RTTI and installs exit cleanup.
   */
  void register_CAnimationManipulatorTypeInfo()
  {
    (void)GetCAnimationManipulatorTypeInfo();
    (void)std::atexit(&CleanupCAnimationManipulatorTypeInfoAtexit);
  }
} // namespace moho

namespace
{
  struct CAnimationManipulatorStartupBootstrap
  {
    CAnimationManipulatorStartupBootstrap()
    {
      moho::register_CAnimationManipulatorTypeInfo();
      moho::register_CAnimationManipulatorConstruct();
      (void)moho::register_CAnimationManipulatorSerializer();
    }
  };

  [[maybe_unused]] CAnimationManipulatorStartupBootstrap gCAnimationManipulatorStartupBootstrap;
} // namespace
