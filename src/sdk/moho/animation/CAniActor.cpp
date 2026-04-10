#include "CAniActor.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/animation/IAniManipulator.h"

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
  constexpr std::uint32_t kWatchBoneEnabledFlag = 0x8000u;

  alignas(moho::CAniActorTypeInfo) unsigned char gCAniActorTypeInfoStorage[sizeof(moho::CAniActorTypeInfo)] = {};
  bool gCAniActorTypeInfoConstructed = false;

  moho::CAniActorConstruct gCAniActorConstruct{};
  moho::CAniActorSerializer gCAniActorSerializer{};

  gpg::RType* gCAniPoseType = nullptr;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedCAniActorType()
  {
    if (!moho::CAniActor::sType) {
      moho::CAniActor::sType = gpg::LookupRType(typeid(moho::CAniActor));
    }
    return moho::CAniActor::sType;
  }

  [[nodiscard]] gpg::RType* CachedCAniPoseType()
  {
    if (!gCAniPoseType) {
      gCAniPoseType = gpg::LookupRType(typeid(moho::CAniPose));
    }
    return gCAniPoseType;
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    if (!moho::IAniManipulator::sType) {
      moho::IAniManipulator::sType = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return moho::IAniManipulator::sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* object, gpg::RType* staticType)
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

  [[noreturn]] void ThrowPointerTypeMismatch(const gpg::RRef& source, gpg::RType* const expectedType, const char* fallback)
  {
    const char* const expected = expectedType ? expectedType->GetName() : fallback;
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : fallback,
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  template <typename TObject>
  TObject* UpcastTrackedPointer(const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType, const char* fallback)
  {
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<TObject*>(upcast.mObj);
    }

    ThrowPointerTypeMismatch(source, expectedType, fallback);
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
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
      tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
    );
    tracked.sharedObject = tracked.object;
    tracked.sharedControl = control;
    tracked.state = gpg::TrackedPointerState::Shared;
  }

  void ReadSharedCAniPosePointer(
    boost::SharedPtrRaw<moho::CAniPose>& outPointer,
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

    if (tracked.state != gpg::TrackedPointerState::Shared) {
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    if (!tracked.sharedObject || !tracked.sharedControl) {
      throw gpg::SerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCAniPoseType());
    if (!upcast.mObj) {
      ThrowPointerTypeMismatch(source, CachedCAniPoseType(), "CAniPose");
    }

    boost::SharedPtrRaw<moho::CAniPose> sourceShared{};
    sourceShared.px = static_cast<moho::CAniPose*>(tracked.sharedObject);
    sourceShared.pi = tracked.sharedControl;
    outPointer.assign_retain(sourceShared);
  }

  void WriteSharedCAniPosePointer(
    const boost::SharedPtrRaw<moho::CAniPose>& pointer,
    gpg::WriteArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeDerivedRef(pointer.px, CachedCAniPoseType());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Shared, ownerRef);
  }

  [[nodiscard]] moho::IAniManipulator* ReadOwnedManipulatorPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.state != gpg::TrackedPointerState::Unowned) {
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    moho::IAniManipulator* const manipulator =
      UpcastTrackedPointer<moho::IAniManipulator>(tracked, CachedIAniManipulatorType(), "IAniManipulator");
    tracked.state = gpg::TrackedPointerState::Owned;
    return manipulator;
  }

  [[nodiscard]] moho::IAniManipulator* ListNodeToManipulator(
    moho::TDatListItem<moho::IAniManipulator, void>* const node
  )
  {
    if (!node) {
      return nullptr;
    }

    return reinterpret_cast<moho::IAniManipulator*>(
      reinterpret_cast<std::uintptr_t>(node) - offsetof(moho::IAniManipulator, mActorOrderLink)
    );
  }

  /**
   * Address: 0x0063B7C0 (FUN_0063B7C0)
   *
   * What it does:
   * Finds the first watch-bone binding on `manipulator` whose skeleton bone
   * name wildcard-matches `bonePattern`, then toggles the active-flag bit.
   */
  [[nodiscard]] bool SetManipulatorWatchBoneEnabledByPattern(
    moho::IAniManipulator* const manipulator, const char* const bonePattern, const bool enabled
  )
  {
    if (!manipulator || !bonePattern) {
      return false;
    }

    for (moho::SAniManipBinding* binding = manipulator->mWatchBones.mBegin; binding != manipulator->mWatchBones.mEnd;
         ++binding) {
      const moho::CAniActor* const ownerActor = manipulator->mOwnerActor;
      if (ownerActor == nullptr) {
        continue;
      }

      const boost::shared_ptr<const moho::CAniSkel> skeleton = ownerActor->GetSkeleton();
      if (!skeleton) {
        continue;
      }

      const moho::SAniSkelBone* const bone = skeleton->GetBone(static_cast<std::uint32_t>(binding->mBoneIndex));
      const char* const candidateBoneName = (bone != nullptr) ? bone->mBoneName : nullptr;
      if (candidateBoneName == nullptr) {
        continue;
      }

      if (!gpg::STR_MatchWildcard(candidateBoneName, bonePattern)) {
        continue;
      }

      if (enabled) {
        binding->mFlags |= kWatchBoneEnabledFlag;
      } else {
        binding->mFlags &= ~kWatchBoneEnabledFlag;
      }
      return true;
    }

    return false;
  }

  [[nodiscard]] bool ManipulatorHasWatchBoneIndex(const moho::IAniManipulator* const manipulator, const int index)
  {
    if (!manipulator) {
      return false;
    }

    for (const moho::SAniManipBinding* binding = manipulator->mWatchBones.mBegin; binding != manipulator->mWatchBones.mEnd;
         ++binding) {
      if (binding->mBoneIndex == index) {
        return true;
      }
    }

    return false;
  }

  [[nodiscard]] bool
  ManipulatorHasWatchBonePattern(const moho::IAniManipulator* const manipulator, const char* const bonePattern)
  {
    if (!manipulator || !bonePattern) {
      return false;
    }

    const moho::CAniActor* const ownerActor = manipulator->mOwnerActor;
    if (ownerActor == nullptr) {
      return false;
    }

    const boost::shared_ptr<const moho::CAniSkel> skeleton = ownerActor->GetSkeleton();
    if (!skeleton) {
      return false;
    }

    for (const moho::SAniManipBinding* binding = manipulator->mWatchBones.mBegin; binding != manipulator->mWatchBones.mEnd;
         ++binding) {
      const moho::SAniSkelBone* const bone = skeleton->GetBone(static_cast<std::uint32_t>(binding->mBoneIndex));
      const char* const candidateBoneName = (bone != nullptr) ? bone->mBoneName : nullptr;
      if (candidateBoneName != nullptr && gpg::STR_MatchWildcard(candidateBoneName, bonePattern)) {
        return true;
      }
    }

    return false;
  }

  template <typename TPredicate>
  void DeleteMatchingManipulators(moho::CAniActor* const actor, TPredicate&& shouldDelete)
  {
    if (actor == nullptr) {
      return;
    }

    auto* const listHead = static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&actor->mManipulatorsByPrecedence);
    for (auto* node = actor->mManipulatorsByPrecedence.mNext; node != listHead;) {
      auto* const next = node->mNext;
      moho::IAniManipulator* const manipulator = ListNodeToManipulator(node);
      if (manipulator != nullptr && shouldDelete(*manipulator)) {
        delete manipulator;
      }
      node = next;
    }
  }

  void DeserializeManipulatorList(moho::CAniActor* const actor, gpg::ReadArchive* const archive)
  {
    const gpg::RRef owner{};
    moho::IAniManipulator* manipulator = ReadOwnedManipulatorPointer(archive, owner);
    auto* const listHead =
      static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&actor->mManipulatorsByPrecedence);

    while (manipulator) {
      manipulator->mActorOrderLink.ListLinkBefore(listHead);
      manipulator = ReadOwnedManipulatorPointer(archive, owner);
    }
  }

  void SerializeManipulatorList(const moho::CAniActor* const actor, gpg::WriteArchive* const archive)
  {
    const auto* const listHead =
      static_cast<const moho::TDatListItem<moho::IAniManipulator, void>*>(&actor->mManipulatorsByPrecedence);
    const gpg::RRef owner{};

    for (auto* node = actor->mManipulatorsByPrecedence.mNext; node != listHead; node = node->mNext) {
      moho::IAniManipulator* const manipulator = ListNodeToManipulator(node);
      const gpg::RRef objectRef = MakeDerivedRef(manipulator, CachedIAniManipulatorType());
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Owned, owner);
    }

    gpg::WriteRawPointer(
      archive, MakeDerivedRef<moho::IAniManipulator>(nullptr, CachedIAniManipulatorType()), gpg::TrackedPointerState::Owned, owner
    );
  }

  void ResetActorListHeadLinks(moho::CAniActor* const actor)
  {
    auto* const head =
      static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&actor->mManipulatorsByPrecedence);
    head->ListUnlink();
  }

  [[nodiscard]] moho::CAniActorTypeInfo* AcquireCAniActorTypeInfo()
  {
    if (!gCAniActorTypeInfoConstructed) {
      new (gCAniActorTypeInfoStorage) moho::CAniActorTypeInfo();
      gCAniActorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CAniActorTypeInfo*>(gCAniActorTypeInfoStorage);
  }

  /**
   * Address: 0x00BFAC70 (FUN_00BFAC70, sub_BFAC70)
   *
   * What it does:
   * Releases startup-owned `CAniActorTypeInfo` storage.
   */
  void cleanup_CAniActorTypeInfo_Impl()
  {
    if (!gCAniActorTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(AcquireCAniActorTypeInfo())->~RType();
    gCAniActorTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFACD0 (FUN_00BFACD0, Moho::CAniActorConstruct::~CAniActorConstruct)
   *
   * What it does:
   * Unlinks `CAniActorConstruct` helper node from intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAniActorConstruct_Impl()
  {
    return UnlinkHelperNode(gCAniActorConstruct);
  }

  /**
   * Address: 0x00BFAD00 (FUN_00BFAD00, sub_BFAD00)
   *
   * What it does:
   * Unlinks `CAniActorSerializer` helper node from intrusive helper list.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAniActorSerializer_Impl()
  {
    return UnlinkHelperNode(gCAniActorSerializer);
  }

  void CleanupCAniActorTypeInfoAtexit()
  {
    cleanup_CAniActorTypeInfo_Impl();
  }

  void CleanupCAniActorConstructAtexit()
  {
    (void)cleanup_CAniActorConstruct_Impl();
  }

  void CleanupCAniActorSerializerAtexit()
  {
    (void)cleanup_CAniActorSerializer_Impl();
  }

  /**
   * Address: 0x0063C160 (FUN_0063C160, sub_63C160)
   *
   * What it does:
   * Initializes `CAniActorConstruct` helper callbacks and returns helper singleton.
   */
  [[nodiscard]] moho::CAniActorConstruct* setup_CAniActorConstructHelper()
  {
    InitializeHelperNode(gCAniActorConstruct);
    gCAniActorConstruct.mSerConstructFunc = reinterpret_cast<gpg::RType::construct_func_t>(&moho::CAniActorConstruct::Construct);
    gCAniActorConstruct.mDeleteFunc = &moho::CAniActorConstruct::Deconstruct;
    return &gCAniActorConstruct;
  }

  /**
   * Address: 0x0063C1E0 (FUN_0063C1E0, sub_63C1E0)
   *
   * What it does:
   * Initializes `CAniActorSerializer` helper callbacks and returns helper singleton.
   */
  [[nodiscard]] moho::CAniActorSerializer* setup_CAniActorSerializerHelper()
  {
    InitializeHelperNode(gCAniActorSerializer);
    gCAniActorSerializer.mSerLoadFunc = &moho::CAniActorSerializer::Deserialize;
    gCAniActorSerializer.mSerSaveFunc = &moho::CAniActorSerializer::Serialize;
    return &gCAniActorSerializer;
  }
} // namespace

namespace moho
{
  gpg::RType* CAniActor::sType = nullptr;

  /**
   * Address: 0x0063A8F0 (FUN_0063A8F0, ??0CAniActor@Moho@@QAE@ABV?$shared_ptr@VCAniPose@Moho@@@boost@@0@Z)
   */
  CAniActor::CAniActor(const boost::SharedPtrRaw<CAniPose>& priorPose, const boost::SharedPtrRaw<CAniPose>& pose)
  {
    mPose.assign_retain(pose);
    mPriorPose.assign_retain(priorPose);
    mManipulatorsByPrecedence.ListResetLinks();
  }

  /**
   * Address: 0x0063A930 (FUN_0063A930, ??1CAniActor@Moho@@QAE@XZ)
   */
  CAniActor::~CAniActor()
  {
    auto* const listHead = static_cast<TDatListItem<IAniManipulator, void>*>(&mManipulatorsByPrecedence);
    while (listHead->mNext != listHead) {
      IAniManipulator* const manipulator = ListNodeToManipulator(listHead->mNext);
      if (!manipulator) {
        break;
      }
      delete manipulator;
    }

    ResetActorListHeadLinks(this);
    mPriorPose.release();
    mPose.release();
  }

  /**
   * Address: 0x0063B020 (FUN_0063B020, Moho::CAniActorConstruct::Construct)
   */
  void CAniActor::MemberConstruct(gpg::SerConstructResult* const result)
  {
    CAniActor* actor = nullptr;
    void* const storage = ::operator new(sizeof(CAniActor), std::nothrow);
    if (storage) {
      actor = new (storage) CAniActor();
    }

    if (!result) {
      delete actor;
      return;
    }
    result->SetUnowned(MakeDerivedRef(actor, CachedCAniActorType()), 0u);
  }

  /**
   * Address: 0x0063E200 (FUN_0063E200, sub_63E200)
   */
  void CAniActor::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    archive->TrackPointer(MakeDerivedRef(mPose.px, CachedCAniPoseType()));
    archive->TrackPointer(MakeDerivedRef(mPriorPose.px, CachedCAniPoseType()));

    ReadSharedCAniPosePointer(mPose, archive, gpg::RRef{});
    ReadSharedCAniPosePointer(mPriorPose, archive, gpg::RRef{});
    DeserializeManipulatorList(this, archive);
  }

  /**
   * Address: 0x0063CB10 (FUN_0063CB10, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CAniActor deserialize thunk alias into
   * `CAniActor::MemberDeserialize`.
   */
  void DeserializeCAniActorThunkVariantA(moho::CAniActor* const actor, gpg::ReadArchive* const archive)
  {
    if (!actor) {
      return;
    }

    actor->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0063D3D0 (FUN_0063D3D0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CAniActor deserialize thunk alias into
   * `CAniActor::MemberDeserialize`.
   */
  void DeserializeCAniActorThunkVariantB(moho::CAniActor* const actor, gpg::ReadArchive* const archive)
  {
    if (!actor) {
      return;
    }

    actor->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0063E2A0 (FUN_0063E2A0, sub_63E2A0)
   */
  void CAniActor::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    archive->PreCreatedPtr(MakeDerivedRef(mPose.px, CachedCAniPoseType()));
    archive->PreCreatedPtr(MakeDerivedRef(mPriorPose.px, CachedCAniPoseType()));

    WriteSharedCAniPosePointer(mPose, archive, gpg::RRef{});
    WriteSharedCAniPosePointer(mPriorPose, archive, gpg::RRef{});
    SerializeManipulatorList(this, archive);
  }

  /**
   * Address: 0x0063CB20 (FUN_0063CB20, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CAniActor serialize thunk alias into
   * `CAniActor::MemberSerialize`.
   */
  void SerializeCAniActorThunkVariantA(const moho::CAniActor* const actor, gpg::WriteArchive* const archive)
  {
    if (!actor) {
      return;
    }

    actor->MemberSerialize(archive);
  }

  /**
   * Address: 0x0063D3E0 (FUN_0063D3E0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CAniActor serialize thunk alias into
   * `CAniActor::MemberSerialize`.
   */
  void SerializeCAniActorThunkVariantB(const moho::CAniActor* const actor, gpg::WriteArchive* const archive)
  {
    if (!actor) {
      return;
    }

    actor->MemberSerialize(archive);
  }

  /**
   * Address: 0x005E3CF0 (FUN_005E3CF0, ?GetSkeleton@CAniActor@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<const CAniSkel> CAniActor::GetSkeleton() const
  {
    return mPose.px->GetSkeleton();
  }

  /**
   * Address: 0x0063AD40 (FUN_0063AD40, Moho::CAniActor::ResolveBoneIndex)
   *
   * What it does:
   * Resolves one Lua bone selector (index/name/nil) into a validated bone
   * index for this actor's current skeleton.
   */
  int CAniActor::ResolveBoneIndex(LuaPlus::LuaStackObject& boneArg)
  {
    LuaPlus::LuaState* const state = boneArg.m_state;
    lua_State* const rawState = state ? state->m_state : nullptr;
    const int stackIndex = boneArg.m_stackIndex;
    if (state == nullptr || rawState == nullptr) {
      return -1;
    }

    if (lua_type(rawState, stackIndex) == LUA_TNUMBER) {
      if (lua_type(rawState, stackIndex) != LUA_TNUMBER) {
        boneArg.TypeError("integer");
      }

      const int boneIndex = static_cast<int>(lua_tonumber(rawState, stackIndex));
      bool isInvalid = true;
      if (boneIndex >= -2) {
        const boost::shared_ptr<const CAniSkel> skeleton = GetSkeleton();
        const int boneCount = skeleton ? static_cast<int>(skeleton->mBones.size()) : 0;
        isInvalid = boneIndex >= boneCount;
      }

      if (isInvalid) {
        LuaPlus::LuaState::Error(state, "Arg %d: invalid bone index (%d)", stackIndex, boneIndex);
      }
      return boneIndex;
    }

    if (lua_isstring(rawState, stackIndex) != 0) {
      const char* boneName = lua_tostring(rawState, stackIndex);
      if (boneName == nullptr) {
        boneArg.TypeError("string");
        boneName = "";
      }

      const boost::shared_ptr<const CAniSkel> skeleton = GetSkeleton();
      const int boneIndex = skeleton ? skeleton->FindBoneIndex(boneName) : -1;
      if (boneIndex < 0) {
        const LuaPlus::LuaObject boneIdentifier(boneArg);
        LuaPlus::LuaState::Error(state, "Arg %d: unit has no bone \"%s\".", stackIndex, boneIdentifier.ToString());
      }
      return boneIndex;
    }

    if (lua_type(rawState, stackIndex) == LUA_TNIL) {
      return -1;
    }

    LuaPlus::LuaState::Error(
      state,
      "Arg %d: invalid bone identifier; must be string, integer, or nil",
      stackIndex
    );
    return -1;
  }

  /**
   * Address: 0x0063AB50 (FUN_0063AB50, Moho::CAniActor::EnableBoneIndex)
   *
   * What it does:
   * Enables/disables all manipulator watch-bone bindings that target one
   * exact bone index.
   */
  void CAniActor::EnableBoneIndex(const bool enabled, const int index)
  {
    auto* const listHead = static_cast<TDatListItem<IAniManipulator, void>*>(&mManipulatorsByPrecedence);
    for (auto* node = mManipulatorsByPrecedence.mNext; node != listHead; node = node->mNext) {
      IAniManipulator* const manipulator = ListNodeToManipulator(node);
      if (!manipulator) {
        continue;
      }

      for (SAniManipBinding* binding = manipulator->mWatchBones.mBegin; binding != manipulator->mWatchBones.mEnd;
           ++binding) {
        if (binding->mBoneIndex != index) {
          continue;
        }

        if (enabled) {
          binding->mFlags |= kWatchBoneEnabledFlag;
        } else {
          binding->mFlags &= ~kWatchBoneEnabledFlag;
        }
        break;
      }
    }
  }

  /**
   * Address: 0x0063ABC0 (FUN_0063ABC0, Moho::CAniActor::EnableBoneString)
   *
   * What it does:
   * Enables/disables the first wildcard-matching watch-bone binding per
   * manipulator.
   */
  void CAniActor::EnableBoneString(const char* const boneName, const bool enabled)
  {
    auto* const listHead = static_cast<TDatListItem<IAniManipulator, void>*>(&mManipulatorsByPrecedence);
    for (auto* node = mManipulatorsByPrecedence.mNext; node != listHead; node = node->mNext) {
      IAniManipulator* const manipulator = ListNodeToManipulator(node);
      if (!manipulator) {
        continue;
      }

      (void)SetManipulatorWatchBoneEnabledByPattern(manipulator, boneName, enabled);
    }
  }

  /**
   * Address: 0x0063AC00 (FUN_0063AC00, Moho::CAniActor::KillManipulatorByBoneIndex)
   *
   * What it does:
   * Deletes each manipulator whose watch-bone list contains `index`.
   */
  void CAniActor::KillManipulatorByBoneIndex(const int index)
  {
    DeleteMatchingManipulators(this, [index](const IAniManipulator& manipulator) {
      return ManipulatorHasWatchBoneIndex(&manipulator, index);
    });
  }

  /**
   * Address: 0x0063AC50 (FUN_0063AC50, Moho::CAniActor::KillManipulatorsByBonePattern)
   *
   * What it does:
   * Deletes each manipulator that has at least one watch bone whose skeleton
   * name wildcard-matches `bonePattern`.
   */
  void CAniActor::KillManipulatorsByBonePattern(const char* const bonePattern)
  {
    DeleteMatchingManipulators(this, [bonePattern](const IAniManipulator& manipulator) {
      return ManipulatorHasWatchBonePattern(&manipulator, bonePattern);
    });
  }

  /**
   * Address: 0x0063ACA0 (FUN_0063ACA0, Moho::CAniActor::KillManipulator)
   *
   * What it does:
   * Deletes the exact manipulator object when found in this actor's precedence
   * list.
   */
  void CAniActor::KillManipulator(IAniManipulator* const manipulator)
  {
    if (manipulator == nullptr) {
      return;
    }

    auto* const listHead = static_cast<TDatListItem<IAniManipulator, void>*>(&mManipulatorsByPrecedence);
    for (auto* node = mManipulatorsByPrecedence.mNext; node != listHead; node = node->mNext) {
      IAniManipulator* const current = ListNodeToManipulator(node);
      if (current != manipulator) {
        continue;
      }

      delete current;
      return;
    }
  }

  /**
   * Address: 0x0063B020 (FUN_0063B020, Moho::CAniActorConstruct::Construct)
   */
  void CAniActorConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result)
  {
    if (!result) {
      return;
    }
    CAniActor::MemberConstruct(result);
  }

  /**
   * Address: 0x0063CAB0 (FUN_0063CAB0, Moho::CAniActorConstruct::Deconstruct)
   */
  void CAniActorConstruct::Deconstruct(void* const objectPtr)
  {
    delete static_cast<CAniActor*>(objectPtr);
  }

  /**
   * Address: 0x0063C190 (FUN_0063C190, sub_63C190)
   */
  void CAniActorConstruct::RegisterConstructFunctions()
  {
    gpg::RType* const type = CachedCAniActorType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mSerConstructFunc);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x0063B0A0 (FUN_0063B0A0, Moho::CAniActorSerializer::Deserialize)
   */
  void CAniActorSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const actor = reinterpret_cast<CAniActor*>(static_cast<std::uintptr_t>(objectPtr));
    if (!actor) {
      return;
    }
    actor->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0063B0C0 (FUN_0063B0C0, Moho::CAniActorSerializer::Serialize)
   */
  void CAniActorSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const actor = reinterpret_cast<const CAniActor*>(static_cast<std::uintptr_t>(objectPtr));
    if (!actor) {
      return;
    }
    actor->MemberSerialize(archive);
  }

  /**
   * Address: 0x0063C210 (FUN_0063C210, sub_63C210)
   */
  void CAniActorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCAniActorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x0063A770 (FUN_0063A770, ??0CAniActorTypeInfo@Moho@@QAE@@Z)
   */
  CAniActorTypeInfo::CAniActorTypeInfo()
  {
    gpg::PreRegisterRType(typeid(CAniActor), this);
  }

  /**
   * Address: 0x0063A800 (FUN_0063A800, Moho::CAniActorTypeInfo::dtr)
   */
  CAniActorTypeInfo::~CAniActorTypeInfo() = default;

  /**
   * Address: 0x0063A7F0 (FUN_0063A7F0, Moho::CAniActorTypeInfo::GetName)
   */
  const char* CAniActorTypeInfo::GetName() const
  {
    return "CAniActor";
  }

  /**
   * Address: 0x0063A7D0 (FUN_0063A7D0, Moho::CAniActorTypeInfo::Init)
   */
  void CAniActorTypeInfo::Init()
  {
    size_ = sizeof(CAniActor);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BFAC70 (FUN_00BFAC70, sub_BFAC70)
   *
   * What it does:
   * Releases startup-owned `CAniActorTypeInfo` storage.
   */
  void cleanup_CAniActorTypeInfo()
  {
    cleanup_CAniActorTypeInfo_Impl();
  }

  /**
   * Address: 0x00BFACD0 (FUN_00BFACD0, Moho::CAniActorConstruct::~CAniActorConstruct)
   *
   * What it does:
   * Unlinks global construct helper node from intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CAniActorConstruct()
  {
    return cleanup_CAniActorConstruct_Impl();
  }

  /**
   * Address: 0x00BFAD00 (FUN_00BFAD00, sub_BFAD00)
   *
   * What it does:
   * Unlinks global serializer helper node from intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CAniActorSerializer()
  {
    return cleanup_CAniActorSerializer_Impl();
  }

  /**
   * Address: 0x00BD2B00 (FUN_00BD2B00, register_CAniActorTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAniActorTypeInfo` and installs process-exit cleanup.
   */
  void register_CAniActorTypeInfo()
  {
    (void)AcquireCAniActorTypeInfo();
    (void)std::atexit(&CleanupCAniActorTypeInfoAtexit);
  }

  /**
   * Address: 0x00BD2B20 (FUN_00BD2B20, register_CAniActorConstruct)
   *
   * What it does:
   * Initializes global construct helper callbacks and installs exit cleanup.
   */
  void register_CAniActorConstruct()
  {
    CAniActorConstruct* const construct = setup_CAniActorConstructHelper();
    construct->RegisterConstructFunctions();
    (void)std::atexit(&CleanupCAniActorConstructAtexit);
  }

  /**
   * Address: 0x00BD2B60 (FUN_00BD2B60, register_CAniActorSerializer)
   *
   * What it does:
   * Initializes global serializer helper callbacks and installs exit cleanup.
   */
  void register_CAniActorSerializer()
  {
    CAniActorSerializer* const serializer = setup_CAniActorSerializerHelper();
    serializer->RegisterSerializeFunctions();
    (void)std::atexit(&CleanupCAniActorSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct CAniActorStartupBootstrap
  {
    CAniActorStartupBootstrap()
    {
      moho::register_CAniActorTypeInfo();
      moho::register_CAniActorConstruct();
      moho::register_CAniActorSerializer();
    }
  };

  [[maybe_unused]] CAniActorStartupBootstrap gCAniActorStartupBootstrap;
} // namespace
