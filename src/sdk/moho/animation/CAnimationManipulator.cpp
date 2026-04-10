#include "CAnimationManipulator.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniSkel.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

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
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kCreateAnimatorName = "CreateAnimator";
  constexpr const char* kCreateAnimatorClassName = "<global>";
  constexpr const char* kCreateAnimatorHelpText = "CreateAnimator(unit) -- create a manipulator for playing animations";
  constexpr const char* kPlayAnimName = "PlayAnim";
  constexpr const char* kSetRateName = "SetRate";
  constexpr const char* kGetRateName = "GetRate";
  constexpr const char* kGetAnimationFractionName = "GetAnimationFraction";
  constexpr const char* kSetAnimationFractionName = "SetAnimationFraction";
  constexpr const char* kGetAnimationTimeName = "GetAnimationTime";
  constexpr const char* kSetAnimationTimeName = "SetAnimationTime";
  constexpr const char* kGetAnimationDurationName = "GetAnimationDuration";
  constexpr const char* kSetBoneEnabledName = "SetBoneEnabled";
  constexpr const char* kSetOverwriteModeName = "SetOverwriteMode";
  constexpr const char* kSetDisableOnSignalName = "SetDisableOnSignal";
  constexpr const char* kSetDirectionalAnimName = "SetDirectionalAnim";
  constexpr const char* kAnimationLuaClassName = "CAnimationManipulator";
  constexpr const char* kSetRateHelpText =
    "AnimationManipulator:SetRate(rate)\n"
    "Set the relative rate at which this anim plays; 1.0 is normal speed.\n"
    "Rate can be negative to play backwards or 0 to pause.";
  constexpr const char* kGetRateHelpText = "rate = AnimationManipulator:GetRate()";
  constexpr const char* kGetAnimationFractionHelpText =
    "fraction = AnimationManipulator:GetAnimationFraction()";
  constexpr const char* kSetAnimationFractionHelpText = "AnimationManipulator:SetAnimationFraction(fraction)";
  constexpr const char* kGetAnimationTimeHelpText = "time = AnimationManipulator:GetAnimationTime()";
  constexpr const char* kSetAnimationTimeHelpText = "AnimationManipulator:SetAnimationTime(fraction)";
  constexpr const char* kGetAnimationDurationHelpText =
    "duration = AnimationManipulator:GetAnimationDuration()";
  constexpr const char* kSetBoneEnabledHelpText =
    "AnimationManipulator:SetBoneEnabled(bone, value, include_decscendants=true)";
  constexpr const char* kSetOverwriteModeHelpText = "AnimationManipulator:SetOverwriteMode(bool)";
  constexpr const char* kSetDisableOnSignalHelpText = "AnimationManipulator:SetDisableOnSignal(bool)";
  constexpr const char* kSetDirectionalAnimHelpText = "AnimationManipulator:SetDirectionalAnim(bool)";
  constexpr const char* kPlayAnimHelpText = "AnimManipulator:PlayAnim(entity, animName, looping=false)";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] LuaPlus::LuaObject func_CreateCAnimationManipulatorObject(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::CAnimationManipulator>::Instance().Get(state);
  }

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

  [[noreturn]] void RaiseLuaErrorWithMessage(lua_State* const rawState, const char* const message)
  {
    lua_pushstring(rawState, message);
    (void)lua_gettop(rawState);
    lua_error(rawState);
  }

  /**
   * Address: 0x006413A0 (FUN_006413A0, func_GetAnimationBone)
   *
   * What it does:
   * Resolves one Lua bone selector (name/index) for the manipulator owner
   * actor skeleton and raises Lua errors for unknown/invalid selectors.
   */
  [[nodiscard]] int ResolveAnimationBoneIndex(
    LuaPlus::LuaStackObject& boneArg,
    const moho::CAnimationManipulator& manipulator,
    lua_State* const rawState
  )
  {
    if (lua_isstring(rawState, boneArg.m_stackIndex) != 0) {
      const char* boneName = lua_tostring(rawState, boneArg.m_stackIndex);
      if (boneName == nullptr) {
        boneArg.TypeError("string");
        boneName = "";
      }

      const moho::CAniActor* const ownerActor = manipulator.mOwnerActor;
      GPG_ASSERT(ownerActor != nullptr);
      const boost::shared_ptr<const moho::CAniSkel> skeleton = ownerActor ? ownerActor->GetSkeleton() : boost::shared_ptr<const moho::CAniSkel>{};
      const int boneIndex = skeleton ? skeleton->FindBoneIndex(boneName) : -1;
      if (boneIndex < 0) {
        const msvc8::string msg = gpg::STR_Printf("Unknown bone %s", boneName);
        RaiseLuaErrorWithMessage(rawState, msg.c_str());
      }
      return boneIndex;
    }

    if (lua_type(rawState, boneArg.m_stackIndex) != LUA_TNUMBER) {
      RaiseLuaErrorWithMessage(rawState, "Could not resolve bone from lua object. Must be string or int.");
    }

    const int boneIndex = boneArg.GetInteger();
    const moho::CAniActor* const ownerActor = manipulator.mOwnerActor;
    GPG_ASSERT(ownerActor != nullptr);
    const boost::shared_ptr<const moho::CAniSkel> skeleton = ownerActor ? ownerActor->GetSkeleton() : boost::shared_ptr<const moho::CAniSkel>{};
    const moho::SAniSkelBone* const bone =
      (skeleton != nullptr && boneIndex >= 0) ? skeleton->GetBone(static_cast<std::uint32_t>(boneIndex)) : nullptr;
    if (bone == nullptr) {
      const msvc8::string msg = gpg::STR_Printf("Unknown bone %i", boneIndex);
      RaiseLuaErrorWithMessage(rawState, msg.c_str());
    }

    return boneIndex;
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
   * Address: 0x006423A0 (FUN_006423A0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CAnimationManipulator deserialize thunk alias into the
   * shared deserialize helper body.
   */
  void DeserializeCAnimationManipulatorThunkVariantA(
    moho::CAnimationManipulator* const object, gpg::ReadArchive* const archive
  )
  {
    DeserializeCAnimationManipulatorState(object, archive);
  }

  /**
   * Address: 0x00642800 (FUN_00642800, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CAnimationManipulator deserialize thunk alias into
   * the shared deserialize helper body.
   */
  void DeserializeCAnimationManipulatorThunkVariantB(
    moho::CAnimationManipulator* const object, gpg::ReadArchive* const archive
  )
  {
    DeserializeCAnimationManipulatorState(object, archive);
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

  /**
   * Address: 0x006423B0 (FUN_006423B0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CAnimationManipulator serialize thunk alias into the
   * shared serialize helper body.
   */
  void SerializeCAnimationManipulatorThunkVariantA(
    const moho::CAnimationManipulator* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeCAnimationManipulatorState(object, archive);
  }

  /**
   * Address: 0x00642810 (FUN_00642810, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CAnimationManipulator serialize thunk alias into
   * the shared serialize helper body.
   */
  void SerializeCAnimationManipulatorThunkVariantB(
    const moho::CAnimationManipulator* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeCAnimationManipulatorState(object, archive);
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
  int cfunc_CreateAnimator(lua_State* luaContext);
  int cfunc_CAnimationManipulatorPlayAnim(lua_State* luaContext);

  gpg::RType* CAnimationManipulator::sType = nullptr;
  CScrLuaMetatableFactory<CAnimationManipulator> CScrLuaMetatableFactory<CAnimationManipulator>::sInstance{};

  /**
   * Address: 0x10015880 (constructor shape)
   *
   * What it does:
   * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
   */
  CScrLuaMetatableFactory<CAnimationManipulator>::CScrLuaMetatableFactory()
    : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
  {}

  CScrLuaMetatableFactory<CAnimationManipulator>& CScrLuaMetatableFactory<CAnimationManipulator>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00641E10 (FUN_00641E10, ?Create@?$CScrLuaMetatableFactory@VCAnimationManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
   *
   * What it does:
   * Creates the default metatable used by `CAnimationManipulator` Lua userdata.
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CAnimationManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x006404B0 (FUN_006404B0, cfunc_CreateAnimator)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CreateAnimatorL`.
   */
  int cfunc_CreateAnimator(lua_State* const luaContext)
  {
    return cfunc_CreateAnimatorL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006404D0 (FUN_006404D0, func_CreateAnimator_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateAnimator(unit, [bindGoalUnit])` Lua binder.
   */
  CScrLuaInitForm* func_CreateAnimator_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateAnimatorName,
      &moho::cfunc_CreateAnimator,
      nullptr,
      kCreateAnimatorClassName,
      kCreateAnimatorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640530 (FUN_00640530, cfunc_CreateAnimatorL)
   *
   * What it does:
   * Reads `(unit, [bool])`, creates one animation manipulator bound to that
   * unit's actor/sim lane, and returns the Lua userdata.
   */
  int cfunc_CreateAnimatorL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedRangeWarning, kCreateAnimatorHelpText, 1, 2, argumentCount);
    }

    const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    Unit* const unit = SCR_FromLua_Unit(unitObject);
    const bool bindGoalUnit = argumentCount > 1 ? LuaPlus::LuaStackObject(state, 2).GetBoolean() : false;

    CAnimationManipulator* const manipulator =
      new CAnimationManipulator(unit->SimulationRef, unit->AniActor, bindGoalUnit ? unit : nullptr);
    manipulator->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00640690 (FUN_00640690, func_CAnimationManipulatorPlayAnim_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:PlayAnim(...)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorPlayAnim_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kPlayAnimName,
      &moho::cfunc_CAnimationManipulatorPlayAnim,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kPlayAnimHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640A20 (FUN_00640A20, cfunc_CAnimationManipulatorSetRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetRateL`.
   */
  int cfunc_CAnimationManipulatorSetRate(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetRateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00640A40 (FUN_00640A40, func_CAnimationManipulatorSetRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetRate(rate)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetRate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetRateName,
      &moho::cfunc_CAnimationManipulatorSetRate,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetRateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640AA0 (FUN_00640AA0, cfunc_CAnimationManipulatorSetRateL)
   *
   * What it does:
   * Resolves one animation manipulator object and applies a new playback rate.
   */
  int cfunc_CAnimationManipulatorSetRateL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetRateHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject rateArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      rateArg.TypeError("number");
    }

    const float rate = static_cast<float>(lua_tonumber(rawState, 2));
    manipulator->SetRate(rate);
    lua_settop(rawState, 1);
    return 1;
  }

  /**
   * Address: 0x006408E0 (FUN_006408E0, cfunc_CAnimationManipulatorGetRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetRateL`.
   */
  int cfunc_CAnimationManipulatorGetRate(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorGetRateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00640900 (FUN_00640900, func_CAnimationManipulatorGetRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetRate()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetRate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetRateName,
      &moho::cfunc_CAnimationManipulatorGetRate,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kGetRateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640960 (FUN_00640960, cfunc_CAnimationManipulatorGetRateL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns current playback
   * rate.
   */
  int cfunc_CAnimationManipulatorGetRateL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetRateHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);
    lua_pushnumber(rawState, manipulator->GetRate());
    return 1;
  }

  /**
   * Address: 0x00640BA0 (FUN_00640BA0, cfunc_CAnimationManipulatorGetAnimationFraction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationFractionL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationFraction(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorGetAnimationFractionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00640BC0 (FUN_00640BC0, func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationFraction()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationFraction_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetAnimationFractionName,
      &moho::cfunc_CAnimationManipulatorGetAnimationFraction,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kGetAnimationFractionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640C20 (FUN_00640C20, cfunc_CAnimationManipulatorGetAnimationFractionL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns normalized
   * animation progress.
   */
  int cfunc_CAnimationManipulatorGetAnimationFractionL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAnimationFractionHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);
    lua_pushnumber(rawState, manipulator->GetAnimationFraction());
    return 1;
  }

  /**
   * Address: 0x00640D10 (FUN_00640D10, cfunc_CAnimationManipulatorSetAnimationFraction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetAnimationFractionL`.
   */
  int cfunc_CAnimationManipulatorSetAnimationFraction(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetAnimationFractionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00640D30 (FUN_00640D30, func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetAnimationFraction(fraction)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationFraction_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetAnimationFractionName,
      &moho::cfunc_CAnimationManipulatorSetAnimationFraction,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetAnimationFractionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640D90 (FUN_00640D90, cfunc_CAnimationManipulatorSetAnimationFractionL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua, clamps fraction into `[0, 1]`
   * and applies the new playback position.
   */
  int cfunc_CAnimationManipulatorSetAnimationFractionL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAnimationFractionHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject fractionArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      fractionArg.TypeError("number");
    }

    float fraction = static_cast<float>(lua_tonumber(rawState, 2));
    fraction = std::clamp(fraction, 0.0f, 1.0f);
    manipulator->SetAnimationFraction(fraction);
    return 1;
  }

  /**
   * Address: 0x00640EB0 (FUN_00640EB0, cfunc_CAnimationManipulatorGetAnimationTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationTimeL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationTime(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorGetAnimationTimeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00640ED0 (FUN_00640ED0, func_CAnimationManipulatorGetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationTime()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationTime_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetAnimationTimeName,
      &moho::cfunc_CAnimationManipulatorGetAnimationTime,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kGetAnimationTimeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00640F30 (FUN_00640F30, cfunc_CAnimationManipulatorGetAnimationTimeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns current animation
   * time in seconds.
   */
  int cfunc_CAnimationManipulatorGetAnimationTimeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAnimationTimeHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);
    lua_pushnumber(rawState, manipulator->GetAnimationTime());
    return 1;
  }

  /**
   * Address: 0x00640FF0 (FUN_00640FF0, cfunc_CAnimationManipulatorSetAnimationTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetAnimationTimeL`.
   */
  int cfunc_CAnimationManipulatorSetAnimationTime(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetAnimationTimeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00641010 (FUN_00641010, func_CAnimationManipulatorSetAnimationTime_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetAnimationTime(fraction)` Lua
   * binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetAnimationTime_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetAnimationTimeName,
      &moho::cfunc_CAnimationManipulatorSetAnimationTime,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetAnimationTimeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00641070 (FUN_00641070, cfunc_CAnimationManipulatorSetAnimationTimeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and applies the requested
   * absolute animation time.
   */
  int cfunc_CAnimationManipulatorSetAnimationTimeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAnimationTimeHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject timeArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      timeArg.TypeError("number");
    }

    const float timeSeconds = static_cast<float>(lua_tonumber(rawState, 2));
    manipulator->SetAnimationTime(timeSeconds);
    return 1;
  }

  /**
   * Address: 0x00641160 (FUN_00641160, cfunc_CAnimationManipulatorGetAnimationDuration)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorGetAnimationDurationL`.
   */
  int cfunc_CAnimationManipulatorGetAnimationDuration(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorGetAnimationDurationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00641180 (FUN_00641180, func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:GetAnimationDuration()` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorGetAnimationDuration_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetAnimationDurationName,
      &moho::cfunc_CAnimationManipulatorGetAnimationDuration,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kGetAnimationDurationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006411E0 (FUN_006411E0, cfunc_CAnimationManipulatorGetAnimationDurationL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and returns clip duration in
   * seconds.
   */
  int cfunc_CAnimationManipulatorGetAnimationDurationL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAnimationDurationHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);
    lua_pushnumber(rawState, manipulator->GetAnimationDuration());
    return 1;
  }

  /**
   * Address: 0x006415F0 (FUN_006415F0, cfunc_CAnimationManipulatorSetBoneEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetBoneEnabledL`.
   */
  int cfunc_CAnimationManipulatorSetBoneEnabled(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetBoneEnabledL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00641610 (FUN_00641610, func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the
   * `CAnimationManipulator:SetBoneEnabled(bone, value, include_decscendants=true)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetBoneEnabled_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetBoneEnabledName,
      &moho::cfunc_CAnimationManipulatorSetBoneEnabled,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetBoneEnabledHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00641670 (FUN_00641670, cfunc_CAnimationManipulatorSetBoneEnabledL)
   *
   * What it does:
   * Resolves one animation manipulator, one bone selector (name/index), and
   * enable flags from Lua, then toggles the bone lane.
   */
  int cfunc_CAnimationManipulatorSetBoneEnabledL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 3 || argumentCount > 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kSetBoneEnabledHelpText,
        3,
        4,
        argumentCount
      );
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    const int boneIndex = ResolveAnimationBoneIndex(boneArg, *manipulator, rawState);

    LuaPlus::LuaStackObject enabledArg(state, 3);
    const bool enabled = enabledArg.GetBoolean();

    bool includeDescendants = true;
    if (lua_gettop(rawState) >= 4) {
      LuaPlus::LuaStackObject includeArg(state, 4);
      includeDescendants = includeArg.GetBoolean();
    }

    manipulator->SetBoneEnabled(boneIndex, includeDescendants, enabled);
    lua_settop(rawState, 1);
    return 1;
  }

  /**
   * Address: 0x006417B0 (FUN_006417B0, cfunc_CAnimationManipulatorSetOverwriteMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetOverwriteModeL`.
   */
  int cfunc_CAnimationManipulatorSetOverwriteMode(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetOverwriteModeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006417D0 (FUN_006417D0, func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetOverwriteMode(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetOverwriteMode_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetOverwriteModeName,
      &moho::cfunc_CAnimationManipulatorSetOverwriteMode,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetOverwriteModeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00641830 (FUN_00641830, cfunc_CAnimationManipulatorSetOverwriteModeL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates overwrite-mode
   * behavior.
   */
  int cfunc_CAnimationManipulatorSetOverwriteModeL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetOverwriteModeHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    manipulator->SetOverwriteMode(valueArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x006418F0 (FUN_006418F0, cfunc_CAnimationManipulatorSetDisableOnSignal)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetDisableOnSignalL`.
   */
  int cfunc_CAnimationManipulatorSetDisableOnSignal(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetDisableOnSignalL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00641910 (FUN_00641910, func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetDisableOnSignal(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetDisableOnSignal_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetDisableOnSignalName,
      &moho::cfunc_CAnimationManipulatorSetDisableOnSignal,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetDisableOnSignalHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00641970 (FUN_00641970, cfunc_CAnimationManipulatorSetDisableOnSignalL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates disable-on-signal
   * behavior.
   */
  int cfunc_CAnimationManipulatorSetDisableOnSignalL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetDisableOnSignalHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    manipulator->SetDisableOnSignal(valueArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x00641A30 (FUN_00641A30, cfunc_CAnimationManipulatorSetDirectionalAnim)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CAnimationManipulatorSetDirectionalAnimL`.
   */
  int cfunc_CAnimationManipulatorSetDirectionalAnim(lua_State* const luaContext)
  {
    return cfunc_CAnimationManipulatorSetDirectionalAnimL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00641A50 (FUN_00641A50, func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CAnimationManipulator:SetDirectionalAnim(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CAnimationManipulatorSetDirectionalAnim_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetDirectionalAnimName,
      &moho::cfunc_CAnimationManipulatorSetDirectionalAnim,
      &CScrLuaMetatableFactory<CAnimationManipulator>::Instance(),
      kAnimationLuaClassName,
      kSetDirectionalAnimHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00641AB0 (FUN_00641AB0, cfunc_CAnimationManipulatorSetDirectionalAnimL)
   *
   * What it does:
   * Resolves one animation manipulator from Lua and updates directional
   * animation behavior.
   */
  int cfunc_CAnimationManipulatorSetDirectionalAnimL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetDirectionalAnimHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
    CAnimationManipulator* const manipulator = SCR_FromLua_CAnimationManipulator(manipObject, state);

    const LuaPlus::LuaStackObject valueArg(state, 2);
    manipulator->SetDirectionalAnim(valueArg.GetBoolean());
    return 0;
  }

  /**
   * Address context:
   * - constructor lane used by `cfunc_CreateAnimatorL` (`FUN_00640530`).
   *
   * What it does:
   * Builds one manipulator bound to sim/actor ownership, optionally tracks one
   * goal-motion unit weak ref, and initializes Lua userdata.
   */
  CAnimationManipulator::CAnimationManipulator(
    Sim* const sim, CAniActor* const ownerActor, Unit* const goalMotionScaleUnit
  )
    : IAniManipulator(sim, ownerActor, 0)
    , mRate(1.0f)
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
    AnimationGoalWeakPtr(this)->ResetFromObject(goalMotionScaleUnit);

    if (sim != nullptr && sim->mLuaState != nullptr) {
      LuaPlus::LuaObject arg3{};
      LuaPlus::LuaObject arg2{};
      LuaPlus::LuaObject arg1{};
      LuaPlus::LuaObject scriptFactory = func_CreateCAnimationManipulatorObject(sim->mLuaState);
      CreateLuaObject(scriptFactory, arg1, arg2, arg3);
    }
  }

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
