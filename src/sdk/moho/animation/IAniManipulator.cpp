#include "IAniManipulator.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/animation/CAniActor.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"

namespace
{
  constexpr std::uint16_t kWatchBoneActiveFlag = 0x8000;
  constexpr const char* kIAniManipulatorLuaClassName = "IAniManipulator";
  constexpr const char* kIAniManipulatorSetPrecedenceName = "SetPrecedence";
  constexpr const char* kIAniManipulatorEnableName = "Enable";
  constexpr const char* kIAniManipulatorDisableName = "Disable";
  constexpr const char* kIAniManipulatorDestroyName = "Destroy";
  constexpr const char* kIAniManipulatorSetPrecedenceHelpText =
    "Manipulator:SetPrecedence(integer) -- change the precedence of this manipulator. "
    "Manipulators with higher precedence run first.";
  constexpr const char* kIAniManipulatorEnableHelpText =
    "Manipulator:Enable() -- enable a manipulator. Manipulators start out enabled so you only need this after "
    "calling Disable().";
  constexpr const char* kIAniManipulatorDisableHelpText =
    "Manipulator:Disable() -- disable a manipulator. This immediately removes it from the bone computation, which "
    "may result in the bone's position snapping.";
  constexpr const char* kIAniManipulatorDestroyHelpText = "Manipulator:Destroy() -- destroy a manipulator.";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] moho::SAniManipBinding* InlineWatchBoneStorage(moho::IAniManipulator* const manipulator) noexcept
  {
    return &manipulator->mWatchBones.mInlineEntries[0];
  }

  [[nodiscard]] std::int32_t BindingPointerToInt32(const moho::SAniManipBinding* const binding) noexcept
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(binding));
  }

  [[nodiscard]] moho::SAniManipBinding* Int32ToBindingPointer(const std::int32_t value) noexcept
  {
    return reinterpret_cast<moho::SAniManipBinding*>(static_cast<std::uintptr_t>(value));
  }

  void InitializeWatchBoneStorage(moho::IAniManipulator* const manipulator)
  {
    auto* const inlineStorage = InlineWatchBoneStorage(manipulator);
    manipulator->mWatchBones.mInlineStorage = inlineStorage;
    manipulator->mWatchBones.mBegin = inlineStorage;
    manipulator->mWatchBones.mEnd = inlineStorage;
    manipulator->mWatchBones.mCapacityEnd = inlineStorage + 2;
  }

  [[nodiscard]] moho::SAniManipBinding* CopyBindingRange(
    moho::SAniManipBinding* destination,
    const moho::SAniManipBinding* sourceEnd,
    const moho::SAniManipBinding* sourceBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination) {
        *destination = *sourceBegin;
      }
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0063C950 (FUN_0063C950, sub_63C950)
   *
   * What it does:
   * Allocates a new watch-bone buffer, inserts one contiguous range at
   * `insertPosition`, then updates/cleans old storage and writes the new
   * `{begin,end,capacity}` triple.
   */
  std::int32_t ReallocateWatchBoneStorageForInsert(
    moho::SAniManipBinding* const insertPosition,
    moho::SAniManipBindingStorage* const storage,
    std::int32_t newCapacity,
    const moho::SAniManipBinding* const insertBegin,
    const moho::SAniManipBinding* const insertEnd
  )
  {
    auto* const newStorage = new moho::SAniManipBinding[newCapacity];
    auto* const afterPrefix = CopyBindingRange(newStorage, insertPosition, storage->mBegin);
    auto* const afterInserted = CopyBindingRange(afterPrefix, insertEnd, insertBegin);
    auto* const newEnd = CopyBindingRange(afterInserted, storage->mEnd, insertPosition);

    if (storage->mBegin == storage->mInlineStorage) {
      // Mirrors the inline-buffer sentinel write in FUN_0063C950.
      storage->mInlineStorage->mBoneIndex = BindingPointerToInt32(storage->mCapacityEnd);
    } else {
      delete[] storage->mBegin;
    }

    storage->mBegin = newStorage;
    storage->mEnd = newEnd;
    storage->mCapacityEnd = newStorage + newCapacity;
    return newCapacity;
  }

  /**
   * Address: 0x0063C5F0 (FUN_0063C5F0, func_AppendBone)
   *
   * What it does:
   * Appends one binding and grows storage with the original doubling policy
   * when the watch-bone buffer is full.
   */
  void AppendWatchBoneBinding(moho::SAniManipBindingStorage* const storage, const moho::SAniManipBinding& binding)
  {
    auto* const end = storage->mEnd;
    if (end == storage->mCapacityEnd) {
      const auto currentSize = static_cast<std::int32_t>(storage->mEnd - storage->mBegin);
      const auto currentCapacity = static_cast<std::int32_t>(storage->mCapacityEnd - storage->mBegin);
      std::int32_t newCapacity = currentSize + 1;
      const std::int32_t doubledCapacity = currentCapacity * 2;
      if (newCapacity < doubledCapacity) {
        newCapacity = doubledCapacity;
      }

      ReallocateWatchBoneStorageForInsert(end, storage, newCapacity, &binding, &binding + 1);
      return;
    }

    if (end) {
      *end = binding;
    }
    ++storage->mEnd;
  }

  /**
   * Address: 0x0063ACE0 (FUN_0063ACE0, sub_63ACE0)
   *
   * What it does:
   * Inserts `manipulator` into CAniActor's intrusive order list sorted by
   * ascending `mPrecedence`.
   */
  void RegisterWithOwnerActorOrderList(moho::CAniActor* const ownerActor, moho::IAniManipulator* const manipulator)
  {
    auto* const listHead =
      static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&ownerActor->mManipulatorsByPrecedence);
    auto* insertBefore = ownerActor->mManipulatorsByPrecedence.mNext;
    while (insertBefore != listHead) {
      auto* const current = reinterpret_cast<moho::IAniManipulator*>(
        reinterpret_cast<std::uintptr_t>(insertBefore) - offsetof(moho::IAniManipulator, mActorOrderLink)
      );
      if (manipulator->mPrecedence < current->mPrecedence) {
        break;
      }
      insertBefore = insertBefore->mNext;
    }

    manipulator->mActorOrderLink.ListLinkBefore(insertBefore);
  }

  gpg::RType* CachedIAniManipulatorType()
  {
    if (!moho::IAniManipulator::sType) {
      moho::IAniManipulator::sType = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return moho::IAniManipulator::sType;
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

  void AddCScriptEventBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(moho::CScriptEvent));
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  alignas(moho::IAniManipulatorTypeInfo)
  unsigned char gIAniManipulatorTypeInfoStorage[sizeof(moho::IAniManipulatorTypeInfo)] = {};
  bool gIAniManipulatorTypeInfoConstructed = false;

  gpg::RType* gCAniActorType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gFastVectorSAniManipBindingType = nullptr;

  moho::IAniManipulatorSerializer gIAniManipulatorSerializer{};

  [[nodiscard]] gpg::RType* CachedCAniActorType()
  {
    if (!gCAniActorType) {
      gCAniActorType = gpg::LookupRType(typeid(moho::CAniActor));
    }
    return gCAniActorType;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!gSimType) {
      gSimType = gpg::LookupRType(typeid(moho::Sim));
      moho::Sim::sType = gSimType;
    }
    return gSimType;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorSAniManipBindingType()
  {
    if (!gFastVectorSAniManipBindingType) {
      gFastVectorSAniManipBindingType = gpg::LookupRType(typeid(gpg::fastvector<moho::SAniManipBinding>));
    }
    return gFastVectorSAniManipBindingType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptEventType()
  {
    if (!moho::CScriptEvent::sType) {
      moho::CScriptEvent::sType = gpg::LookupRType(typeid(moho::CScriptEvent));
    }
    return moho::CScriptEvent::sType;
  }

  [[nodiscard]] moho::IAniManipulatorTypeInfo* AcquireIAniManipulatorTypeInfo()
  {
    if (!gIAniManipulatorTypeInfoConstructed) {
      auto* const typeInfo = new (gIAniManipulatorTypeInfoStorage) moho::IAniManipulatorTypeInfo();
      gpg::PreRegisterRType(typeid(moho::IAniManipulator), typeInfo);
      gIAniManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::IAniManipulatorTypeInfo*>(gIAniManipulatorTypeInfoStorage);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadUnownedPointer(gpg::ReadArchive* const archive, gpg::RType* const expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  void WriteUnownedPointer(gpg::WriteArchive* const archive, TObject* const object, gpg::RType* const expectedType)
  {
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = expectedType;
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

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

  void cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl()
  {
    if (!gIAniManipulatorTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(AcquireIAniManipulatorTypeInfo())->~RType();
    gIAniManipulatorTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::SerHelperBase* cleanup_IAniManipulatorSerializer_00BFAE20_Impl()
  {
    return UnlinkHelperNode(gIAniManipulatorSerializer);
  }

  void CleanupIAniManipulatorTypeInfoAtexit()
  {
    cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl();
  }

  void CleanupIAniManipulatorSerializerAtexit()
  {
    (void)cleanup_IAniManipulatorSerializer_00BFAE20_Impl();
  }

  /**
   * Address: 0x0063E380 (FUN_0063E380, sub_63E380)
   *
   * What it does:
   * Loads IAniManipulator base serialization fields into an existing object.
   */
  void DeserializeIAniManipulatorState(moho::IAniManipulator* const object, gpg::ReadArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedCScriptEventType(), object, nullOwner);
    archive->ReadBool(&object->mEnabled);
    object->mOwnerActor = ReadUnownedPointer<moho::CAniActor>(archive, CachedCAniActorType());
    object->mOwnerSim = ReadUnownedPointer<moho::Sim>(archive, CachedSimType());
    archive->ReadInt(&object->mPrecedence);
    archive->Read(CachedFastVectorSAniManipBindingType(), &object->mWatchBones, nullOwner);
  }

  /**
   * Address: 0x0063E450 (FUN_0063E450, sub_63E450)
   *
   * What it does:
   * Saves IAniManipulator base serialization fields from an existing object.
   */
  void SerializeIAniManipulatorState(const moho::IAniManipulator* const object, gpg::WriteArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedCScriptEventType(), const_cast<moho::IAniManipulator*>(object), nullOwner);
    archive->WriteBool(object->mEnabled);
    WriteUnownedPointer(archive, object->mOwnerActor, CachedCAniActorType());
    WriteUnownedPointer(archive, object->mOwnerSim, CachedSimType());
    archive->WriteInt(object->mPrecedence);
    archive->Write(
      CachedFastVectorSAniManipBindingType(),
      const_cast<moho::SAniManipBindingStorage*>(&object->mWatchBones),
      nullOwner
    );
  }
} // namespace

namespace moho
{
  gpg::RType* IAniManipulator::sType = nullptr;

  /**
   * Address: 0x0063B5D0 (FUN_0063B5D0, ??0IAniManipulator@Moho@@QAE@XZ)
   */
  IAniManipulator::IAniManipulator()
    : mOwnerActor(nullptr)
    , mOwnerSim(nullptr)
    , mPrecedence(0)
  {
    InitializeWatchBoneStorage(this);
  }

  /**
   * Address: 0x0063B640 (FUN_0063B640, ??0IAniManipulator@Moho@@QAE@PAVSim@1@PAVCAniActor@1@H@Z)
   */
  IAniManipulator::IAniManipulator(Sim* const sim, CAniActor* const ownerActor, const int precedence)
    : mOwnerActor(ownerActor)
    , mOwnerSim(sim)
    , mPrecedence(precedence)
  {
    mEnabled = true;
    InitializeWatchBoneStorage(this);
    RegisterWithOwnerActorOrderList(ownerActor, this);
  }

  /**
   * Address: 0x0062FC70 (FUN_0062FC70, ??1IAniManipulator@Moho@@UAE@XZ)
   */
  IAniManipulator::~IAniManipulator()
  {
    ResetWatchBoneStorage();
    mActorOrderLink.ListUnlink();
  }

  /**
   * Address: 0x0062FC30 (FUN_0062FC30, ?GetClass@IAniManipulator@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* IAniManipulator::GetClass() const
  {
    return CachedIAniManipulatorType();
  }

  /**
   * Address: 0x0062FC50 (FUN_0062FC50, ?GetDerivedObjectRef@IAniManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef IAniManipulator::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, CachedIAniManipulatorType());
  }

  /**
   * Address: 0x0063B6D0 (FUN_0063B6D0, ?AddWatchBone@IAniManipulator@Moho@@QAEHH@Z)
   */
  int IAniManipulator::AddWatchBone(const int boneIndex)
  {
    SAniManipBinding watchBone{};
    watchBone.mBoneIndex = boneIndex;
    watchBone.mFlags = kWatchBoneActiveFlag;
    AppendWatchBoneBinding(&mWatchBones, watchBone);
    return static_cast<int>(mWatchBones.mEnd - mWatchBones.mBegin - 1);
  }

  /**
   * Address: 0x0063BAC0 (FUN_0063BAC0, cfunc_IAniManipulatorSetPrecedence)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorSetPrecedenceL`.
   */
  int cfunc_IAniManipulatorSetPrecedence(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorSetPrecedenceL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BAE0 (FUN_0063BAE0, func_IAniManipulatorSetPrecedence_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:SetPrecedence(integer)` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorSetPrecedence_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorSetPrecedenceName,
      &moho::cfunc_IAniManipulatorSetPrecedence,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorSetPrecedenceHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BB40 (FUN_0063BB40, cfunc_IAniManipulatorSetPrecedenceL)
   *
   * What it does:
   * Reads `(manipulator, precedence)`, updates manipulator precedence, and
   * reinserts it into the owning actor precedence list.
   */
  int cfunc_IAniManipulatorSetPrecedenceL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorSetPrecedenceHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);

    LuaPlus::LuaStackObject precedenceArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      precedenceArg.TypeError("integer");
    }

    const int precedence = static_cast<int>(lua_tonumber(rawState, 2));

    manipulator->mActorOrderLink.ListUnlink();
    manipulator->mPrecedence = precedence;
    RegisterWithOwnerActorOrderList(manipulator->mOwnerActor, manipulator);

    lua_settop(rawState, 1);
    return 1;
  }

  /**
   * Address: 0x0063BC60 (FUN_0063BC60, cfunc_IAniManipulatorEnable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorEnableL`.
   */
  int cfunc_IAniManipulatorEnable(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorEnableL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BC80 (FUN_0063BC80, func_IAniManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorEnable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorEnableName,
      &moho::cfunc_IAniManipulatorEnable,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorEnableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BCE0 (FUN_0063BCE0, cfunc_IAniManipulatorEnableL)
   *
   * What it does:
   * Validates `IAniManipulator:Enable()`, resolves one manipulator, and marks
   * it enabled.
   */
  int cfunc_IAniManipulatorEnableL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorEnableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
    if (manipulator) {
      manipulator->mEnabled = true;
    }

    return 0;
  }

  /**
   * Address: 0x0063BD90 (FUN_0063BD90, cfunc_IAniManipulatorDisable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDisableL`.
   */
  int cfunc_IAniManipulatorDisable(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorDisableL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BDB0 (FUN_0063BDB0, func_IAniManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDisable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorDisableName,
      &moho::cfunc_IAniManipulatorDisable,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorDisableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BE10 (FUN_0063BE10, cfunc_IAniManipulatorDisableL)
   *
   * What it does:
   * Validates `IAniManipulator:Disable()`, resolves one manipulator, and marks
   * it disabled.
   */
  int cfunc_IAniManipulatorDisableL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorDisableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
    if (manipulator) {
      manipulator->mEnabled = false;
    }

    return 0;
  }

  /**
   * Address: 0x0063BEC0 (FUN_0063BEC0, cfunc_IAniManipulatorDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IAniManipulatorDestroyL`.
   */
  int cfunc_IAniManipulatorDestroy(lua_State* const luaContext)
  {
    return cfunc_IAniManipulatorDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0063BEE0 (FUN_0063BEE0, func_IAniManipulatorDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `IAniManipulator:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_IAniManipulatorDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIAniManipulatorDestroyName,
      &moho::cfunc_IAniManipulatorDestroy,
      &CScrLuaMetatableFactory<IAniManipulator>::Instance(),
      kIAniManipulatorLuaClassName,
      kIAniManipulatorDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0063BF40 (FUN_0063BF40, cfunc_IAniManipulatorDestroyL)
   *
   * What it does:
   * Validates `IAniManipulator:Destroy()`, resolves one optional manipulator
   * pointer, and destroys the object when still alive.
   */
  int cfunc_IAniManipulatorDestroyL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kIAniManipulatorDestroyHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    IAniManipulator* const manipulator = SCR_FromLua_IAniManipulatorOpt(manipulatorObject, state);
    if (manipulator) {
      delete manipulator;
    }

    return 0;
  }

  void IAniManipulator::ResetWatchBoneStorage()
  {
    auto& storage = mWatchBones;
    auto* const inlineStorage = storage.mInlineStorage;
    if (storage.mBegin != inlineStorage) {
      delete[] storage.mBegin;
      storage.mBegin = inlineStorage;
      storage.mCapacityEnd = Int32ToBindingPointer(inlineStorage->mBoneIndex);
    }

    storage.mEnd = storage.mBegin;
  }

  /**
   * Address: 0x0063C540 (FUN_0063C540, sub_63C540)
   */
  void IAniManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIAniManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x0063BA10 (FUN_0063BA10, Moho::IAniManipulatorSerializer::Deserialize)
   */
  void IAniManipulatorSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    DeserializeIAniManipulatorState(reinterpret_cast<IAniManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x0063BA20 (FUN_0063BA20, Moho::IAniManipulatorSerializer::Serialize)
   */
  void IAniManipulatorSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    SerializeIAniManipulatorState(reinterpret_cast<const IAniManipulator*>(objectPtr), archive);
  }

  /**
   * Address: 0x0063B520 (FUN_0063B520, scalar deleting destructor thunk)
   */
  IAniManipulatorTypeInfo::~IAniManipulatorTypeInfo() = default;

  /**
   * Address: 0x0063B510 (FUN_0063B510, ?GetName@IAniManipulatorTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* IAniManipulatorTypeInfo::GetName() const
  {
    return "IAniManipulator";
  }

  /**
   * Address: 0x0063B4E0 (FUN_0063B4E0, ?Init@IAniManipulatorTypeInfo@Moho@@UAEXXZ)
   */
  void IAniManipulatorTypeInfo::Init()
  {
    size_ = sizeof(IAniManipulator);
    gpg::RType::Init();
    AddCScriptEventBase(this);
    Finish();
  }

  /**
   * Address: 0x0063B480 (FUN_0063B480, sub_63B480)
   *
   * What it does:
   * Constructs/preregisters startup RTTI storage for IAniManipulator.
   */
  gpg::RType* register_IAniManipulatorTypeInfo_00()
  {
    return AcquireIAniManipulatorTypeInfo();
  }

  /**
   * Address: 0x00BFADC0 (FUN_00BFADC0, sub_BFADC0)
   *
   * What it does:
   * Releases startup-owned IAniManipulator RTTI storage.
   */
  void cleanup_IAniManipulatorTypeInfo()
  {
    cleanup_IAniManipulatorTypeInfo_00BFADC0_Impl();
  }

  /**
   * Address: 0x00BD2C20 (FUN_00BD2C20, sub_BD2C20)
   *
   * What it does:
   * Registers IAniManipulator RTTI startup ownership and installs exit cleanup.
   */
  int register_IAniManipulatorTypeInfo_AtExit()
  {
    (void)register_IAniManipulatorTypeInfo_00();
    return std::atexit(&CleanupIAniManipulatorTypeInfoAtexit);
  }

  /**
   * Address: 0x00BFAE20 (FUN_00BFAE20, Moho::IAniManipulatorSerializer::~IAniManipulatorSerializer)
   *
   * What it does:
   * Unlinks IAniManipulator serializer helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_IAniManipulatorSerializer()
  {
    return cleanup_IAniManipulatorSerializer_00BFAE20_Impl();
  }

  /**
   * Address: 0x00BD2C40 (FUN_00BD2C40, register_IAniManipulatorSerializer)
   *
   * What it does:
   * Initializes IAniManipulator serializer helper callbacks and installs exit cleanup.
   */
  void register_IAniManipulatorSerializer()
  {
    InitializeHelperNode(gIAniManipulatorSerializer);
    gIAniManipulatorSerializer.mSerLoadFunc = &IAniManipulatorSerializer::Deserialize;
    gIAniManipulatorSerializer.mSerSaveFunc = &IAniManipulatorSerializer::Serialize;
    gIAniManipulatorSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupIAniManipulatorSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct IAniManipulatorStartupBootstrap
  {
    IAniManipulatorStartupBootstrap()
    {
      (void)moho::register_IAniManipulatorTypeInfo_AtExit();
      moho::register_IAniManipulatorSerializer();
    }
  };

  [[maybe_unused]] IAniManipulatorStartupBootstrap gIAniManipulatorStartupBootstrap;
} // namespace
