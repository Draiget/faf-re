#include "Reflection.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <sstream>
#include <stdexcept>

#include "BadRefCast.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "moho/audio/CSndParams.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CLuaConOutputHandler.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ESquadClass.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "lua/LuaObject.h"
using namespace gpg;

namespace
{
  RType* CachedRect2iType()
  {
    RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  RType* CachedRect2fType()
  {
    RType* type = gpg::Rect2f::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2f));
      gpg::Rect2f::sType = type;
    }
    return type;
  }

  RType* CachedIntType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  /**
   * Address: 0x0040E140 (FUN_0040E140)
   *
   * What it does:
   * Lazily resolves and caches the reflection descriptor for `float`.
   */
  RType* CachedFloatType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

RType* CachedUIntType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(unsigned int));
    }
    return cached;
}

RType* CachedCTaskThreadType()
{
    RType* cached = moho::CTaskThread::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CTaskThread));
        moho::CTaskThread::sType = cached;
    }
    return cached;
}

RType* CachedCAcquireTargetTaskType()
{
    RType* cached = moho::CAcquireTargetTask::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CAcquireTargetTask));
        moho::CAcquireTargetTask::sType = cached;
    }
    return cached;
}

RType* CachedEntityType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::Entity));
    }
    return cached;
}

RType* CachedCEconomyEventType()
{
    RType* cached = moho::CEconomyEvent::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CEconomyEvent));
        moho::CEconomyEvent::sType = cached;
    }
    return cached;
}

RType* CachedCLuaConOutputHandlerType()
{
    RType* cached = moho::CLuaConOutputHandler::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CLuaConOutputHandler));
        moho::CLuaConOutputHandler::sType = cached;
    }
    return cached;
}

RType* CachedCScriptObjectType()
{
    RType* cached = moho::CScriptObject::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CScriptObject));
        moho::CScriptObject::sType = cached;
    }
    return cached;
}

RType* CachedCSndParamsType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CSndParams));
    }
    return cached;
}

  constexpr const char* kReflectionHeaderPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.h";

  struct TypeInfoRTypePair
  {
    const std::type_info* typeInfo;
    gpg::RType* rType;
  };

  struct TypeInfoCache3
  {
    bool initialized;
    TypeInfoRTypePair entries[3];
  };

  template <class TObject>
  [[nodiscard]] gpg::RRef* BuildTypedRefWithCache(
    gpg::RRef* const out,
    TObject* const object,
    const std::type_info& declaredType,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (!out) {
      return nullptr;
    }

    gpg::RType* declaredRType = declaredTypeCache;
    if (!declaredRType) {
      declaredRType = gpg::LookupRType(declaredType);
      declaredTypeCache = declaredRType;
    }

    const std::type_info* runtimeTypeInfo = &declaredType;
    if constexpr (std::is_polymorphic_v<TObject>) {
      if (object) {
        runtimeTypeInfo = &typeid(*object);
      }
    }

    if (!object || (*runtimeTypeInfo == declaredType)) {
      out->mObj = object;
      out->mType = declaredRType;
      return out;
    }

    if (!cache.initialized) {
      cache.initialized = true;
      for (TypeInfoRTypePair& entry : cache.entries) {
        entry.typeInfo = nullptr;
        entry.rType = nullptr;
      }
    }

    int foundSlot = 0;
    while (foundSlot < 3) {
      const TypeInfoRTypePair& entry = cache.entries[foundSlot];
      if (entry.typeInfo == runtimeTypeInfo || (entry.typeInfo && (*entry.typeInfo == *runtimeTypeInfo))) {
        break;
      }
      ++foundSlot;
    }

    gpg::RType* runtimeRType = nullptr;
    if (foundSlot >= 3) {
      runtimeRType = gpg::LookupRType(*runtimeTypeInfo);
      foundSlot = 2;
    } else {
      runtimeRType = cache.entries[foundSlot].rType;
    }

    for (int slot = foundSlot; slot > 0; --slot) {
      cache.entries[slot] = cache.entries[slot - 1];
    }
    cache.entries[0].typeInfo = runtimeTypeInfo;
    cache.entries[0].rType = runtimeRType;

    int32_t baseOffset = 0;
    if (!runtimeRType->IsDerivedFrom(declaredRType, &baseOffset)) {
      gpg::HandleAssertFailure("isDer", 458, kReflectionHeaderPath);
    }

    out->mType = runtimeRType;
    out->mObj = static_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    return out;
  }

  gpg::RType* gUIntRRefType = nullptr;
  thread_local TypeInfoCache3 gUIntRRefCache{false, {}};
  gpg::RType* gESquadClassRRefType = nullptr;
  thread_local TypeInfoCache3 gESquadClassRRefCache{false, {}};
  gpg::RType* gEMauiEventTypeRRefType = nullptr;
  thread_local TypeInfoCache3 gEMauiEventTypeRRefCache{false, {}};
  gpg::RType* gCTaskThreadRRefType = nullptr;
  thread_local TypeInfoCache3 gCTaskThreadRRefCache{false, {}};
  gpg::RType* gUnitRRefType = nullptr;
  thread_local TypeInfoCache3 gUnitRRefCache{false, {}};
  gpg::RType* gRUnitBlueprintRRefType = nullptr;
  thread_local TypeInfoCache3 gRUnitBlueprintRRefCache{false, {}};
  gpg::RType* gRRuleGameRulesRRefType = nullptr;
  thread_local TypeInfoCache3 gRRuleGameRulesRRefCache{false, {}};
  gpg::RType* gCUnitCommandRRefType = nullptr;
  thread_local TypeInfoCache3 gCUnitCommandRRefCache{false, {}};
  gpg::RType* gCRandomStreamRRefType = nullptr;
  thread_local TypeInfoCache3 gCRandomStreamRRefCache{false, {}};
  gpg::RType* gCPlatoonRRefType = nullptr;
  thread_local TypeInfoCache3 gCPlatoonRRefCache{false, {}};
  gpg::RType* gIdPoolRRefType = nullptr;
  thread_local TypeInfoCache3 gIdPoolRRefCache{false, {}};
  gpg::RType* gCLuaConOutputHandlerRRefType = nullptr;
  thread_local TypeInfoCache3 gCLuaConOutputHandlerRRefCache{false, {}};
  gpg::RType* gLuaStateRRefType = nullptr;
  thread_local TypeInfoCache3 gLuaStateRRefCache{false, {}};

/**
 * Address: 0x004023E0 (FUN_004023E0)
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `gpg::RType`.
 */
RType* CachedRTypeDescriptor()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(RType));
    }
    return cached;
}

template <class T>
RType* CachedPointerType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(T*));
    }
    return cached;
}

template <class T>
RRef MakePointerSlotRef(T** const slot)
{
    RRef out{};
    out.mObj = slot;
    out.mType = CachedPointerType<T>();
    return out;
}

template <class T>
T* const* TryUpcastPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, CachedPointerType<T>());
    if (!upcast.mObj) {
        throw gpg::BadRefCast("type error");
    }

    return static_cast<T* const*>(upcast.mObj);
}

template <class T>
RRef MakePointeeRef(T* const object, RType* const baseType)
{
    RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;

    if (!object || !baseType) {
        return out;
    }

    RType* dynamicType = baseType;
    try {
        dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
        dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
        out.mObj = object;
        out.mType = dynamicType;
        return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
}

template <class T>
msvc8::string BuildPointerLexical(void* const slotObject, RType* const pointeeType)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (!slot || !*slot) {
        return msvc8::string("NULL");
    }

    const RRef pointeeRef = MakePointeeRef<T>(*slot, pointeeType);
    if (!pointeeRef.mObj) {
        return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return STR_Printf("[%s]", inner.c_str());
}

msvc8::string BuildPointerName(RType* const pointeeType)
{
    const char* pointeeName = pointeeType ? pointeeType->GetName() : "null";
    if (!pointeeName) {
        pointeeName = "null";
    }
    return STR_Printf("%s*", pointeeName);
}

template <class T>
RRef NewPointerSlotRef()
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    return MakePointerSlotRef<T>(slot);
}

template <class T>
RRef CopyPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    *slot = nullptr;
    if (sourceRef) {
        T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakePointerSlotRef<T>(slot);
}

template <class T>
RRef ConstructPointerSlotRef(void* const slotObject)
{
    return MakePointerSlotRef<T>(static_cast<T**>(slotObject));
}

template <class T>
RRef MovePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakePointerSlotRef<T>(slot);
}

template <class T>
void DeletePointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

/**
 * Address: 0x0040D3B0 (FUN_0040D3B0, sub_40D3B0)
 *
 * What it does:
 * Wraps a `CTaskThread*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCTaskThreadPointerSlotRef(moho::CTaskThread** const slot)
{
    return MakePointerSlotRef<moho::CTaskThread>(slot);
}

/**
 * Address: 0x0040D580 (FUN_0040D580, sub_40D580)
 *
 * What it does:
 * Attempts to upcast one reflected reference lane to `CTaskThread*` slot and
 * returns null on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlot(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, moho::CTaskThread::GetPointerType());
    return static_cast<moho::CTaskThread**>(upcast.mObj);
}

/**
 * Address: 0x0040D3E0 (FUN_0040D3E0, gpg::RRef::TryUpcast_CTaskThread_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CTaskThread*` slot and throws
 * `BadRefCast` on mismatch.
 */
moho::CTaskThread** TryUpcastCTaskThreadPointerSlotOrThrow(const RRef& source)
{
    moho::CTaskThread** const slot = TryUpcastCTaskThreadPointerSlot(source);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x0040CDB0 (FUN_0040CDB0, sub_40CDB0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and returns it as typed `RRef`.
 */
RRef NewCTaskThreadPointerSlotRef()
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CDE0 (FUN_0040CDE0, sub_40CDE0)
 *
 * What it does:
 * Allocates one `CTaskThread*` slot and copies pointer lane value from source.
 */
RRef CopyCTaskThreadPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(::operator new(sizeof(moho::CTaskThread*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CE70 (FUN_0040CE70, sub_40CE70)
 *
 * What it does:
 * Wraps existing `CTaskThread*` slot storage as typed `RRef`.
 */
RRef ConstructCTaskThreadPointerSlotRef(void* const slotObject)
{
    return MakeCTaskThreadPointerSlotRef(static_cast<moho::CTaskThread**>(slotObject));
}

/**
 * Address: 0x0040CEA0 (FUN_0040CEA0, sub_40CEA0)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CTaskThread*` slot.
 */
RRef MoveCTaskThreadPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CTaskThread**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CTaskThread** const sourceSlot = TryUpcastCTaskThreadPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCTaskThreadPointerSlotRef(slot);
}

/**
 * Address: 0x0040CD90 (FUN_0040CD90, sub_40CD90)
 *
 * What it does:
 * Binds new/construct callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCTaskThreadPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x0040CDA0 (FUN_0040CDA0, sub_40CDA0)
 *
 * What it does:
 * Binds copy/move callback lanes for `CTaskThread*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCTaskThreadPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCTaskThreadPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCTaskThreadPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421910 (FUN_00421910, gpg::RRef_CLuaConOutputHandler_P)
 *
 * What it does:
 * Wraps one `CLuaConOutputHandler*` slot pointer as reflected pointer-slot `RRef`.
 */
RRef MakeCLuaConOutputHandlerPointerSlotRef(moho::CLuaConOutputHandler** const slot)
{
    return MakePointerSlotRef<moho::CLuaConOutputHandler>(slot);
}

/**
 * Address: 0x00421BD0 (FUN_00421BD0, gpg::RRef::TryUpcast_CLuaConOutputHandler_P)
 *
 * What it does:
 * Upcasts one reflected reference lane to `CLuaConOutputHandler*` slot and
 * throws `BadRefCast` on mismatch.
 */
moho::CLuaConOutputHandler** TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, CachedPointerType<moho::CLuaConOutputHandler>());
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(upcast.mObj);
    if (!slot) {
        throw gpg::BadRefCast("type error");
    }
    return slot;
}

/**
 * Address: 0x00421680 (FUN_00421680, sub_421680)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and returns it as typed `RRef`.
 */
RRef NewCLuaConOutputHandlerPointerSlotRef()
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x004216B0 (FUN_004216B0, sub_4216B0)
 *
 * What it does:
 * Allocates one `CLuaConOutputHandler*` slot and copies pointer lane value from source.
 */
RRef CopyCLuaConOutputHandlerPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(::operator new(sizeof(moho::CLuaConOutputHandler*)));
    *slot = nullptr;
    if (sourceRef) {
        moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421740 (FUN_00421740, sub_421740)
 *
 * What it does:
 * Wraps existing `CLuaConOutputHandler*` slot storage as typed `RRef`.
 */
RRef ConstructCLuaConOutputHandlerPointerSlotRef(void* const slotObject)
{
    return MakeCLuaConOutputHandlerPointerSlotRef(static_cast<moho::CLuaConOutputHandler**>(slotObject));
}

/**
 * Address: 0x00421770 (FUN_00421770, sub_421770)
 *
 * What it does:
 * Moves/copies pointer lane value into destination `CLuaConOutputHandler*` slot.
 */
RRef MoveCLuaConOutputHandlerPointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<moho::CLuaConOutputHandler**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            moho::CLuaConOutputHandler** const sourceSlot = TryUpcastCLuaConOutputHandlerPointerSlotOrThrow(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakeCLuaConOutputHandlerPointerSlotRef(slot);
}

/**
 * Address: 0x00421660 (FUN_00421660, sub_421660)
 *
 * What it does:
 * Binds new/construct callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerNewAndConstruct(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->newRefFunc_ = &NewCLuaConOutputHandlerPointerSlotRef;
    typeInfo->ctorRefFunc_ = &ConstructCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421670 (FUN_00421670, sub_421670)
 *
 * What it does:
 * Binds copy/move callback lanes for `CLuaConOutputHandler*` pointer reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerCopyAndMove(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->cpyRefFunc_ = &CopyCLuaConOutputHandlerPointerSlotRef;
    typeInfo->movRefFunc_ = &MoveCLuaConOutputHandlerPointerSlotRef;
    return typeInfo;
}

/**
 * Address: 0x00421620 (FUN_00421620, sub_421620)
 *
 * What it does:
 * Applies full pointer-slot callback wiring and lane metadata for
 * `CLuaConOutputHandler*` reflection.
 */
gpg::RPointerTypeBase* BindCLuaConOutputHandlerPointerAll(gpg::RPointerTypeBase* const typeInfo)
{
    typeInfo->v24 = true;
    typeInfo->size_ = sizeof(moho::CLuaConOutputHandler*);
    BindCLuaConOutputHandlerPointerNewAndConstruct(typeInfo);
    BindCLuaConOutputHandlerPointerCopyAndMove(typeInfo);
    typeInfo->deleteFunc_ = &DeletePointerSlot<moho::CLuaConOutputHandler>;
    return typeInfo;
}

  void SerializeRect2i(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteInt(rect->x0);
    archive->WriteInt(rect->z0);
    archive->WriteInt(rect->x1);
    archive->WriteInt(rect->z1);
  }

  void DeserializeRect2i(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadInt(&rect->x0);
    archive->ReadInt(&rect->z0);
    archive->ReadInt(&rect->x1);
    archive->ReadInt(&rect->z1);
  }

  void SerializeRect2f(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteFloat(rect->x0);
    archive->WriteFloat(rect->z0);
    archive->WriteFloat(rect->x1);
    archive->WriteFloat(rect->z1);
  }

  void DeserializeRect2f(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadFloat(&rect->x0);
    archive->ReadFloat(&rect->z0);
    archive->ReadFloat(&rect->x1);
    archive->ReadFloat(&rect->z1);
  }

  void AddRect2IntField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedIntType(), offset));
  }

  void AddRect2FloatField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedFloatType(), offset));
  }

  template <class TTypeInfo>
  struct TypeInfoStorage
  {
    alignas(TTypeInfo) unsigned char bytes[sizeof(TTypeInfo)];
    bool constructed;
  };

  template <class TTypeInfo>
  [[nodiscard]] TTypeInfo& EnsureTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      new (storage.bytes) TTypeInfo();
      storage.constructed = true;
    }

    return *reinterpret_cast<TTypeInfo*>(storage.bytes);
  }

  template <class TTypeInfo>
  void DestroyTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    reinterpret_cast<TTypeInfo*>(storage.bytes)->~TTypeInfo();
    storage.constructed = false;
  }

  TypeInfoStorage<gpg::Rect2iTypeInfo> gRect2iTypeInfoStorage{};
  TypeInfoStorage<gpg::Rect2fTypeInfo> gRect2fTypeInfoStorage{};
  gpg::Rect2iSerializer gRect2iSerializer;
  gpg::Rect2fSerializer gRect2fSerializer;
  gpg::RPointerType<moho::CTaskThread> gCTaskThreadPointerType;
  gpg::RPointerType<moho::CAcquireTargetTask> gCAcquireTargetTaskPointerType;
  gpg::RPointerType<moho::Entity> gEntityPointerType;
  gpg::RPointerType<moho::CEconomyEvent> gCEconomyEventPointerType;
  gpg::RPointerType<moho::CLuaConOutputHandler> gCLuaConOutputHandlerPointerType;
  gpg::RPointerType<moho::CScriptObject> gCScriptObjectPointerType;
  gpg::RPointerType<moho::CSndParams> gCSndParamsPointerType;

  [[nodiscard]] gpg::Rect2iTypeInfo& GetRect2iTypeInfo() noexcept
  {
    return EnsureTypeInfo(gRect2iTypeInfoStorage);
  }

  [[nodiscard]] gpg::Rect2fTypeInfo& GetRect2fTypeInfo() noexcept
  {
    return EnsureTypeInfo(gRect2fTypeInfoStorage);
  }

  /**
   * Address: 0x00C09760 (FUN_00C09760, gpg::Rect2iTypeInfo::~Rect2iTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `Rect2<int>` descriptor.
   */
  void cleanup_Rect2iTypeInfo()
  {
    DestroyTypeInfo(gRect2iTypeInfoStorage);
  }

  /**
   * Address: 0x00C097C0 (FUN_00C097C0, gpg::Rect2fTypeInfo::~Rect2fTypeInfo)
   *
   * What it does:
   * Runs startup-registered teardown for the global `Rect2<float>` descriptor.
   */
  void cleanup_Rect2fTypeInfo()
  {
    DestroyTypeInfo(gRect2fTypeInfoStorage);
  }

  /**
   * Address: 0x00BE9DB0 (FUN_00BE9DB0, register_Rect2iTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `Rect2<int>` reflection type descriptor and
   * wires its teardown callback into CRT `atexit`.
   */
  void register_Rect2iTypeInfo()
  {
    gpg::Rect2iTypeInfo& typeInfo = GetRect2iTypeInfo();
    gpg::PreRegisterRType(typeid(gpg::Rect2i), &typeInfo);
    (void)std::atexit(&cleanup_Rect2iTypeInfo);
  }

  /**
   * Address: 0x00BE9E50 (FUN_00BE9E50, register_Rect2fTypeInfo)
   *
   * What it does:
   * Constructs and preregisters the `Rect2<float>` reflection type descriptor
   * and wires its teardown callback into CRT `atexit`.
   */
  void register_Rect2fTypeInfo()
  {
    gpg::Rect2fTypeInfo& typeInfo = GetRect2fTypeInfo();
    gpg::PreRegisterRType(typeid(gpg::Rect2f), &typeInfo);
    (void)std::atexit(&cleanup_Rect2fTypeInfo);
  }

  struct Rect2ReflectionRegistration
  {
    Rect2ReflectionRegistration()
    {
      register_Rect2iTypeInfo();
      register_Rect2fTypeInfo();

      gRect2iSerializer.mHelperNext = nullptr;
      gRect2iSerializer.mHelperPrev = nullptr;
      gRect2iSerializer.mLoadCallback = &DeserializeRect2i;
      gRect2iSerializer.mSaveCallback = &SerializeRect2i;

      gRect2fSerializer.mHelperNext = nullptr;
      gRect2fSerializer.mHelperPrev = nullptr;
      gRect2fSerializer.mLoadCallback = &DeserializeRect2f;
      gRect2fSerializer.mSaveCallback = &SerializeRect2f;

      gRect2iSerializer.RegisterSerializeFunctions();
      gRect2fSerializer.RegisterSerializeFunctions();
    }
  };

Rect2ReflectionRegistration gRect2ReflectionRegistration;

struct PointerTypeRegistration
{
    PointerTypeRegistration()
    {
        gpg::PreRegisterRType(typeid(moho::CAcquireTargetTask*), &gCAcquireTargetTaskPointerType);
        gpg::PreRegisterRType(typeid(moho::Entity*), &gEntityPointerType);
        gpg::PreRegisterRType(typeid(moho::CEconomyEvent*), &gCEconomyEventPointerType);
        gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), &gCLuaConOutputHandlerPointerType);
        gpg::PreRegisterRType(typeid(moho::CScriptObject*), &gCScriptObjectPointerType);
        gpg::PreRegisterRType(typeid(moho::CSndParams*), &gCSndParamsPointerType);
    }
};

PointerTypeRegistration gPointerTypeRegistration;
} // namespace

RType* RType::sType = nullptr;

RField::RField()
  : mName(nullptr)
  , mType(nullptr)
  , mOffset(0)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset, const int v, const char* desc)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(v)
  , mDesc(desc)
{}

RType* gpg::LookupRType(const std::type_info& typeInfo)
{
  TypeInfoMap& preregistered = GetRTypePreregisteredMap();
  const TypeInfoMap::iterator it = preregistered.find(&typeInfo);
  if (it == preregistered.end()) {
    const msvc8::string msg =
      STR_Printf("Attempting to lookup the RType for %s before it is registered.", typeInfo.name());
    throw std::runtime_error(msg.c_str());
  }

  RType* type = it->second;
  if (!type->finished_) {
    type->finished_ = true;
    type->Init();
    type->RegisterType();
    type->initFinished_ = true;
  }

  return type;
}

/**
 * Address: 0x008DF850 (FUN_008DF850, gpg::PreRegisterRType)
 *
 * What it does:
 * Adds `{type_info*, RType*}` to the preregistration map used by lazy
 * reflection type finalization.
 */
void gpg::PreRegisterRType(const std::type_info& typeInfo, RType* type)
{
  GetRTypePreregisteredMap().insert(TypeInfoMap::value_type(&typeInfo, type));
}

void gpg::REF_RegisterAllTypes()
{
  std::stringstream errs;

  for (TypeInfoMap::const_iterator it = GetRTypePreregisteredMap().begin(); it != GetRTypePreregisteredMap().end();
       ++it) {
    try {
      (void)LookupRType(*it->first);
    } catch (const std::exception& ex) {
      errs << ex.what() << std::endl;
    }
  }

  const std::string aggregated = errs.str();
  if (!aggregated.empty()) {
    throw std::runtime_error(aggregated);
  }
}

const RType* gpg::REF_GetTypeIndexed(const int index)
{
  return GetRTypeVec()[index];
}

RType* gpg::REF_FindTypeNamed(const char* const name)
{
  if (!name) {
    return nullptr;
  }

  const TypeMap::const_iterator it = GetRTypeMap().find(name);
  if (it == GetRTypeMap().end()) {
    return nullptr;
  }

  return it->second;
}

/**
 * Address: 0x008D9590 (FUN_008D9590, gpg::REF_UpcastPtr)
 *
 * What it does:
 * Recursively traverses reflected base lanes to find one compatible base pointer
 * view and returns `{nullptr, targetType}` for null-object upcast lanes.
 */
RRef gpg::REF_UpcastPtr(const RRef& source, const RType* const targetType)
{
  if (source.mType == targetType) {
    return source;
  }

  if (!source.mObj) {
    return RRef{nullptr, const_cast<RType*>(targetType)};
  }

  if (!source.mType) {
    return {};
  }

  const RField* base = source.mType->bases_.begin();
  if (!base) {
    return {};
  }

  const RField* const baseEnd = source.mType->bases_.end();
  for (; base != baseEnd; ++base) {
    RRef baseRef{};
    baseRef.mObj =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(source.mObj) + static_cast<std::uintptr_t>(base->mOffset));
    baseRef.mType = base->mType;

    const RRef upcast = REF_UpcastPtr(baseRef, targetType);
    if (upcast.mObj) {
      return upcast;
    }
  }

  return {};
}

RRef gpg::RRef_ArchiveToken(ArchiveToken* const token)
{
  RRef out{};
  out.mObj = token;

  try {
    out.mType = LookupRType(typeid(ArchiveToken));
  } catch (...) {
    out.mType = nullptr;
  }

  return out;
}

/**
 * Address: 0x00402400 (FUN_00402400, gpg::SerHelperBase::SerHelperBase)
 *
 * What it does:
 * Unlinks this helper node from current intrusive links, then self-links it.
 */
gpg::SerHelperBase::SerHelperBase()
{
  ResetLinks();
}

/**
 * Address: 0x004027D0 (FUN_004027D0, duplicate helper body)
 *
 * What it does:
 * Unlinks this helper node from current intrusive links, then self-links it.
 */
void gpg::SerHelperBase::ResetLinks()
{
  mNext->mPrev = mPrev;
  mPrev->mNext = mNext;
  mPrev = this;
  mNext = this;
}

/**
 * Address: 0x00403020 (FUN_00403020, gpg::RRef_uint)
 *
 * What it does:
 * Builds a reflection reference for `unsigned int` using cached RTTI lookups.
 */
gpg::RRef* gpg::RRef_uint(RRef* const out, unsigned int* const value)
{
  return BuildTypedRefWithCache<unsigned int>(out, value, typeid(unsigned int), gUIntRRefType, gUIntRRefCache);
}

/**
 * Address: 0x00402D30 (FUN_00402D30, sub_402D30)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_uint` and copies lanes out.
 */
gpg::RRef* gpg::AssignUIntRef(RRef* const out, unsigned int* const value)
{
  RRef tmp{};
  RRef_uint(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00593BC0 (FUN_00593BC0, gpg::RRef_ESquadClass)
 *
 * What it does:
 * Builds a reflection reference for `moho::ESquadClass` using cached RTTI
 * lookup.
 */
gpg::RRef* gpg::RRef_ESquadClass(RRef* const out, moho::ESquadClass* const value)
{
  return BuildTypedRefWithCache<moho::ESquadClass>(
    out,
    value,
    typeid(moho::ESquadClass),
    gESquadClassRRefType,
    gESquadClassRRefCache
  );
}

/**
 * Address: 0x00704040 (FUN_00704040, sub_704040)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_ESquadClass` and copies
 * lanes out.
 */
gpg::RRef* gpg::AssignESquadClassRef(RRef* const out, moho::ESquadClass* const value)
{
  RRef tmp{};
  RRef_ESquadClass(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00795E00 (FUN_00795E00, gpg::RRef_EMauiEventType)
 *
 * What it does:
 * Builds a reflection reference for `moho::EMauiEventType` using cached RTTI
 * lookup.
 */
gpg::RRef* gpg::RRef_EMauiEventType(RRef* const out, moho::EMauiEventType* const value)
{
  return BuildTypedRefWithCache<moho::EMauiEventType>(
    out,
    value,
    typeid(moho::EMauiEventType),
    gEMauiEventTypeRRefType,
    gEMauiEventTypeRRefCache
  );
}

/**
 * Address: 0x0040C030 (FUN_0040C030, gpg::RRef_CTaskThread_P)
 *
 * What it does:
 * Builds a reflection reference for `moho::CTaskThread` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_CTaskThread(RRef* const out, moho::CTaskThread* const value)
{
  return BuildTypedRefWithCache<moho::CTaskThread>(
    out,
    value,
    typeid(moho::CTaskThread),
    gCTaskThreadRRefType,
    gCTaskThreadRRefCache
  );
}

/**
 * Address: 0x005A2A40 (FUN_005A2A40, gpg::RRef_Unit)
 *
 * What it does:
 * Builds a reflection reference for `moho::Unit` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_Unit(RRef* const out, moho::Unit* const value)
{
  return BuildTypedRefWithCache<moho::Unit>(out, value, typeid(moho::Unit), gUnitRRefType, gUnitRRefCache);
}

/**
 * Address: 0x00526C80 (FUN_00526C80, gpg::RRef_RUnitBlueprint)
 *
 * What it does:
 * Builds a reflection reference for `moho::RUnitBlueprint` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_RUnitBlueprint(RRef* const out, moho::RUnitBlueprint* const value)
{
  return BuildTypedRefWithCache<moho::RUnitBlueprint>(
    out,
    value,
    typeid(moho::RUnitBlueprint),
    gRUnitBlueprintRRefType,
    gRUnitBlueprintRRefCache
  );
}

/**
 * Address: 0x00511940 (FUN_00511940, gpg::RRef_RRuleGameRules)
 *
 * What it does:
 * Builds a reflection reference for `moho::RRuleGameRules` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_RRuleGameRules(RRef* const out, moho::RRuleGameRules* const value)
{
  return BuildTypedRefWithCache<moho::RRuleGameRules>(
    out,
    value,
    typeid(moho::RRuleGameRules),
    gRRuleGameRulesRRefType,
    gRRuleGameRulesRRefCache
  );
}

/**
 * Address: 0x005F5280 (FUN_005F5280, gpg::RRef_CUnitCommand)
 *
 * What it does:
 * Builds a reflection reference for `moho::CUnitCommand` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_CUnitCommand(RRef* const out, moho::CUnitCommand* const value)
{
  return BuildTypedRefWithCache<moho::CUnitCommand>(
    out,
    value,
    typeid(moho::CUnitCommand),
    gCUnitCommandRRefType,
    gCUnitCommandRRefCache
  );
}

/**
 * Address: 0x004041F0 (FUN_004041F0, gpg::RRef_IdPool)
 *
 * What it does:
 * Builds a reflection reference for `moho::IdPool` using cached RTTI lookups.
 */
gpg::RRef* gpg::RRef_IdPool(RRef* const out, moho::IdPool* const value)
{
  return BuildTypedRefWithCache<moho::IdPool>(out, value, typeid(moho::IdPool), gIdPoolRRefType, gIdPoolRRefCache);
}

/**
 * Address: 0x00404180 (FUN_00404180, sub_404180)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_IdPool` and copies lanes out.
 */
gpg::RRef* gpg::AssignIdPoolRef(RRef* const out, moho::IdPool* const value)
{
  RRef tmp{};
  RRef_IdPool(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x0040F600 (FUN_0040F600, gpg::RRef_CRandomStream)
 *
 * What it does:
 * Builds a reflection reference for `moho::CRandomStream` using cached RTTI lookups.
 */
gpg::RRef* gpg::RRef_CRandomStream(RRef* const out, moho::CRandomStream* const value)
{
  return BuildTypedRefWithCache<moho::CRandomStream>(
    out,
    value,
    typeid(moho::CRandomStream),
    gCRandomStreamRRefType,
    gCRandomStreamRRefCache
  );
}

/**
 * Address: 0x0040F590 (FUN_0040F590, sub_40F590)
 *
 * What it does:
 * Thin wrapper that materializes a temporary `RRef_CRandomStream` and copies lanes out.
 */
gpg::RRef* gpg::AssignCRandomStreamRef(RRef* const out, moho::CRandomStream* const value)
{
  RRef tmp{};
  RRef_CRandomStream(&tmp, value);
  out->mObj = tmp.mObj;
  out->mType = tmp.mType;
  return out;
}

/**
 * Address: 0x00705120 (FUN_00705120, gpg::RRef_CPlatoon)
 *
 * What it does:
 * Builds a reflection reference for `moho::CPlatoon` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_CPlatoon(RRef* const out, moho::CPlatoon* const value)
{
  return BuildTypedRefWithCache<moho::CPlatoon>(
    out,
    value,
    typeid(moho::CPlatoon),
    gCPlatoonRRefType,
    gCPlatoonRRefCache
  );
}

/**
 * Address: 0x004220D0 (FUN_004220D0, gpg::RRef_CLuaConOutputHandler)
 *
 * What it does:
 * Builds a reflection reference for `moho::CLuaConOutputHandler` using cached
 * RTTI lookup and derived-type normalization.
 */
gpg::RRef* gpg::RRef_CLuaConOutputHandler(RRef* const out, moho::CLuaConOutputHandler* const value)
{
  return BuildTypedRefWithCache<moho::CLuaConOutputHandler>(
    out,
    value,
    typeid(moho::CLuaConOutputHandler),
    gCLuaConOutputHandlerRRefType,
    gCLuaConOutputHandlerRRefCache
  );
}

/**
 * Address: 0x004C16D0 (FUN_004C16D0, gpg::RRef_LuaState)
 *
 * What it does:
 * Builds a reflection reference for `LuaPlus::LuaState` using cached RTTI
 * lookups and derived-type normalization.
 */
gpg::RRef* gpg::RRef_LuaState(RRef* const out, LuaPlus::LuaState* const value)
{
  return BuildTypedRefWithCache<LuaPlus::LuaState>(
    out,
    value,
    typeid(LuaPlus::LuaState),
    gLuaStateRRefType,
    gLuaStateRRefCache
  );
}

/**
 * Address: 0x00401280 (FUN_00401280)
 *
 * What it does:
 * Initializes an empty reflection reference `{nullptr, nullptr}`.
 */
RRef::RRef() noexcept
  : mObj(nullptr)
  , mType(nullptr)
{}

/**
 * Address: 0x00401290 (FUN_00401290)
 *
 * What it does:
 * Initializes a reflection reference from explicit object/type lanes.
 */
RRef::RRef(void* const ptr, RType* const type) noexcept
  : mObj(ptr)
  , mType(type)
{}

/**
 * Address: 0x004012B0 (FUN_004012B0)
 *
 * What it does:
 * Returns the raw referenced object pointer lane.
 */
void* RRef::GetObject() const noexcept
{
  return mObj;
}

/**
 * Address: 0x004C1690 (FUN_004C1690, gpg::RRef::CastLuaState)
 *
 * What it does:
 * Upcasts this reflected reference to one `LuaPlus::LuaState` pointer lane.
 */
LuaPlus::LuaState* RRef::CastLuaState()
{
  if (!gLuaStateRRefType) {
    gLuaStateRRefType = gpg::LookupRType(typeid(LuaPlus::LuaState));
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(*this, gLuaStateRRefType);
  return static_cast<LuaPlus::LuaState*>(upcast.mObj);
}

/**
 * Address: 0x004A35D0 (FUN_004A35D0)
 *
 * What it does:
 * Reads this reference as lexical text using the bound reflection type.
 */
msvc8::string RRef::GetLexical() const
{
  return mType->GetLexical(*this);
}

/**
 * Address: 0x004A3600 (FUN_004A3600)
 *
 * What it does:
 * Writes one lexical text value through the bound reflection type.
 */
bool RRef::SetLexical(const char* name) const
{
  return mType->SetLexical(*this, name);
}

/**
 * Address: 0x00406690 (FUN_00406690)
 *
 * What it does:
 * Returns reflected type name for this reference, or `"null"` when untyped.
 */
const char* RRef::GetName() const
{
  if (!mType) {
    return "null";
  }

  return mType->GetName();
}

/**
 * Address: 0x004A3610 (FUN_004A3610)
 *
 * What it does:
 * Returns the indexed child reference at `ind`.
 */
RRef RRef::operator[](const unsigned int ind) const
{
  const RIndexed* indexed = mType->IsIndexed();
  return indexed->SubscriptIndex(mObj, static_cast<int>(ind));
}

/**
 * Address: 0x004A3630 (FUN_004A3630)
 *
 * What it does:
 * Returns indexed element count for this reference, or zero when unindexed.
 */
size_t RRef::GetCount() const
{
  const RIndexed* indexed = mType->IsIndexed();
  if (!indexed) {
    return 0;
  }

  return indexed->GetCount(mObj);
}

/**
 * Address: 0x004A3650 (FUN_004A3650)
 *
 * What it does:
 * Returns the bound runtime reflection type descriptor.
 */
const RType* RRef::GetRType() const
{
  return mType;
}

/**
 * Address: 0x004A3660 (FUN_004A3660)
 *
 * What it does:
 * Returns indexed-view support for the bound type.
 */
const RIndexed* RRef::IsIndexed() const
{
  return mType->IsIndexed();
}

const RIndexed* RRef::IsPointer() const
{
  return mType->IsPointer();
}

int RRef::GetNumBases() const
{
  const RField* first = mType->bases_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->bases_.end() - first);
}

RRef RRef::GetBase(const int ind) const
{
  const RField* first = mType->bases_.begin();
  const RField& base = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + base.mOffset;
  out.mType = base.mType;
  return out;
}

int RRef::GetNumFields() const
{
  const RField* first = mType->fields_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->fields_.end() - first);
}

RRef RRef::GetField(const int ind) const
{
  const RField* first = mType->fields_.begin();
  const RField& field = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + field.mOffset;
  out.mType = field.mType;
  return out;
}

const char* RRef::GetFieldName(const int ind) const
{
  return mType->fields_.begin()[ind].mName;
}

void RRef::Delete()
{
  if (!mObj) {
    return;
  }

  GPG_ASSERT(mType->deleteFunc_);
  mType->deleteFunc_(mObj);
}

/**
 * Address: 0x004012C0 (FUN_004012C0)
 * Demangled: gpg::RObject::RObject
 *
 * What it does:
 * Initializes the base vftable lane for reflected objects.
 */
RObject::RObject() noexcept = default;

/**
 * Address: 0x004012D0 (FUN_004012D0)
 * Demangled: gpg::RObject::dtr
 *
 * What it does:
 * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
 */
RObject::~RObject() noexcept = default;

/**
 * Address: 0x004012F0 (FUN_004012F0)
 * Demangled: gpg::RIndexed::SetCount
 *
 * What it does:
 * Base implementation rejects resize/count mutation for non-resizable indexed types.
 */
void RIndexed::SetCount(void*, int) const
{
  throw std::bad_cast{};
}

/**
 * Address: 0x00401320 (FUN_00401320)
 * Demangled: gpg::RIndexed::AssignPointer
 *
 * What it does:
 * Base implementation rejects pointer assignment for non-pointer indexed types.
 */
void RIndexed::AssignPointer(void*, const RRef&) const
{
    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB00 (FUN_0040CB00, gpg::RPointerType_CTaskThread::SubscriptIndex)
 * Address: 0x004214F0 (FUN_004214F0, gpg::RPointerType_CLuaConOutputHandler::SubscriptIndex)
 */
RRef gpg::RPointerTypeBase::SubscriptIndex(void* const obj, const int ind) const
{
    auto* const slot = static_cast<void**>(obj);
    RType* const pointeeType = GetPointeeType();

    RRef out{};
    out.mType = pointeeType;
    if (!slot || !pointeeType || !*slot) {
        out.mObj = nullptr;
        return out;
    }

    const std::ptrdiff_t byteOffset =
      static_cast<std::ptrdiff_t>(pointeeType->size_) * static_cast<std::ptrdiff_t>(ind);
    auto* const base = static_cast<std::uint8_t*>(*slot);
    out.mObj = static_cast<void*>(base + byteOffset);

    if (pointeeType->ctorRefFunc_) {
        return pointeeType->ctorRefFunc_(out.mObj);
    }

    return out;
}

/**
 * Address: 0x0040CAF0 (FUN_0040CAF0, gpg::RPointerType_CTaskThread::GetCount)
 * Address: 0x004214E0 (FUN_004214E0, gpg::RPointerType_CLuaConOutputHandler::GetCount)
 */
size_t gpg::RPointerTypeBase::GetCount(void* const obj) const
{
    auto* const slot = static_cast<void**>(obj);
    return (slot && *slot) ? 1u : 0u;
}

void gpg::RPointerTypeBase::SetCount(void* const obj, const int count) const
{
    auto* const slot = static_cast<void**>(obj);
    if (!slot) {
        throw std::bad_cast{};
    }

    if (count == 0) {
        *slot = nullptr;
        return;
    }
    if (count == 1) {
        return;
    }

    throw std::bad_cast{};
}

/**
 * Address: 0x0040CB40 (FUN_0040CB40, gpg::RPointerType_CTaskThread::AssignPointer)
 * Address: 0x00421530 (FUN_00421530, gpg::RPointerType_CLuaConOutputHandler::AssignPointer)
 */
void gpg::RPointerTypeBase::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<void**>(obj);
    GPG_ASSERT(slot != nullptr);
    if (!slot) {
        return;
    }

    if (!from.mObj) {
        *slot = nullptr;
        return;
    }

    const RRef upcast = REF_UpcastPtr(from, GetPointeeType());
    if (!upcast.mObj) {
        throw BadRefCast("type error");
    }

    *slot = upcast.mObj;
}

const RIndexed* gpg::RPointerTypeBase::AsIndexedSelf() const noexcept
{
    return this;
}

/**
 * Address: 0x0040C8B0 (FUN_0040C8B0)
 * Demangled: sub_40C8B0
 */
gpg::RPointerType<moho::CTaskThread>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CTaskThread*), this);
}

/**
 * Address: 0x0040CBD0 (FUN_0040CBD0)
 * Demangled: sub_40CBD0
 */
gpg::RPointerType<moho::CTaskThread>::~RPointerType() = default;

/**
 * Address: 0x0040C7C0 (FUN_0040C7C0)
 * Demangled: gpg::RPointerType_CTaskThread::GetName
 */
const char* gpg::RPointerType<moho::CTaskThread>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0040C950 (FUN_0040C950)
 * Demangled: gpg::RPointerType_CTaskThread::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CTaskThread>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CTaskThread>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0040CAD0 (FUN_0040CAD0)
 * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040CAE0 (FUN_0040CAE0)
 * Demangled: gpg::RPointerType_CTaskThread::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040C920 (FUN_0040C920)
 * Demangled: gpg::RPointerType_CTaskThread::Init
 */
void gpg::RPointerType<moho::CTaskThread>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CTaskThread*);
    BindCTaskThreadPointerNewAndConstruct(this);
    BindCTaskThreadPointerCopyAndMove(this);
    deleteFunc_ = &DeletePointerSlot<moho::CTaskThread>;
}

RType* gpg::RPointerType<moho::CTaskThread>::GetPointeeType() const
{
    return CachedCTaskThreadType();
}

/**
 * Address: 0x005DE390 (FUN_005DE390)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::dtr
 */
gpg::RPointerType<moho::CAcquireTargetTask>::~RPointerType() = default;

/**
 * Address: 0x005DDF20 (FUN_005DDF20)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetName
 */
const char* gpg::RPointerType<moho::CAcquireTargetTask>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x005DE0B0 (FUN_005DE0B0)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CAcquireTargetTask>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CAcquireTargetTask>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x005DE230 (FUN_005DE230)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE240 (FUN_005DE240)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CAcquireTargetTask>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x005DE080 (FUN_005DE080)
 * Demangled: gpg::RPointerType_CAcquireTargetTask::Init
 */
void gpg::RPointerType<moho::CAcquireTargetTask>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CAcquireTargetTask*);
    newRefFunc_ = &NewPointerSlotRef<moho::CAcquireTargetTask>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CAcquireTargetTask>;
    deleteFunc_ = &DeletePointerSlot<moho::CAcquireTargetTask>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CAcquireTargetTask>;
    movRefFunc_ = &MovePointerSlotRef<moho::CAcquireTargetTask>;
}

RType* gpg::RPointerType<moho::CAcquireTargetTask>::GetPointeeType() const
{
    return CachedCAcquireTargetTaskType();
}

/**
 * Address: 0x0067E750 (FUN_0067E750)
 * Demangled: gpg::RPointerType_Entity::dtr
 */
gpg::RPointerType<moho::Entity>::~RPointerType() = default;

/**
 * Address: 0x0067E320 (FUN_0067E320)
 * Demangled: gpg::RPointerType_Entity::GetName
 */
const char* gpg::RPointerType<moho::Entity>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0067E4B0 (FUN_0067E4B0)
 * Demangled: gpg::RPointerType_Entity::GetLexical
 */
msvc8::string gpg::RPointerType<moho::Entity>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::Entity>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0067E630 (FUN_0067E630)
 * Demangled: gpg::RPointerType_Entity::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E640 (FUN_0067E640)
 * Demangled: gpg::RPointerType_Entity::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::Entity>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0067E480 (FUN_0067E480)
 * Demangled: gpg::RPointerType_Entity::Init
 */
void gpg::RPointerType<moho::Entity>::Init()
{
    v24 = true;
    size_ = sizeof(moho::Entity*);
    newRefFunc_ = &NewPointerSlotRef<moho::Entity>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::Entity>;
    deleteFunc_ = &DeletePointerSlot<moho::Entity>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::Entity>;
    movRefFunc_ = &MovePointerSlotRef<moho::Entity>;
}

RType* gpg::RPointerType<moho::Entity>::GetPointeeType() const
{
    return CachedEntityType();
}

/**
 * Address: 0x006B2920 (FUN_006B2920)
 * Demangled: gpg::RPointerType_CEconomyEvent::dtr
 */
gpg::RPointerType<moho::CEconomyEvent>::~RPointerType() = default;

/**
 * Address: 0x006B2510 (FUN_006B2510)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetName
 */
const char* gpg::RPointerType<moho::CEconomyEvent>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x006B26A0 (FUN_006B26A0)
 * Demangled: gpg::RPointerType_CEconomyEvent::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CEconomyEvent>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CEconomyEvent>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x006B2820 (FUN_006B2820)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2830 (FUN_006B2830)
 * Demangled: gpg::RPointerType_CEconomyEvent::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CEconomyEvent>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x006B2670 (FUN_006B2670)
 * Demangled: gpg::RPointerType_CEconomyEvent::Init
 */
void gpg::RPointerType<moho::CEconomyEvent>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CEconomyEvent*);
    newRefFunc_ = &NewPointerSlotRef<moho::CEconomyEvent>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CEconomyEvent>;
    deleteFunc_ = &DeletePointerSlot<moho::CEconomyEvent>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CEconomyEvent>;
    movRefFunc_ = &MovePointerSlotRef<moho::CEconomyEvent>;
}

RType* gpg::RPointerType<moho::CEconomyEvent>::GetPointeeType() const
{
    return CachedCEconomyEventType();
}

/**
 * Address: 0x004212A0 (FUN_004212A0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::RPointerType
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::RPointerType()
  : RPointerTypeBase()
{
    gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), this);
}

/**
 * Address: 0x004215C0 (FUN_004215C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::~RPointerType() = default;

/**
 * Address: 0x004211B0 (FUN_004211B0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
 */
const char* gpg::RPointerType<moho::CLuaConOutputHandler>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x00421340 (FUN_00421340)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CLuaConOutputHandler>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CLuaConOutputHandler>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004214C0 (FUN_004214C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004214D0 (FUN_004214D0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00421310 (FUN_00421310)
 * Address: 0x00421620 (FUN_00421620, sub_421620 helper lane)
 * Address: 0x00421660 (FUN_00421660, sub_421660 helper lane)
 * Address: 0x00421670 (FUN_00421670, sub_421670 helper lane)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
 */
void gpg::RPointerType<moho::CLuaConOutputHandler>::Init()
{
    BindCLuaConOutputHandlerPointerAll(this);
}

RType* gpg::RPointerType<moho::CLuaConOutputHandler>::GetPointeeType() const
{
    return CachedCLuaConOutputHandlerType();
}

/**
 * Address: 0x004C8A00 (FUN_004C8A00)
 * Demangled: gpg::RPointerType_CScriptObject::dtr
 */
gpg::RPointerType<moho::CScriptObject>::~RPointerType() = default;

/**
 * Address: 0x004C85F0 (FUN_004C85F0)
 * Demangled: gpg::RPointerType_CScriptObject::GetName
 */
const char* gpg::RPointerType<moho::CScriptObject>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x004C8780 (FUN_004C8780)
 * Demangled: gpg::RPointerType_CScriptObject::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CScriptObject>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CScriptObject>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004C8900 (FUN_004C8900)
 * Demangled: gpg::RPointerType_CScriptObject::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8910 (FUN_004C8910)
 * Demangled: gpg::RPointerType_CScriptObject::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CScriptObject>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004C8750 (FUN_004C8750)
 * Demangled: gpg::RPointerType_CScriptObject::Init
 */
void gpg::RPointerType<moho::CScriptObject>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CScriptObject*);
    newRefFunc_ = &NewPointerSlotRef<moho::CScriptObject>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CScriptObject>;
    deleteFunc_ = &DeletePointerSlot<moho::CScriptObject>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CScriptObject>;
    movRefFunc_ = &MovePointerSlotRef<moho::CScriptObject>;
}

RType* gpg::RPointerType<moho::CScriptObject>::GetPointeeType() const
{
    return CachedCScriptObjectType();
}

/**
 * Address: 0x004E5FD0 (FUN_004E5FD0)
 * Demangled: sub_4E5FD0
 */
gpg::RPointerType<moho::CSndParams>::~RPointerType() = default;

/**
 * Address: 0x004E5BC0 (FUN_004E5BC0)
 * Demangled: gpg::RPointerType_CSndParams::GetName
 */
const char* gpg::RPointerType<moho::CSndParams>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x004E5D50 (FUN_004E5D50)
 * Demangled: gpg::RPointerType_CSndParams::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CSndParams>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CSndParams>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004E5ED0 (FUN_004E5ED0)
 * Demangled: gpg::RPointerType_CSndParams::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5EE0 (FUN_004E5EE0)
 * Demangled: gpg::RPointerType_CSndParams::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CSndParams>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004E5D20 (FUN_004E5D20)
 * Demangled: gpg::RPointerType_CSndParams::Init
 */
void gpg::RPointerType<moho::CSndParams>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CSndParams*);
    newRefFunc_ = &NewPointerSlotRef<moho::CSndParams>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CSndParams>;
    deleteFunc_ = &DeletePointerSlot<moho::CSndParams>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CSndParams>;
    movRefFunc_ = &MovePointerSlotRef<moho::CSndParams>;
}

RType* gpg::RPointerType<moho::CSndParams>::GetPointeeType() const
{
    return CachedCSndParamsType();
}

/**
 * Address: 0x008DD950 (FUN_008DD950, ??0RType@gpg@@QAE@XZ_0)
 * Demangled: gpg::RType::RType
 *
 * What it does:
 * Initializes one reflection type descriptor to an empty, uninitialized state:
 * callback lanes cleared, vectors empty, and version/size reset to zero.
 */
RType::RType()
  : finished_(false)
  , initFinished_(false)
  , size_(0)
  , version_(0)
  , serSaveConstructArgsFunc_(nullptr)
  , serSaveFunc_(nullptr)
  , serConstructFunc_(nullptr)
  , serLoadFunc_(nullptr)
  , v8(0)
  , v9(0)
  , bases_()
  , fields_()
  , newRefFunc_(nullptr)
  , cpyRefFunc_(nullptr)
  , deleteFunc_(nullptr)
  , ctorRefFunc_(nullptr)
  , movRefFunc_(nullptr)
  , dtrFunc_(nullptr)
  , v24(false)
{}

/**
 * Address: 0x008DD9D0 (FUN_008DD9D0)
 * Demangled: gpg::RType::dtr
 *
 * What it does:
 * Destroys base reflection type descriptor state.
 */
RType::~RType() = default;

/**
 * Address: 0x00401350 (FUN_00401350)
 * Demangled: gpg::RType::StaticGetClass
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `RType`.
 */
RType* RType::StaticGetClass()
{
  if (!sType) {
    sType = CachedRTypeDescriptor();
  }
  return sType;
}

/**
 * Address: 0x00401370 (FUN_00401370)
 * Demangled: gpg::RType::GetClass
 *
 * What it does:
 * Lazily resolves and caches the family descriptor for `RType`.
 */
RType* RType::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x00401390 (FUN_00401390)
 * Demangled: gpg::RType::GetDerivedObjectRef
 *
 * What it does:
 * Packs `{this, GetClass()}` into an `RRef` handle.
 */
RRef RType::GetDerivedObjectRef()
{
  RRef out{};
  out.mObj = this;
  out.mType = GetClass();
  return out;
}

/**
 * Address: 0x008DB100 (FUN_008DB100)
 * Demangled: gpg::RType::GetLexical
 *
 * What it does:
 * Returns default lexical text in the form `"<name> at 0x<ptr>"`.
 */
msvc8::string RType::GetLexical(const RRef& ref) const
{
  const auto name = GetName();
  return STR_Printf("%s at 0x%p", name, ref.mObj);
}

/**
 * Address: 0x008D86E0 (FUN_008D86E0)
 * Demangled: gpg::RType::SetLexical
 *
 * What it does:
 * Base implementation rejects lexical assignment and returns false.
 */
bool RType::SetLexical(const RRef&, const char*) const
{
  return false;
}

/**
 * Address: 0x004013B0 (FUN_004013B0)
 * Demangled: gpg::RType::IsIndexed
 *
 * What it does:
 * Base implementation reports non-indexed type.
 */
const RIndexed* RType::IsIndexed() const
{
  return nullptr;
}

/**
 * Address: 0x004013C0 (FUN_004013C0)
 * Demangled: gpg::RType::IsPointer
 *
 * What it does:
 * Base implementation reports non-pointer type.
 */
const RIndexed* RType::IsPointer() const
{
  return nullptr;
}

/**
 * Address: 0x004013D0 (FUN_004013D0)
 * Demangled: gpg::RType::IsEnumType
 *
 * What it does:
 * Base implementation reports non-enum type.
 */
const REnumType* RType::IsEnumType() const
{
  return nullptr;
}

void RType::Init() {}

void RType::Finish()
{
  GPG_ASSERT(!initFinished_);

  RField* first = fields_.begin();
  if (!first) {
    return;
  }

  RField* last = fields_.end();
  if (first == last) {
    return;
  }

  std::sort(first, last, [](const RField& a, const RField& b) {
    return std::strcmp(a.mName, b.mName) < 0;
  });
}

void RType::Version(const int version)
{
  GPG_ASSERT(version_ == 0 || version_ == version);
  version_ = version;
}

/**
 * Address: 0x008DF500 (FUN_008DF500)
 *
 * gpg::RField const &
 *
 * IDA signature:
 * void __thiscall gpg::RType::AddBase(gpg::RType *this, gpg::RField const *field);
 *
 * What it does:
 * Appends one direct base descriptor and flattens all fields from the base
 * type into this type's field table with subobject-offset adjustment.
 */
void RType::AddBase(const RField& field)
{
  GPG_ASSERT(!initFinished_);

  // Register the base link itself.
  bases_.push_back(field);

  // Flatten base fields into this->fields_ with offset adjustment.
  const RType* baseType = field.mType;
  if (!baseType) {
    return;
  }

  // MSVC8 vector layout may expose raw pointers;
  // keep null-safe checks like in the original.
  const RField* it = baseType->fields_.begin();
  const RField* end = baseType->fields_.end();
  if (!it)
    return; // consistent with original early-exit when start==nullptr

  for (; it < end; ++it) {
    // Copy-by-value semantics;
    // strings/descriptions are pointer aliases in the original.
    RField out{
      // same literal pointer as in base
      it->mName,
      // same field type
      it->mType,
      // adjust offset by base field offset
      field.mOffset + it->mOffset
    };

    out.v4 = it->v4;
    out.mDesc = it->mDesc;

    fields_.push_back(out);
  }
}

void RType::RegisterType()
{
  // 1) Map name -> type
  // original: this->vtable->GetName(this)
  const char* name = GetName();
  // original: *sub_8DF330(map, &name) = this;
  GetRTypeMap()[name] = this;

  // 2) Append to global type list
  GetRTypeVec().push_back(this);
}

/**
 * Address: 0x0040DFA0 (FUN_0040DFA0, gpg::RType::AddField_float)
 */
RField* RType::AddFieldFloat(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedFloatType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

/**
 * Address: 0x0040E020 (FUN_0040E020, gpg::RType::AddField_uint)
 */
RField* RType::AddFieldUInt(const char* const name, const int offset)
{
  GPG_ASSERT(!initFinished_);
  RField field{name, CachedUIntType(), offset};
  fields_.push_back(field);
  return &fields_.back();
}

const RField* RType::GetFieldNamed(const char* name) const
{
  GPG_ASSERT(initFinished_);

  const RField* start = fields_.begin();
  if (!start) {
    return nullptr;
  }

  const RField* finish = fields_.end();
  if (start == finish) {
    return nullptr;
  }

  // Classic binary search over [lo, hi)
  std::size_t lo = 0;
  std::size_t hi = static_cast<std::size_t>(finish - start);

  while (lo < hi) {
    const std::size_t mid = (lo + hi) >> 1;
    const RField* elem = &start[mid];

    const int cmp = std::strcmp(name, elem->mName);
    if (cmp < 0) {
      hi = mid;
    } else if (cmp > 0) {
      lo = mid + 1;
    } else {
      // exact match
      return elem;
    }
  }
  return nullptr;
}

bool RType::IsDerivedFrom(const RType* baseType, int32_t* outOffset) const
{
  if (this == baseType) {
    if (outOffset) {
      *outOffset = 0;
    }

    return true;
  }

  const RField* first = bases_.begin();
  if (!first) {
    return false;
  }

  const RField* last = bases_.end();
  if (first == last) {
    return false;
  }

  bool found = false;

  for (const RField* it = first; it != last; ++it) {
    if (it->mType->IsDerivedFrom(baseType, outOffset)) {
      if (found) {
        throw std::runtime_error("Ambiguous base class");
      }

      if (!outOffset) {
        return true;
      }

      if (outOffset) {
        *outOffset += it->mOffset;
      }

      found = true;
    }
  }

  return found;
}

/**
 * Address: 0x00905E40 (FUN_00905E40)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<int>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<int> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2iSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2iType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00905EE0 (FUN_00905EE0)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<float>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<float> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2fSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2fType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00906020 (FUN_00906020)
 * Demangled: gpg::Rect2iTypeInfo::GetName
 */
const char* gpg::Rect2iTypeInfo::GetName() const
{
  return "Rect2i";
}

/**
 * Address: 0x009060D0 (FUN_009060D0)
 * Demangled: gpg::Rect2fTypeInfo::GetName
 */
const char* gpg::Rect2fTypeInfo::GetName() const
{
  return "Rect2f";
}

/**
 * Address: 0x00906270 (FUN_00906270)
 * Demangled: gpg::Rect2iTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers int fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2iTypeInfo::Init()
{
  size_ = sizeof(Rect2i);
  gpg::RType::Init();
  AddRect2IntField(this, "x0", offsetof(Rect2i, x0));
  AddRect2IntField(this, "y0", offsetof(Rect2i, z0));
  AddRect2IntField(this, "x1", offsetof(Rect2i, x1));
  AddRect2IntField(this, "y1", offsetof(Rect2i, z1));
  Finish();
}

/**
 * Address: 0x009062D0 (FUN_009062D0)
 * Demangled: gpg::Rect2fTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers float fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2fTypeInfo::Init()
{
  size_ = sizeof(Rect2f);
  gpg::RType::Init();
  AddRect2FloatField(this, "x0", offsetof(Rect2f, x0));
  AddRect2FloatField(this, "y0", offsetof(Rect2f, z0));
  AddRect2FloatField(this, "x1", offsetof(Rect2f, x1));
  AddRect2FloatField(this, "y1", offsetof(Rect2f, z1));
  Finish();
}

/**
 * Address: 0x004180A0 (FUN_004180A0, gpg::REnumType::REnumType)
 */
gpg::REnumType::REnumType()
  : gpg::RType()
  , mPrefix(nullptr)
  , mEnumNames()
{}

/**
 * Address: 0x00418120 (FUN_00418120, gpg::REnumType::~REnumType)
 */
gpg::REnumType::~REnumType() = default;

msvc8::string REnumType::GetLexical(const RRef& ref) const
{
  const int* enumValue = static_cast<const int*>(ref.mObj);
  const int value = enumValue ? *enumValue : 0;

  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (it->mValue == value) {
      return msvc8::string(it->mName ? it->mName : "");
    }
  }

  return STR_Printf("%d", value);
}

bool REnumType::SetLexical(const RRef& dest, const char* str) const
{
  if (!str || !dest.mObj) {
    return false;
  }

  int acc = 0;

  while (true) {
    // Find next separator and define token range
    const char* sep = std::strchr(str, '|');
    const char* tokenEnd = sep ? sep : (str + std::strlen(str));

    // Optional, case-sensitive prefix stripping
    const char* tokenBegin = str;
    if (mPrefix) {
      const std::size_t pn = std::strlen(mPrefix);
      if (std::strncmp(str, mPrefix, pn) == 0) {
        tokenBegin = str + pn;
      }
    }

    const std::size_t n = static_cast<std::size_t>(tokenEnd - tokenBegin);

    int num = 0;
    bool matched = false;

    // Try case-insensitive exact name match
    for (const ROptionValue& opt : mEnumNames) {
      const char* name = opt.mName ? opt.mName : "";

      const bool eq = STR_EqualsNoCaseN(tokenBegin, name, n) && name[n] == '\0';

      if (eq) {
        num = opt.mValue;
        matched = true;
        break;
      }
    }

    // Fallback: numeric parse from span [tokenBegin, tokenEnd)
    if (!matched) {
      if (!ParseNum(tokenBegin, tokenEnd, &num)) {
        return false;
      }
    }

    // Accumulate OR
    acc |= num;

    // Commit on last token
    if (!sep) {
      *static_cast<int*>(dest.mObj) = acc;
      return true;
    }

    // Next token
    str = sep + 1;
  }
}

const char* REnumType::StripPrefix(const char* name) const
{
  // Fast path: no prefix configured
  if (!mPrefix || !*mPrefix) {
    return name;
  }

  // Compute prefix length once (the original code effectively did strlen twice)
  const std::size_t n = std::strlen(mPrefix);
  if (std::strncmp(name, mPrefix, n) == 0) {
    return name + n;
  }

  return name;
}

bool REnumType::GetEnumValue(const char* name, int* outVal) const
{
  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (STR_EqualsNoCase(it->mName, name)) {
      *outVal = it->mValue;
      return true;
    }
  }
  return false;
}

void REnumType::AddEnum(char const* name, const int index)
{
  const ROptionValue opt{index, name};
  mEnumNames.push_back(opt);
}
