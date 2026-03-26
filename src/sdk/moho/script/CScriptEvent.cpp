#include "CScriptEvent.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

using namespace moho;

namespace
{
  gpg::RType* CachedCScriptEventType()
  {
    if (!CScriptEvent::sType) {
      CScriptEvent::sType = gpg::LookupRType(typeid(CScriptEvent));
    }
    return CScriptEvent::sType;
  }

  gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  gpg::RType* CachedCTaskEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTaskEvent));
    }
    return cached;
  }

  gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject*));
    }
    return cached;
  }

  LuaPlus::LuaObject GetTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* fieldName)
  {
    LuaPlus::LuaObject out;
    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, top);
    return out;
  }

  gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const raw = lua_touserdata(lstate, -1);
    if (raw) {
      out = *static_cast<gpg::RRef*>(raw);
    }
    lua_settop(lstate, top);
    return out;
  }

  template <typename T>
  gpg::RRef MakeTypedRef(T* object, gpg::RType* staticType)
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

  void AddCTaskEventBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const taskEventType = CachedCTaskEventType();
    gpg::RField baseField{};
    baseField.mName = taskEventType->GetName();
    baseField.mType = taskEventType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void AddCScriptObjectBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const scriptObjectType = CachedCScriptObjectType();
    gpg::RField baseField{};
    baseField.mName = scriptObjectType->GetName();
    baseField.mType = scriptObjectType;
    baseField.mOffset = 0x10;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x004CB570 (FUN_004CB570, CScriptEventTypeInfo::newRefFunc_)
   */
  [[nodiscard]]
  gpg::RRef CreateScriptEventRefOwned()
  {
    return MakeTypedRef(new CScriptEvent(), CachedCScriptEventType());
  }

  /**
   * Address: 0x004CB5E0 (FUN_004CB5E0, CScriptEventTypeInfo::deleteFunc_)
   */
  void DeleteScriptEventOwned(void* object)
  {
    delete static_cast<CScriptEvent*>(object);
  }

  /**
   * Address: 0x004CB600 (FUN_004CB600, CScriptEventTypeInfo::ctorRefFunc_)
   */
  [[nodiscard]]
  gpg::RRef ConstructScriptEventRefInPlace(void* objectStorage)
  {
    auto* const event = static_cast<CScriptEvent*>(objectStorage);
    if (event) {
      new (event) CScriptEvent();
    }
    return MakeTypedRef(event, CachedCScriptEventType());
  }

  /**
   * Address: 0x004CB670 (FUN_004CB670, CScriptEventTypeInfo::dtrFunc_)
   */
  void DestroyScriptEventInPlace(void* object)
  {
    auto* const event = static_cast<CScriptEvent*>(object);
    if (event) {
      event->~CScriptEvent();
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CScriptEvent::sType = nullptr;
}

/**
 * Address: 0x004C9420 (FUN_004C9420, ??0CScriptEvent@Moho@@QAE@@Z)
 */
CScriptEvent::CScriptEvent() = default;

/**
 * Address: 0x004C94C0 (FUN_004C94C0, ??1CScriptEvent@Moho@@UAE@XZ)
 */
CScriptEvent::~CScriptEvent() = default;

/**
 * Address: 0x004C93E0 (FUN_004C93E0, ?GetClass@CScriptEvent@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CScriptEvent::GetClass() const
{
  return CachedCScriptEventType();
}

/**
 * Address: 0x004C9400 (FUN_004C9400, ?GetDerivedObjectRef@CScriptEvent@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CScriptEvent::GetDerivedObjectRef()
{
  return MakeTypedRef(this, CachedCScriptEventType());
}

/**
 * Address: 0x004C8270 (FUN_004C8270, func_GetCObj_CScriptObject)
 */
CScriptObject* moho::SCR_GetScriptObjectFromLuaObject(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaObject payload(object);
  if (payload.IsTable()) {
    payload = GetTableFieldByName(payload, "_c_object");
  }

  if (!payload.IsUserData()) {
    return nullptr;
  }

  const gpg::RRef userDataRef = ExtractUserDataRef(payload);
  if (!userDataRef.mObj) {
    return nullptr;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
  auto** const scriptObjectSlot = static_cast<CScriptObject**>(upcast.mObj);
  if (!scriptObjectSlot) {
    return nullptr;
  }

  return *scriptObjectSlot;
}

/**
 * Address: 0x004C9030 (FUN_004C9030, func_RRefCScriptObject)
 */
gpg::RRef moho::SCR_MakeScriptObjectRef(CScriptObject* object)
{
  return MakeTypedRef(object, CachedCScriptObjectType());
}

/**
 * Address: 0x004CBE30 (FUN_004CBE30, func_UpCastCScriptEventUnsafe)
 */
CScriptEvent* moho::SCR_UpCastScriptEventUnsafe(const gpg::RRef& source)
{
  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCScriptEventType());
  return static_cast<CScriptEvent*>(upcast.mObj);
}

/**
 * Address: 0x004CB980 (FUN_004CB980, sub_4CB980)
 */
CScriptEvent* moho::SCR_GetScriptEventFromLuaObject(const LuaPlus::LuaObject& object)
{
  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(object);
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef ref = SCR_MakeScriptObjectRef(scriptObject);
  return SCR_UpCastScriptEventUnsafe(ref);
}

/**
 * Address: 0x004CB0A0 (FUN_004CB0A0, sub_4CB0A0)
 */
void CScriptEventSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCScriptEventType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x004CA1D0 (FUN_004CA1D0, scalar deleting destructor thunk)
 */
CScriptEventTypeInfo::~CScriptEventTypeInfo() = default;

/**
 * Address: 0x004CA1C0 (FUN_004CA1C0, ?GetName@CScriptEventTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CScriptEventTypeInfo::GetName() const
{
  return "CScriptEvent";
}

/**
 * Address: 0x004CA170 (FUN_004CA170, ?Init@CScriptEventTypeInfo@Moho@@UAEXXZ)
 */
void CScriptEventTypeInfo::Init()
{
  size_ = sizeof(CScriptEvent);
  newRefFunc_ = &CreateScriptEventRefOwned;
  deleteFunc_ = &DeleteScriptEventOwned;
  ctorRefFunc_ = &ConstructScriptEventRefInPlace;
  dtrFunc_ = &DestroyScriptEventInPlace;
  gpg::RType::Init();
  AddCScriptObjectBaseToTypeInfo(this);
  AddCTaskEventBaseToTypeInfo(this);
  Finish();
}
