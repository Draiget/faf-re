#include "CScriptEvent.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiNavigatorImpl.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/entity/Entity.h"
#include "moho/projectile/Projectile.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CPlatoon.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/UserUnit.h"

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

  gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Unit));
    }
    return cached;
  }

  gpg::RType* CachedUnitWeaponType()
  {
    if (!UnitWeapon::sType) {
      UnitWeapon::sType = gpg::LookupRType(typeid(UnitWeapon));
    }
    return UnitWeapon::sType;
  }

  gpg::RType* CachedUserUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UserUnit));
    }
    return cached;
  }

  gpg::RType* CachedCAiBrainType()
  {
    if (!CAiBrain::sType) {
      CAiBrain::sType = gpg::LookupRType(typeid(CAiBrain));
    }
    return CAiBrain::sType;
  }

  gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
    }
    return cached;
  }

  gpg::RType* CachedCAiPersonalityType()
  {
    if (!CAiPersonality::sType) {
      CAiPersonality::sType = gpg::LookupRType(typeid(CAiPersonality));
    }
    return CAiPersonality::sType;
  }

  gpg::RType* CachedCAiNavigatorImplType()
  {
    if (!CAiNavigatorImpl::sType) {
      CAiNavigatorImpl::sType = gpg::LookupRType(typeid(CAiNavigatorImpl));
    }
    return CAiNavigatorImpl::sType;
  }

  gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Entity));
    }
    return cached;
  }

  gpg::RType* CachedProjectileType()
  {
    if (!Projectile::sType) {
      Projectile::sType = gpg::LookupRType(typeid(Projectile));
    }
    return Projectile::sType;
  }

  gpg::RType* CachedCPlatoonType()
  {
    if (!CPlatoon::sType) {
      CPlatoon::sType = gpg::LookupRType(typeid(CPlatoon));
    }
    return CPlatoon::sType;
  }

  gpg::RType* CachedCLobbyType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CLobby");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CLobby");
    }
    return cached;
  }

  gpg::RType* CachedCameraImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CameraImpl));
    }
    return cached;
  }

  gpg::RType* CachedCUIWorldViewType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CUIWorldView");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CUIWorldView");
    }
    return cached;
  }

  gpg::RType* CachedCMauiItemListType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiItemList");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiItemList");
    }
    return cached;
  }

  gpg::RType* CachedCMauiControlType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiControl");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiControl");
    }
    return cached;
  }

  gpg::RType* CachedCMauiBitmapType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CMauiBitmap");
    }
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("Moho::CMauiBitmap");
    }
    return cached;
  }

  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

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

  CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
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
    return static_cast<CScriptObject**>(upcast.mObj);
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
 * Address: 0x004CB820 (FUN_004CB820, Moho::CScriptEvent::MemberDeserialize)
 */
void CScriptEvent::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef ownerRef{};

  gpg::RType* const taskEventType = CachedCTaskEventType();
  archive->Read(taskEventType, static_cast<CTaskEvent*>(this), ownerRef);

  gpg::RType* scriptObjectType = CScriptObject::sType;
  if (!scriptObjectType) {
    scriptObjectType = gpg::LookupRType(typeid(CScriptObject));
    CScriptObject::sType = scriptObjectType;
  }
  archive->Read(scriptObjectType, static_cast<CScriptObject*>(this), ownerRef);
}

/**
 * Address: 0x004CB8A0 (FUN_004CB8A0, Moho::CScriptEvent::MemberSerialize)
 */
void CScriptEvent::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RRef ownerRef{};

  gpg::RType* const taskEventType = CachedCTaskEventType();
  archive->Write(taskEventType, static_cast<CTaskEvent*>(this), ownerRef);

  gpg::RType* scriptObjectType = CScriptObject::sType;
  if (!scriptObjectType) {
    scriptObjectType = gpg::LookupRType(typeid(CScriptObject));
    CScriptObject::sType = scriptObjectType;
  }
  archive->Write(scriptObjectType, static_cast<CScriptObject*>(this), ownerRef);
}

/**
 * Address: 0x004C8270 (FUN_004C8270, func_GetCObj_CScriptObject)
 */
CScriptObject* moho::SCR_GetScriptObjectFromLuaObject(const LuaPlus::LuaObject& object)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    return nullptr;
  }

  return *scriptObjectSlot;
}

/**
 * Address: 0x005936C0 (FUN_005936C0, Moho::SCR_FromLua_Unit)
 */
Unit* moho::SCR_FromLua_Unit(const LuaPlus::LuaObject& object)
{
  LuaPlus::LuaState* const activeState = object.GetActiveState();
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitType());
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Unit*>(upcast.mObj);
}

/**
 * Address: 0x00633220 (FUN_00633220, Moho::SCR_FromLua_UnitWeapon)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UnitWeapon*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
UnitWeapon* moho::SCR_FromLua_UnitWeapon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitWeaponType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UnitWeapon*>(upcast.mObj);
}

/**
 * Address: 0x00822B80 (FUN_00822B80, Moho::SCR_FromLua_UserUnit)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `UserUnit*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
UserUnit* moho::SCR_FromLua_UserUnit(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<UserUnit*>(upcast.mObj);
}

/**
 * Address: 0x005930D0 (FUN_005930D0, Moho::SCR_FromLua_CAiBrain)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiBrain*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CAiBrain* moho::SCR_FromLua_CAiBrain(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiBrainType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiBrain*>(upcast.mObj);
}

/**
 * Address: 0x005DEF90 (FUN_005DEF90, Moho::SCR_FromLua_CAiAttackerImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiAttackerImpl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiAttackerImpl* moho::SCR_FromLua_CAiAttackerImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiAttackerImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiAttackerImpl*>(upcast.mObj);
}

/**
 * Address: 0x005BD320 (FUN_005BD320, Moho::SCR_FromLua_CAiPersonality)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiPersonality*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiPersonality* moho::SCR_FromLua_CAiPersonality(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiPersonalityType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiPersonality*>(upcast.mObj);
}

/**
 * Address: 0x005A7F50 (FUN_005A7F50, Moho::SCR_FromLua_CAiNavigatorImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CAiNavigatorImpl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CAiNavigatorImpl* moho::SCR_FromLua_CAiNavigatorImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCAiNavigatorImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CAiNavigatorImpl*>(upcast.mObj);
}

/**
 * Address: 0x00593AF0 (FUN_00593AF0, Moho::SCR_FromLua_CPlatoon)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CPlatoon*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CPlatoon* moho::SCR_FromLua_CPlatoon(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCPlatoonType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CPlatoon*>(upcast.mObj);
}

/**
 * Address: 0x007CB7E0 (FUN_007CB7E0, Moho::SCR_FromLua_CLobby)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CLobby*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CLobby* moho::SCR_FromLua_CLobby(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const lobbyType = CachedCLobbyType();
  const gpg::RRef upcast = lobbyType ? gpg::REF_UpcastPtr(sourceRef, lobbyType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CLobby*>(upcast.mObj);
}

/**
 * Address: 0x007B0E90 (FUN_007B0E90, Moho::SCR_FromLua_CameraImpl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CameraImpl*` and raises Lua errors
 * for missing, destroyed, or type-mismatched game objects.
 */
CameraImpl* moho::SCR_FromLua_CameraImpl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCameraImplType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<CameraImpl*>(upcast.mObj);
}

/**
 * Address: 0x00873A70 (FUN_00873A70, Moho::SCR_FromLua_CUIWorldView)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CUIWorldView*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CUIWorldView* moho::SCR_FromLua_CUIWorldView(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  LuaPlus::LuaState* activeState = state;
  if (!activeState) {
    activeState = object.GetActiveState();
  }

  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const worldViewType = CachedCUIWorldViewType();
  const gpg::RRef upcast = worldViewType ? gpg::REF_UpcastPtr(sourceRef, worldViewType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CUIWorldView*>(upcast.mObj);
}

/**
 * Address: 0x0079C9C0 (FUN_0079C9C0, Moho::SCR_FromLua_CMauiItemList)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiItemList*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiItemList* moho::SCR_FromLua_CMauiItemList(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCMauiItemListType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiItemList*>(upcast.mObj);
}

/**
 * Address: 0x00783BA0 (FUN_00783BA0, Moho::SCR_FromLua_CMauiControl)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiControl*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiControl* moho::SCR_FromLua_CMauiControl(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiControlType = CachedCMauiControlType();
  const gpg::RRef upcast = mauiControlType ? gpg::REF_UpcastPtr(sourceRef, mauiControlType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiControl*>(upcast.mObj);
}

/**
 * Address: 0x00783C70 (FUN_00783C70, Moho::SCR_FromLua_CMauiBitmap)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `CMauiBitmap*` and raises Lua
 * errors for missing, destroyed, or type-mismatched game objects.
 */
CMauiBitmap* moho::SCR_FromLua_CMauiBitmap(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RType* const mauiBitmapType = CachedCMauiBitmapType();
  const gpg::RRef upcast = mauiBitmapType ? gpg::REF_UpcastPtr(sourceRef, mauiBitmapType) : gpg::RRef{};
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return reinterpret_cast<CMauiBitmap*>(upcast.mObj);
}

/**
 * Address: 0x005A8020 (FUN_005A8020, Moho::SCR_FromLua_Entity)
 */
Entity* moho::SCR_FromLua_Entity(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  LuaPlus::LuaState* activeState = state;
  if (!activeState) {
    activeState = object.GetActiveState();
  }

  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedEntityType());
  if (!upcast.mObj) {
    luaL_error(activeState ? activeState->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Entity*>(upcast.mObj);
}

/**
 * Address: 0x005E3800 (FUN_005E3800, Moho::SCR_FromLuaNoError_Entity)
 *
 * What it does:
 * Converts one Lua `_c_object` payload to `Entity*` without raising Lua
 * errors; returns nullptr for missing, destroyed, or type-mismatched values.
 */
Entity* moho::SCR_FromLuaNoError_Entity(const LuaPlus::LuaObject& object)
{
  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(object);
  if (!scriptObject) {
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedEntityType());
  if (!upcast.mObj) {
    return nullptr;
  }

  return static_cast<Entity*>(upcast.mObj);
}

/**
 * Address: 0x006A44C0 (FUN_006A44C0, Moho::SCR_FromLua_Projectile)
 */
Projectile* moho::SCR_FromLua_Projectile(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
{
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
  if (!scriptObjectSlot) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
    return nullptr;
  }

  CScriptObject* const scriptObject = *scriptObjectSlot;
  if (!scriptObject) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
    return nullptr;
  }

  const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
  const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedProjectileType());
  if (!upcast.mObj) {
    luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
    return nullptr;
  }

  return static_cast<Projectile*>(upcast.mObj);
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
 * Address: 0x004CA280 (FUN_004CA280, Moho::CScriptEventSerializer::Deserialize)
 */
void CScriptEventSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const object = reinterpret_cast<CScriptEvent*>(objectPtr);
  object->MemberDeserialize(archive);
}

/**
 * Address: 0x004CA290 (FUN_004CA290, Moho::CScriptEventSerializer::Serialize)
 */
void CScriptEventSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const object = reinterpret_cast<CScriptEvent*>(objectPtr);
  object->MemberSerialize(archive);
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
 * Address: 0x004CB760 (FUN_004CB760, Moho::CScriptEventTypeInfo::AddBase_CScriptObject)
 */
void CScriptEventTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
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
 * Address: 0x004CB7C0 (FUN_004CB7C0, Moho::CScriptEventTypeInfo::AddBase_CTaskEvent)
 */
void CScriptEventTypeInfo::AddBase_CTaskEvent(gpg::RType* const typeInfo)
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
  AddBase_CScriptObject(this);
  AddBase_CTaskEvent(this);
  Finish();
}
