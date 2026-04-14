#include "CScriptObject.h"

#include <cstdint>
#include <exception>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/entity/Prop.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

gpg::RType* CScriptObject::sType = nullptr;
gpg::RType* CScriptObject::sPointerType = nullptr;

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kIsDestroyedName = "IsDestroyed";
  constexpr const char* kIsDestroyedHelpText = "Has the c++ object been destroyed?";
  constexpr const char* kPrintUserName = "print";
  constexpr const char* kPrintUserHelpText = "Print a log message";
  constexpr const char* kLogName = "LOG";
  constexpr const char* kLogHelpText = "Print a log message";
  constexpr const char* kWarnName = "WARN";
  constexpr const char* kWarnHelpText = "Pop up a warning dialog";
  constexpr const char* kSpewName = "SPEW";
  constexpr const char* kSpewHelpText = "Spew to log";
  constexpr const char* kDoscriptName = "doscript";
  constexpr const char* kDoscriptHelpText =
    "doscript(script, [env]) -- run another script. The environment table, if given, will be used for the script's "
    "global variables.";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("user");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CScriptObject::GetPointerType());
    return static_cast<CScriptObject**>(upcast.mObj);
  }

  void ClearWeakObjectChain(WeakObject& weakObject) noexcept
  {
    auto* cursor = reinterpret_cast<WeakObject::WeakLinkNodeView**>(weakObject.WeakLinkHeadSlot());
    while (cursor && *cursor) {
      WeakObject::WeakLinkNodeView* const node = *cursor;
      *cursor = node->nextInOwner;
      node->ownerLinkSlot = nullptr;
      node->nextInOwner = nullptr;
    }
  }

  gpg::RType* CachedLuaObjectType()
  {
    gpg::RType* cached = LuaPlus::LuaObject::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = cached;
    }
    return cached;
  }

  LuaPlus::LuaObject GetScriptObjectMetatable(LuaPlus::LuaState* state)
  {
    return CScrLuaMetatableFactory<CScriptObject*>::Instance().Get(state);
  }

  /**
   * Address: 0x004C81B0 (FUN_004C81B0, func_CreateLuaScriptObject)
   *
   * What it does:
   * Builds `_c_object` userdata lane for one `CScriptObject*` owner slot and
   * applies `CScrLuaMetatableFactory<CScriptObject*>` metatable.
   */
  [[nodiscard]]
  LuaPlus::LuaObject CreateLuaScriptObject(LuaPlus::LuaState* const state, CScriptObject** const objectSlot)
  {
    LuaPlus::LuaObject out;
    if (!state || !objectSlot) {
      return out;
    }

    LuaPlus::LuaObject metatable = GetScriptObjectMetatable(state);
    gpg::RRef objectRef{};
    gpg::RRef_CScriptObject_P(&objectRef, objectSlot);
    out.AssignNewUserData(state, objectRef);
    out.SetMetaTable(metatable);
    return out;
  }

  [[nodiscard]] bool LuaValueToBool(const LuaPlus::LuaObject& value) noexcept
  {
    if (!value) {
      return false;
    }
    if (value.IsBoolean()) {
      return value.GetBoolean();
    }
    if (value.IsNumber()) {
      return value.GetNumber() != 0.0;
    }
    return false;
  }

  [[nodiscard]] float LuaValueToFloat(const LuaPlus::LuaObject& value) noexcept
  {
    LuaPlus::LuaState* const state = value.GetActiveState();
    if (!state) {
      return 0.0f;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return 0.0f;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(value).PushStack(lstate);
    const float out = static_cast<float>(lua_tonumber(lstate, -1));
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] LuaPlus::LuaObject ResolveUnitLuaObjectFromWeakLink(const WeakPtr<Unit>& unitLink)
  {
    Unit* const unit = unitLink.GetObjectPtr();
    if (!unit) {
      return {};
    }
    return unit->GetLuaObject();
  }

  [[nodiscard]] LuaPlus::LuaObject ResolveEntityLuaObjectFromWeakLink(const WeakPtr<Entity>& entityLink)
  {
    const Entity* const entity = entityLink.GetObjectPtr();
    if (!entity) {
      return {};
    }

    const CScriptObject* const scriptObject = static_cast<const CScriptObject*>(entity);
    if (!scriptObject->cObject.m_state) {
      return {};
    }
    return scriptObject->cObject;
  }

  struct WeakEntityUnlinkScope
  {
    explicit WeakEntityUnlinkScope(WeakPtr<Entity>& linkRef)
      : link(linkRef)
    {
    }

    ~WeakEntityUnlinkScope()
    {
      link.UnlinkFromOwnerChain();
    }

    WeakPtr<Entity>& link;
  };

  /**
   * Address: 0x0073AB00 (FUN_0073AB00, LuaPlus::LuaFunction::Call_ObjectWeakentNumString_Num)
   *
   * LuaPlus::LuaObject,float,std::string,Moho::WeakPtr_Entity
   *
   * IDA signature:
   * float __userpurge LuaPlus::LuaFunction::Call_ObjectWeakentNumString_Num@<xmm0>(
   *   LuaPlus::LuaFunction *this@<ecx>, LuaPlus::LuaObject a2, float a3, std::string a4, Moho::WeakPtr_Entity a5);
   *
   * What it does:
   * Calls one Lua function with `(selfObject, weakEntityLuaObjectOrNil, amount, damageType)`
   * and returns the numeric Lua result while restoring the caller stack top.
   */
  [[nodiscard]] float CallObjectWeakEntityNumStringNum(
    LuaPlus::LuaFunction<LuaPlus::LuaObject>& function,
    LuaPlus::LuaObject selfObject,
    float amount,
    std::string damageType,
    WeakPtr<Entity> weakSource
  )
  {
    WeakEntityUnlinkScope unlinkScope(weakSource);

    lua_State* const activeState = function.GetActiveCState();
    const int savedTop = lua_gettop(activeState);

    function.PushStack(activeState);
    selfObject.PushStack(activeState);

    const Entity* const sourceEntity = weakSource.GetObjectPtr();
    if (!sourceEntity) {
      lua_pushnil(activeState);
    } else {
      const auto* const sourceScriptObject = static_cast<const CScriptObject*>(sourceEntity);
      if (!sourceScriptObject->mLuaObj.m_state) {
        lua_pushnil(activeState);
      } else {
        const_cast<LuaPlus::LuaObject&>(sourceScriptObject->mLuaObj).PushStack(activeState);
      }
    }

    lua_pushnumber(activeState, static_cast<lua_Number>(amount));
    lua_pushlstring(activeState, damageType.c_str(), static_cast<size_t>(damageType.size()));
    lua_call(activeState, 4, 1);

    const float result = static_cast<float>(lua_tonumber(activeState, -1));
    lua_settop(activeState, savedTop);
    return result;
  }

  /**
   * Address: 0x0073AC30 (FUN_0073AC30, LuaPlus::LuaFunction::Call_ObjectNumObjectStringWeakent)
   *
   * What it does:
   * Calls one Lua function with `(selfObject, weakEntityLuaObjectOrNil, amount,
   * payloadObject, damageType)` and restores the caller stack top.
   */
  void CallObjectNumObjectStringWeakEntity(
    LuaPlus::LuaFunction<LuaPlus::LuaObject>& function,
    LuaPlus::LuaObject selfObject,
    const float amount,
    LuaPlus::LuaObject payloadObject,
    std::string damageType,
    WeakPtr<Entity> weakSource
  )
  {
    WeakEntityUnlinkScope unlinkScope(weakSource);

    lua_State* const activeState = function.GetActiveCState();
    const int savedTop = lua_gettop(activeState);

    function.PushStack(activeState);
    selfObject.PushStack(activeState);

    const Entity* const sourceEntity = weakSource.GetObjectPtr();
    if (!sourceEntity) {
      lua_pushnil(activeState);
    } else {
      const auto* const sourceScriptObject = static_cast<const CScriptObject*>(sourceEntity);
      if (!sourceScriptObject->mLuaObj.m_state) {
        lua_pushnil(activeState);
      } else {
        const_cast<LuaPlus::LuaObject&>(sourceScriptObject->mLuaObj).PushStack(activeState);
      }
    }

    lua_pushnumber(activeState, static_cast<lua_Number>(amount));
    payloadObject.PushStack(activeState);
    lua_pushlstring(activeState, damageType.c_str(), static_cast<size_t>(damageType.size()));
    lua_call(activeState, 5, 1);
    lua_settop(activeState, savedTop);
  }

  /**
   * Address: 0x004CD680 (FUN_004CD680)
   *
   * What it does:
   * Applies one byte of print-concat formatting:
   * newline flushes, tab expands to the next 8-column stop, and other
   * control bytes map to a literal tab.
   */
  void AppendConcatByteToLogLine(
    const std::uint8_t byteValue,
    std::string& lineBuffer,
    LuaPlus::LuaState* const state,
    const moho::ScrConcatArgsSink sink
  )
  {
    if (byteValue == '\n') {
      sink(state, lineBuffer.c_str());
      lineBuffer.clear();
      return;
    }

    if (byteValue == '\t') {
      const std::uint8_t sizeLowByte = static_cast<std::uint8_t>(lineBuffer.size());
      const std::size_t spaceCount =
        static_cast<std::size_t>((static_cast<std::uint8_t>(sizeLowByte - 1u) & 0x07u) + 1u);
      lineBuffer.append(spaceCount, ' ');
      return;
    }

    if (byteValue < 0x20u) {
      lineBuffer.push_back('\t');
      return;
    }

    lineBuffer.push_back(static_cast<char>(byteValue));
  }

  /**
   * Address: 0x004CD8E0 (FUN_004CD8E0)
   *
   * What it does:
   * Prints one concat-produced line to the console output stream.
   */
  void EmitConcatLineToConsole(LuaPlus::LuaState* const state, const char* const line)
  {
    (void)state;
    moho::CON_Printf("%s", line ? line : "");
  }

  /**
   * Address: 0x004CD990 (FUN_004CD990)
   *
   * What it does:
   * Emits one concat-produced line through info-severity logging.
   */
  void EmitConcatLineToLogf(LuaPlus::LuaState* const state, const char* const line)
  {
    (void)state;
    gpg::Logf("%s", line ? line : "");
  }

  /**
   * Address: 0x004CDA40 (FUN_004CDA40)
   *
   * What it does:
   * Emits one concat-produced line through warn-severity logging.
   */
  void EmitConcatLineToWarnf(LuaPlus::LuaState* const state, const char* const line)
  {
    (void)state;
    gpg::Warnf("%s", line ? line : "");
  }

  /**
   * Address: 0x004CDAF0 (FUN_004CDAF0)
   *
   * What it does:
   * Emits one concat-produced line through debug-severity logging.
   */
  void EmitConcatLineToDebugf(LuaPlus::LuaState* const state, const char* const line)
  {
    (void)state;
    gpg::Debugf("%s", line ? line : "");
  }

  /**
   * Address: 0x006B0940 (FUN_006B0940) guard prologue/epilogue pattern
   *
   * Mirrors the weak-object intrusive guard chain used by callback wrappers.
   * Shared guard mechanics live in WeakObject so callback helpers do not
   * duplicate owner-link traversal logic.
   */
  class CallbackWeakGuard final
  {
  public:
    explicit CallbackWeakGuard(CScriptObject* obj) : m_guard(static_cast<WeakObject*>(obj)) {}

    [[nodiscard]]
    CScriptObject* ResolveObjectForWarning() const
    {
      const WeakObject::WeakLinkSlot* const ownerLinkSlot = m_guard.OwnerLinkSlotAddress();
      if (!ownerLinkSlot) {
        return nullptr;
      }
      return WeakPtr<CScriptObject>::DecodeOwnerObject(
        reinterpret_cast<void*>(const_cast<WeakObject::WeakLinkSlot*>(ownerLinkSlot))
      );
    }

  private:
    WeakObject::ScopedWeakLinkGuard m_guard;
  };

  /**
   * Address: 0x004C7C30 (FUN_004C7C30)
   *
   * IDA signature:
   * _DWORD *__thiscall sub_4C7C30(_DWORD *this);
   *
   * What it does:
   * Unlinks one `CScriptObject_base` node from the active-invocation
   * singly-linked chain used by every `CScriptObject::RunScript*` /
   * `Call` variant (54 call sites). During a script invocation the
   * caller installs its local stack-cell address into the object's
   * `mNextPtr` field and stores the previous chain pointer inside that
   * stack cell; on exit this helper walks the chain starting at
   * `this->mNextPtr`, locates the slot whose stored back-pointer equals
   * `this`, and replaces it with the saved predecessor pointer held in
   * the companion slot at `this[1]`. This is the compiler-outlined form
   * of the inline unlink loop that appears in
   * `CScriptObject::Call` (FUN_00581930) and its 53 siblings.
   */
  [[maybe_unused]] void** UnlinkActiveScriptInvocationChainNode(void** const chainNode) noexcept
  {
    void** cursor = static_cast<void**>(chainNode[0]);
    if (chainNode[0] != nullptr) {
      while (*cursor != static_cast<void*>(chainNode)) {
        cursor = reinterpret_cast<void**>(reinterpret_cast<char*>(*cursor) + sizeof(void*));
      }
      *cursor = chainNode[1];
    }
    return cursor;
  }

  /**
   * Address: 0x004C8360 (FUN_004C8360)
   * Address: 0x004C8390 (FUN_004C8390)
   *
   * What it does:
   * Copy-assigns one source `LuaObject` range `[sourceBegin, sourceEnd)`
   * so the copied block ends at `destinationEnd`, walking both ranges
   * backward one 20-byte element at a time and invoking
   * `LuaPlus::LuaObject::operator=`. Emitted twice by the compiler for
   * the two distinct inlining lanes inside
   * `LuaObjectFastVector::InsertAt` / `GrowInsert`.
   */
  [[maybe_unused]] LuaPlus::LuaObject* CopyAssignLuaObjectRangeBackward(
    LuaPlus::LuaObject* destinationEnd,
    const LuaPlus::LuaObject* sourceBegin,
    const LuaPlus::LuaObject* sourceEnd
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

} // namespace

/**
 * Address: 0x004C7DC0 (FUN_004C7DC0, Moho::InstanceCounter<Moho::CScriptObject>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CScriptObject
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CScriptObject>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CScriptObject).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x004C6F70 (??0CScriptObject@Moho@@IAE@XZ)
 *
 * What it does:
 * Initializes weak-link storage and tracks CScriptObject instance count.
 */
CScriptObject::CScriptObject()
{
  weakLinkHead_ = 0u;
  AddStatCounter(InstanceCounter<CScriptObject>::GetStatItem(), 1);
}

/**
 * Address: 0x004C7010 (??0CScriptObject@Moho@@IAE@ABVLuaObject@LuaPlus@@000@Z)
 *
 * What it does:
 * Initializes base storage then creates/attaches Lua object state.
 */
CScriptObject::CScriptObject(
  const LuaPlus::LuaObject& metaOrFactory,
  const LuaPlus::LuaObject& arg1,
  const LuaPlus::LuaObject& arg2,
  const LuaPlus::LuaObject& arg3
)
  : CScriptObject()
{
  CreateLuaObject(metaOrFactory, arg1, arg2, arg3);
}

/**
 * Address: 0x004C7340 (FUN_004C7340, Moho::CScriptObject::~CScriptObject)
 *
 * What it does:
 * Clears Lua `_c_object` back-reference, decrements tracked instance count,
 * and unlinks all intrusive weak-reference nodes owned by this object.
 */
CScriptObject::~CScriptObject()
{
  if (cObject.m_state) {
    CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(cObject);
    if (scriptObjectSlot) {
      *scriptObjectSlot = nullptr;
    }
  }

  AddStatCounter(InstanceCounter<CScriptObject>::GetStatItem(), -1);
  ClearWeakObjectChain(*static_cast<WeakObject*>(this));
}

gpg::RType* CScriptObject::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CScriptObject));
  }
  return sType;
}

/**
 * Address: 0x004C8530 (FUN_004C8530, Moho::CScriptObject::GetPointerType)
 */
gpg::RType* CScriptObject::GetPointerType()
{
  gpg::RType* cached = sPointerType;
  if (!cached) {
    cached = gpg::LookupRType(typeid(CScriptObject*));
    sPointerType = cached;
  }
  return cached;
}

/**
 * Address: 0x004C8DC0 (FUN_004C8DC0, Moho::CScriptObject::MemberDeserialize)
 */
void CScriptObject::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef ownerRef{};
  gpg::RType* luaObjectType = CachedLuaObjectType();
  archive->Read(luaObjectType, &cObject, ownerRef);

  luaObjectType = CachedLuaObjectType();
  archive->Read(luaObjectType, &mLuaObj, ownerRef);
}

/**
 * Address: 0x004C8E40 (FUN_004C8E40, Moho::CScriptObject::MemberSerialize)
 */
void CScriptObject::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RRef ownerRef{};
  gpg::RType* luaObjectType = CachedLuaObjectType();
  archive->Write(luaObjectType, &cObject, ownerRef);

  luaObjectType = CachedLuaObjectType();
  archive->Write(luaObjectType, &mLuaObj, ownerRef);
}

/**
 * Address: 0x004C70A0
 */
msvc8::string CScriptObject::GetErrorDescription()
{
  return gpg::STR_Printf("CScriptObject at %08x", reinterpret_cast<uintptr_t>(this));
}

/**
 * Address: 0x004C70D0
 */
void CScriptObject::CreateLuaObject(
  const LuaPlus::LuaObject& metaOrFactory,
  const LuaPlus::LuaObject& arg1,
  const LuaPlus::LuaObject& arg2,
  const LuaPlus::LuaObject& arg3
)
{
  LuaPlus::LuaState* state = metaOrFactory.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  LuaPlus::LuaObject callObject;
  metaOrFactory.PushStack(lstate);
  if (lua_getmetatable(lstate, -1) != 0) {
    lua_pushstring(lstate, "__call");
    lua_gettable(lstate, -2);
    callObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
  }
  lua_settop(lstate, stackTop);

  LuaPlus::LuaObject created;
  if (callObject.IsNil()) {
    created.AssignNewTable(state, 0, 1);
    created.SetMetaTable(metaOrFactory);
  } else {
    callObject.PushStack(lstate);
    const int funcTop = lua_gettop(lstate);

    metaOrFactory.PushStack(lstate);
    if (arg1.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg1).PushStack(lstate);
    }
    if (arg2.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg2).PushStack(lstate);
    }
    if (arg3.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg3).PushStack(lstate);
    }

    const int nargs = lua_gettop(lstate) - funcTop;
    if (lua_pcall(lstate, nargs, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      gpg::Warnf("Error in lua: %s", err.GetString());
      lua_settop(lstate, stackTop);
      return;
    }

    created = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, stackTop);
  }

  SetLuaObject(created);
}

/**
 * Address: 0x004C72D0
 */
void CScriptObject::SetLuaObject(const LuaPlus::LuaObject& obj)
{
  LuaPlus::LuaState* const state = obj.GetActiveState();
  if (!state || obj.IsNil()) {
    return;
  }

  mLuaObj = obj;
  CScriptObject* objectSlot = this;
  LuaPlus::LuaObject created = CreateLuaScriptObject(state, &objectSlot);
  cObject = created;
  mLuaObj.SetObject("_c_object", cObject);
}

/**
 * Address: 0x004C7410
 */
void CScriptObject::LogScriptWarning(CScriptObject* obj, const char* which, const char* message)
{
  const char* where = "<deleted object>";
  msvc8::string description;
  if (obj) {
    description = obj->GetErrorDescription();
    where = description.c_str();
  }

  gpg::Warnf("Error running %s script in %s: %s", which ? which : "<unknown>", where, message ? message : "");
}

/**
 * Address: 0x004C74B0
 */
LuaPlus::LuaObject CScriptObject::FindScript(LuaPlus::LuaObject* dest, const char* name)
{
  if (!dest) {
    return {};
  }

  *dest = LuaPlus::LuaObject{};

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return *dest;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  mLuaObj.PushStack(lstate);
  lua_pushstring(lstate, name ? name : "");
  lua_gettable(lstate, -2);

  *dest = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
  lua_settop(lstate, stackTop);
  return *dest;
}

/**
 * Address: 0x004C7580
 */
bool CScriptObject::RunScriptMultiRet(
  const char* funcName,
  gpg::core::FastVector<LuaPlus::LuaObject>& out,
  LuaPlus::LuaObject arg1,
  LuaPlus::LuaObject arg2,
  LuaPlus::LuaObject arg3,
  LuaPlus::LuaObject arg4,
  LuaPlus::LuaObject arg5
)
{
  out.Clear();

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return false;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  mLuaObj.PushStack(lstate);
  const int tableIndex = lua_gettop(lstate);
  lua_pushstring(lstate, funcName ? funcName : "");
  lua_gettable(lstate, -2);
  if (lua_isnil(lstate, -1)) {
    lua_settop(lstate, stackTop);
    return false;
  }

  const int funcTop = lua_gettop(lstate);
  mLuaObj.PushStack(lstate);
  if (arg1.m_state) {
    arg1.PushStack(lstate);
  }
  if (arg2.m_state) {
    arg2.PushStack(lstate);
  }
  if (arg3.m_state) {
    arg3.PushStack(lstate);
  }
  if (arg4.m_state) {
    arg4.PushStack(lstate);
  }
  if (arg5.m_state) {
    arg5.PushStack(lstate);
  }

  const int nargs = lua_gettop(lstate) - funcTop;
  if (lua_pcall(lstate, nargs, LUA_MULTRET, 0) != 0) {
    const LuaPlus::LuaStackObject err(state, -1);
    LogScriptWarning(this, funcName ? funcName : "<unknown>", err.GetString());
    out.Clear();
    lua_settop(lstate, stackTop);
    return false;
  }

  const int retCount = lua_gettop(lstate) - tableIndex;
  if (retCount > 0) {
    out.Reserve(static_cast<size_t>(retCount));
    for (int i = -retCount; i <= -1; ++i) {
      LuaPlus::LuaObject value{LuaPlus::LuaStackObject(state, i)};
      out.PushBack(value);
    }
  }

  lua_settop(lstate, stackTop);
  return true;
}

/**
 * Address: 0x00623F10 (FUN_00623F10, Moho::CScriptObject::TaskTick)
 */
int CScriptObject::TaskTick()
{
  LuaPlus::LuaObject taskTickCallback;
  FindScript(&taskTickCallback, "TaskTick");
  if (!taskTickCallback) {
    return 0;
  }

  LuaPlus::LuaFunction<int> taskTick{taskTickCallback};
  return taskTick(mLuaObj);
}

/**
 * Address: 0x004C7A90 (FUN_004C7A90, cfunc_IsDestroyed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsDestroyedL`.
 */
int moho::cfunc_IsDestroyed(lua_State* const luaContext)
{
  return cfunc_IsDestroyedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004C7AB0 (FUN_004C7AB0, func_IsDestroyed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder for `IsDestroyed`.
 */
moho::CScrLuaInitForm* moho::func_IsDestroyed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    kIsDestroyedName,
    &moho::cfunc_IsDestroyed,
    nullptr,
    "<global>",
    kIsDestroyedHelpText
  );
  return &binder;
}

/**
 * Address: 0x004C7B10 (FUN_004C7B10, cfunc_IsDestroyedL)
 *
 * What it does:
 * Returns whether one Lua `_c_object` payload is missing or already nulled.
 */
int moho::cfunc_IsDestroyedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsDestroyedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject scriptObjectArg(LuaPlus::LuaStackObject(state, 1));
  CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(scriptObjectArg);
  const bool isDestroyed = (scriptObjectSlot == nullptr) || (*scriptObjectSlot == nullptr);
  lua_pushboolean(rawState, isDestroyed ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00BC60C0 (FUN_00BC60C0, register_IsDestroyed_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_IsDestroyed_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_IsDestroyed_LuaFuncDef()
{
  return func_IsDestroyed_LuaFuncDef();
}

/**
 * Address: 0x004CD740 (FUN_004CD740, Moho::SCR_ConcatArgsAndCall)
 *
 * What it does:
 * Concatenates Lua args through `tostring`, applies print-control formatting,
 * and emits line fragments through the supplied sink.
 */
void moho::SCR_ConcatArgsAndCall(
  LuaPlus::LuaState* const state,
  const std::uint8_t delimiterControlCode,
  const ScrConcatArgsSink sink
)
{
  if (!state || !state->m_state || !sink) {
    return;
  }

  LuaPlus::LuaObject toStringObject = state->GetGlobals()["tostring"];
  if (!toStringObject.IsFunction()) {
    toStringObject.TypeError("call");
  }
  LuaPlus::LuaFunction<LuaPlus::LuaObject> toStringCallable(toStringObject);

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  std::string lineBuffer;

  for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
    if (argumentIndex != 1) {
      AppendConcatByteToLogLine(delimiterControlCode, lineBuffer, state, sink);
    }

    const char* argumentText = nullptr;
    std::string argumentTextStorage;
    if (lua_isstring(rawState, argumentIndex) != 0) {
      argumentText = lua_tostring(rawState, argumentIndex);
      if (!argumentText) {
        LuaPlus::LuaStackObject stackArgument(state, argumentIndex);
        LuaPlus::LuaStackObject::TypeError(&stackArgument, "string");
      }
    } else {
      LuaPlus::LuaStackObject stackArgument(state, argumentIndex);
      const LuaPlus::LuaObject argumentObject(stackArgument);
      const LuaPlus::LuaObject textObject = toStringCallable.Call_Object_Obj(argumentObject);
      argumentText = textObject.GetString();
      if (argumentText != nullptr) {
        argumentTextStorage.assign(argumentText);
        argumentText = argumentTextStorage.c_str();
      }
      if (!argumentText) {
        LuaPlus::LuaStackObject::TypeError(&stackArgument, "string");
      }
    }

    for (const std::uint8_t* cursor = reinterpret_cast<const std::uint8_t*>(argumentText); *cursor != '\0'; ++cursor) {
      AppendConcatByteToLogLine(*cursor, lineBuffer, state, sink);
    }
  }

  if (!lineBuffer.empty()) {
    sink(state, lineBuffer.c_str());
  }
}

/**
 * Address: 0x004CD8F0 (FUN_004CD8F0, cfunc_printUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and emits concatenated args to console.
 */
int moho::cfunc_printUser(lua_State* const luaContext)
{
  SCR_ConcatArgsAndCall(ResolveBindingState(luaContext), '\t', &EmitConcatLineToConsole);
  return 0;
}

/**
 * Address: 0x004CD910 (FUN_004CD910, func_printUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane global Lua binder for `print`.
 */
moho::CScrLuaInitForm* moho::func_printUser_LuaFuncDef()
{
  static CScrLuaBinder
    binder(UserLuaInitSet(), kPrintUserName, &moho::cfunc_printUser, nullptr, "<global>", kPrintUserHelpText);
  return &binder;
}

/**
 * Address: 0x004CD9A0 (FUN_004CD9A0, cfunc_LOG)
 *
 * What it does:
 * Unwraps raw Lua callback context and emits concatenated args to `gpg::Logf`.
 */
int moho::cfunc_LOG(lua_State* const luaContext)
{
  SCR_ConcatArgsAndCall(ResolveBindingState(luaContext), 0u, &EmitConcatLineToLogf);
  return 0;
}

/**
 * Address: 0x004CD9C0 (FUN_004CD9C0, func_LOG_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-lane global Lua binder for `LOG`.
 */
moho::CScrLuaInitForm* moho::func_LOG_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), kLogName, &moho::cfunc_LOG, nullptr, "<global>", kLogHelpText);
  return &binder;
}

/**
 * Address: 0x004CDA50 (FUN_004CDA50, cfunc_WARN)
 *
 * What it does:
 * Unwraps raw Lua callback context and emits concatenated args to `gpg::Warnf`.
 */
int moho::cfunc_WARN(lua_State* const luaContext)
{
  SCR_ConcatArgsAndCall(ResolveBindingState(luaContext), 0u, &EmitConcatLineToWarnf);
  return 0;
}

/**
 * Address: 0x004CDA70 (FUN_004CDA70, func_WARN_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-lane global Lua binder for `WARN`.
 */
moho::CScrLuaInitForm* moho::func_WARN_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), kWarnName, &moho::cfunc_WARN, nullptr, "<global>", kWarnHelpText);
  return &binder;
}

/**
 * Address: 0x004CDB00 (FUN_004CDB00, cfunc_SPEW)
 *
 * What it does:
 * Unwraps raw Lua callback context and emits concatenated args to `gpg::Debugf`.
 */
int moho::cfunc_SPEW(lua_State* const luaContext)
{
  SCR_ConcatArgsAndCall(ResolveBindingState(luaContext), 0u, &EmitConcatLineToDebugf);
  return 0;
}

/**
 * Address: 0x004CDB20 (FUN_004CDB20, func_SPEW_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-lane global Lua binder for `SPEW`.
 */
moho::CScrLuaInitForm* moho::func_SPEW_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), kSpewName, &moho::cfunc_SPEW, nullptr, "<global>", kSpewHelpText);
  return &binder;
}

/**
 * Address: 0x004CEAF0 (FUN_004CEAF0, cfunc_doscript)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_doscriptL`.
 */
int moho::cfunc_doscript(lua_State* const luaContext)
{
  return cfunc_doscriptL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004CEB10 (FUN_004CEB10, func_doscript_LuaFuncDef)
 *
 * What it does:
 * Publishes the core-lane global Lua binder for `doscript`.
 */
moho::CScrLuaInitForm* moho::func_doscript_LuaFuncDef()
{
  static CScrLuaBinder
    binder(CoreLuaInitSet(), kDoscriptName, &moho::cfunc_doscript, nullptr, "<global>", kDoscriptHelpText);
  return &binder;
}

/**
 * Address: 0x004CEB70 (FUN_004CEB70, cfunc_doscriptL)
 *
 * What it does:
 * Validates `(script, [envTable])`, then dispatches to `func_LuaDoScript`.
 */
int moho::cfunc_doscriptL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kDoscriptHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(rawState, 2);
  if (lua_isstring(rawState, 1) == 0) {
    LuaPlus::LuaStackObject scriptArgument(state, 1);
    LuaPlus::LuaStackObject::TypeError(&scriptArgument, "string");
  }

  const int environmentType = lua_type(rawState, 2);
  if (environmentType != LUA_TNIL && environmentType != LUA_TTABLE) {
    LuaPlus::LuaStackObject environmentArgument(state, 2);
    LuaPlus::LuaStackObject::TypeError(&environmentArgument, "table");
  }

  LuaPlus::LuaStackObject scriptArgument(state, 1);
  const char* const scriptPath = lua_tostring(rawState, 1);
  if (scriptPath == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&scriptArgument, "string");
  }

  LuaPlus::LuaObject environmentObject{};
  LuaPlus::LuaObject* environmentPtr = nullptr;
  if (environmentType == LUA_TTABLE) {
    environmentObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 2));
    environmentPtr = &environmentObject;
  }

  func_LuaDoScript(state, scriptPath, environmentPtr);
  return 0;
}

/**
 * Address: 0x00BC6410 (FUN_00BC6410, register_printUser_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_printUser_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_printUser_LuaFuncDef()
{
  return func_printUser_LuaFuncDef();
}

/**
 * Address: 0x00BC6420 (FUN_00BC6420, register_LOG_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_LOG_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_LOG_LuaFuncDef()
{
  return func_LOG_LuaFuncDef();
}

/**
 * Address: 0x00BC6430 (FUN_00BC6430, register_WARN_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_WARN_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_WARN_LuaFuncDef()
{
  return func_WARN_LuaFuncDef();
}

/**
 * Address: 0x00BC6440 (FUN_00BC6440, register_SPEW_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_SPEW_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_SPEW_LuaFuncDef()
{
  return func_SPEW_LuaFuncDef();
}

/**
 * Address: 0x00BC64A0 (FUN_00BC64A0, register_doscript_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_doscript_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_doscript_LuaFuncDef()
{
  return func_doscript_LuaFuncDef();
}

/**
 * Address: 0x00581AA0
 */
void CScriptObject::CallbackStr(const char* callback)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);

    if (lua_pcall(lstate, 1, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005FCFE0
 */
void CScriptObject::CallbackStr(const char* callback, const char** arg0)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (arg0 && *arg0) ? *arg0 : nullptr);

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0067F450
 */
void CScriptObject::CallbackStr(const char* callback, const char** arg0, const char** arg1)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (arg0 && *arg0) ? *arg0 : nullptr);
    lua_pushstring(lstate, (arg1 && *arg1) ? *arg1 : nullptr);

    if (lua_pcall(lstate, 3, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x006B0940
 */
void CScriptObject::CallbackInt(const char* callback, const int value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushnumber(lstate, static_cast<lua_Number>(value));

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
      lua_settop(lstate, stackTop);
      return;
    }

    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x006753A0
 */
void CScriptObject::LuaPCall(const char* scriptName, const char* const* args, LuaPlus::LuaObject* obj)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (args && *args) ? *args : nullptr);
    LuaPush(lstate, obj);

    if (lua_pcall(lstate, 3, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005C9480 (FUN_005C9480, Moho::CScriptObject::RunScript_Int)
 */
void CScriptObject::RunScriptInt(const char* const scriptName, const int intValue)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, intValue);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005D0540 (FUN_005D0540, Moho::CScriptObject::RunScript_Obj_Num)
 */
float CScriptObject::RunScriptObjNum(const char* const scriptName)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return 0.0f;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj);
    return LuaValueToFloat(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }

  return 0.0f;
}

/**
 * Address: 0x005D06B0 (FUN_005D06B0, Moho::CScriptObject::RunScript_Weap)
 */
void CScriptObject::RunScriptWeapon(const char* const scriptName, UnitWeapon* const weapon)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, weapon);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005EC1C0 (FUN_005EC1C0, Moho::CScriptObject::RunScript_Obj)
 */
void CScriptObject::RunScriptUnit(const char* const scriptName, Unit* const unit)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, unit);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005F48A0 (FUN_005F48A0, Moho::CScriptObject::RunScript_Bool)
 */
bool CScriptObject::RunScriptBool(const char* const scriptName)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x005FCA70 (FUN_005FCA70, Moho::CScriptObject::GetLuaValue)
 */
float CScriptObject::GetLuaValue(const char* const key) const
{
  LuaPlus::LuaState* const state = mLuaObj.GetActiveState();
  if (!state) {
    return 0.0f;
  }

  lua_State* const lstate = state->GetCState();
  if (!lstate) {
    return 0.0f;
  }

  const int stackTop = lua_gettop(lstate);
  const LuaPlus::LuaObject value = mLuaObj.GetByName(key);
  const_cast<LuaPlus::LuaObject&>(value).PushStack(lstate);
  const float out = static_cast<float>(lua_tonumber(lstate, -1));
  lua_settop(lstate, stackTop);
  return out;
}

/**
 * Address: 0x005FCB70 (FUN_005FCB70, Moho::CScriptObject::SetLuaValue)
 */
void CScriptObject::SetLuaValue(const char* const key, const float value)
{
  (void)mLuaObj.GetActiveState();
  mLuaObj.SetNumber(key, value);
}

/**
 * Address: 0x005FD1C0 (FUN_005FD1C0, Moho::CScriptObject::RunScript_Weakunit)
 */
void CScriptObject::RunScriptWeakUnit(const char* const scriptName, const WeakPtr<Unit>& unitLink)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject unitObject = ResolveUnitLuaObjectFromWeakLink(unitLink);
    fn(mLuaObj, unitObject);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x00605600 (FUN_00605600, Moho::CScriptObject::RunScript_Weakent)
 */
void CScriptObject::RunScriptWeakEntity(const char* const scriptName, const WeakPtr<Entity>& entityLink)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject entityObject = ResolveEntityLuaObjectFromWeakLink(entityLink);
    fn(mLuaObj, entityObject);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x00633070 (FUN_00633070, Moho::CScriptObject::Call_Str)
 */
void CScriptObject::CallString(const char* const scriptName, const std::string& stringValue)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    std::string valueCopy = stringValue;
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, valueCopy);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x00638970 (FUN_00638970, Moho::CScriptObject::RunScript_StrNum3)
 */
void CScriptObject::RunScriptStringNum3(
  const char* const scriptName,
  const char* const text,
  const float a,
  const float b,
  const float c
)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, text ? text : "", a, b, c);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0067F180 (FUN_0067F180, Moho::CScriptObject::RunScript_Ent)
 */
void CScriptObject::RunScriptEntity(const char* const scriptName, Entity* const entityArg)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, entityArg);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0067F2E0 (FUN_0067F2E0, Moho::CScriptObject::RunScript_Num2)
 */
void CScriptObject::RunScriptNum2(const char* const scriptName, const float a, const float b)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, a, b);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0069F550 (FUN_0069F550, Moho::CScriptObject::RunScriptBool)
 */
void CScriptObject::RunScriptWithBool(const char* const scriptName, const bool value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, value);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x006B07D0 (FUN_006B07D0, Moho::CScriptObject::RunScript_ObjStr)
 */
void CScriptObject::RunScriptObjectString(
  const char* const scriptName,
  const LuaPlus::LuaObject& objectArg,
  const char* const text
)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, objectArg, text ? text : "");
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0078A870 (FUN_0078A870, Moho::CScriptObject::RunScript_Num)
 */
void CScriptObject::RunScriptNum(const char* const scriptName, const float value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, value);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0078AB70 (FUN_0078AB70, Moho::CScriptObject::RunScript_StrNum)
 */
void CScriptObject::RunScriptStringNum(const char* const scriptName, const char* const text, const float value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, text ? text : "", value);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x007950D0 (FUN_007950D0, Moho::CScriptObject::RunScript_String)
 */
bool CScriptObject::RunScriptStringBool(const char* const scriptName, const std::string& value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return false;
  }

  try {
    std::string valueCopy = value;
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj, valueCopy);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x00795260 (FUN_00795260, Moho::CScriptObject::RunScript_IntObject)
 */
void CScriptObject::RunScriptIntObject(
  const char* const scriptName,
  const int intValue,
  const LuaPlus::LuaObject& objectArg
)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, intValue, objectArg);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x007953D0 (FUN_007953D0, Moho::CScriptObject::RunScript_OnCharPressed)
 */
bool CScriptObject::RunScriptOnCharPressed(const int keyCode)
{
  constexpr const char* kOnCharPressed = "OnCharPressed";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnCharPressed);
  if (!script) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj, keyCode);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCharPressed, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCharPressed, "unknown exception");
  }

  return false;
}

/**
 * Address: 0x0057A500 (FUN_0057A500, Moho::CScriptObject::OnSpawnPreBuiltUnits)
 */
void CScriptObject::OnSpawnPreBuiltUnits()
{
  CallbackStr("OnSpawnPreBuiltUnits");
}

/**
 * Address: 0x00620760 (FUN_00620760, Moho::CScriptObject::RunScript_CreateWreckageProp)
 */
LuaPlus::LuaObject CScriptObject::RunScriptCreateWreckageProp(const float reclaimFraction)
{
  constexpr const char* kCreateWreckageProp = "CreateWreckageProp";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kCreateWreckageProp);
  if (!script) {
    return {};
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    return fn(mLuaObj, reclaimFraction);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kCreateWreckageProp, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kCreateWreckageProp, "unknown exception");
  }

  return {};
}

/**
 * Address: 0x006B0660 (FUN_006B0660, Moho::CScriptObject::RunScript_OnAdjacentTo)
 */
void CScriptObject::RunScriptOnAdjacentTo(Unit* const sourceUnit, Unit* const adjacentUnit)
{
  constexpr const char* kOnAdjacentTo = "OnAdjacentTo";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnAdjacentTo);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceUnit, adjacentUnit);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnAdjacentTo, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnAdjacentTo, "unknown exception");
  }
}

/**
 * Address: 0x006DD430 (FUN_006DD430, Moho::CScriptObject::GetWeaponClass)
 */
LuaPlus::LuaObject CScriptObject::GetWeaponClass(const LuaPlus::LuaObject& weaponBlueprintClass)
{
  constexpr const char* kGetWeaponClass = "GetWeaponClass";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kGetWeaponClass);
  if (!script) {
    return {};
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    return fn(mLuaObj, weaponBlueprintClass);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kGetWeaponClass, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kGetWeaponClass, "unknown exception");
  }

  return {};
}

/**
 * Address: 0x005EBED0 (FUN_005EBED0, Moho::CScriptObject::RunScript_Unit_Bool)
 */
bool CScriptObject::RunScriptUnitBool(const char* const scriptName, Unit* const unitArg)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj, unitArg);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x00581930
 */
void CScriptObject::LuaCall(const char* fileName, LuaPlus::LuaObject* obj)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, fileName);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    LuaPush(lstate, obj);

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005EC040 (FUN_005EC040, Moho::CScriptObject::RunScript_UnitOnDamage)
 */
void CScriptObject::RunScriptUnitOnDamage(Unit* const sourceUnit, const int amount, const bool canTakeDamageFlag)
{
  constexpr const char* kOnDamage = "OnDamage";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnDamage);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceUnit, amount, canTakeDamageFlag, "Damage");
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, "unknown exception");
  }
}

/**
 * Address: 0x005FC730 (FUN_005FC730, Moho::CScriptObject::OnStopBuild)
 *
 * What it does:
 * Invokes script callback `OnStopBuild(self, reason, unitObject)` when present.
 */
void CScriptObject::OnStopBuild(const WeakPtr<Unit>& unitLink, const std::string& reason)
{
  constexpr const char* kOnStopBuild = "OnStopBuild";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnStopBuild);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject unitObject = ResolveUnitLuaObjectFromWeakLink(unitLink);
    fn(mLuaObj, reason, unitObject);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStopBuild, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStopBuild, "unknown exception");
  }
}

/**
 * Address: 0x005FC8E0 (FUN_005FC8E0, Moho::CScriptObject::RunScript_OnStartBuild)
 *
 * What it does:
 * Invokes `OnStartBuild(self, focusUnit, buildAction)` callback when present.
 */
void CScriptObject::RunScriptOnStartBuild(Unit* const focusUnit, const std::string& buildAction)
{
  constexpr const char* kOnStartBuild = "OnStartBuild";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnStartBuild);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, focusUnit, buildAction);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStartBuild, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStartBuild, "unknown exception");
  }
}

/**
 * Address: 0x005FCBF0 (FUN_005FCBF0, Moho::CScriptObject::RunScript_OnBuildProgress)
 *
 * What it does:
 * Invokes `OnBuildProgress(self, sourceUnit, previousProgress, currentProgress)` callback when present.
 */
void CScriptObject::RunScriptOnBuildProgress(
  const WeakPtr<Unit>& sourceUnitLink,
  const float previousProgress,
  const float currentProgress
)
{
  constexpr const char* kOnBuildProgress = "OnBuildProgress";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnBuildProgress);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject sourceUnitObject = ResolveUnitLuaObjectFromWeakLink(sourceUnitLink);
    fn(mLuaObj, sourceUnitObject, previousProgress, currentProgress);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnBuildProgress, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnBuildProgress, "unknown exception");
  }
}

/**
 * Address: 0x005C92C0 (FUN_005C92C0, Moho::CScriptObject::RunScript_OnIntelChange)
 *
 * What it does:
 * Invokes `OnIntelChange(self, blip, intelSenseName, gained)` callback when present.
 */
void CScriptObject::RunScriptOnIntelChange(
  ReconBlip* const blip,
  const std::string& intelSenseName,
  const bool gained
)
{
  constexpr const char* kOnIntelChange = "OnIntelChange";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnIntelChange);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, blip, intelSenseName, gained);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnIntelChange, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnIntelChange, "unknown exception");
  }
}

/**
 * Address: 0x0073A330 (FUN_0073A330, Moho::CScriptObject::RunScript_OnGetDamageAbsorption)
 *
 * What it does:
 * Invokes `OnGetDamageAbsorption(self, sourceEntity, amount, damageType)` and
 * returns the numeric script result (or 0.0 on failure/missing callback).
 */
float CScriptObject::RunScriptOnGetDamageAbsorption(
  const WeakPtr<Entity>& sourceLink,
  const float amount,
  const std::string& damageType
)
{
  constexpr const char* kOnGetDamageAbsorption = "OnGetDamageAbsorption";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnGetDamageAbsorption);
  if (!script) {
    return 0.0f;
  }

  try {
    WeakPtr<Entity> guardedSource{};
    guardedSource.ResetFromObject(sourceLink.GetObjectPtr());

    std::string damageTypeCopy = damageType;
    LuaPlus::LuaObject selfObject(mLuaObj);
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    return CallObjectWeakEntityNumStringNum(fn, selfObject, amount, damageTypeCopy, guardedSource);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnGetDamageAbsorption, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnGetDamageAbsorption, "unknown exception");
  }

  return 0.0f;
}

/**
 * Address: 0x0073A4F0 (FUN_0073A4F0, Moho::CScriptObject::RunScript_EntityOnDamage)
 *
 * What it does:
 * Invokes `OnDamage(self, amount, payload, damageType, sourceEntity)` callback.
 */
void CScriptObject::RunScriptEntityOnDamage(
  const WeakPtr<Entity>& sourceLink,
  const float amount,
  const LuaPlus::LuaObject& payload,
  const std::string& damageType
)
{
  constexpr const char* kOnDamage = "OnDamage";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnDamage);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    LuaPlus::LuaObject selfObject(mLuaObj);
    LuaPlus::LuaObject payloadObject(payload);
    std::string damageTypeCopy = damageType;
    WeakPtr<Entity> weakSource{};
    weakSource.ResetFromObject(sourceLink.GetObjectPtr());
    CallObjectNumObjectStringWeakEntity(fn, selfObject, amount, payloadObject, damageTypeCopy, weakSource);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, "unknown exception");
  }
}

/**
 * Address: 0x00598660 (FUN_00598660, Moho::CScriptObject::RunScript_OnCollision)
 *
 * What it does:
 * Invokes `OnCollision(self, otherObject, a, b, c, d)` callback when present.
 */
void CScriptObject::RunScriptOnCollision(
  const LuaPlus::LuaObject& otherObject,
  const float collisionParamA,
  const float collisionParamB,
  const float collisionParamC,
  const float collisionParamD
)
{
  constexpr const char* kOnCollision = "OnCollision";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnCollision);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, otherObject, collisionParamA, collisionParamB, collisionParamC, collisionParamD);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCollision, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCollision, "unknown exception");
  }
}

/**
 * Address: 0x005FCD80 (FUN_005FCD80, Moho::CScriptObject::RunScript_OnBeingBuiltProgress)
 *
 * What it does:
 * Invokes `OnBeingBuiltProgress(self, sourceUnit, progress, buildRate)` callback when present.
 */
void CScriptObject::RunScriptOnBeingBuiltProgress(
  Unit* const sourceUnit,
  const float progress,
  const float buildRate
)
{
  constexpr const char* kOnBeingBuiltProgress = "OnBeingBuiltProgress";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnBeingBuiltProgress);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceUnit, progress, buildRate);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnBeingBuiltProgress, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnBeingBuiltProgress, "unknown exception");
  }
}

/**
 * Address: 0x00602CA0 (FUN_00602CA0, Moho::CScriptObject::StartTransportBeamUp)
 *
 * What it does:
 * Invokes `OnStartTransportBeamUp(self, attachBone, sourceUnit)` callback when present.
 */
void CScriptObject::StartTransportBeamUp(const WeakPtr<Unit>& sourceUnitLink, const int attachBone)
{
  constexpr const char* kOnStartTransportBeamUp = "OnStartTransportBeamUp";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnStartTransportBeamUp);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject sourceUnitObject = ResolveUnitLuaObjectFromWeakLink(sourceUnitLink);
    fn(mLuaObj, attachBone, sourceUnitObject);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStartTransportBeamUp, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStartTransportBeamUp, "unknown exception");
  }
}

/**
 * Address: 0x0060C590 (FUN_0060C590, Moho::CScriptObject::RunScript_OnTeleportUnit)
 *
 * What it does:
 * Invokes `OnTeleportUnit(self, argA, argB, argC)` callback when present.
 */
void CScriptObject::RunScriptOnTeleportUnit(
  const LuaPlus::LuaObject& argA,
  const LuaPlus::LuaObject& argB,
  const LuaPlus::LuaObject& argC
)
{
  constexpr const char* kOnTeleportUnit = "OnTeleportUnit";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnTeleportUnit);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, argA, argB, argC);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnTeleportUnit, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnTeleportUnit, "unknown exception");
  }
}

/**
 * Address: 0x006B0AB0 (FUN_006B0AB0, Moho::CScriptObject::RunScript_UnitOnKilled)
 *
 * What it does:
 * Invokes `OnKilled(self, sourceEntity, reason, value)` callback for unit-owned scripts.
 */
void CScriptObject::RunScriptUnitOnKilled(Entity* const sourceEntity, const char* const reason, const float value)
{
  constexpr const char* kOnKilled = "OnKilled";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnKilled);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceEntity, reason, value);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnKilled, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnKilled, "unknown exception");
  }
}

/**
 * Address: 0x006B0C50 (FUN_006B0C50, Moho::CScriptObject::RunScript_OnTerrainTypeChange)
 *
 * What it does:
 * Invokes `OnTerrainTypeChange(self, oldTerrain, newTerrain)` callback when present.
 */
void CScriptObject::RunScriptOnTerrainTypeChange(
  const LuaPlus::LuaObject& oldTerrain,
  const LuaPlus::LuaObject& newTerrain
)
{
  constexpr const char* kOnTerrainTypeChange = "OnTerrainTypeChange";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnTerrainTypeChange);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, oldTerrain, newTerrain);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnTerrainTypeChange, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnTerrainTypeChange, "unknown exception");
  }
}

/**
 * Address: 0x006B0DD0 (FUN_006B0DD0, Moho::CScriptObject::RunScript_WeakunitStr)
 *
 * What it does:
 * Invokes `OnStopBeingBuilt(self, sourceUnit, layerName)` callback when present.
 */
void CScriptObject::RunScriptOnStopBeingBuilt(const WeakPtr<Unit>& sourceUnitLink, const char* const layerName)
{
  constexpr const char* kOnStopBeingBuilt = "OnStopBeingBuilt";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnStopBeingBuilt);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    const LuaPlus::LuaObject sourceUnitObject = ResolveUnitLuaObjectFromWeakLink(sourceUnitLink);
    fn(mLuaObj, sourceUnitObject, layerName ? layerName : "");
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStopBeingBuilt, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnStopBeingBuilt, "unknown exception");
  }
}

/**
 * Address: 0x006DD5D0 (FUN_006DD5D0, Moho::CScriptObject::RunScript_OnCollisionCheckWeapon)
 *
 * What it does:
 * Invokes `OnCollisionCheckWeapon(self, weapon)` and returns Lua-bool result.
 */
bool CScriptObject::RunScriptOnCollisionCheckWeapon(UnitWeapon* const weapon)
{
  constexpr const char* kOnCollisionCheckWeapon = "OnCollisionCheckWeapon";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnCollisionCheckWeapon);
  if (!script) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj, weapon);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCollisionCheckWeapon, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnCollisionCheckWeapon, "unknown exception");
  }

  return false;
}

/**
 * Address: 0x006FAC00 (FUN_006FAC00, Moho::CScriptObject::RunScript_PropOnKilled)
 *
 * What it does:
 * Invokes `OnKilled(self, sourceProp, reason, value)` callback for prop-owned scripts.
 */
void CScriptObject::RunScriptPropOnKilled(Prop* const sourceProp, const char* const reason, const float value)
{
  constexpr const char* kOnKilled = "OnKilled";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnKilled);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceProp, reason, value);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnKilled, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnKilled, "unknown exception");
  }
}

/**
 * Address: 0x007CB940
 */
void CScriptObject::RunScriptObj(LuaPlus::LuaObject& out, const char* name)
{
  out = LuaPlus::LuaObject{};

  gpg::core::FastVector<LuaPlus::LuaObject> returns;
  if (!RunScriptMultiRet(
        name,
        returns,
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{}
      )) {
    return;
  }

  if (!returns.Empty()) {
    out = returns[0];
  }
}

/**
 * Address: 0x00675CF0
 */
void CScriptObject::LuaInvoke3_DiscardReturn(
  LuaPlus::LuaObject& func, LuaPlus::LuaObject& selfObj, const char* stringArg, LuaPlus::LuaObject& payloadObj
)
{
  LuaPlus::LuaState* state = func.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  func.PushStack(lstate);
  selfObj.PushStack(lstate);
  lua_pushstring(lstate, stringArg ? stringArg : "");
  payloadObj.PushStack(lstate);

  lua_call(lstate, 3, 1);
  lua_settop(lstate, stackTop);
}
