#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCLuaWldUIProviderDestroyHelpText = "WldUIProvider:Destroy() - destroy the wldUIProvider";

  [[nodiscard]] gpg::RType* CachedCLuaWldUIProviderType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("CLuaWldUIProvider");
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("Moho::CLuaWldUIProvider");
      }
    }
    return cached;
  }

  /**
   * Address: 0x0086AC50 (FUN_0086AC50, func_GetCLuaWldUIProviderObjectOpt)
   *
   * What it does:
   * Resolves one optional `CLuaWldUIProvider` from Lua object payload; raises
   * Lua errors for non-game-object or incorrect-type payloads and returns
   * null for destroyed objects.
   */
  [[nodiscard]] moho::CLuaWldUIProvider* ResolveCLuaWldUIProviderOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    gpg::RType* const providerType = CachedCLuaWldUIProviderType();
    if (providerType == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, providerType);
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CLuaWldUIProvider*>(upcast.mObj);
  }
}


/**
 * Address: 0x0086A530 (??0CLuaWldUIProvider@Moho@@QAE@@Z, Moho::CLuaWldUIProvider::CLuaWldUIProvider)
 * Mangled: ??0CLuaWldUIProvider@Moho@@QAE@@Z
 *
 * IDA signature:
 * Moho::CLuaWldUIProvider *__thiscall Moho::CLuaWldUIProvider::CLuaWldUIProvider(
 *     Moho::CLuaWldUIProvider *this, LuaPlus::LuaObject *a2);
 *
 * What it does:
 * Constructs the multiple-inheritance world-UI provider: publishes the
 * `IWldUIProvider` sub-object vtable, default-constructs the embedded
 * `CScriptObject` base, seeds the prefetch-texture cache lane to empty, then
 * binds the incoming script object via the protected base helper. The
 * transient in-construction vtable publish and the final vtable publish are
 * emitted by the C++ front-end from the multiple-inheritance ctor sequence
 * (matching the `mov [esi], IWldUIProvider vftable` / `mov [esi],
 * CLuaWldUIProvider vftable` stores in the binary).
 */
moho::CLuaWldUIProvider::CLuaWldUIProvider(
  LuaPlus::LuaObject* const luaObject
)
  : IWldUIProvider()
  , CScriptObject()
{
  // mPrefetchData default-constructs empty: the three `mov [esi+3Ch/40h/44h], 0`
  // stores are its first/last/end.
  SetLuaObject(*luaObject);
}

/**
 * Address: 0x0086A650 (FUN_0086A650, Moho::CLuaWldUIProvider::StartLoadingDialog)
 *
 * What it does:
 * Dispatches the `StartLoadingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StartLoadingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StartLoadingDialog");
}

/**
 * Address: 0x0086A660 (FUN_0086A660, Moho::CLuaWldUIProvider::UpdateLoadingDialog)
 *
 * What it does:
 * Dispatches the `UpdateLoadingDialog` Lua callback with one float argument.
 */
void moho::CLuaWldUIProvider::UpdateLoadingDialog(
  const float deltaSeconds
)
{
  static_cast<CScriptObject*>(this)->RunScriptNum("UpdateLoadingDialog", deltaSeconds);
}

/**
 * Address: 0x0086A680 (FUN_0086A680, Moho::CLuaWldUIProvider::StopLoadingDialog)
 *
 * What it does:
 * Dispatches the `StopLoadingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StopLoadingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StopLoadingDialog");
}

/**
 * Address: 0x0086A690 (FUN_0086A690, Moho::CLuaWldUIProvider::StartWaitingDialog)
 *
 * What it does:
 * Dispatches the `StartWaitingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StartWaitingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StartWaitingDialog");
}

/**
 * Address: 0x0086A6A0 (FUN_0086A6A0, Moho::CLuaWldUIProvider::UpdateWaitingDialog)
 *
 * What it does:
 * Dispatches the `UpdateWaitingDialog` Lua callback with one float argument.
 */
void moho::CLuaWldUIProvider::UpdateWaitingDialog(
  const float deltaSeconds
)
{
  static_cast<CScriptObject*>(this)->RunScriptNum("UpdateWaitingDialog", deltaSeconds);
}

/**
 * Address: 0x0086A6C0 (FUN_0086A6C0, Moho::CLuaWldUIProvider::StopWaitingDialog)
 *
 * What it does:
 * Dispatches the `StopWaitingDialog` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::StopWaitingDialog()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("StopWaitingDialog");
}

/**
 * Address: 0x0086A6D0 (FUN_0086A6D0, Moho::CLuaWldUIProvider::OnStart)
 *
 * What it does:
 * Dispatches the `OnStart` Lua callback on the embedded script object base
 * lane.
 */
void moho::CLuaWldUIProvider::OnStart()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("OnStart");
}

/**
 * Address: 0x0086A8C0 (FUN_0086A8C0, Moho::CLuaWldUIProvider::DestroyGameInterface)
 *
 * What it does:
 * Dispatches the `DestroyGameInterface` Lua callback on the embedded script
 * object base lane.
 */
void moho::CLuaWldUIProvider::DestroyGameInterface()
{
  (void)static_cast<CScriptObject*>(this)->RunScript("DestroyGameInterface");
}
/**
 * Address: 0x0086AA50 (FUN_0086AA50, cfunc_CLuaWldUIProviderDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CLuaWldUIProviderDestroyL`.
 */
int moho::cfunc_CLuaWldUIProviderDestroy(
  lua_State* const luaContext
)
{
  return cfunc_CLuaWldUIProviderDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086AA70 (FUN_0086AA70, func_CLuaWldUIProviderDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `WldUIProvider:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CLuaWldUIProviderDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CLuaWldUIProviderDestroy,
    &moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance(),
    "CLuaWldUIProvider",
    kCLuaWldUIProviderDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086AAD0 (FUN_0086AAD0, cfunc_CLuaWldUIProviderDestroyL)
 *
 * What it does:
 * Resolves one optional world-ui provider object and destroys it when alive.
 */
int moho::cfunc_CLuaWldUIProviderDestroyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCLuaWldUIProviderDestroyHelpText);

  const LuaPlus::LuaObject providerObject(LuaPlus::LuaStackObject(state, 1));
  CLuaWldUIProvider* const provider = ResolveCLuaWldUIProviderOptionalOrError(providerObject, state);
  if (provider != nullptr) {
    delete static_cast<IWldUIProvider*>(provider);
    if (sWldUIProvider != nullptr) {
      delete sWldUIProvider;
      sWldUIProvider = nullptr;
    }
  }
  return 0;
}

/**
 * Address: 0x0086A380 (FUN_0086A380, Moho::CLuaWldUIProvider::GetClass)
 *
 * What it does:
 * Returns the reflection descriptor for the `CLuaWldUIProvider` type (cached,
 * looked up by name on first use). The empty stub returned nullptr, which
 * broke reflection (GetDerivedObjectRef packed a null type).
 */
gpg::RType* moho::CLuaWldUIProvider::GetClass() const
{
  return CachedCLuaWldUIProviderType();
}

/**
 * Address: 0x0086A3C0 (FUN_0086A3C0, Moho::CLuaWldUIProvider::GetDerivedObjectRef)
 *
 * IDA signature:
 * gpg::RRef *__thiscall Moho::CLuaWldUIProvider::GetDerivedObjectRef(
 *   CLuaWldUIProvider *this, gpg::RRef *out);
 *
 * What it does:
 * Packs `{this, GetClass()}` into a reflection reference handle.
 *
 * The `add esi, -4` at 0x0086A3CF is the compiler's, not the source's: this
 * override sits in the table for the `RObject` sub-object at +4 (vftable
 * 0x00E47D78), so it receives that sub-object and steps back to the complete
 * object. Spelling it `reinterpret_cast<char*>(this) - 4` here, where `this` is
 * already the complete object, published a reference 4 bytes before it.
 */
gpg::RRef moho::CLuaWldUIProvider::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x0086A6E0 (FUN_0086A6E0, Moho::CLuaWldUIProvider::CreateGameInterface)
 *
 * IDA signature:
 * void __thiscall Moho::CLuaWldUIProvider::CreateGameInterface(
 *   CLuaWldUIProvider *this, bool createGameInterface);
 *
 * What it does:
 * Runs the provider's `GetPrefetchTextures` script; if it returns a table of
 * texture paths, prefetches each one through the live D3D device resources into
 * mPrefetchData, then dispatches the `CreateGameInterface` script callback with
 * the create flag. The empty stub skipped both prefetch and the callback.
 */
void moho::CLuaWldUIProvider::CreateGameInterface(
  bool createGameInterface
)
{
  const LuaPlus::LuaObject prefetchTextures = RunScript("GetPrefetchTextures");
  if (!prefetchTextures.IsNil()) {
    if (!prefetchTextures.IsTable()) {
      throw std::runtime_error("GetPrefetchTextures did not return a table of strings");
    }

    for (LuaPlus::LuaTableIterator iter(const_cast<LuaPlus::LuaObject*>(&prefetchTextures), 1); !iter.m_isDone;
         iter.Next()) {
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      if (iter.m_isDone) {
        throw LuaPlus::LuaAssertion("IsValid()");
      }

      const char* const texturePath = iter.m_valueObj.GetString();
      boost::shared_ptr<PrefetchData> handle{};
      resources->LoadPrefetchData(handle, texturePath);
      mPrefetchData.push_back(handle);
    }
  }

  RunScript("CreateGameInterface", createGameInterface);
}
