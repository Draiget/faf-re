#include "moho/script/ScriptedDecal.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <typeinfo>

#include "lua/LuaRuntimeTypes.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/RCamManager.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldSession.h"
#include "moho/script/CScriptEvent.h"
#include "Wm3Vector2.h"

using namespace moho;

namespace moho
{
  template <>
  class CScrLuaMetatableFactory<ScriptedDecal> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<ScriptedDecal>) == 0x08, "CScrLuaMetatableFactory<ScriptedDecal> size must be 0x08");
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kScriptedDecalLuaClassName = "ScriptedDecal";

  constexpr const char* kScriptedDecalSetTextureName = "SetTexture";
  constexpr const char* kScriptedDecalSetTextureHelpText = "Set the texture and add it to the decal manager";
  constexpr const char* kScriptedDecalSetScaleName = "SetScale";
  constexpr const char* kScriptedDecalSetScaleHelpText = "Scale the text";
  constexpr const char* kScriptedDecalSetPositionByScreenName = "SetPositionByScreen";
  constexpr const char* kScriptedDecalSetPositionByScreenHelpText = "Set the position based on screen space mouse coords";
  constexpr const char* kScriptedDecalSetPositionName = "SetPosition";
  constexpr const char* kScriptedDecalSetPositionHelpText = "Set the position based on wolrd coords";
  constexpr const char* kScriptedDecalDestroyName = "Destroy";
  constexpr const char* kScriptedDecalDestroyHelpText = "Kill it";
  constexpr const char* kScriptedDecalCreateDecalName = "_c_CreateDecal";
  constexpr const char* kScriptedDecalCreateDecalHelpText = "Create a decal in the user layer";

  constexpr std::uintptr_t kDeletedRuntimeLinkTag = 0x4;

  class IScriptedDecalWorldCamera
  {
  public:
    virtual void Slot00() = 0;
    virtual void Slot01() = 0;
    virtual void Slot02() = 0;
    virtual void Slot03() = 0;
    virtual void Slot04() = 0;
    virtual void Slot05() = 0;
    virtual void Slot06() = 0;
    virtual Wm3::Vector3f* CameraScreenToSurface(Wm3::Vector3f* outSurfacePoint, const Wm3::Vector2f* screenPoint) = 0;
  };

  class IDecalRuntimeEntry
  {
  public:
    virtual void Slot00() = 0;
    virtual void Slot01_SetTexturePath(const std::string& texturePath, std::int32_t lane) = 0;
    virtual void Slot02() = 0;
    virtual void Slot03_SetUnknown(std::int32_t value) = 0;
    virtual void Slot04() = 0;
    virtual void Slot05() = 0;
    virtual void Slot06_CommitTransform() = 0;
  };

  struct ScriptedDecalRuntimeEntryView
  {
    IDecalRuntimeEntry* mVftable;          // +0x00
    moho::ScriptedDecalRuntimeLink mLink;  // +0x04
    moho::SpatialDB_MeshInstance mSpatialEntry; // +0x0C
    std::uint8_t pad_0014_001C[0x1C - 0x14];
    std::int32_t mDecalMode;               // +0x1C
    std::int32_t mRuntimeFlags;            // +0x20
    std::uint8_t pad_0024_005C[0x5C - 0x24];
    float mScaleX;                         // +0x5C
    float mScaleY;                         // +0x60
    float mScaleZ;                         // +0x64
    Wm3::Vector3f mWorldPosition;          // +0x68
    std::uint8_t pad_0074_0080[0x80 - 0x74];
    float mDissolveCutoff;                 // +0x80
    float mDissolveFade;                   // +0x84
  };

  static_assert(offsetof(ScriptedDecalRuntimeEntryView, mLink) == 0x04, "ScriptedDecalRuntimeEntryView::mLink offset must be 0x04");
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mSpatialEntry) == 0x0C,
    "ScriptedDecalRuntimeEntryView::mSpatialEntry offset must be 0x0C"
  );
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mDecalMode) == 0x1C,
    "ScriptedDecalRuntimeEntryView::mDecalMode offset must be 0x1C"
  );
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mRuntimeFlags) == 0x20,
    "ScriptedDecalRuntimeEntryView::mRuntimeFlags offset must be 0x20"
  );
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mScaleX) == 0x5C,
    "ScriptedDecalRuntimeEntryView::mScaleX offset must be 0x5C"
  );
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mWorldPosition) == 0x68,
    "ScriptedDecalRuntimeEntryView::mWorldPosition offset must be 0x68"
  );
  static_assert(
    offsetof(ScriptedDecalRuntimeEntryView, mDissolveCutoff) == 0x80,
    "ScriptedDecalRuntimeEntryView::mDissolveCutoff offset must be 0x80"
  );

  [[nodiscard]] bool IsValidWorldPosition(const Wm3::Vector3f& worldPosition) noexcept
  {
    return std::isfinite(worldPosition.x) && std::isfinite(worldPosition.y) && std::isfinite(worldPosition.z);
  }

  [[nodiscard]] gpg::RType* CachedScriptedDecalType()
  {
    if (!ScriptedDecal::sType) {
      ScriptedDecal::sType = gpg::LookupRType(typeid(ScriptedDecal));
    }
    return ScriptedDecal::sType;
  }

  [[nodiscard]] gpg::RRef MakeScriptedDecalRef(ScriptedDecal* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedScriptedDecalType();
    return ref;
  }

  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("user"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("user");
    return fallbackSet;
  }

  [[nodiscard]] ScriptedDecalRuntimeEntryView*
  RuntimeEntryFromLink(moho::ScriptedDecalRuntimeLink* const runtimeLink) noexcept
  {
    if (runtimeLink == nullptr) {
      return nullptr;
    }

    const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(runtimeLink);
    if (linkAddress <= kDeletedRuntimeLinkTag) {
      return nullptr;
    }

    return reinterpret_cast<ScriptedDecalRuntimeEntryView*>(
      linkAddress - offsetof(ScriptedDecalRuntimeEntryView, mLink)
    );
  }

  /**
   * Address: 0x008679E0 (FUN_008679E0, sub_8679E0)
   *
   * What it does:
   * Relinks one scripted-decal runtime-link node into or out of the runtime
   * owner chain (`runtimeOwner + 0x04` link lane).
   */
  moho::ScriptedDecalRuntimeLink*
  RelinkRuntimeNode(moho::ScriptedDecalRuntimeLink* const linkNode, void* const runtimeOwner) noexcept
  {
    auto* const newHead = runtimeOwner
      ? reinterpret_cast<moho::ScriptedDecalRuntimeLink*>(
          reinterpret_cast<std::uintptr_t>(runtimeOwner) + sizeof(std::uint32_t)
        )
      : nullptr;

    moho::ScriptedDecalRuntimeLink* const currentHead = linkNode->mHead;
    if (newHead == currentHead) {
      return linkNode;
    }

    if (currentHead != nullptr) {
      moho::ScriptedDecalRuntimeLink* cursor = currentHead;
      while (cursor->mHead != linkNode) {
        cursor = reinterpret_cast<moho::ScriptedDecalRuntimeLink*>(
          reinterpret_cast<std::uintptr_t>(cursor->mHead) + sizeof(std::uint32_t)
        );
      }
      cursor->mHead = linkNode->mNext;
    }

    linkNode->mHead = newHead;
    if (newHead != nullptr) {
      linkNode->mNext = newHead->mHead;
      newHead->mHead = linkNode;
    } else {
      linkNode->mNext = nullptr;
    }

    return linkNode;
  }

  [[nodiscard]] IDecalRuntimeService* ResolveDecalService(CWldSession* const) noexcept
  {
    // Terrain decal-manager accessor is still being recovered for IWldTerrainRes.
    return nullptr;
  }
} // namespace

CScrLuaMetatableFactory<ScriptedDecal> CScrLuaMetatableFactory<ScriptedDecal>::sInstance{};

CScrLuaMetatableFactory<ScriptedDecal>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<ScriptedDecal>& CScrLuaMetatableFactory<ScriptedDecal>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject CScrLuaMetatableFactory<ScriptedDecal>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

gpg::RType* ScriptedDecal::sType = nullptr;

/**
 * Address: 0x0087EB60 (FUN_0087EB60, Moho::ScriptedDecal::ScriptedDecal)
 *
 * What it does:
 * Initializes one scripted decal from the active world session and the
 * supplied Lua object payload.
 */
ScriptedDecal::ScriptedDecal(CWldSession* const session, LuaPlus::LuaObject luaObject)
  : CScriptObject()
{
  mRuntimeLink.mHead = nullptr;
  mRuntimeLink.mNext = nullptr;
  mDynamicTexture.reset();
  mDecalService = nullptr;
  mWorldCamera = nullptr;
  mScaleX = 1.0f;
  mScaleY = 1.0f;
  mScaleZ = 1.0f;
  mDecalService = ResolveDecalService(session);
  mWorldCamera = CAM_GetManager()->GetCamera("WorldCamera");

  SetLuaObject(luaObject);
}

/**
 * Address: 0x0087EC20 (FUN_0087EC20, non-deleting body)
 */
ScriptedDecal::~ScriptedDecal()
{
  ScriptedDecalRuntimeEntryView* const runtimeEntry = RuntimeEntryFromLink(mRuntimeLink.mHead);
  if (runtimeEntry && mDecalService) {
    mDecalService->RemoveRuntimeDecal(runtimeEntry);
  }

  RelinkRuntimeNode(&mRuntimeLink, nullptr);
}

/**
 * Address: 0x0087F030 (FUN_0087F030, ?GetClass@ScriptedDecal@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* ScriptedDecal::GetClass() const
{
  return CachedScriptedDecalType();
}

/**
 * Address: 0x0087F050 (FUN_0087F050, ?GetDerivedObjectRef@ScriptedDecal@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef ScriptedDecal::GetDerivedObjectRef()
{
  return MakeScriptedDecalRef(this);
}

/**
 * Address: 0x0087F1E0 (FUN_0087F1E0, cfunc__c_CreateDecal)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc__c_CreateDecalL`.
 */
int moho::cfunc__c_CreateDecal(lua_State* const luaContext)
{
  return cfunc__c_CreateDecalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F200 (FUN_0087F200, func__c_CreateDecal_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `_c_CreateDecal`.
 */
moho::CScrLuaInitForm* moho::func__c_CreateDecal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalCreateDecalName,
    &moho::cfunc__c_CreateDecal,
    nullptr,
    "<global>",
    kScriptedDecalCreateDecalHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F260 (FUN_0087F260, cfunc__c_CreateDecalL)
 *
 * What it does:
 * Creates one scripted decal from the active world session and returns its
 * Lua object, or nil when no session is active.
 */
int moho::cfunc__c_CreateDecalL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalCreateDecalHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
    ScriptedDecal* const decal = new ScriptedDecal(session, decalObject);
    decal->mLuaObj.PushStack(state);
    return 1;
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0087ECE0 (FUN_0087ECE0, Moho::ScriptedDecal::SetPosition)
 *
 * What it does:
 * Validates and stores one world-space position, then updates the linked
 * runtime decal entry.
 */
bool ScriptedDecal::SetPosition(const Wm3::Vector3f* const worldPosition)
{
  if (worldPosition == nullptr || !IsValidWorldPosition(*worldPosition)) {
    return false;
  }

  if (mDecalService) {
    mDecalService->Slot27_NotifyRuntimeUpdate();
  }

  mWorldPosition = *worldPosition;
  mWorldPosition.x -= mScaleX * 0.5f;
  mWorldPosition.z -= mScaleZ * 0.5f;

  if (ScriptedDecalRuntimeEntryView* const runtimeEntry = RuntimeEntryFromLink(mRuntimeLink.mHead); runtimeEntry != nullptr) {
    runtimeEntry->mWorldPosition = mWorldPosition;
    runtimeEntry->mVftable->Slot06_CommitTransform();
  }

  return true;
}

/**
 * Address: 0x0087EDE0 (FUN_0087EDE0, Moho::ScriptedDecal::SetTexture)
 *
 * What it does:
 * Loads one dynamic texture sheet by path and refreshes this decal's
 * runtime decal-entry state.
 */
ScriptedDecal* ScriptedDecal::SetTexture(const char* const texturePath)
{
  if (
    mDecalService != nullptr && mRuntimeLink.mHead != nullptr &&
    reinterpret_cast<std::uintptr_t>(mRuntimeLink.mHead) != kDeletedRuntimeLinkTag
  ) {
    if (ScriptedDecalRuntimeEntryView* const runtimeEntry = RuntimeEntryFromLink(mRuntimeLink.mHead); runtimeEntry != nullptr) {
      mDecalService->RemoveRuntimeDecal(runtimeEntry);
    }
  }

  ID3DDeviceResources::TextureResourceHandle loadedTexture;
  if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
    if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
      resources->GetTexture(loadedTexture, texturePath, 0, true);
    }
  }
  mDynamicTexture = loadedTexture;

  if (mDynamicTexture && mDecalService != nullptr) {
    void* const runtimeOwner = mDecalService->Slot07(0);
    RelinkRuntimeNode(&mRuntimeLink, runtimeOwner);

    if (ScriptedDecalRuntimeEntryView* const runtimeEntry = RuntimeEntryFromLink(mRuntimeLink.mHead); runtimeEntry != nullptr) {
      runtimeEntry->mRuntimeFlags = 0;
      runtimeEntry->mDecalMode = 4;

      const std::string safeTexturePath = (texturePath != nullptr) ? texturePath : "";
      runtimeEntry->mVftable->Slot01_SetTexturePath(safeTexturePath, 0);
      runtimeEntry->mDissolveFade = 0.0f;
      runtimeEntry->mDissolveCutoff = std::numeric_limits<float>::max();
      runtimeEntry->mSpatialEntry.UpdateDissolveCutoff(runtimeEntry->mDissolveCutoff);
      runtimeEntry->mVftable->Slot03_SetUnknown(0);
      mDecalService->Slot18_CommitRuntimeDecal(runtimeEntry);
    }
  }

  return this;
}

/**
 * Address: 0x0087F360 (FUN_0087F360, cfunc_ScriptedDecalSetTexture)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetTextureL`.
 */
int moho::cfunc_ScriptedDecalSetTexture(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetTextureL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F380 (FUN_0087F380, func_ScriptedDecalSetTexture_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetTexture(path)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetTexture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetTextureName,
    &moho::cfunc_ScriptedDecalSetTexture,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetTextureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F3E0 (FUN_0087F3E0, cfunc_ScriptedDecalSetTextureL)
 *
 * What it does:
 * Validates one scripted decal plus one texture-path string, then applies the texture.
 */
int moho::cfunc_ScriptedDecalSetTextureL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetTextureHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const char* const texturePath = lua_tostring(rawState, 2);
  if (texturePath == nullptr) {
    LuaPlus::LuaStackObject textureArg(state, 2);
    LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
    return 0;
  }

  decal->SetTexture(texturePath);
  return 0;
}

/**
 * Address: 0x0087F4C0 (FUN_0087F4C0, cfunc_ScriptedDecalSetScale)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetScaleL`.
 */
int moho::cfunc_ScriptedDecalSetScale(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetScaleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F4E0 (FUN_0087F4E0, func_ScriptedDecalSetScale_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetScale(scaleVec3)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetScale_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetScaleName,
    &moho::cfunc_ScriptedDecalSetScale,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetScaleHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F540 (FUN_0087F540, cfunc_ScriptedDecalSetScaleL)
 *
 * What it does:
 * Reads one scale vector, updates runtime decal scale lanes, and reapplies position.
 */
int moho::cfunc_ScriptedDecalSetScaleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetScaleHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const LuaPlus::LuaObject scaleObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f scale = SCR_FromLuaCopy<Wm3::Vector3f>(scaleObject);

  decal->mScaleX = scale.x;
  decal->mScaleY = scale.y;
  decal->mScaleZ = scale.z;

  if (ScriptedDecalRuntimeEntryView* const runtimeEntry = RuntimeEntryFromLink(decal->mRuntimeLink.mHead); runtimeEntry != nullptr) {
    runtimeEntry->mScaleX = scale.x;
    runtimeEntry->mScaleY = scale.y;
    runtimeEntry->mScaleZ = scale.z;
    runtimeEntry->mVftable->Slot06_CommitTransform();
  }

  (void)decal->SetPosition(&decal->mWorldPosition);
  return 0;
}

/**
 * Address: 0x0087F660 (FUN_0087F660, cfunc_ScriptedDecalSetPositionByScreen)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_ScriptedDecalSetPositionByScreenL`.
 */
int moho::cfunc_ScriptedDecalSetPositionByScreen(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetPositionByScreenL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F680 (FUN_0087F680, func_ScriptedDecalSetPositionByScreen_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetPositionByScreen(screenPoint)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetPositionByScreen_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetPositionByScreenName,
    &moho::cfunc_ScriptedDecalSetPositionByScreen,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetPositionByScreenHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F6E0 (FUN_0087F6E0, cfunc_ScriptedDecalSetPositionByScreenL)
 *
 * What it does:
 * Converts one screen-space point via world camera projection and applies it.
 */
int moho::cfunc_ScriptedDecalSetPositionByScreenL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kScriptedDecalSetPositionByScreenHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  const LuaPlus::LuaObject screenPointObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector2f screenPoint = SCR_FromLuaCopy<Wm3::Vector2f>(screenPointObject);

  Wm3::Vector3f worldPoint{};
  if (decal->mWorldCamera != nullptr) {
    auto* const camera = reinterpret_cast<IScriptedDecalWorldCamera*>(decal->mWorldCamera);
    camera->CameraScreenToSurface(&worldPoint, &screenPoint);
  }

  (void)decal->SetPosition(&worldPoint);
  return 0;
}

/**
 * Address: 0x0087F7E0 (FUN_0087F7E0, cfunc_ScriptedDecalSetPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalSetPositionL`.
 */
int moho::cfunc_ScriptedDecalSetPosition(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalSetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F800 (FUN_0087F800, func_ScriptedDecalSetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:SetPosition(worldPoint)` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalSetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalSetPositionName,
    &moho::cfunc_ScriptedDecalSetPosition,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalSetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F860 (FUN_0087F860, cfunc_ScriptedDecalSetPositionL)
 *
 * What it does:
 * Reads one world-space vector argument and applies it via `ScriptedDecal::SetPosition`.
 */
int moho::cfunc_ScriptedDecalSetPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalSetPositionHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);

  // Binary parity note (FUN_0087F860): argument lane is read from stack index 3.
  const LuaPlus::LuaObject worldPointObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vector3f worldPoint = SCR_FromLuaCopy<Wm3::Vector3f>(worldPointObject);
  (void)decal->SetPosition(&worldPoint);
  return 0;
}

/**
 * Address: 0x0087F950 (FUN_0087F950, cfunc_ScriptedDecalDestroy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_ScriptedDecalDestroyL`.
 */
int moho::cfunc_ScriptedDecalDestroy(lua_State* const luaContext)
{
  return cfunc_ScriptedDecalDestroyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0087F970 (FUN_0087F970, func_ScriptedDecalDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `ScriptedDecal:Destroy()` Lua binder.
 */
CScrLuaInitForm* moho::func_ScriptedDecalDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kScriptedDecalDestroyName,
    &moho::cfunc_ScriptedDecalDestroy,
    &CScrLuaMetatableFactory<ScriptedDecal>::Instance(),
    kScriptedDecalLuaClassName,
    kScriptedDecalDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0087F9D0 (FUN_0087F9D0, cfunc_ScriptedDecalDestroyL)
 *
 * What it does:
 * Resolves one scripted decal object and destroys it through virtual delete lane.
 */
int moho::cfunc_ScriptedDecalDestroyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kScriptedDecalDestroyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject decalObject(LuaPlus::LuaStackObject(state, 1));
  ScriptedDecal* const decal = SCR_FromLua_ScriptedDecal(decalObject, state);
  if (decal != nullptr) {
    delete decal;
  }

  return 0;
}



