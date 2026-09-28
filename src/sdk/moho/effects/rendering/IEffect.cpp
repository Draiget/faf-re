#include "moho/effects/rendering/IEffect.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/sim/Sim.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  gpg::RType* IEffect::sType = nullptr;
  gpg::RType* IEffect::sPointerType = nullptr;

  namespace
  {
    /**
     * Address: 0x0066CB30 (FUN_0066CB30)
     * Address: 0x00BFC0F0 (FUN_00BFC0F0, atexit destructor of the static `RPointerType<IEffect>` descriptor)
     *
     * What it does:
     * Constructs the static `RPointerType<IEffect>` descriptor that the
     * binary exposes as `Moho::IEffect::PointerType` and pre-registers it
     * under the `IEffect*` type-info key, so subsequent `LookupRType` queries
     * from the lazy `GetPointerType` lane resolve to this descriptor. The
     * binary holds the descriptor as a function-local static of
     * `GetPointerType`; it lives here because the preregister phase has to
     * construct it before any consumer looks up `IEffect*`.
     */
    gpg::RType* PreregisterIEffectPointerType()
    {
      static gpg::RPointerType<moho::IEffect> sDescriptor;
      gpg::PreRegisterRType(typeid(moho::IEffect*), &sDescriptor);
      return &sDescriptor;
    }
  } // namespace

  /**
   * Address: 0x0066C980 (FUN_0066C980, Moho::IEffect::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<IEffect>`
   * descriptor. After that, lazily caches the
   * `LookupRType(typeid(IEffect*))` result in `sPointerType` and returns it.
   */
  gpg::RType* IEffect::GetPointerType()
  {
    static const bool sOnceInit = (PreregisterIEffectPointerType(), true);
    (void)sOnceInit;

    if (!sPointerType) {
      sPointerType = gpg::LookupRType(typeid(IEffect*));
    }
    return sPointerType;
  }

  namespace
  {
    [[nodiscard]] LuaPlus::LuaObject BuildEffectLuaFactoryObject(CEffectManagerImpl* const manager)
    {
      LuaPlus::LuaObject factory{};
      if (manager == nullptr) {
        return factory;
      }

      Sim* const sim = manager->GetSim();
      LuaPlus::LuaState* const luaState = sim != nullptr ? sim->GetLuaState() : nullptr;
      (void)func_CreateLuaIEffect(&factory, luaState);
      return factory;
    }
  } // namespace

  /**
   * Address: 0x00658F00 (FUN_00658F00, Moho::IEffect::IEffect)
   */
  IEffect::IEffect()
    : CScriptObject()
  {
    mManager = nullptr;
    mScriptObjectToken = -1;
  }

  /**
   * Address: 0x00658F70 (FUN_00658F70, Moho::IEffect::IEffect)
   *
   * What it does:
   * Builds manager-bound script metadata from the owning sim Lua state and
   * initializes one effect runtime lane with manager and script token fields.
   */
  IEffect::IEffect(CEffectManagerImpl* const manager, const int scriptObjectToken)
    : CScriptObject(BuildEffectLuaFactoryObject(manager), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
  {
    mManager = manager;
    mScriptObjectToken = scriptObjectToken;
  }

  /**
   * Address: 0x00659950 (FUN_00659950)
   *
   * What it does:
   * Initializes one effect-manager intrusive node to singleton self-links.
   */
  [[maybe_unused]] IEffect::ManagerListNode* InitializeIEffectManagerNodeSelfLinks(
    IEffect::ManagerListNode* const node
  ) noexcept
  {
    node->mNext = node;
    node->mPrev = node;
    return node;
  }

  /**
   * Address: 0x00654260 (FUN_00654260)
   *
   * What it does:
   * Returns the effect manager that owns this effect's intrusive-list lane.
   */
  [[maybe_unused]] IEffectManager* ReadIEffectManagerOwner(const IEffect* const effect) noexcept
  {
    return effect->mManager;
  }

  struct RefCountedRuntimeView
  {
    void** vtable = nullptr; // +0x00
    volatile long refCount = 0; // +0x04
  };
  static_assert(sizeof(RefCountedRuntimeView) == 0x08, "RefCountedRuntimeView size must be 0x08");
  static_assert(offsetof(RefCountedRuntimeView, refCount) == 0x04, "RefCountedRuntimeView::refCount offset must be 0x04");

  /**
   * Address: 0x00658440 (FUN_00658440)
   *
   * What it does:
   * Releases one ref-counted object pointer lane and nulls the caller slot.
   */
  [[maybe_unused]] RefCountedRuntimeView** ReleaseRefCountedPointerAndClearSlot(
    RefCountedRuntimeView** const objectSlot
  ) noexcept
  {
    RefCountedRuntimeView* const object = *objectSlot;
    if (object != nullptr) {
#if defined(_WIN32)
      if (::InterlockedExchangeAdd(&object->refCount, -1L) == 1L)
#else
      if (--object->refCount == 0L)
#endif
      {
        using DeleteWithFlagFn = void(__thiscall*)(RefCountedRuntimeView*, int);
        const auto destroy = reinterpret_cast<DeleteWithFlagFn>(object->vtable[0]);
        destroy(object, 1);
      }
    }

    *objectSlot = nullptr;
    return objectSlot;
  }

  /**
   * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
   */
  gpg::RType* IEffect::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IEffect));
    }
    return sType;
  }

  /**
    * Alias of FUN_00654220 (non-canonical helper lane).
   */
  gpg::RType* IEffect::GetClass() const
  {
    return StaticGetClass();
  }

  /**
   * Address: 0x00654240 (FUN_00654240, Moho::IEffect::GetDerivedObjectRef)
   */
  gpg::RRef IEffect::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x006543D0 (FUN_006543D0, Moho::IEffect::dtr)
   * Address: 0x00654180 (FUN_00654180, Moho::IEffect::~IEffect body)
   */
  IEffect::~IEffect() = default;

  /**
   * Address: 0x00654270 (FUN_00654270, Moho::IEffect::OnInit)
   */
  void IEffect::OnInit(const std::int32_t, const char*)
  {}

  /**
   * Address: 0x00654280 (FUN_00654280, Moho::IEffect::GetStringParam)
   */
  msvc8::string* IEffect::GetStringParam(const std::int32_t)
  {
    return nullptr;
  }

  /**
   * Address: 0x00654290 (FUN_00654290, Moho::IEffect::GetTextureParam)
   */
  CParticleTexture** IEffect::GetTextureParam(CParticleTexture** const outTexture, const std::int32_t)
  {
    *outTexture = nullptr;
    return outTexture;
  }

  /**
   * Address: 0x006542A0 (FUN_006542A0, Moho::IEffect::GetFloatParam)
   */
  float IEffect::GetFloatParam(const std::int32_t)
  {
    return 0.0f;
  }

  /**
   * Address: 0x006542B0 (FUN_006542B0, Moho::IEffect::GetVectorParam)
   */
  Wm3::Vector3f* IEffect::GetVectorParam(Wm3::Vector3f* const outValue, const std::int32_t)
  {
    *outValue = Wm3::Vector3f::Zero();
    return outValue;
  }

  /**
   * Address: 0x006542E0 (FUN_006542E0, Moho::IEffect::GetQuatParam)
   */
  Vector4f* IEffect::GetQuatParam(Vector4f* const outValue, const std::int32_t)
  {
    outValue->x = 0.0f;
    outValue->y = 0.0f;
    outValue->z = 0.0f;
    outValue->w = 0.0f;
    return outValue;
  }

  /**
   * Address: 0x00654350 (FUN_00654350, Moho::IEffect::GetCurveParam)
   */
  SEfxCurve* IEffect::GetCurveParam(const std::int32_t)
  {
    return nullptr;
  }

  /**
   * Address: 0x00654370 (FUN_00654370, Moho::IEffect::SetVectorParam)
   */
  void IEffect::SetVectorParam(const std::int32_t, const Wm3::Vector3f*)
  {}

  /**
   * Address: 0x00654360 (FUN_00654360, Moho::IEffect::SetFloatParam)
   */
  void IEffect::SetFloatParam(const std::int32_t, const float)
  {}

  /**
   * Address: 0x00654380 (FUN_00654380, Moho::IEffect::SetNParam)
   */
  void IEffect::SetNParam(const std::int32_t, const float*, const std::int32_t)
  {}

  /**
   * Address: 0x00654390 (FUN_00654390, Moho::IEffect::SetCurveParam)
   */
  void IEffect::SetCurveParam(const std::int32_t, const SEfxCurve*)
  {}

  /**
   * Address: 0x006543A0 (FUN_006543A0, Moho::IEffect::SetEntity)
   */
  void IEffect::SetEntity(Entity*)
  {}

  /**
   * Address: 0x006543B0 (FUN_006543B0, Moho::IEffect::SetBone)
   */
  void IEffect::SetBone(Entity*, const std::int32_t)
  {}

  /**
    * Alias of FUN_006543C0 (non-canonical helper lane).
   */
  void IEffect::OnTick()
  {}
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterIEffectPointerType_32e2fd, moho::PreregisterIEffectPointerType)
