#include "moho/effects/rendering/IEffect.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/sim/Sim.h"

namespace moho
{
  gpg::RType* IEffect::sType = nullptr;
  gpg::RType* IEffect::sPointerType = nullptr;

  /**
   * Address: 0x0066C980 (FUN_0066C980, Moho::IEffect::GetPointerType)
   * Address: 0x00BFC0F0 (FUN_00BFC0F0, `atexit` destructor of `sDescriptor`)
   *
   * What it does:
   * Constructs `sDescriptor` on the first call -- guard bit 0 of 0x010C8670,
   * constructor 0x0066CB30, `atexit(0x00BFC0F0)` -- and resolves
   * `typeid(IEffect*)` into `sPointerType`. The descriptor is never read by
   * name: its constructor pre-registers it, and that is what the lookup finds.
   */
  gpg::RType* IEffect::GetPointerType()
  {
    static gpg::RPointerType<IEffect> sDescriptor;

    if (!sPointerType) {
      sPointerType = gpg::LookupRType(typeid(IEffect*));
    }
    return sPointerType;
  }

  /**
   * Address: 0x00658F00 (FUN_00658F00, Moho::IEffect::IEffect)
   */
  IEffect::IEffect()
    : CScriptObject()
    , mManager(nullptr)
    , mScriptObjectToken(-1)
  {}

  namespace
  {
    /**
     * The `IEffect` metatable object for `state`, as the first argument of
     * `CScriptObject`'s binding constructor. `func_CreateLuaIEffect` fills a
     * caller-provided slot; returning it by value keeps that slot the
     * constructor's argument temporary, which is what 0x00658FE1 passes.
     */
    [[nodiscard]] LuaPlus::LuaObject IEffectMetatable(LuaPlus::LuaState* const state)
    {
      LuaPlus::LuaObject metatable;
      (void)func_CreateLuaIEffect(&metatable, state);
      return metatable;
    }
  } // namespace

  /**
   * Address: 0x00658F70 (FUN_00658F70, Moho::IEffect::IEffect)
   *
   * What it does:
   * Evaluates the three empty `LuaObject` arguments first (right to left),
   * then `manager->GetSim()` through the manager's vtable and the metatable
   * for that sim's Lua state, and chains into `CScriptObject`. The binary
   * checks neither the manager nor the sim for null.
   */
  IEffect::IEffect(CEffectManagerImpl* const manager, const int scriptObjectToken)
    : CScriptObject(
        IEffectMetatable(manager->GetSim()->mLuaState), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}
      )
    , mManager(manager)
    , mScriptObjectToken(scriptObjectToken)
  {}

  /**
   * What it does:
   * Returns the reflection descriptor for `IEffect`, resolving it into
   * `sType` on first use.
   */
  gpg::RType* IEffect::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IEffect));
    }
    return sType;
  }

  /**
   * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
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
   * Address: 0x00654260 (FUN_00654260)
   */
  IEffectManager* IEffect::GetManager() const noexcept
  {
    return mManager;
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
   * Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick)
   *
   * What it does:
   * Nothing. `CEffectImpl` inherits this slot unchanged: its vtable holds the
   * same 0x006543C0.
   */
  void IEffect::OnTick()
  {}
} // namespace moho
