#pragma once

#include <cstdint>
#include <cstddef>

#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "moho/math/Vector4f.h"
#include "moho/script/CScriptObject.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CParticleTexture;
  class CEffectManagerImpl;
  class IEffectManager;
  class Entity;
  struct SEfxCurve;

  /**
   * Base of every sim effect (emitters, beams, trails).
   *
   * `CEffectImpl`'s RTTI base-class array places the bases at `CScriptObject`
   * +0x00, `TDatListItem<IEffect, void>` +0x34 and the empty
   * `InstanceCounter<IEffect>` +0x3C. The list item is this effect's link in
   * its manager's `mActiveEffects` / `mDestroyedEffects` ring. Declaration
   * order is what the binary's ctor and dtor follow: 0x00658F00 self-links
   * +0x34 and then bumps the instance count, 0x00654180 drops the count and
   * then unlinks +0x34.
   */
  class IEffect : public CScriptObject, public TDatListItem<IEffect, void>, public InstanceCounter<IEffect>
  {
  public:
    /**
     * Address: 0x00771450 (FUN_00771450)
     *
     * What it does:
     * Saves this object's members.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x007713E0 (FUN_007713E0)
     *
     * What it does:
     * Loads this object's members.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    static gpg::RType* sType;
    static gpg::RType* sPointerType;

    /**
     * What it does:
     * Returns the reflection descriptor for `IEffect`, resolving it into
     * `sType` on first use. Inlined into every body that names the type
     * (0x006585F0, 0x0066CA40, 0x0066CDC0, ...); its one out-of-line copy is
     * `GetClass`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0066C980 (FUN_0066C980, Moho::IEffect::GetPointerType)
     * Address: 0x00BFC0F0 (FUN_00BFC0F0, `atexit` destructor of its local descriptor)
     *
     * What it does:
     * Returns the reflection descriptor for `IEffect*`. The first call
     * constructs the function-local `gpg::RPointerType<IEffect>`, whose
     * constructor pre-registers it under `typeid(IEffect*)`, so the lookup
     * that follows always resolves.
     */
    [[nodiscard]]
    static gpg::RType* GetPointerType();

    /**
     * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
     * Slot: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00658F00 (FUN_00658F00, Moho::IEffect::IEffect)
     *
     * What it does:
     * Default-constructs the script object with no Lua binding, leaving the
     * effect unowned (`mManager` null, `mScriptObjectToken` -1). This is the
     * serializer's construction path.
     */
    IEffect();

    /**
     * Address: 0x00658F70 (FUN_00658F70, Moho::IEffect::IEffect)
     *
     * What it does:
     * Binds the script object to the `IEffect` metatable in the manager's sim
     * Lua state, then records the owning manager and the script token.
     */
    IEffect(CEffectManagerImpl* manager, int scriptObjectToken);

    /**
     * Address: 0x00654240 (FUN_00654240, Moho::IEffect::GetDerivedObjectRef)
     * Slot: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00654260 (FUN_00654260)
     *
     * What it does:
     * Returns the manager that owns this effect.
     *
     * The out-of-line copy sits among IEffect's own members (between
     * `GetDerivedObjectRef` at 0x00654240 and `OnInit` at 0x00654270) and
     * nothing references it; every use is inlined.
     */
    [[nodiscard]]
    IEffectManager* GetManager() const noexcept;

    /**
     * Address: 0x006543D0 (FUN_006543D0, Moho::IEffect::dtr)
     * Address: 0x00654180 (FUN_00654180, Moho::IEffect::~IEffect body)
     *
     * What it does:
     * Nothing of its own: the body is the base destructors, in reverse
     * declaration order -- the instance count drops, the manager-list link
     * unlinks, then `CScriptObject` tears down.
     */
    ~IEffect() override;

    /** Address: 0x00654270 (FUN_00654270, Moho::IEffect::OnInit) */
    virtual void OnInit(std::int32_t paramIndex, const char* paramName);
    /** Address: 0x00654280 (FUN_00654280, Moho::IEffect::GetStringParam) */
    virtual msvc8::string* GetStringParam(std::int32_t paramIndex);
    /** Address: 0x00654290 (FUN_00654290, Moho::IEffect::GetTextureParam) */
    virtual CParticleTexture** GetTextureParam(CParticleTexture** outTexture, std::int32_t paramIndex);
    /** Address: 0x006542A0 (FUN_006542A0, Moho::IEffect::GetFloatParam) */
    virtual float GetFloatParam(std::int32_t paramIndex);
    /** Address: 0x006542B0 (FUN_006542B0, Moho::IEffect::GetVectorParam) */
    virtual Wm3::Vector3f* GetVectorParam(Wm3::Vector3f* outValue, std::int32_t paramIndex);
    /** Address: 0x006542E0 (FUN_006542E0, Moho::IEffect::GetQuatParam) */
    virtual Vector4f* GetQuatParam(Vector4f* outValue, std::int32_t paramIndex);
    /** Address: 0x00654350 (FUN_00654350, Moho::IEffect::GetCurveParam) */
    virtual SEfxCurve* GetCurveParam(std::int32_t paramIndex);
    /** Address: 0x00654370 (FUN_00654370, Moho::IEffect::SetVectorParam) */
    virtual void SetVectorParam(std::int32_t paramIndex, const Wm3::Vector3f* value);
    /** Address: 0x00654360 (FUN_00654360, Moho::IEffect::SetFloatParam) */
    virtual void SetFloatParam(std::int32_t paramIndex, float value);
    /** Address: 0x00654380 (FUN_00654380, Moho::IEffect::SetNParam) */
    virtual void SetNParam(std::int32_t paramIndex, const float* values, std::int32_t valueCount);
    /** Address: 0x00654390 (FUN_00654390, Moho::IEffect::SetCurveParam) */
    virtual void SetCurveParam(std::int32_t paramIndex, const SEfxCurve* curve);
    /** Address: 0x006543A0 (FUN_006543A0, Moho::IEffect::SetEntity) */
    virtual void SetEntity(Entity* entity);
    /** Address: 0x006543B0 (FUN_006543B0, Moho::IEffect::SetBone) */
    virtual void SetBone(Entity* entity, std::int32_t boneIndex);
    /** Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick) */
    virtual void OnTick();

  public:
    IEffectManager* mManager;        // +0x3C
    std::int32_t mScriptObjectToken; // +0x40
  };

  static_assert(sizeof(CScriptObject) == 0x34, "CScriptObject size must be 0x34 (IEffect's list link sits at +0x34)");
  static_assert(offsetof(IEffect, mManager) == 0x3C, "IEffect::mManager offset must be 0x3C");
  static_assert(offsetof(IEffect, mScriptObjectToken) == 0x40, "IEffect::mScriptObjectToken offset must be 0x40");
  static_assert(sizeof(IEffect) == 0x44, "IEffect size must be 0x44");

  /**
   * Address: 0x0065A730 (FUN_0065A730, func_CreateLuaIEffect)
   *
   * What it does:
   * Returns cached `IEffect` metatable object from Lua object-factory storage.
   */
  LuaPlus::LuaObject* func_CreateLuaIEffect(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);
} // namespace moho
