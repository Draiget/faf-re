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
  class Entity;

  class IEffect : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for `IEffect`.
     */
    [[nodiscard]]
    static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00654220 (FUN_00654220, Moho::IEffect::GetClass)
     * Slot: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00654240 (FUN_00654240, Moho::IEffect::GetDerivedObjectRef)
     * Slot: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x006543D0 (FUN_006543D0, Moho::IEffect::dtr)
     * Address: 0x00654180 (FUN_00654180, Moho::IEffect::~IEffect body)
     *
     * What it does:
     * Unlinks this effect from the manager intrusive list before base script-object teardown.
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
    virtual std::int32_t GetCurveParam(std::int32_t paramIndex);
    /** Address: 0x00654370 (FUN_00654370, Moho::IEffect::SetVectorParam) */
    virtual void SetVectorParam(std::int32_t paramIndex, const Wm3::Vector3f* value);
    /** Address: 0x00654360 (FUN_00654360, Moho::IEffect::SetFloatParam) */
    virtual void SetFloatParam(std::int32_t paramIndex, float value);
    /** Address: 0x00654380 (FUN_00654380, Moho::IEffect::SetNParam) */
    virtual void SetNParam(std::int32_t paramIndex, const float* values, std::int32_t valueCount);
    /** Address: 0x00654390 (FUN_00654390, Moho::IEffect::SetCurveParam) */
    virtual void SetCurveParam(std::int32_t paramIndex, const void* curveData);
    /** Address: 0x006543A0 (FUN_006543A0, Moho::IEffect::SetEntity) */
    virtual void SetEntity(Entity* entity);
    /** Address: 0x006543B0 (FUN_006543B0, Moho::IEffect::SetBone) */
    virtual void SetBone(Entity* entity, std::int32_t boneIndex);
    /** Address: 0x006543C0 (FUN_006543C0, Moho::IEffect::OnTick) */
    virtual void OnTick();

  public:
    using ManagerList = TDatList<IEffect, void>;
    using ManagerListNode = TDatListItem<IEffect, void>;

    TDatListItem<IEffect, void> mManagerListNode; // +0x34
    std::uint32_t mUnknown3C;                     // +0x3C
    std::uint32_t mUnknown40;                     // +0x40
  };

  static_assert(offsetof(IEffect, mManagerListNode) == 0x34, "IEffect::mManagerListNode offset must be 0x34");
  static_assert(offsetof(IEffect, mUnknown3C) == 0x3C, "IEffect::mUnknown3C offset must be 0x3C");
  static_assert(offsetof(IEffect, mUnknown40) == 0x40, "IEffect::mUnknown40 offset must be 0x40");
  static_assert(sizeof(IEffect) == 0x44, "IEffect size must be 0x44");
} // namespace moho
