#include "moho/effects/rendering/IEffectTypeInfo.h"

#include <typeinfo>

#include "moho/effects/rendering/IEffect.h"
#include "moho/script/CScriptObject.h"

namespace moho
{
  /**
   * Address: 0x00771130 (FUN_00771130, Moho::IEffectTypeInfo::dtr)
   *
   * IDA signature:
   * void **__thiscall Moho::IEffectTypeInfo::dtr(void **this, char a2);
   */
  IEffectTypeInfo::~IEffectTypeInfo() = default;

  /**
   * Address: 0x00771120 (FUN_00771120, Moho::IEffectTypeInfo::GetName)
   *
   * IDA signature:
   * const char *Moho::IEffectTypeInfo::GetName();
   */
  const char* IEffectTypeInfo::GetName() const
  {
    return "IEffect";
  }

  /**
   * Address: 0x007710F0 (FUN_007710F0, Moho::IEffectTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::IEffectTypeInfo::Init(gpg::RType *this);
   */
  void IEffectTypeInfo::Init()
  {
    size_ = sizeof(IEffect);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00771090 (FUN_00771090, preregister_IEffectTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::IEffect`.
   */
  [[nodiscard]] gpg::RType* preregister_IEffectTypeInfo()
  {
    static IEffectTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(IEffect), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00771340 (FUN_00771340, Moho::IEffectTypeInfo::AddBase_CScriptObject)
   *
   * IDA signature:
   * void __stdcall sub_771340(gpg::RType *a1);
   */
  void IEffectTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CScriptObject::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
