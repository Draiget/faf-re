#include "moho/effects/rendering/IEffectManagerTypeInfo.h"

#include <typeinfo>

#include "moho/effects/rendering/IEffectManager.h"

namespace moho
{
  /**
   * Address: 0x00770FE0 (FUN_00770FE0, Moho::IEffectManagerTypeInfo::dtr)
   *
   * IDA signature:
   * void **__thiscall Moho::IEffectManagerTypeInfo::dtr(void **this, char a2);
   */
  IEffectManagerTypeInfo::~IEffectManagerTypeInfo() = default;

  /**
   * Address: 0x00770FD0 (FUN_00770FD0, Moho::IEffectManagerTypeInfo::GetName)
   *
   * IDA signature:
   * const char *Moho::IEffectManagerTypeInfo::GetName();
   */
  const char* IEffectManagerTypeInfo::GetName() const
  {
    return "IEffectManager";
  }

  /**
   * Address: 0x00770FB0 (FUN_00770FB0, Moho::IEffectManagerTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::IEffectManagerTypeInfo::Register(gpg::RType *this);
   */
  void IEffectManagerTypeInfo::Init()
  {
    size_ = sizeof(IEffectManager);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00770F50 (FUN_00770F50, preregister_IEffectManagerTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::IEffectManager`.
   */
  [[nodiscard]] gpg::RType* preregister_IEffectManagerTypeInfo()
  {
    static IEffectManagerTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(IEffectManager), &typeInfo);
    return &typeInfo;
  }
} // namespace moho
