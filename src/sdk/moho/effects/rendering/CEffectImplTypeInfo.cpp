#include "moho/effects/rendering/CEffectImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEffectImpl.h"

namespace
{
  alignas(moho::CEffectImplTypeInfo) unsigned char gCEffectImplTypeInfoStorage[sizeof(moho::CEffectImplTypeInfo)] = {};
  bool gCEffectImplTypeInfoConstructed = false;

  [[nodiscard]] moho::CEffectImplTypeInfo* AcquireCEffectImplTypeInfo()
  {
    if (!gCEffectImplTypeInfoConstructed) {
      new (gCEffectImplTypeInfoStorage) moho::CEffectImplTypeInfo();
      gCEffectImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CEffectImplTypeInfo*>(gCEffectImplTypeInfoStorage);
  }

  struct CEffectImplTypeInfoBootstrap
  {
    CEffectImplTypeInfoBootstrap()
    {
      (void)moho::register_CEffectImplTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] CEffectImplTypeInfoBootstrap gCEffectImplTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006597F0 (FUN_006597F0, Moho::CEffectImplTypeInfo::dtr)
   */
  CEffectImplTypeInfo::~CEffectImplTypeInfo() = default;

  /**
   * Address: 0x006597E0 (FUN_006597E0, Moho::CEffectImplTypeInfo::GetName)
   */
  const char* CEffectImplTypeInfo::GetName() const
  {
    return "CEffectImpl";
  }

  /**
   * Address: 0x006597B0 (FUN_006597B0, Moho::CEffectImplTypeInfo::Init)
   */
  void CEffectImplTypeInfo::Init()
  {
    size_ = sizeof(CEffectImpl);
    AddBase_IEffect(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0065A750 (FUN_0065A750, Moho::CEffectImplTypeInfo::AddBase_IEffect)
   */
  void CEffectImplTypeInfo::AddBase_IEffect(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IEffect::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00659750 (FUN_00659750, register_CEffectImplTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEffectImpl`.
   */
  gpg::RType* register_CEffectImplTypeInfo_00()
  {
    CEffectImplTypeInfo* const typeInfo = AcquireCEffectImplTypeInfo();
    gpg::PreRegisterRType(typeid(CEffectImpl), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFB9C0 (FUN_00BFB9C0, cleanup_CEffectImplTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEffectImplTypeInfo` reflection storage.
   */
  void cleanup_CEffectImplTypeInfo()
  {
    if (!gCEffectImplTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(AcquireCEffectImplTypeInfo())->~RType();
    gCEffectImplTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD40C0 (FUN_00BD40C0, register_CEffectImplTypeInfo_AtExit)
   *
   * What it does:
   * Registers `CEffectImpl` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEffectImplTypeInfo_AtExit()
  {
    (void)register_CEffectImplTypeInfo_00();
    return std::atexit(&cleanup_CEffectImplTypeInfo);
  }
} // namespace moho
