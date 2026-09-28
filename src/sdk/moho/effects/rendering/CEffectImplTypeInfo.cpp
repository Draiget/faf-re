#include "moho/effects/rendering/CEffectImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEffectImpl.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BFB9C0 (FUN_00BFB9C0, atexit destructor of the moho::CEffectImplTypeInfo object)
   */
  [[nodiscard]] moho::CEffectImplTypeInfo* AcquireCEffectImplTypeInfo()
  {
    static moho::CEffectImplTypeInfo sInstance;
    return &sInstance;
  }

  struct CEffectImplTypeInfoBootstrap
  {
    CEffectImplTypeInfoBootstrap()
    {
      (void)moho::register_CEffectImplTypeInfo();
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
   * Address: 0x00BD40C0 (FUN_00BD40C0, register_CEffectImplTypeInfo)
   *
   * What it does:
   * Registers `CEffectImpl` RTTI bootstrap and installs process-exit cleanup.
   */
  void register_CEffectImplTypeInfo()
  {
    (void)register_CEffectImplTypeInfo_00();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEffectImplTypeInfo_00_261522, moho::register_CEffectImplTypeInfo_00)
