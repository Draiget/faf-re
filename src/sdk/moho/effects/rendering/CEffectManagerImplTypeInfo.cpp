#include "moho/effects/rendering/CEffectManagerImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffectManager.h"

namespace
{
  alignas(moho::CEffectManagerImplTypeInfo)
    unsigned char gCEffectManagerImplTypeInfoStorage[sizeof(moho::CEffectManagerImplTypeInfo)] = {};
  bool gCEffectManagerImplTypeInfoConstructed = false;

  [[nodiscard]] moho::CEffectManagerImplTypeInfo* AcquireCEffectManagerImplTypeInfo()
  {
    if (!gCEffectManagerImplTypeInfoConstructed) {
      new (gCEffectManagerImplTypeInfoStorage) moho::CEffectManagerImplTypeInfo();
      gCEffectManagerImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CEffectManagerImplTypeInfo*>(gCEffectManagerImplTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0066B330 (FUN_0066B330, Moho::CEffectManagerImplTypeInfo::dtr)
   *
   * IDA signature:
   * void **__thiscall sub_66B330(void **this, char a2);
   */
  CEffectManagerImplTypeInfo::~CEffectManagerImplTypeInfo() = default;

  /**
   * Address: 0x0066B320 (FUN_0066B320, Moho::CEffectManagerImplTypeInfo::GetName)
   *
   * IDA signature:
   * const char *sub_66B320();
   */
  const char* CEffectManagerImplTypeInfo::GetName() const
  {
    return "CEffectManagerImpl";
  }

  /**
   * Address: 0x0066B300 (FUN_0066B300, Moho::CEffectManagerImplTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall sub_66B300(gpg::RType *this);
   */
  void CEffectManagerImplTypeInfo::Init()
  {
    size_ = sizeof(CEffectManagerImpl);
    gpg::RType::Init();
    AddBase_IEffectManager(this);
    Finish();
  }

  /**
   * Address: 0x0066C220 (FUN_0066C220, Moho::CEffectManagerImplTypeInfo::AddBase_IEffectManager)
   *
   * IDA signature:
   * void __stdcall sub_66C220(gpg::RType *a1);
   */
  void CEffectManagerImplTypeInfo::AddBase_IEffectManager(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = IEffectManager::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x0066B2A0 (FUN_0066B2A0, register_CEffectManagerImplTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEffectManagerImpl`.
   */
  gpg::RType* register_CEffectManagerImplTypeInfo_00()
  {
    CEffectManagerImplTypeInfo* const typeInfo = AcquireCEffectManagerImplTypeInfo();
    gpg::PreRegisterRType(typeid(CEffectManagerImpl), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFBFA0 (FUN_00BFBFA0, cleanup_CEffectManagerImplTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEffectManagerImplTypeInfo` reflection storage.
   */
  void cleanup_CEffectManagerImplTypeInfo()
  {
    if (!gCEffectManagerImplTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::RType*>(AcquireCEffectManagerImplTypeInfo())->~RType();
    gCEffectManagerImplTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4570 (FUN_00BD4570, register_CEffectManagerImplTypeInfo_AtExit)
   *
   * What it does:
   * Registers `CEffectManagerImpl` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEffectManagerImplTypeInfo_AtExit()
  {
    (void)register_CEffectManagerImplTypeInfo_00();
    return std::atexit(&cleanup_CEffectManagerImplTypeInfo);
  }
} // namespace moho

namespace
{
  struct CEffectManagerImplTypeInfoBootstrap
  {
    CEffectManagerImplTypeInfoBootstrap()
    {
      (void)moho::register_CEffectManagerImplTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] CEffectManagerImplTypeInfoBootstrap gCEffectManagerImplTypeInfoBootstrap;
} // namespace
