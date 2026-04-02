#include "moho/effects/rendering/CEfxBeamTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEffectImpl.h"

namespace
{
  alignas(moho::CEfxBeamTypeInfo) unsigned char gCEfxBeamTypeInfoStorage[sizeof(moho::CEfxBeamTypeInfo)] = {};
  bool gCEfxBeamTypeInfoConstructed = false;
  bool gCEfxBeamTypeInfoRegistered = false;

  [[nodiscard]] moho::CEfxBeamTypeInfo* AcquireCEfxBeamTypeInfo()
  {
    if (!gCEfxBeamTypeInfoConstructed) {
      new (gCEfxBeamTypeInfoStorage) moho::CEfxBeamTypeInfo();
      gCEfxBeamTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CEfxBeamTypeInfo*>(gCEfxBeamTypeInfoStorage);
  }

  [[nodiscard]] gpg::RRef MakeCEfxBeamRef(moho::CEfxBeam* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CEfxBeam::StaticGetClass();
    return out;
  }

  struct CEfxBeamTypeInfoBootstrap
  {
    CEfxBeamTypeInfoBootstrap()
    {
      (void)moho::register_CEfxBeamTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] CEfxBeamTypeInfoBootstrap gCEfxBeamTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00655EB0 (FUN_00655EB0, Moho::CEfxBeamTypeInfo::dtr)
   */
  CEfxBeamTypeInfo::~CEfxBeamTypeInfo() = default;

  /**
   * Address: 0x00655EA0 (FUN_00655EA0, Moho::CEfxBeamTypeInfo::GetName)
   */
  const char* CEfxBeamTypeInfo::GetName() const
  {
    return "CEfxBeam";
  }

  /**
   * Address: 0x00655E60 (FUN_00655E60, Moho::CEfxBeamTypeInfo::Init)
   */
  void CEfxBeamTypeInfo::Init()
  {
    size_ = sizeof(CEfxBeam);
    newRefFunc_ = &CEfxBeamTypeInfo::NewRef;
    ctorRefFunc_ = &CEfxBeamTypeInfo::CtrRef;
    deleteFunc_ = &CEfxBeamTypeInfo::Delete;
    dtrFunc_ = &CEfxBeamTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CEffectImpl(this);
    Finish();
  }

  /**
   * Address: 0x00658320 (FUN_00658320, Moho::CEfxBeamTypeInfo::NewRef)
   */
  gpg::RRef CEfxBeamTypeInfo::NewRef()
  {
    return MakeCEfxBeamRef(new (std::nothrow) CEfxBeam());
  }

  /**
   * Address: 0x006583C0 (FUN_006583C0, Moho::CEfxBeamTypeInfo::CtrRef)
   */
  gpg::RRef CEfxBeamTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CEfxBeam*>(objectStorage);
    if (object) {
      new (object) CEfxBeam();
    }
    return MakeCEfxBeamRef(object);
  }

  /**
   * Address: 0x006583A0 (FUN_006583A0, Moho::CEfxBeamTypeInfo::Delete)
   */
  void CEfxBeamTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CEfxBeam*>(objectStorage);
  }

  /**
   * Address: 0x00658430 (FUN_00658430, Moho::CEfxBeamTypeInfo::Destruct)
   */
  void CEfxBeamTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CEfxBeam*>(objectStorage);
    if (object) {
      object->~CEfxBeam();
    }
  }

  /**
   * Address: 0x00658570 (FUN_00658570, Moho::CEfxBeamTypeInfo::AddBase_CEffectImpl)
   */
  void CEfxBeamTypeInfo::AddBase_CEffectImpl(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CEffectImpl::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00655E00 (FUN_00655E00, register_CEfxBeamTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEfxBeam`.
   */
  gpg::RType* register_CEfxBeamTypeInfo_00()
  {
    CEfxBeamTypeInfo* const typeInfo = AcquireCEfxBeamTypeInfo();
    gpg::PreRegisterRType(typeid(CEfxBeam), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFB8B0 (FUN_00BFB8B0, cleanup_CEfxBeamTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEfxBeamTypeInfo` reflection storage.
   */
  void cleanup_CEfxBeamTypeInfo()
  {
    if (!gCEfxBeamTypeInfoConstructed) {
      return;
    }

    AcquireCEfxBeamTypeInfo()->~CEfxBeamTypeInfo();
    gCEfxBeamTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD3F30 (FUN_00BD3F30, register_CEfxBeamTypeInfo_AtExit)
   *
   * What it does:
   * Registers `CEfxBeam` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEfxBeamTypeInfo_AtExit()
  {
    if (gCEfxBeamTypeInfoRegistered) {
      return 0;
    }

    (void)register_CEfxBeamTypeInfo_00();
    gCEfxBeamTypeInfoRegistered = true;
    return std::atexit(&cleanup_CEfxBeamTypeInfo);
  }
} // namespace moho
