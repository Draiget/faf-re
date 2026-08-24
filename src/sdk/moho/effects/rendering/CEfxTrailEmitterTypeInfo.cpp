#include "moho/effects/rendering/CEfxTrailEmitterTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEfxTrailEmitter.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::CEfxTrailEmitterTypeInfo)
  unsigned char gCEfxTrailEmitterTypeInfoStorage[sizeof(moho::CEfxTrailEmitterTypeInfo)] = {};
  bool gCEfxTrailEmitterTypeInfoConstructed = false;
  bool gCEfxTrailEmitterTypeInfoRegistered = false;

  [[nodiscard]] moho::CEfxTrailEmitterTypeInfo* AcquireCEfxTrailEmitterTypeInfo()
  {
    if (!gCEfxTrailEmitterTypeInfoConstructed) {
      new (gCEfxTrailEmitterTypeInfoStorage) moho::CEfxTrailEmitterTypeInfo();
      gCEfxTrailEmitterTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CEfxTrailEmitterTypeInfo*>(gCEfxTrailEmitterTypeInfoStorage);
  }

  struct CEfxTrailEmitterTypeInfoBootstrap
  {
    CEfxTrailEmitterTypeInfoBootstrap()
    {
      (void)moho::register_CEfxTrailEmitterTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] CEfxTrailEmitterTypeInfoBootstrap gCEfxTrailEmitterTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00671F80 (FUN_00671F80, Moho::CEfxTrailEmitterTypeInfo::dtr)
   */
  CEfxTrailEmitterTypeInfo::~CEfxTrailEmitterTypeInfo() = default;

  /**
   * Address: 0x00671F70 (FUN_00671F70, Moho::CEfxTrailEmitterTypeInfo::GetName)
   */
  const char* CEfxTrailEmitterTypeInfo::GetName() const
  {
    return "CEfxTrailEmitter";
  }

  /**
   * Address: 0x00671F30 (FUN_00671F30, Moho::CEfxTrailEmitterTypeInfo::Init)
   */
  void CEfxTrailEmitterTypeInfo::Init()
  {
    size_ = sizeof(CEfxTrailEmitter);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CEfxTrailEmitterTypeInfo::NewRef,
      &CEfxTrailEmitterTypeInfo::CtrRef,
      &CEfxTrailEmitterTypeInfo::Delete,
      &CEfxTrailEmitterTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CEffectImpl(this);
    Finish();
  }

  /**
   * Address: 0x00672380 (FUN_00672380, Moho::CEfxTrailEmitterTypeInfo::NewRef)
   */
  gpg::RRef CEfxTrailEmitterTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CEfxTrailEmitter();
    gpg::RRef out{};
    gpg::RRef_CEfxTrailEmitter(&out, object);
    return out;
  }

  /**
   * Address: 0x00672410 (FUN_00672410, Moho::CEfxTrailEmitterTypeInfo::CtrRef)
   */
  gpg::RRef CEfxTrailEmitterTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CEfxTrailEmitter*>(objectStorage);
    if (object) {
      new (object) CEfxTrailEmitter();
    }
    gpg::RRef out{};
    gpg::RRef_CEfxTrailEmitter(&out, object);
    return out;
  }

  /**
   * Address: 0x006723F0 (FUN_006723F0, Moho::CEfxTrailEmitterTypeInfo::Delete)
   */
  void CEfxTrailEmitterTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CEfxTrailEmitter*>(objectStorage);
  }

  /**
   * Address: 0x00672480 (FUN_00672480, Moho::CEfxTrailEmitterTypeInfo::Destruct)
   */
  void CEfxTrailEmitterTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CEfxTrailEmitter*>(objectStorage);
    if (object) {
      object->~CEfxTrailEmitter();
    }
  }

  /**
   * Address: 0x00672490 (FUN_00672490, Moho::CEfxTrailEmitterTypeInfo::AddBase_CEffectImpl)
   */
  void CEfxTrailEmitterTypeInfo::AddBase_CEffectImpl(gpg::RType* const typeInfo)
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
   * Address: 0x00671ED0 (FUN_00671ED0, register_CEfxTrailEmitterTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEfxTrailEmitter`.
   */
  gpg::RType* register_CEfxTrailEmitterTypeInfo_00()
  {
    CEfxTrailEmitterTypeInfo* const typeInfo = AcquireCEfxTrailEmitterTypeInfo();
    gpg::PreRegisterRType(typeid(CEfxTrailEmitter), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFC1F0 (FUN_00BFC1F0, cleanup_CEfxTrailEmitterTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEfxTrailEmitterTypeInfo` reflection storage.
   */
  void cleanup_CEfxTrailEmitterTypeInfo()
  {
    if (!gCEfxTrailEmitterTypeInfoConstructed) {
      return;
    }

    AcquireCEfxTrailEmitterTypeInfo()->~CEfxTrailEmitterTypeInfo();
    gCEfxTrailEmitterTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4950 (FUN_00BD4950, register_CEfxTrailEmitterTypeInfo_AtExit)
   *
   * What it does:
   * Registers `CEfxTrailEmitter` RTTI bootstrap and installs process-exit
   * cleanup.
   */
  int register_CEfxTrailEmitterTypeInfo_AtExit()
  {
    if (gCEfxTrailEmitterTypeInfoRegistered) {
      return 0;
    }

    (void)register_CEfxTrailEmitterTypeInfo_00();
    gCEfxTrailEmitterTypeInfoRegistered = true;
    return std::atexit(&cleanup_CEfxTrailEmitterTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEfxTrailEmitterTypeInfo_00_a17c2d, moho::register_CEfxTrailEmitterTypeInfo_00)
