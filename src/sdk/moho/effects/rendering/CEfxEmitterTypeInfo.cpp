#include "moho/effects/rendering/CEfxEmitterTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEfxEmitter.h"

namespace
{
  alignas(moho::CEfxEmitterTypeInfo)
    unsigned char gCEfxEmitterTypeInfoStorage[sizeof(moho::CEfxEmitterTypeInfo)] = {};
  bool gCEfxEmitterTypeInfoConstructed = false;

  [[nodiscard]] moho::CEfxEmitterTypeInfo* AcquireCEfxEmitterTypeInfo()
  {
    if (!gCEfxEmitterTypeInfoConstructed) {
      new (gCEfxEmitterTypeInfoStorage) moho::CEfxEmitterTypeInfo();
      gCEfxEmitterTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CEfxEmitterTypeInfo*>(gCEfxEmitterTypeInfoStorage);
  }

  struct CEfxEmitterTypeInfoBootstrap
  {
    CEfxEmitterTypeInfoBootstrap()
    {
      (void)moho::register_CEfxEmitterTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] CEfxEmitterTypeInfoBootstrap gCEfxEmitterTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0065DFE0 (FUN_0065DFE0)
   * Mangled: ??0CEfxEmitterTypeInfo@Moho@@QAE@@Z
   *
   * What it does:
   * Constructs base `RType` and preregisters the `CEfxEmitter` RTTI descriptor.
   */
  CEfxEmitterTypeInfo::CEfxEmitterTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CEfxEmitter), this);
  }

  /**
   * Address: 0x0065E090 (FUN_0065E090, Moho::CEfxEmitterTypeInfo::dtr)
   *
   * What it does:
   * Releases reflected base/field vectors for `CEfxEmitterTypeInfo`.
   */
  CEfxEmitterTypeInfo::~CEfxEmitterTypeInfo() = default;

  /**
   * Address: 0x0065E080 (FUN_0065E080, Moho::CEfxEmitterTypeInfo::GetName)
   */
  const char* CEfxEmitterTypeInfo::GetName() const
  {
    return "CEfxEmitter";
  }

  /**
   * Address: 0x0065E040 (FUN_0065E040, Moho::CEfxEmitterTypeInfo::Init)
   *
   * What it does:
   * Sets size, lifetime callbacks, initializes base reflection chain,
   * adds CEffectImpl as reflected base, and finishes type registration.
   *
   * NOTE: NewRef/CtrRef/Delete/Destruct statics are declared but not yet
   * implemented -- CEfxEmitter class definition is not yet recovered.
   * Init body is provided from binary evidence but will not link until
   * those statics and CEfxEmitter are available.
   */
  void CEfxEmitterTypeInfo::Init()
  {
    size_ = 0x6F8;  // sizeof(CEfxEmitter)
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CEfxEmitterTypeInfo::NewRef,
      &CEfxEmitterTypeInfo::CtrRef,
      &CEfxEmitterTypeInfo::Delete,
      &CEfxEmitterTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CEffectImpl(this);
    Finish();
  }

  /**
   * Address: 0x0065F9A0 (FUN_0065F9A0, Moho::CEfxEmitterTypeInfo::AddBase_CEffectImpl)
   *
   * What it does:
   * Looks up the CEffectImpl reflection type and registers it as a base class
   * at offset 0 for this type.
   */
  void CEfxEmitterTypeInfo::AddBase_CEffectImpl(gpg::RType* const typeInfo)
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
    * Alias of FUN_0065DFE0 (non-canonical helper lane).
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::CEfxEmitter`.
   */
  gpg::RType* register_CEfxEmitterTypeInfo_00()
  {
    CEfxEmitterTypeInfo* const typeInfo = AcquireCEfxEmitterTypeInfo();
    gpg::PreRegisterRType(typeid(CEfxEmitter), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFBD50 (FUN_00BFBD50, cleanup_CEfxEmitterTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CEfxEmitterTypeInfo` reflection storage.
   */
  void cleanup_CEfxEmitterTypeInfo()
  {
    if (!gCEfxEmitterTypeInfoConstructed) {
      return;
    }

    AcquireCEfxEmitterTypeInfo()->~CEfxEmitterTypeInfo();
    gCEfxEmitterTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD42F0 (FUN_00BD42F0, register_CEfxEmitterTypeInfo)
   *
   * What it does:
   * Registers `CEfxEmitter` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_CEfxEmitterTypeInfo_AtExit()
  {
    (void)register_CEfxEmitterTypeInfo_00();
    return std::atexit(&cleanup_CEfxEmitterTypeInfo);
  }
} // namespace moho
