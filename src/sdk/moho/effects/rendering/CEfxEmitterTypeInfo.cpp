#include "moho/effects/rendering/CEfxEmitterTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/effects/rendering/CEfxEmitter.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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
   * The NewRef/CtrRef/Delete/Destruct statics below provide the
   * reflection lifecycle binding chain (allocate/in-place-construct/free/
   * in-place-destroy) for `CEfxEmitter` instances.
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
   * Address: 0x0065F790 (FUN_0065F790, Moho::CEfxEmitterTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CEfxEmitter` instance via the heap, default-constructs
   * it, and returns a typed reflection reference wrapping the new object.
   * On allocation failure (nothrow returns nullptr) the returned RRef is
   * built from a nullptr object pointer, matching the binary's
   * `v2 = 0; RRef_CEfxEmitter(&v5, v2)` fallback.
   */
  gpg::RRef CEfxEmitterTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CEfxEmitter();
    gpg::RRef ref{};
    gpg::RRef_CEfxEmitter(&ref, object);
    return ref;
  }

  /**
   * Address: 0x0065F830 (FUN_0065F830, Moho::CEfxEmitterTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CEfxEmitter` instance in caller-provided
   * storage and returns a typed reflection reference. When the caller
   * passes `nullptr` the constructor is skipped and the RRef is built
   * from a nullptr object pointer.
   */
  gpg::RRef CEfxEmitterTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = (objectStorage != nullptr)
      ? new (objectStorage) CEfxEmitter()
      : nullptr;
    gpg::RRef ref{};
    gpg::RRef_CEfxEmitter(&ref, object);
    return ref;
  }

  /**
   * Address: 0x0065F810 (FUN_0065F810, Moho::CEfxEmitterTypeInfo::Delete)
   *
   * What it does:
   * Releases one heap-owned `CEfxEmitter` by invoking the virtual
   * scalar-deleting destructor (vtable slot for `~CEfxEmitter`),
   * which runs the destructor body and frees the storage block.
   */
  void CEfxEmitterTypeInfo::Delete(void* const objectStorage)
  {
    if (objectStorage != nullptr) {
      delete static_cast<CEfxEmitter*>(objectStorage);
    }
  }

  /**
   * Address: 0x0065F8A0 (FUN_0065F8A0, Moho::CEfxEmitterTypeInfo::Destruct)
   *
   * What it does:
   * Runs one in-place `CEfxEmitter` destructor through the virtual dtor
   * slot without freeing the backing storage. Used by the reflection
   * system when caller-owned storage must be retained after destruction.
   */
  void CEfxEmitterTypeInfo::Destruct(void* const objectStorage)
  {
    if (objectStorage != nullptr) {
      static_cast<CEfxEmitter*>(objectStorage)->~CEfxEmitter();
    }
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEfxEmitterTypeInfo_00_e6e4eb, moho::register_CEfxEmitterTypeInfo_00)
