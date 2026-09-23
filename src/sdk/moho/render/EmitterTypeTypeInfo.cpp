#include "moho/render/EmitterTypeTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/render/EmitterType.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EmitterTypeTypeInfo) unsigned char gEmitterTypeTypeInfoStorage[sizeof(moho::EmitterTypeTypeInfo)] = {};
  bool gEmitterTypeTypeInfoConstructed = false;

  /**
   * Address: 0x00BD42B0 (FUN_00BD42B0, dynamic initializer for the global
   * `PrimitiveSerHelper<EmitterType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (which self-links this
   * helper onto the process-global pending-helper list) and binds the
   * load/save callback fields; `Init()` is dispatched later, from
   * `gpg::SerHelperBase::InitNewHelpers`. Prior to this recovery, this
   * global was a hand-rolled POD that never actually inherited
   * `SerHelperBase`, so `EmitterType`'s serialize/deserialize callbacks
   * were never installed under any code path.
   */
  moho::EmitterTypePrimitiveSerializer gEmitterTypePrimitiveSerializer;

  [[nodiscard]] moho::EmitterTypeTypeInfo* AcquireEmitterTypeTypeInfo()
  {
    if (!gEmitterTypeTypeInfoConstructed) {
      new (gEmitterTypeTypeInfoStorage) moho::EmitterTypeTypeInfo();
      gEmitterTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EmitterTypeTypeInfo*>(gEmitterTypeTypeInfoStorage);
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
   */
  EmitterTypeTypeInfo::~EmitterTypeTypeInfo() = default;

  /**
   * Address: 0x0065DF30 (FUN_0065DF30)
   *
   * What it does:
   * Returns the reflection type name literal for EmitterType.
   */
  const char* EmitterTypeTypeInfo::GetName() const
  {
    return "EmitterType";
  }

  /**
   * Address: 0x0065DF10 (FUN_0065DF10)
   *
   * What it does:
   * Writes enum width and finalizes metadata.
   */
  void EmitterTypeTypeInfo::Init()
  {
    size_ = sizeof(EmitterType);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0065DEB0 (FUN_0065DEB0, register_EmitterTypeTypeInfo_00)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `moho::EmitterType`.
   */
  gpg::RType* register_EmitterTypeTypeInfo_00()
  {
    EmitterTypeTypeInfo* const typeInfo = AcquireEmitterTypeTypeInfo();
    gpg::PreRegisterRType(typeid(EmitterType), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BFBD10 (FUN_00BFBD10, cleanup_EmitterTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EmitterTypeTypeInfo` reflection storage.
   */
  void cleanup_EmitterTypeTypeInfo()
  {
    if (!gEmitterTypeTypeInfoConstructed) {
      return;
    }

    static_cast<gpg::REnumType*>(AcquireEmitterTypeTypeInfo())->~REnumType();
    gEmitterTypeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo_AtExit)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  int register_EmitterTypeTypeInfo_AtExit()
  {
    (void)register_EmitterTypeTypeInfo_00();
    return std::atexit(&cleanup_EmitterTypeTypeInfo);
  }
} // namespace moho

namespace
{
  struct EmitterTypeTypeInfoBootstrap
  {
    EmitterTypeTypeInfoBootstrap()
    {
      (void)moho::register_EmitterTypeTypeInfo_AtExit();
    }
  };

  [[maybe_unused]] EmitterTypeTypeInfoBootstrap gEmitterTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EmitterTypeTypeInfo_00_78818e, moho::register_EmitterTypeTypeInfo_00)
