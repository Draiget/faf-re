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
   *
   * Demangled: gpg::PrimitiveSerHelper<enum moho::EmitterType,int>
   * VFTABLE: 0x00E2416C
   * COL: 0x00E7E4A8
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EmitterType@Moho@@H@gpg'`):
   * `FUN_00BD42B0` (real, `__xc_a`-reachable; no dead low-address duplicate
   * found for this instantiation). Previously modeled in this file as a
   * hand-rolled `{ void* mVtable; SerHelperBase* mHelperNext, mHelperPrev;
   * ... }` POD plus manual `InitializeHelperNode`/`UnlinkHelperNode`
   * splicing and an eager `register_EmitterTypePrimitiveSerializer()`
   * bootstrap call -- none of which the real binary does; `SerHelperBase`'s
   * own ctor performs the real self-registration onto the pending-helper
   * list.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BFBD20` (atexit target
   * pushed by the real ctor above); `FUN_0065DF80`/`FUN_0065DFB0` are dead,
   * zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneX` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::EmitterType, int> gEmitterTypePrimitiveSerializer;

  /**
   * Address: 0x00BFBD10 (FUN_00BFBD10, atexit destructor of the moho::EmitterTypeTypeInfo object)
   */
  [[nodiscard]] moho::EmitterTypeTypeInfo* AcquireEmitterTypeTypeInfo()
  {
    static moho::EmitterTypeTypeInfo sInstance;
    return &sInstance;
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
   * Address: 0x00BD4290 (FUN_00BD4290, register_EmitterTypeTypeInfo)
   *
   * What it does:
   * Registers `EmitterType` RTTI bootstrap and installs process-exit cleanup.
   */
  void register_EmitterTypeTypeInfo()
  {
    (void)register_EmitterTypeTypeInfo_00();
  }
} // namespace moho

namespace
{
  struct EmitterTypeTypeInfoBootstrap
  {
    EmitterTypeTypeInfoBootstrap()
    {
      (void)moho::register_EmitterTypeTypeInfo();
    }
  };

  [[maybe_unused]] EmitterTypeTypeInfoBootstrap gEmitterTypeTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EmitterTypeTypeInfo_00_78818e, moho::register_EmitterTypeTypeInfo_00)
