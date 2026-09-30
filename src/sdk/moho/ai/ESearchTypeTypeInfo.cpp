#include "moho/ai/ESearchTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF71A0 (FUN_00BF71A0, atexit destructor of the ESearchTypeTypeInfo object)
   */
  [[nodiscard]] ESearchTypeTypeInfo* AcquireESearchTypeTypeInfo()
  {
    static ESearchTypeTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AEC54 -- process-global `PrimitiveSerHelper<ESearchType,int>`
  // singleton (constructed by FUN_00BCCD10, self-registering via `__xc_a`; see
  // ESearchTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESearchType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESearchType@Moho@@H@gpg'`):
   * `FUN_00BCCD10` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005AB520`/`FUN_005AB540`, installs the
   * `PrimitiveSerHelper<ESearchType,int>` vtable, and pushes plain unmangled
   * `FUN_00BF71B0` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESearchTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESearchTypeTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed. `FUN_005AB120`'s asm (lazy `LookupRType(
   * typeid(ESearchType))` into a cached global, two `GPG_ASSERT`-shaped
   * null checks, then `serLoadFunc_`/`serSaveFunc_` writes) matches this
   * template's generic `Init()` exactly and is now provided by
   * `gpg::PrimitiveSerHelper<T,int>::Init()` in Reflection.h.
   */
  gpg::PrimitiveSerHelper<moho::ESearchType, int> gESearchTypePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005A9D90 (FUN_005A9D90, Moho::ESearchTypeTypeInfo::ESearchTypeTypeInfo)
 */
ESearchTypeTypeInfo::ESearchTypeTypeInfo()
{
  gpg::PreRegisterRType(typeid(ESearchType), this);
}

/**
 * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
 */
ESearchTypeTypeInfo::~ESearchTypeTypeInfo() = default;

/**
 * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
 */
const char* ESearchTypeTypeInfo::GetName() const
{
  return "ESearchType";
}

/**
 * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
 */
void ESearchTypeTypeInfo::Init()
{
  size_ = sizeof(ESearchType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `ESearchType`.
 */
void moho::register_ESearchTypeTypeInfo()
{
  (void)AcquireESearchTypeTypeInfo();
}

namespace
{
  struct ESearchTypeTypeInfoBootstrap
  {
    ESearchTypeTypeInfoBootstrap()
    {
      moho::register_ESearchTypeTypeInfo();
    }
  };

  [[maybe_unused]] ESearchTypeTypeInfoBootstrap gESearchTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESearchTypeTypeInfo_e65689, moho::register_ESearchTypeTypeInfo)
