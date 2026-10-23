#include "moho/ai/EPathTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF7410 (FUN_00BF7410, atexit destructor of the EPathTypeTypeInfo object)
   */
  [[nodiscard]] EPathTypeTypeInfo* AcquireEPathTypeTypeInfo()
  {
    static EPathTypeTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AEFEC -- process-global `PrimitiveSerHelper<EPathType,int>`
  // singleton (constructed by FUN_00BCD290, self-registering via `__xc_a`; see
  // EPathTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EPathType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EPathType@Moho@@H@gpg'`):
   * `FUN_00BCD290` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005B4E90`/`FUN_005B4EB0`, installs the
   * `PrimitiveSerHelper<EPathType,int>` vtable, and pushes plain unmangled
   * `FUN_00BF7420` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EPathTypePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EPathTypeTypeInfoBootstrap` constructor -- absent from the real ctor's
   * disassembly; removed.
   */
  gpg::PrimitiveSerHelper<moho::EPathType, int> gEPathTypePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005B20B0 (FUN_005B20B0, scalar deleting thunk)
 */
/**
 * Address: 0x005B2020 (FUN_005B2020, Moho::EPathTypeTypeInfo::EPathTypeTypeInfo)
 *
 * IDA signature:
 * Moho::EPathTypeTypeInfo *__thiscall
 * Moho::EPathTypeTypeInfo::EPathTypeTypeInfo(EPathTypeTypeInfo *this);
 *
 * What it does:
 * Constructs the `EPathType` enum reflection descriptor and hands it to
 * `gpg::PreRegisterRType` so the enum resolves through `gpg::LookupRType`.
 *
 *   0x005B2042  call ??0REnumType@gpg@@QAE@@Z     ; base
 *   0x005B2059  mov  vftable, ??_7EPathTypeTypeInfo@Moho@@6B@
 *   0x005B2063  call gpg::PreRegisterRType(typeid(EPathType), this)
 *
 * The vftable store is the compiler's; only the base call and the
 * pre-registration are this body's own work.
 */
EPathTypeTypeInfo::EPathTypeTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EPathType), this);
}

EPathTypeTypeInfo::~EPathTypeTypeInfo() = default;

/**
 * Address: 0x005B20A0 (FUN_005B20A0)
 */
const char* EPathTypeTypeInfo::GetName() const
{
  return "EPathType";
}

/**
 * Address: 0x005B2080 (FUN_005B2080)
 */
void EPathTypeTypeInfo::Init()
{
  size_ = sizeof(EPathType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCD270 (FUN_00BCD270, register_EPathTypeTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `EPathType`.
 */
void moho::register_EPathTypeTypeInfo()
{
  (void)AcquireEPathTypeTypeInfo();
}

namespace
{
  struct EPathTypeTypeInfoBootstrap
  {
    EPathTypeTypeInfoBootstrap()
    {
      moho::register_EPathTypeTypeInfo();
    }
  };

  [[maybe_unused]] EPathTypeTypeInfoBootstrap gEPathTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EPathTypeTypeInfo_22c3ce, moho::register_EPathTypeTypeInfo)

GPG_PREREGISTER_INIT(AcquireEPathTypeTypeInfo_22c3ce, AcquireEPathTypeTypeInfo)
