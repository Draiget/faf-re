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
  alignas(EPathTypeTypeInfo) unsigned char gEPathTypeTypeInfoStorage[sizeof(EPathTypeTypeInfo)] = {};
  bool gEPathTypeTypeInfoConstructed = false;

  [[nodiscard]] EPathTypeTypeInfo* AcquireEPathTypeTypeInfo()
  {
    if (!gEPathTypeTypeInfoConstructed) {
      auto* const typeInfo = new (gEPathTypeTypeInfoStorage) EPathTypeTypeInfo();
      gpg::PreRegisterRType(typeid(EPathType), typeInfo);
      gEPathTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<EPathTypeTypeInfo*>(gEPathTypeTypeInfoStorage);
  }

  /**
   * Address: 0x00BF7410 (FUN_00BF7410, cleanup_EPathTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EPathTypeTypeInfo` reflection storage.
   */
  void cleanup_EPathTypeTypeInfo()
  {
    if (!gEPathTypeTypeInfoConstructed) {
      return;
    }

    AcquireEPathTypeTypeInfo()->~EPathTypeTypeInfo();
    gEPathTypeTypeInfoConstructed = false;
  }

  // Address: 0x010AEFEC -- process-global `PrimitiveSerHelper<EPathType,int>`
  // singleton (constructed by FUN_00BCD290, self-registering via `__xc_a`; see
  // EPathTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::EPathTypePrimitiveSerializer gEPathTypePrimitiveSerializer;
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
 * Constructs/preregisters startup RTTI descriptor for `EPathType` and
 * installs process-exit cleanup.
 */
int moho::register_EPathTypeTypeInfo()
{
  (void)AcquireEPathTypeTypeInfo();
  return std::atexit(&cleanup_EPathTypeTypeInfo);
}

namespace
{
  struct EPathTypeTypeInfoBootstrap
  {
    EPathTypeTypeInfoBootstrap()
    {
      (void)moho::register_EPathTypeTypeInfo();
    }
  };

  [[maybe_unused]] EPathTypeTypeInfoBootstrap gEPathTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EPathTypeTypeInfo_22c3ce, moho::register_EPathTypeTypeInfo)

GPG_PREREGISTER_INIT(AcquireEPathTypeTypeInfo_22c3ce, AcquireEPathTypeTypeInfo)
