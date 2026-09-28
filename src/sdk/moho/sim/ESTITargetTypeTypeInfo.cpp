#include "moho/sim/ESTITargetTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF50D0 (FUN_00BF50D0, atexit destructor of the ESTITargetTypeTypeInfo object)
   */
  [[nodiscard]] ESTITargetTypeTypeInfo& Acquire()
  {
    static ESTITargetTypeTypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { moho::register_ESTITargetTypeTypeInfoStartup(); } };
  Bootstrap gBootstrap;

  /**
   * Address: 0x00BCA2B0 (FUN_00BCA2B0, dynamic initializer for the global
   * `PrimitiveSerHelper<ESTITargetType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). Prior to this recovery, this
   * helper's raw-struct stand-in was never constructed anywhere in
   * `src/sdk` (no register function existed for it at all), so
   * `ESTITargetType`'s serialize/deserialize callbacks were never
   * installed under any code path.
   */
  moho::ESTITargetTypePrimitiveSerializer gESTITargetTypePrimitiveSerializer;
} // namespace

/**
 * Address: 0x0055AE70 (FUN_0055AE70, sub_55AE70)
 *
 * What it does:
 * Constructs the REnumType base, registers under typeid(ESTITargetType),
 * and installs the typeinfo vtable.
 */
ESTITargetTypeTypeInfo::ESTITargetTypeTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(ESTITargetType), this);
}

ESTITargetTypeTypeInfo::~ESTITargetTypeTypeInfo() = default;

/** Address: 0x0055AEF0 (FUN_0055AEF0) */
const char* ESTITargetTypeTypeInfo::GetName() const { return "ESTITargetType"; }

/**
 * Address: 0x0055AED0 (FUN_0055AED0)
 *
 * What it does:
 * Sets size = sizeof(ESTITargetType), invokes RType::Init(), populates
 * named enum values via AddEnums, and finalizes.
 */
void ESTITargetTypeTypeInfo::Init()
{
  size_ = sizeof(ESTITargetType);
  gpg::RType::Init();
  AddEnums(this);
  Finish();
}

/**
 * Address: 0x0055AF30 (FUN_0055AF30, AddEnums)
 *
 * What it does:
 * Sets enum prefix `STITARGET_` and registers None=0, Entity=1, Position=2.
 */
void ESTITargetTypeTypeInfo::AddEnums(gpg::REnumType* const enumType)
{
  enumType->mPrefix = "STITARGET_";
  enumType->AddEnum(enumType->StripPrefix("STITARGET_None"), 0);
  enumType->AddEnum(enumType->StripPrefix("STITARGET_Entity"), 1);
  enumType->AddEnum(enumType->StripPrefix("STITARGET_Position"), 2);
}

/**
 * Address: 0x00BCA290 (FUN_00BCA290, register_ESTITargetTypeTypeInfo)
 */
void moho::register_ESTITargetTypeTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESTITargetTypeTypeInfoStartup_11d329, moho::register_ESTITargetTypeTypeInfoStartup)
