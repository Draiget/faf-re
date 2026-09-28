#include "moho/ui/EUIActionTypeTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C05E00 (FUN_00C05E00, atexit destructor of the EUIActionTypeTypeInfo object)
   */
  [[nodiscard]] EUIActionTypeTypeInfo& Acquire()
  {
    static EUIActionTypeTypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { moho::register_EUIActionTypeTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/** Address: 0x008220A0 (FUN_008220A0, sub_8220A0) */
EUIActionTypeTypeInfo::EUIActionTypeTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EUIActionType), this);
}

EUIActionTypeTypeInfo::~EUIActionTypeTypeInfo() = default;

/** Address: 0x00822120 */
const char* EUIActionTypeTypeInfo::GetName() const { return "EUIActionType"; }

/**
 * Address: 0x00822100 (FUN_00822100, Init)
 *
 * What it does:
 * Sets size = sizeof(EUIActionType), populates enum values, finalizes.
 */
void EUIActionTypeTypeInfo::Init()
{
  size_ = sizeof(EUIActionType);
  gpg::RType::Init();
  AddEnums(this);
  Finish();
}

/**
 * Address: 0x00822160 (FUN_00822160, AddEnums)
 */
void EUIActionTypeTypeInfo::AddEnums(gpg::REnumType* const enumType)
{
  enumType->mPrefix = "EUIAT";
  enumType->AddEnum(enumType->StripPrefix("EUIAT_None"), 0);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_Command"), 1);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_Build"), 2);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_BuildAnchored"), 3);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_Select"), 4);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_EditGraphDrag"), 5);
  enumType->AddEnum(enumType->StripPrefix("EUIAT_Cancel"), 7);
}

/**
 * Address: 0x00BE3A50 (FUN_00BE3A50, register_EUIActionTypeTypeInfoStartup)
 *
 * What it does:
 * Constructs the `EUIActionType` enum type-info object.
 */
void moho::register_EUIActionTypeTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EUIActionTypeTypeInfoStartup_4d556a, moho::register_EUIActionTypeTypeInfoStartup)
