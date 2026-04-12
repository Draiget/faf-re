#include "moho/ui/EUIActionTypeTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

using namespace moho;

namespace
{
  alignas(EUIActionTypeTypeInfo) unsigned char gStorage[sizeof(EUIActionTypeTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] EUIActionTypeTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) EUIActionTypeTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<EUIActionTypeTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<EUIActionTypeTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
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

void moho::register_EUIActionTypeTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
