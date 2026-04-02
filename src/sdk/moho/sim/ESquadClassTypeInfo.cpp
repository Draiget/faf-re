#include "moho/sim/ESquadClassTypeInfo.h"

#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::ESquadClassTypeInfo) unsigned char gESquadClassTypeInfoStorage[sizeof(moho::ESquadClassTypeInfo)]{};
  bool gESquadClassTypeInfoConstructed = false;

  /**
   * Address: 0x00723B10 (FUN_00723B10, ESquadClassTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `ESquadClassTypeInfo` object and pre-registers RTTI
   * ownership for `ESquadClass`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructESquadClassTypeInfo()
  {
    if (!gESquadClassTypeInfoConstructed) {
      new (gESquadClassTypeInfoStorage) moho::ESquadClassTypeInfo();
      gESquadClassTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::ESquadClassTypeInfo*>(gESquadClassTypeInfoStorage);
    gpg::PreRegisterRType(typeid(moho::ESquadClass), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00723BC0 (FUN_00723BC0, REnumType dtor thunk for ESquadClass block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant1(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00723BA0 (FUN_00723BA0, Moho::ESquadClassTypeInfo::dtr)
   */
  ESquadClassTypeInfo::~ESquadClassTypeInfo() = default;

  /**
   * Address: 0x00723B90 (FUN_00723B90, Moho::ESquadClassTypeInfo::GetName)
   */
  const char* ESquadClassTypeInfo::GetName() const
  {
    return "ESquadClass";
  }

  /**
   * Address: 0x00723B70 (FUN_00723B70, Moho::ESquadClassTypeInfo::Init)
   */
  void ESquadClassTypeInfo::Init()
  {
    size_ = sizeof(ESquadClass);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00723BD0 (FUN_00723BD0, Moho::ESquadClassTypeInfo::AddEnums)
   */
  void ESquadClassTypeInfo::AddEnums()
  {
    mPrefix = "SQUADCLASS_";
    AddEnum(StripPrefix("SQUADCLASS_Unassigned"), static_cast<std::int32_t>(ESquadClass::Unassigned));
    AddEnum(StripPrefix("SQUADCLASS_Attack"), static_cast<std::int32_t>(ESquadClass::Attack));
    AddEnum(StripPrefix("SQUADCLASS_Artillery"), static_cast<std::int32_t>(ESquadClass::Artillery));
    AddEnum(StripPrefix("SQUADCLASS_Guard"), static_cast<std::int32_t>(ESquadClass::Guard));
    AddEnum(StripPrefix("SQUADCLASS_Support"), static_cast<std::int32_t>(ESquadClass::Support));
    AddEnum(StripPrefix("SQUADCLASS_Scout"), static_cast<std::int32_t>(ESquadClass::Scout));
  }
} // namespace moho

