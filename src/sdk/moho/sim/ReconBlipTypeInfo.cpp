#include "moho/sim/ReconBlipTypeInfo.h"

#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/sim/ReconBlip.h"

namespace moho
{
  /**
   * Address: 0x005BE630 (FUN_005BE630, Moho::ReconBlipTypeInfo::dtr)
   */
  ReconBlipTypeInfo::~ReconBlipTypeInfo() = default;

  /**
   * Address: 0x005BE620 (FUN_005BE620, Moho::ReconBlipTypeInfo::GetName)
   */
  const char* ReconBlipTypeInfo::GetName() const
  {
    return "ReconBlip";
  }

  /**
   * Address: 0x005BE5F0 (FUN_005BE5F0, Moho::ReconBlipTypeInfo::Init)
   */
  void ReconBlipTypeInfo::Init()
  {
    size_ = sizeof(ReconBlip);
    AddBase_Entity(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x005C9010 (FUN_005C9010)
   */
  void ReconBlipTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    static gpg::RType* cachedEntityType = nullptr;
    if (!cachedEntityType) {
      cachedEntityType = gpg::LookupRType(typeid(Entity));
    }

    gpg::RField baseField{};
    baseField.mName = cachedEntityType->GetName();
    baseField.mType = cachedEntityType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
