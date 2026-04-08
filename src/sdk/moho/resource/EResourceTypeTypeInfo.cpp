#include "moho/resource/EResourceTypeTypeInfo.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00545AE0 (FUN_00545AE0, Moho::EResourceTypeTypeInfo::dtr)
   */
  EResourceTypeTypeInfo::~EResourceTypeTypeInfo() = default;

  /**
   * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
   */
  const char* EResourceTypeTypeInfo::GetName() const
  {
    return "EResourceType";
  }

  /**
   * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
   */
  void EResourceTypeTypeInfo::Init()
  {
    size_ = sizeof(EResourceType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
   */
  void EResourceTypeTypeInfo::AddEnums()
  {
    mPrefix = "RESTYPE_";

    AddEnum(StripPrefix("RESTYPE_None"), static_cast<std::int32_t>(RESTYPE_None));
    AddEnum(StripPrefix("RESTYPE_Mass"), static_cast<std::int32_t>(RESTYPE_Mass));
    AddEnum(StripPrefix("RESTYPE_Hydrocarbon"), static_cast<std::int32_t>(RESTYPE_Hydrocarbon));
    AddEnum(StripPrefix("RESTYPE_Max"), static_cast<std::int32_t>(RESTYPE_Max));
  }
} // namespace moho
