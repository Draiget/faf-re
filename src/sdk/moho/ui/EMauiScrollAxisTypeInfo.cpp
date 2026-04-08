#include "moho/ui/EMauiScrollAxisTypeInfo.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x007865F0 (FUN_007865F0, Moho::EMauiScrollAxisTypeInfo::dtr)
   */
  EMauiScrollAxisTypeInfo::~EMauiScrollAxisTypeInfo() = default;

  /**
   * Address: 0x007865E0 (FUN_007865E0, Moho::EMauiScrollAxisTypeInfo::GetName)
   */
  const char* EMauiScrollAxisTypeInfo::GetName() const
  {
    return "EMauiScrollAxis";
  }

  /**
   * Address: 0x00786590 (FUN_00786590, Moho::EMauiScrollAxisTypeInfo::Init)
   */
  void EMauiScrollAxisTypeInfo::Init()
  {
    size_ = sizeof(EMauiScrollAxis);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00786620 (FUN_00786620, Moho::EMauiScrollAxisTypeInfo::AddEnums)
   */
  void EMauiScrollAxisTypeInfo::AddEnums()
  {
    mPrefix = "MSA_";

    AddEnum(StripPrefix("MSA_Vert"), static_cast<std::int32_t>(MSA_Vert));
    AddEnum(StripPrefix("MSA_Horz"), static_cast<std::int32_t>(MSA_Horz));
  }
} // namespace moho

