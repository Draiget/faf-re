#include "moho/unit/core/EJobTypeTypeInfo.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x0055B8A0 (FUN_0055B8A0, Moho::EJobTypeTypeInfo::dtr)
   */
  EJobTypeTypeInfo::~EJobTypeTypeInfo() = default;

  /**
   * Address: 0x0055B890 (FUN_0055B890, Moho::EJobTypeTypeInfo::GetName)
   */
  const char* EJobTypeTypeInfo::GetName() const
  {
    return "EJobType";
  }

  /**
   * Address: 0x0055B870 (FUN_0055B870, Moho::EJobTypeTypeInfo::Init)
   */
  void EJobTypeTypeInfo::Init()
  {
    size_ = sizeof(EJobType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055B8D0 (FUN_0055B8D0, Moho::EJobTypeTypeInfo::AddEnums)
   */
  void EJobTypeTypeInfo::AddEnums()
  {
    mPrefix = "JOB_";

    AddEnum(StripPrefix("JOB_None"), static_cast<std::int32_t>(JOB_None));
    AddEnum(StripPrefix("JOB_Build"), static_cast<std::int32_t>(JOB_Build));
    AddEnum(StripPrefix("JOB_Repair"), static_cast<std::int32_t>(JOB_Repair));
    AddEnum(StripPrefix("JOB_Reclaim"), static_cast<std::int32_t>(JOB_Reclaim));
  }
} // namespace moho
