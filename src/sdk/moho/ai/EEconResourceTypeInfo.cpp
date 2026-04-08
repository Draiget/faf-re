#include "moho/ai/EEconResourceTypeInfo.h"

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
   */
  EEconResourceTypeInfo::~EEconResourceTypeInfo() = default;

  /**
   * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
   */
  const char* EEconResourceTypeInfo::GetName() const
  {
    return "EEconResource";
  }

  /**
   * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
   */
  void EEconResourceTypeInfo::Init()
  {
    size_ = sizeof(EEconResource);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
   */
  void EEconResourceTypeInfo::AddEnums()
  {
    mPrefix = "ECON_";

    AddEnum(StripPrefix("ECON_ENERGY"), static_cast<std::int32_t>(ECON_ENERGY));
    AddEnum(StripPrefix("ECON_MASS"), static_cast<std::int32_t>(ECON_MASS));
  }
} // namespace moho

