#include "moho/ui/EMauiEventTypeTypeInfo.h"

#include <cstdint>

#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{
  /**
   * Address: 0x00795AA0 (FUN_00795AA0, Moho::EMauiEventTypeTypeInfo::dtr)
   */
  EMauiEventTypeTypeInfo::~EMauiEventTypeTypeInfo() = default;

  /**
   * Address: 0x00795A90 (FUN_00795A90, Moho::EMauiEventTypeTypeInfo::GetName)
   */
  const char* EMauiEventTypeTypeInfo::GetName() const
  {
    return "EMauiEventType";
  }

  /**
   * Address: 0x00795A70 (FUN_00795A70, Moho::EMauiEventTypeTypeInfo::Init)
   */
  void EMauiEventTypeTypeInfo::Init()
  {
    size_ = sizeof(EMauiEventType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00795AD0 (FUN_00795AD0, Moho::EMauiEventTypeTypeInfo::AddEnums)
   */
  void EMauiEventTypeTypeInfo::AddEnums()
  {
    mPrefix = "MET_";

    AddEnum(StripPrefix("MET_MouseMotion"), static_cast<std::int32_t>(MET_MouseMotion));
    AddEnum(StripPrefix("MET_MouseEnter"), static_cast<std::int32_t>(MET_MouseEnter));
    AddEnum(StripPrefix("MET_MouseHover"), static_cast<std::int32_t>(MET_MouseHover));
    AddEnum(StripPrefix("MET_MouseExit"), static_cast<std::int32_t>(MET_MouseExit));
    AddEnum(StripPrefix("MET_ButtonPress"), static_cast<std::int32_t>(MET_ButtonPress));
    AddEnum(StripPrefix("MET_ButtonDClick"), static_cast<std::int32_t>(MET_ButtonDClick));
    AddEnum(StripPrefix("MET_ButtonRelease"), static_cast<std::int32_t>(MET_ButtonRelease));
    AddEnum(StripPrefix("MET_WheelRotation"), static_cast<std::int32_t>(MET_WheelRotation));
    AddEnum(StripPrefix("MET_KeyDown"), static_cast<std::int32_t>(MET_KeyDown));
    AddEnum(StripPrefix("MET_KeyUp"), static_cast<std::int32_t>(MET_KeyUp));
    AddEnum(StripPrefix("MET_Char"), static_cast<std::int32_t>(MET_Char));
  }
} // namespace moho
