#include "moho/audio/ISoundManagerTypeInfo.h"

#include "moho/audio/ISoundManager.h"

namespace moho
{
  /**
   * Address: 0x00760B20 (FUN_00760B20, Moho::ISoundManagerTypeInfo::dtr)
   */
  ISoundManagerTypeInfo::~ISoundManagerTypeInfo() = default;

  /**
   * Address: 0x00760B10 (FUN_00760B10, Moho::ISoundManagerTypeInfo::GetName)
   */
  const char* ISoundManagerTypeInfo::GetName() const
  {
    return "ISoundManager";
  }

  /**
   * Address: 0x00760AF0 (FUN_00760AF0, Moho::ISoundManagerTypeInfo::Init)
   */
  void ISoundManagerTypeInfo::Init()
  {
    size_ = sizeof(ISoundManager);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

