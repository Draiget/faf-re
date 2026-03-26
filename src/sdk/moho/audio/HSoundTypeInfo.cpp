#include "moho/audio/HSoundTypeInfo.h"

#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/HSound.h"

namespace moho
{
  /**
   * Address: 0x004E1400 (FUN_004E1400, Moho::HSoundTypeInfo::dtr)
   */
  HSoundTypeInfo::~HSoundTypeInfo() = default;

  /**
   * Address: 0x004E13F0 (FUN_004E13F0, Moho::HSoundTypeInfo::GetName)
   */
  const char* HSoundTypeInfo::GetName() const
  {
    return "HSound";
  }

  /**
   * Address: 0x004E13C0 (FUN_004E13C0, Moho::HSoundTypeInfo::Init)
   */
  void HSoundTypeInfo::Init()
  {
    size_ = sizeof(HSound);
    AddBase_CScriptEvent(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x004E4E80 (FUN_004E4E80, Moho::HSoundTypeInfo::AddBase_CScriptEvent)
   */
  void HSoundTypeInfo::AddBase_CScriptEvent(gpg::RType* const typeInfo)
  {
    audio_reflection::AddBase(typeInfo, audio_reflection::ResolveCScriptEventType());
  }
} // namespace moho

