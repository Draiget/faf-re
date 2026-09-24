#include "moho/misc/ScrPauseEvent.h"

/**
 * Address: 0x00BC5F40 (FUN_00BC5F40, dynamic initializer)
 */
DEFINE_EVENT_TYPE(moho::EVT_SCR_PAUSE)

/**
 * Address: 0x004B4330 (FUN_004B4330)
 */
moho::ScrPauseEvent::ScrPauseEvent(const msvc8::string& sourceName, const int sourceLine)
  : wxEvent(0, EVT_SCR_PAUSE)
  , mSourceName(sourceName)
  , mSourceLine(sourceLine)
{
}

/**
 * Address: 0x004B43F0 (FUN_004B43F0)
 */
wxEvent* moho::ScrPauseEvent::Clone() const
{
  return new ScrPauseEvent(*this);
}
