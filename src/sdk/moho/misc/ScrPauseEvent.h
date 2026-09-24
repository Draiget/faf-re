#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "platform/WxWidgets.h"
#include <wx/event.h>

namespace moho
{
  /**
   * Address: 0x00BC5F40 (FUN_00BC5F40, dynamic initializer)
   *
   * What it does:
   * `wxNewEventType()` into 0x010A8A84, from DEFINE_EVENT_TYPE in
   * ScrPauseEvent.cpp.
   */
  extern const wxEventType EVT_SCR_PAUSE;

  /**
   * VFTABLE: 0x00E07E60 (??_7ScrPauseEvent@Moho@@6B@)
   *
   * Posted to the debugger window when a Lua thread stops at a breakpoint or a
   * step: which source file and line it stopped on.
   *
   * No class info of its own - slot 0 is wxEvent::GetClassInfo, emitted here
   * (0x004B4310). The copy constructor (0x004B44A0) and destructor (0x004B43B0,
   * deleting 0x004B4450) are the compiler's.
   */
  class ScrPauseEvent : public wxEvent
  {
  public:
    /**
     * Address: 0x004B4330 (FUN_004B4330)
     *
     * What it does:
     * `wxEvent(0, EVT_SCR_PAUSE)` carrying the source and line.
     */
    ScrPauseEvent(const msvc8::string& sourceName, int sourceLine);

    /**
     * Address: 0x004B43F0 (FUN_004B43F0)
     *
     * What it does:
     * `new ScrPauseEvent(*this)`, for AddPendingEvent's queued copy.
     */
    wxEvent* Clone() const override;

    msvc8::string mSourceName; // +0x20
    int mSourceLine;           // +0x3C
  };

  static_assert(offsetof(ScrPauseEvent, mSourceName) == 0x20, "ScrPauseEvent::mSourceName offset must be 0x20");
  static_assert(offsetof(ScrPauseEvent, mSourceLine) == 0x3C, "ScrPauseEvent::mSourceLine offset must be 0x3C");
  static_assert(sizeof(ScrPauseEvent) == 0x40, "ScrPauseEvent size must be 0x40");
} // namespace moho
