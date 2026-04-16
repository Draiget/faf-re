#include "moho/misc/ScrPauseEvent.h"

#include <new>

/**
 * Address: 0x00978FD0
 * Mangled: ?wxNewEventType@@YAHXZ
 */
int wxNewEventType();

namespace
{
  void* gScrPauseEventClassInfoTable[1] = {nullptr};

  void InitializeWxEventRuntime(wxEventRuntime& eventRuntime, const int eventType) noexcept
  {
    eventRuntime.mRefData = nullptr;
    eventRuntime.mEventObject = nullptr;
    eventRuntime.mEventType = eventType;
    eventRuntime.mEventTimestamp = 0;
    eventRuntime.mEventId = 0;
    eventRuntime.mCallbackUserData = nullptr;
    eventRuntime.mSkipped = 0;
    eventRuntime.mIsCommandEvent = 0;
    eventRuntime.mReserved1E = 0;
    eventRuntime.mReserved1F = 0;
  }

  void CopyWxEventRuntime(wxEventRuntime& destination, const wxEventRuntime& source) noexcept
  {
    destination.mRefData = source.mRefData;
    destination.mEventObject = source.mEventObject;
    destination.mEventType = source.mEventType;
    destination.mEventTimestamp = source.mEventTimestamp;
    destination.mEventId = source.mEventId;
    destination.mCallbackUserData = source.mCallbackUserData;
    destination.mSkipped = source.mSkipped;
    destination.mIsCommandEvent = source.mIsCommandEvent;
    destination.mReserved1E = source.mReserved1E;
    destination.mReserved1F = source.mReserved1F;
  }
} // namespace

namespace moho
{
  int gScrPauseEventType = 0;
} // namespace moho

/**
 * Address: 0x004B4330 (FUN_004B4330, sub_4B4330)
 *
 * msvc8::string const &,int
 *
 * What it does:
 * Initializes one pause-event payload with source lane and source line.
 */
moho::ScrPauseEvent::ScrPauseEvent(const msvc8::string& sourceName, const int sourceLine)
  : mSourceName()
  , mSourceLine(sourceLine)
{
  InitializeWxEventRuntime(*this, gScrPauseEventType);
  mSourceName.assign(sourceName, 0U, msvc8::string::npos);
}

/**
 * Address: 0x004B44A0 (FUN_004B44A0, sub_4B44A0)
 *
 * What it does:
 * Copy-constructs one pause-event payload.
 */
moho::ScrPauseEvent::ScrPauseEvent(const ScrPauseEvent& other)
  : mSourceName()
  , mSourceLine(other.mSourceLine)
{
  CopyWxEventRuntime(*this, other);
  mSourceName.assign(other.mSourceName, 0U, msvc8::string::npos);
}

/**
 * Address: 0x004B4450 (FUN_004B4450, sub_4B4450)
 *
 * What it does:
 * Releases payload string lanes and wxEvent ref-data state.
 */
moho::ScrPauseEvent::~ScrPauseEvent()
{
  mSourceName.tidy(true, 0U);
  mRefData = nullptr;
}

/**
 * Address: 0x004B4310 (FUN_004B4310, vftable lane)
 *
 * What it does:
 * Returns class-info lane storage used by wx RTTI probes.
 */
void* moho::ScrPauseEvent::GetClassInfo() const
{
  return gScrPauseEventClassInfoTable;
}

/**
  * Alias of FUN_004B4450 (non-canonical helper lane).
 *
 * What it does:
 * Deletes this payload object.
 */
void moho::ScrPauseEvent::DeleteObject()
{
  delete this;
}

/**
 * Address: 0x004B43F0 (FUN_004B43F0, sub_4B43F0)
 *
 * What it does:
 * Allocates and copy-clones one pause-event payload.
 */
moho::ScrPauseEvent* moho::ScrPauseEvent::Clone() const
{
  return new ScrPauseEvent(*this);
}

const msvc8::string& moho::ScrPauseEvent::GetSourceName() const noexcept
{
  return mSourceName;
}

int moho::ScrPauseEvent::GetSourceLine() const noexcept
{
  return mSourceLine;
}

/**
 * Address: 0x00BC5F40 (FUN_00BC5F40, sub_BC5F40)
 *
 * What it does:
 * Allocates one wx event-type lane for `ScrPauseEvent`.
 */
int moho::register_ScrPauseEventType()
{
  gScrPauseEventType = wxNewEventType();
  return gScrPauseEventType;
}

namespace
{
  struct ScrPauseEventTypeBootstrap
  {
    ScrPauseEventTypeBootstrap()
    {
      (void)moho::register_ScrPauseEventType();
    }
  };

  ScrPauseEventTypeBootstrap gScrPauseEventTypeBootstrap;
} // namespace
