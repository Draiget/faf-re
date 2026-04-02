#include "moho/misc/ScrBreakpoint.h"

#include <clocale>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <sstream>

#include "gpg/core/containers/String.h"

namespace
{
  /**
   * Address: 0x004B0070 (FUN_004B0070)
   *
   * What it does:
   * Thunk lane that returns active locale conversion table storage.
   */
  [[maybe_unused]] std::lconv* GetLocaleConventions() noexcept
  {
    return std::localeconv();
  }

  /**
   * Address: 0x004B0080 (FUN_004B0080)
   *
   * What it does:
   * Returns the literal false token used by breakpoint string lanes.
   */
  [[maybe_unused]] const char* GetFalseLiteral() noexcept
  {
    return "false";
  }

  /**
   * Address: 0x004B0090 (FUN_004B0090)
   *
   * What it does:
   * Returns the literal true token used by breakpoint string lanes.
   */
  [[maybe_unused]] const char* GetTrueLiteral() noexcept
  {
    return "true";
  }

  struct DwordLaneRuntime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
    std::uint32_t lane3;
    std::uint32_t lane4;
    std::uint32_t lane5;
    std::uint32_t lane6;
  };

  static_assert(sizeof(DwordLaneRuntime) == 0x1C, "DwordLaneRuntime size must be 0x1C");

  /**
   * Address: 0x004B00A0 (FUN_004B00A0)
   *
   * What it does:
   * Stores one caller-provided dword into lane0 of output storage.
   */
  [[maybe_unused]] DwordLaneRuntime* StoreDwordLane0(
    DwordLaneRuntime* const outLanes,
    const std::uint32_t lane0
  ) noexcept
  {
    outLanes->lane0 = lane0;
    return outLanes;
  }

  /**
   * Address: 0x004B00D0 (FUN_004B00D0)
   *
   * What it does:
   * Returns dword lane4 from caller-provided lane storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane4(
    const DwordLaneRuntime* const lanes
  ) noexcept
  {
    return lanes->lane4;
  }

  /**
   * Address: 0x004B00E0 (FUN_004B00E0)
   *
   * What it does:
   * Returns dword lane5 from caller-provided lane storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane5(
    const DwordLaneRuntime* const lanes
  ) noexcept
  {
    return lanes->lane5;
  }

  /**
   * Address: 0x004B00F0 (FUN_004B00F0)
   *
   * What it does:
   * Returns dword lane6 from caller-provided lane storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane6(
    const DwordLaneRuntime* const lanes
  ) noexcept
  {
    return lanes->lane6;
  }

  /**
   * Address: 0x004B0100 (FUN_004B0100)
   *
   * What it does:
   * Exchanges dword lane6 and returns the previously stored lane value.
   */
  [[maybe_unused]] std::uint32_t ExchangeDwordLane6(
    DwordLaneRuntime* const lanes,
    const std::uint32_t replacementLane6
  ) noexcept
  {
    const std::uint32_t previousLane6 = lanes->lane6;
    lanes->lane6 = replacementLane6;
    return previousLane6;
  }

  /**
   * Address: 0x004B0130 (FUN_004B0130)
   *
   * What it does:
   * Executes one deleting-destructor thunk lane for `ScrBreakpoint` by
   * running object teardown and conditionally freeing storage.
   */
  [[maybe_unused]] moho::ScrBreakpoint* DestructScrBreakpointDeleting(
    moho::ScrBreakpoint* const self,
    const unsigned char deleteFlag
  ) noexcept
  {
    self->~ScrBreakpoint();
    if ((deleteFlag & 1U) != 0U) {
      ::operator delete(static_cast<void*>(self));
    }
    return self;
  }

  /**
   * Address: 0x004B0170 (FUN_004B0170)
   *
   * What it does:
   * Constructs one breakpoint in caller-provided storage with disabled/default
   * state then parses serialized breakpoint lanes.
   */
  [[maybe_unused]] moho::ScrBreakpoint* ConstructScrBreakpointFromString(
    moho::ScrBreakpoint* const outBreakpoint,
    const msvc8::string& serializedBreakpoint
  )
  {
    static const msvc8::string kEmptyName("");
    ::new (static_cast<void*>(outBreakpoint)) moho::ScrBreakpoint(kEmptyName, -1);
    outBreakpoint->enabled = false;
    outBreakpoint->FromString(serializedBreakpoint);
    return outBreakpoint;
  }
} // namespace

/**
 * Address: 0x004B01D0 (FUN_004B01D0, Moho::ScrBreakpoint::ScrBreakpoint)
 *
 * msvc8::string const &,int
 *
 * What it does:
 * Initializes one breakpoint with enabled-state lane set true, copies the
 * name string, and stores the line lane.
 */
moho::ScrBreakpoint::ScrBreakpoint()
  : enabled(false)
  , name()
  , line(-1)
{}

moho::ScrBreakpoint::ScrBreakpoint(
  const msvc8::string& breakpointName,
  const int lineNumber
)
  : enabled(true),
    name(),
    line(lineNumber)
{
  name.assign(breakpointName, 0U, msvc8::string::npos);
}

/**
 * Address: 0x004B0210 (FUN_004B0210, Moho::ScrBreakpoint::~ScrBreakpoint)
 *
 * What it does:
 * Resets breakpoint name storage to empty SSO state.
 */
moho::ScrBreakpoint::~ScrBreakpoint()
{
  name.tidy(true, 0U);
}

/**
 * Address: 0x004B03A0 (FUN_004B03A0, Moho::ScrBreakpoint::AsString)
 *
 * What it does:
 * Serializes breakpoint state into `enabled|disabled:line:name`.
 */
msvc8::string moho::ScrBreakpoint::AsString() const
{
  std::ostringstream stream(std::ios::out);
  stream << (enabled ? "enabled" : "disabled");
  stream << ":";
  stream << line;
  stream << ":";
  stream << name.c_str();

  msvc8::string serialized;
  serialized.assign_owned(stream.str());
  return serialized;
}

/**
 * Address: 0x004B0240 (FUN_004B0240, Moho::ScrBreakpoint::FromString)
 *
 * msvc8::string const &
 *
 * What it does:
 * Parses one serialized `enabled:line:name` string and applies parsed state
 * when all three lanes are present.
 */
void moho::ScrBreakpoint::FromString(const msvc8::string& serializedBreakpoint)
{
  const char* cursor = serializedBreakpoint.c_str();
  msvc8::string token;
  msvc8::string token0;
  msvc8::string token1;
  msvc8::string token2;
  std::uint32_t tokenCount = 0;

  while (gpg::STR_GetToken(cursor, ":", token)) {
    if (tokenCount == 0U) {
      token0.assign(token, 0U, msvc8::string::npos);
    } else if (tokenCount == 1U) {
      token1.assign(token, 0U, msvc8::string::npos);
    } else if (tokenCount == 2U) {
      token2.assign(token, 0U, msvc8::string::npos);
    }
    ++tokenCount;
  }

  if (tokenCount == 3U) {
    enabled = (token0.view() == "enabled");
    line = std::atoi(token1.c_str());
    name.assign(token2, 0U, msvc8::string::npos);
  }
}
