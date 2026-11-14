#include "moho/misc/ScrBreakpoint.h"

#include <clocale>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <sstream>

#include "gpg/core/containers/String.h"

namespace
{
  struct DwordLane
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
    std::uint32_t lane3;
    std::uint32_t lane4;
    std::uint32_t lane5;
    std::uint32_t lane6;
  };

  static_assert(sizeof(DwordLane) == 0x1C, "DwordLane size must be 0x1C");

} // namespace

/**
 * Address: 0x004B01D0 (FUN_004B01D0, Moho::ScrBreakpoint::ScrBreakpoint)
 *
 * fa::string const &,int
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
  const fa::string& breakpointName,
  const int lineNumber
)
  : enabled(true)
  , name()
  , line(lineNumber)
{
  name.assign(breakpointName, 0U, fa::string::npos);
}

/**
 * Address: 0x004B0210 (FUN_004B0210, Moho::ScrBreakpoint::~ScrBreakpoint)
 * Also emitted at: 0x004B0130 -- the scalar deleting destructor MSVC
 * generates for any polymorphic class with a virtual destructor (this class
 * declares `virtual ~ScrBreakpoint()`, no other base). No source line maps
 * to that emission; a standalone `DestructScrBreakpointDeleting` free
 * function previously modelled it as if it needed its own source-level
 * caller, but nothing ever called it (removed).
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
fa::string moho::ScrBreakpoint::AsString() const
{
  std::ostringstream stream(std::ios::out);
  stream << (enabled ? "enabled" : "disabled");
  stream << ":";
  stream << line;
  stream << ":";
  stream << name.c_str();

  fa::string serialized;
  serialized.assign_owned(stream.str());
  return serialized;
}

/**
 * Address: 0x004B0240 (FUN_004B0240, Moho::ScrBreakpoint::FromString)
 *
 * fa::string const &
 *
 * What it does:
 * Parses one serialized `enabled:line:name` string and applies parsed state
 * when all three lanes are present.
 */
void moho::ScrBreakpoint::FromString(
  const fa::string& serializedBreakpoint
)
{
  const char* cursor = serializedBreakpoint.c_str();
  fa::string token;
  fa::string token0;
  fa::string token1;
  fa::string token2;
  std::uint32_t tokenCount = 0;

  while (gpg::STR_GetToken(cursor, ":", token)) {
    if (tokenCount == 0U) {
      token0.assign(token, 0U, fa::string::npos);
    } else if (tokenCount == 1U) {
      token1.assign(token, 0U, fa::string::npos);
    } else if (tokenCount == 2U) {
      token2.assign(token, 0U, fa::string::npos);
    }
    ++tokenCount;
  }

  if (tokenCount == 3U) {
    enabled = (token0.view() == "enabled");
    line = std::atoi(token1.c_str());
    name.assign(token2, 0U, fa::string::npos);
  }
}
