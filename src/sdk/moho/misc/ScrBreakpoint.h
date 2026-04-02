#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace moho
{
  class ScrBreakpoint
  {
  public:
    ScrBreakpoint();

    /**
     * Address: 0x004B01D0 (FUN_004B01D0, Moho::ScrBreakpoint::ScrBreakpoint)
     *
     * msvc8::string const &,int
     *
     * What it does:
     * Initializes one breakpoint with enabled-state lane set true, copies the
     * name string, and stores the line lane.
     */
    ScrBreakpoint(const msvc8::string& breakpointName, int lineNumber);

    /**
     * Address: 0x004B0210 (FUN_004B0210, Moho::ScrBreakpoint::~ScrBreakpoint)
     *
     * What it does:
     * Resets breakpoint name storage to empty SSO state.
     */
    virtual ~ScrBreakpoint();

    /**
     * Address: 0x004B03A0 (FUN_004B03A0, Moho::ScrBreakpoint::AsString)
     *
     * What it does:
     * Serializes breakpoint state into `enabled|disabled:line:name`.
     */
    [[nodiscard]] msvc8::string AsString() const;

    /**
     * Address: 0x004B0240 (FUN_004B0240, Moho::ScrBreakpoint::FromString)
     *
     * msvc8::string const &
     *
     * What it does:
     * Parses one serialized `enabled:line:name` string and applies parsed
     * state when all three lanes are present.
     */
    void FromString(const msvc8::string& serializedBreakpoint);

  public:
    bool enabled;      // +0x04
    msvc8::string name;// +0x08
    int line;          // +0x24
  };

  static_assert(offsetof(ScrBreakpoint, enabled) == 0x04, "ScrBreakpoint::enabled offset must be 0x04");
  static_assert(offsetof(ScrBreakpoint, name) == 0x08, "ScrBreakpoint::name offset must be 0x08");
  static_assert(offsetof(ScrBreakpoint, line) == 0x24, "ScrBreakpoint::line offset must be 0x24");
  static_assert(sizeof(ScrBreakpoint) == 0x28, "ScrBreakpoint size must be 0x28");
} // namespace moho
