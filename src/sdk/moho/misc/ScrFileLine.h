#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace moho
{
  class ScrFileLine
  {
  public:
    /**
     * Address: 0x004C1C60 (FUN_004C1C60, Moho::ScrFileLine::ScrFileLine)
     *
     * int,msvc8::string const &
     *
     * What it does:
     * Initializes one script-source line row with cleared marker state,
     * one formatted line-number text lane, and tab-expanded source text.
     */
    ScrFileLine(int lineNumberOneBased, const msvc8::string& sourceLineText);

    /**
     * Address: 0x004C6150 (FUN_004C6150, Moho::ScrFileLine::ScrFileLine)
     *
     * ScrFileLine const &
     *
     * What it does:
     * Copies vtable, marker state, and both string lanes from the source
     * row using the owning-copy lane so heap-backed source strings are
     * duplicated into fresh owned storage rather than adopted
     * non-owningly.
     */
    ScrFileLine(const ScrFileLine& other);

    /**
     * Address: 0x004C1E10 (FUN_004C1E10, Moho::ScrFileLine::~ScrFileLine)
     *
     * What it does:
     * Releases both line-number/source-text storage lanes.
     */
    virtual ~ScrFileLine();

  public:
    int mMarkerState;                 // +0x04
    msvc8::string mLineNumberText;    // +0x08
    msvc8::string mSourceText;        // +0x24
  };

  static_assert(offsetof(ScrFileLine, mMarkerState) == 0x04, "ScrFileLine::mMarkerState offset must be 0x04");
  static_assert(
    offsetof(ScrFileLine, mLineNumberText) == 0x08,
    "ScrFileLine::mLineNumberText offset must be 0x08"
  );
  static_assert(
    offsetof(ScrFileLine, mSourceText) == 0x24,
    "ScrFileLine::mSourceText offset must be 0x24"
  );
  static_assert(sizeof(ScrFileLine) == 0x40, "ScrFileLine size must be 0x40");
} // namespace moho

