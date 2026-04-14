#include "moho/misc/ScrFileLine.h"

#include <cstddef>
#include <cstring>
#include <exception>
#include <new>
#include <string>

namespace
{
  /**
   * Address: 0x004C1C40 (FUN_004C1C40)
   *
   * What it does:
   * Executes one deleting-destructor thunk lane for `ScrFileLine`.
   */
  [[maybe_unused]] moho::ScrFileLine* DestructScrFileLineDeleting(
    moho::ScrFileLine* const self,
    const unsigned char deleteFlag
  ) noexcept
  {
    self->~ScrFileLine();
    if ((deleteFlag & 1U) != 0U) {
      ::operator delete(static_cast<void*>(self));
    }
    return self;
  }

  /**
   * Address: 0x004C6AB0 (FUN_004C6AB0)
   *
   * IDA signature:
   * int __usercall sub_4C6AB0@<eax>(int a1@<eax>, int a2@<esi>);
   *
   * What it does:
   * Copy-assigns one source ScrFileLine row into one already-constructed
   * destination row by duplicating the marker state and owning-copying
   * both embedded string lanes.
   */
  [[maybe_unused]] moho::ScrFileLine& CopyAssignScrFileLine(
    moho::ScrFileLine& destination,
    const moho::ScrFileLine& source
  )
  {
    destination.mMarkerState = source.mMarkerState;
    destination.mLineNumberText.assign(source.mLineNumberText, 0U, msvc8::string::npos);
    destination.mSourceText.assign(source.mSourceText, 0U, msvc8::string::npos);
    return destination;
  }

  /**
   * Address: 0x004C6B90 (FUN_004C6B90)
   *
   * IDA signature:
   * int __usercall sub_4C6B90@<eax>(int result@<eax>, int a2@<ecx>, int a3@<ebx>);
   *
   * What it does:
   * Copy-assigns one half-open source row range `[sourceBegin, sourceEnd)`
   * into destination rows ending at `destinationEnd`, walking the ranges
   * backward one 64-byte row at a time so overlapping in-place shifts
   * preserve semantics. Returns the destination begin pointer. Matches
   * the legacy `std::copy_backward<ScrFileLine*, ScrFileLine*>`
   * instantiation used by `msvc8::vector<ScrFileLine>` insert paths.
   */
  [[maybe_unused]] moho::ScrFileLine* CopyAssignScrFileLineRangeBackward(
    moho::ScrFileLine* destinationEnd,
    const moho::ScrFileLine* sourceBegin,
    const moho::ScrFileLine* sourceEnd
  )
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      CopyAssignScrFileLine(*destinationEnd, *sourceEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x004C6850 (FUN_004C6850)
   *
   * IDA signature:
   * int __usercall sub_4C6850@<eax>(int result@<eax>, int a2@<ecx>, int a3@<ebx>);
   *
   * What it does:
   * Copy-assigns one half-open source row range `[sourceBegin, sourceEnd)`
   * over the already-constructed destination rows starting at `destination`
   * and returns one-past the last written destination row. Matches the
   * legacy `std::copy<ScrFileLine*, ScrFileLine*>` instantiation emitted
   * for `msvc8::vector<ScrFileLine>` reallocation and insertion paths.
   */
  [[maybe_unused]] moho::ScrFileLine* CopyAssignScrFileLineRange(
    moho::ScrFileLine* destination,
    const moho::ScrFileLine* sourceBegin,
    const moho::ScrFileLine* const sourceEnd
  )
  {
    for (; sourceBegin != sourceEnd; ++sourceBegin, ++destination) {
      CopyAssignScrFileLine(*destination, *sourceBegin);
    }
    return destination;
  }

  /**
   * Address: 0x004C69B0 (FUN_004C69B0)
   *
   * IDA signature:
   * std::string *__usercall sub_4C69B0@<eax>(std::string *result@<eax>,
   *                                          int a2@<edi>,
   *                                          std::string *a3);
   *
   * What it does:
   * Copy-assigns one source row into every already-constructed destination
   * row in the half-open range `[destinationBegin, destinationEnd)` and
   * returns the address of the last assignment's destination string lane,
   * matching the legacy `std::fill<ScrFileLine*, ScrFileLine>` instantiation.
   */
  [[maybe_unused]] void FillScrFileLineRangeFromSource(
    moho::ScrFileLine* destinationBegin,
    moho::ScrFileLine* const destinationEnd,
    const moho::ScrFileLine& source
  )
  {
    for (; destinationBegin != destinationEnd; ++destinationBegin) {
      CopyAssignScrFileLine(*destinationBegin, source);
    }
  }

  /**
   * Address: 0x004C6D30 (FUN_004C6D30)
   *
   * IDA signature:
   * void __thiscall __noreturn sub_4C6D30(char *this, char *a1,
   *                                       void (__thiscall ***a2)(_DWORD, _DWORD));
   *
   * What it does:
   * Uninitialized-constructs one destination ScrFileLine range from a
   * parallel source range by copy-constructing each slot through the
   * ScrFileLine copy constructor. On any thrown exception, walks the
   * already-constructed destination prefix and invokes each row's non-
   * deleting destructor before rethrowing. Matches the legacy
   * `std::_Uninitialized_copy<ScrFileLine*, ScrFileLine*>` instantiation
   * used by `msvc8::vector<ScrFileLine>` grow/insert paths.
   */
  [[maybe_unused]] moho::ScrFileLine* UninitializedCopyScrFileLineRange(
    const moho::ScrFileLine* sourceBegin,
    const moho::ScrFileLine* const sourceEnd,
    moho::ScrFileLine* const destinationBegin
  )
  {
    moho::ScrFileLine* cursor = destinationBegin;
    try {
      while (sourceBegin != sourceEnd) {
        ::new (static_cast<void*>(cursor)) moho::ScrFileLine(*sourceBegin);
        ++cursor;
        ++sourceBegin;
      }
      return cursor;
    } catch (...) {
      for (moho::ScrFileLine* unwind = destinationBegin; unwind != cursor; ++unwind) {
        unwind->~ScrFileLine();
      }
      throw;
    }
  }

  /**
   * Address: 0x004C68A0 (FUN_004C68A0)
   *
   * IDA signature:
   * void __fastcall __noreturn sub_4C68A0(int a1, int a2,
   *                                       void (__thiscall ***a3)(_DWORD, _DWORD));
   *
   * What it does:
   * Uninitialized-constructs `count` ScrFileLine rows starting at
   * `destinationBegin` using the copy-constructor from `sourceRow`; on any
   * thrown exception, invokes the non-deleting destructor for every already-
   * constructed row and rethrows. Matches the legacy
   * `std::_Uninitialized_copy_n<ScrFileLine*>` instantiation used by
   * `msvc8::vector<ScrFileLine>` growth paths.
   */
  [[maybe_unused]] moho::ScrFileLine* UninitializedConstructScrFileLineRun(
    moho::ScrFileLine* const destinationBegin,
    const std::size_t count,
    const moho::ScrFileLine& sourceRow
  )
  {
    moho::ScrFileLine* cursor = destinationBegin;
    std::size_t remaining = count;
    try {
      while (remaining != 0U) {
        ::new (static_cast<void*>(cursor)) moho::ScrFileLine(sourceRow);
        ++cursor;
        --remaining;
      }
      return cursor;
    } catch (...) {
      for (moho::ScrFileLine* unwind = destinationBegin; unwind != cursor; ++unwind) {
        unwind->~ScrFileLine();
      }
      throw;
    }
  }

  void ExpandTabsToVisualColumns(msvc8::string& text)
  {
    std::size_t tabIndex = text.find("\t", 0U, 1U);
    while (tabIndex != msvc8::string::npos) {
      const std::size_t replacementWidth = 4U - (tabIndex & 0x3U);
      const std::string spaces(replacementWidth, ' ');
      if (!text.replace(tabIndex, 1U, spaces)) {
        break;
      }
      tabIndex = text.find("\t", 0U, 1U);
    }
  }
} // namespace

/**
 * Address: 0x004C1C60 (FUN_004C1C60, Moho::ScrFileLine::ScrFileLine)
 *
 * int,msvc8::string const &
 *
 * What it does:
 * Initializes one script-source line row with line-number text and tab-expanded
 * source content.
 */
moho::ScrFileLine::ScrFileLine(const int lineNumberOneBased, const msvc8::string& sourceLineText)
  : mMarkerState(-1)
  , mLineNumberText()
  , mSourceText()
{
  const std::string lineNumberText = std::to_string(lineNumberOneBased);
  mLineNumberText.assign(lineNumberText.c_str(), lineNumberText.size());
  mSourceText.assign(sourceLineText, 0U, msvc8::string::npos);
  ExpandTabsToVisualColumns(mSourceText);
}

/**
 * Address: 0x004C6150 (FUN_004C6150, Moho::ScrFileLine::ScrFileLine)
 *
 * IDA signature:
 * int __userpurge sub_4C6150@<eax>(int a1@<edi>, int a2);
 *
 * What it does:
 * Duplicates marker state and both embedded string lanes of the source
 * row, initializing each string member to empty SSO state and then
 * assigning the owning-copy of the corresponding source string.
 */
moho::ScrFileLine::ScrFileLine(const ScrFileLine& other)
  : mMarkerState(other.mMarkerState)
  , mLineNumberText()
  , mSourceText()
{
  mLineNumberText.assign_owned(other.mLineNumberText.view());
  mSourceText.assign_owned(other.mSourceText.view());
}

/**
 * Address: 0x004C1E10 (FUN_004C1E10, Moho::ScrFileLine::~ScrFileLine)
 *
 * What it does:
 * Releases both line-text storage lanes.
 */
moho::ScrFileLine::~ScrFileLine()
{
  mSourceText.tidy(true, 0U);
  mLineNumberText.tidy(true, 0U);
}

