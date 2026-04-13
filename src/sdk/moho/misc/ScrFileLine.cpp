#include "moho/misc/ScrFileLine.h"

#include <cstddef>
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

