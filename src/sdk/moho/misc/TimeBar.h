#pragma once

#include <cstddef>
#include <cstdint>

namespace msvc8
{
  template <class T>
  class vector;
}

namespace moho
{
  class CD3DPrimBatcher;
  class CTimeBarSection;

  struct STimeBarEventRecord
  {
    std::uint32_t mStartCycleLo; // +0x00
    std::uint32_t mStartCycleHi; // +0x04
    std::uint32_t mEndCycleLo;   // +0x08
    std::uint32_t mEndCycleHi;   // +0x0C
    const char* mName;           // +0x10
    std::uint32_t mColorTag;     // +0x14
  };

  static_assert(
    offsetof(STimeBarEventRecord, mStartCycleLo) == 0x00, "STimeBarEventRecord::mStartCycleLo offset must be 0x00"
  );
  static_assert(
    offsetof(STimeBarEventRecord, mStartCycleHi) == 0x04, "STimeBarEventRecord::mStartCycleHi offset must be 0x04"
  );
  static_assert(
    offsetof(STimeBarEventRecord, mEndCycleLo) == 0x08, "STimeBarEventRecord::mEndCycleLo offset must be 0x08"
  );
  static_assert(
    offsetof(STimeBarEventRecord, mEndCycleHi) == 0x0C, "STimeBarEventRecord::mEndCycleHi offset must be 0x0C"
  );
  static_assert(offsetof(STimeBarEventRecord, mName) == 0x10, "STimeBarEventRecord::mName offset must be 0x10");
  static_assert(offsetof(STimeBarEventRecord, mColorTag) == 0x14, "STimeBarEventRecord::mColorTag offset must be 0x14");
  static_assert(sizeof(STimeBarEventRecord) == 0x18, "STimeBarEventRecord size must be 0x18");

  struct STimeBarThreadInfo
  {
    STimeBarThreadInfo* mPrevNode;    // +0x00
    STimeBarThreadInfo* mNextNode;    // +0x04
    CTimeBarSection* mCurrentSection; // +0x08
    std::uint32_t mColorTag;          // +0x0C
  };

  static_assert(offsetof(STimeBarThreadInfo, mPrevNode) == 0x00, "STimeBarThreadInfo::mPrevNode offset must be 0x00");
  static_assert(offsetof(STimeBarThreadInfo, mNextNode) == 0x04, "STimeBarThreadInfo::mNextNode offset must be 0x04");
  static_assert(
    offsetof(STimeBarThreadInfo, mCurrentSection) == 0x08, "STimeBarThreadInfo::mCurrentSection offset must be 0x08"
  );
  static_assert(offsetof(STimeBarThreadInfo, mColorTag) == 0x0C, "STimeBarThreadInfo::mColorTag offset must be 0x0C");
  static_assert(sizeof(STimeBarThreadInfo) == 0x10, "STimeBarThreadInfo size must be 0x10");

  class CTimeBarSection
  {
  public:
    /**
     * Address: 0x004E6DF0 (FUN_004E6DF0)
     * Mangled: ??0CTimeBarSection@Moho@@QAE@PBD@Z
     *
     * char const *
     *
     * What it does:
     * Opens a scoped time-bar section on the current thread and snapshots the parent segment.
     */
    explicit CTimeBarSection(const char* name);

    /**
     * Address: 0x004E6E90 (FUN_004E6E90)
     * Mangled: ??1CTimeBarSection@Moho@@QAE@XZ
     *
     * void
     *
     * What it does:
     * Closes the current scope, records its elapsed cycle range, and restores the parent section.
     */
    ~CTimeBarSection();

    [[nodiscard]] std::int64_t GetStartCycle() const noexcept;
    void SetStartCycle(std::int64_t cycles) noexcept;

  public:
    CTimeBarSection* mPreviousSection; // +0x00
    std::uint32_t mStartCycleAlignPad; // +0x04 (aligns original 64-bit start-cycle slot)
    std::uint32_t mStartCycleLo;       // +0x08
    std::uint32_t mStartCycleHi;       // +0x0C
    const char* mName;                 // +0x10
  };

  static_assert(
    offsetof(CTimeBarSection, mPreviousSection) == 0x00, "CTimeBarSection::mPreviousSection offset must be 0x00"
  );
  static_assert(
    offsetof(CTimeBarSection, mStartCycleAlignPad) == 0x04, "CTimeBarSection::mStartCycleAlignPad offset must be 0x04"
  );
  static_assert(offsetof(CTimeBarSection, mStartCycleLo) == 0x08, "CTimeBarSection::mStartCycleLo offset must be 0x08");
  static_assert(offsetof(CTimeBarSection, mStartCycleHi) == 0x0C, "CTimeBarSection::mStartCycleHi offset must be 0x0C");
  static_assert(offsetof(CTimeBarSection, mName) == 0x10, "CTimeBarSection::mName offset must be 0x10");
  static_assert(sizeof(CTimeBarSection) == 0x14, "CTimeBarSection size must be 0x14");

  /**
   * Address: 0x004E6F30 (FUN_004E6F30)
   * Mangled: ?TIME_TimeBarEvent@Moho@@YAXPBD@Z
   *
   * char const *
   *
   * What it does:
   * Emits an instantaneous named marker event into the global time-bar history.
   */
  void TIME_TimeBarEvent(const char* name);

  /**
   * Address: 0x004E6FD0 (FUN_004E6FD0)
   *
   * int
   *
   * What it does:
   * Updates the current thread's time-bar color tag used for subsequent samples.
   */
  void TIME_SetTimeBarColor(std::uint32_t colorTag);

  /**
   * Address: 0x004E6FA0 (FUN_004E6FA0)
   * Address: 0x004E6AE0 (FUN_004E6AE0)
   *
   * msvc8::vector<moho::STimeBarEventRecord> &,float
   *
   * What it does:
   * Captures active sections plus recent history events into `outEvents`, newest-first.
   */
  void TIME_CollectTimeBarEvents(msvc8::vector<STimeBarEventRecord>& outEvents, float maxAgeSeconds);

  /**
   * Address: 0x004E83A0 (FUN_004E83A0)
   * Mangled: ?TIME_RenderTimeBars@Moho@@YAXPAVCD3DPrimBatcher@1@MMMMM@Z
   *
   * Moho::CD3DPrimBatcher *,float,float,float,float
   *
   * What it does:
   * Renders the time-bar overlay panel, labels, and per-event timing segments.
   */
  void TIME_RenderTimeBars(CD3DPrimBatcher* primBatcher, float left, float top, float width, float height);
} // namespace moho
