#include "legacy/containers/Map.h"
#include "moho/misc/TimeBar.h"

#include "platform/Platform.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <vector>

#include "boost/mutex.h"
#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "moho/math/Vector3f.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"

namespace moho
{
  // Address: 0x00F57E5C (ren_FrameTimeSeconds)
  extern float ren_FrameTimeSeconds;

  namespace
  {
    constexpr std::int32_t kTimeBarHistoryCapacity = 10000;
    constexpr std::uint32_t kDefaultThreadColorTag = 0xFFFFFFFFu;
    constexpr std::int32_t kFontPointSize = 10;
    constexpr const char* kFontFaceName = "Times New Roman";
    constexpr float kMinWindowSeconds = 0.000001f;
    constexpr float kLabelPadding = 2.0f;

    struct TimeBarEventView
    {
      const STimeBarEventRecord* mRecord;
      std::int64_t mStartCycles;
      std::int64_t mEndCycles;
    };

    struct TimeBarTrackLayout
    {
      const char* mName;
      float mRowY;
    };

    struct CaseInsensitiveCStringLess
    {
      [[nodiscard]] bool operator()(const char* lhs, const char* rhs) const noexcept
      {
        if (lhs == rhs) {
          return false;
        }
        if (!lhs) {
          return rhs != nullptr;
        }
        if (!rhs) {
          return false;
        }
        return gpg::STR_CompareNoCase(lhs, rhs) < 0;
      }
    };

    /**
     * One row per distinct event name, ordered case-insensitively. Node 0x18
     * with colour/nil at `+0x14`/`+0x15` and the `(name*, layout)` pair at
     * `node+0x0C`, which is the ordinary 4-aligned shape for an 0x0C
     * `pair<const char*, TimeBarTrackLayout>`.
     */
    using TimeBarTrackMap = msvc8::map<const char*, TimeBarTrackLayout, CaseInsensitiveCStringLess>;

    struct TimeBarState
    {
      boost::mutex mLock;
      STimeBarThreadInfo mThreadListSentinel;
      std::array<STimeBarEventRecord, kTimeBarHistoryCapacity> mHistory;
      std::int32_t mOldestHistoryIndex;
      std::int32_t mNextHistoryIndex;

      TimeBarState()
        : mLock{}
        , mThreadListSentinel{}
        , mHistory{}
        , mOldestHistoryIndex(0)
        , mNextHistoryIndex(0)
      {
        // TDatListItem's default ctor already self-links mThreadListSentinel
        // (mPrev == mNext == &mThreadListSentinel); only the payload needs
        // setting here.
        mThreadListSentinel.mCurrentSection = nullptr;
        mThreadListSentinel.mColorTag = kDefaultThreadColorTag;
      }
    };

    TimeBarState* gTimeBarState = nullptr;
    std::once_flag gTimeBarStateInitOnce;

    [[nodiscard]] std::int64_t CombineCycles(const std::uint32_t lo, const std::uint32_t hi) noexcept
    {
      const std::uint64_t value = (static_cast<std::uint64_t>(hi) << 32) | lo;
      return static_cast<std::int64_t>(value);
    }

    void SplitCycles(const std::int64_t cycles, std::uint32_t& lo, std::uint32_t& hi) noexcept
    {
      lo = static_cast<std::uint32_t>(cycles & 0xFFFFFFFFll);
      hi = static_cast<std::uint32_t>((static_cast<std::uint64_t>(cycles) >> 32) & 0xFFFFFFFFull);
    }

    [[nodiscard]] std::int64_t QueryCurrentCycles()
    {
      const gpg::time::Timer& timer = gpg::time::GetSystemTimer();
      return timer.ElapsedCycles();
    }

    void InitializeTimeBarState()
    {
      gTimeBarState = new TimeBarState{};
    }

    void ShutdownTimeBarStateAtProcessExit()
    {
      delete gTimeBarState;
      gTimeBarState = nullptr;
    }

    /**
     * Address: 0x004E6D00 (FUN_004E6D00)
     *
     * What it does:
     * Performs one-time time-bar runtime initialization and registers process
     * exit teardown for the time-bar global state.
     */
    void EnsureTimeBarRuntimeInitialized()
    {
      std::call_once(gTimeBarStateInitOnce, []() {
        InitializeTimeBarState();
        std::atexit(ShutdownTimeBarStateAtProcessExit);
      });
    }

    [[nodiscard]] TimeBarState& GetTimeBarState()
    {
      EnsureTimeBarRuntimeInitialized();
      return *gTimeBarState;
    }

    void UnlinkThreadInfoNoLock(STimeBarThreadInfo* const info) noexcept
    {
      if (!info) {
        return;
      }

      info->ListUnlink();
    }

    void ReleaseThreadInfo(STimeBarThreadInfo* info) noexcept
    {
      if (!info) {
        return;
      }

      if (gTimeBarState) {
        TimeBarState& state = *gTimeBarState;
        boost::mutex::scoped_lock guard(state.mLock);
        UnlinkThreadInfoNoLock(info);
      }

      delete info;
    }


    /**
     * Address: 0x004E7130 (FUN_004E7130, boost::thread_specific_ptr<
     * Moho::STimeBarThreadInfo>::ctor)
     *
     * What it does:
     * The binary constructs a `boost::thread_specific_ptr<STimeBarThreadInfo>`
     * whose cleanup callback is bound through the `tss_adapter<STimeBarThreadInfo>`
     * boost::function1 manage/clear chain documented in moho/app/WinApp.cpp
     * (FUN_004E7B40/FUN_004E7BA0/FUN_004E7C50/FUN_004E7D30/FUN_004E7DF0/
     * FUN_004E8010/FUN_004E80B0). This `thread_local TimeBarThreadSlot`
     * declaration is the source-level equivalent -- both mechanisms bind a
     * per-thread `STimeBarThreadInfo*` slot to an automatic teardown callback
     * (`ReleaseThreadInfo`), just via VC8-era boost TLS emulation on the
     * binary side versus C++11 `thread_local` storage here. The whole
     * boost::detail::tss/tss_adapter machinery this ctor would otherwise
     * require is intentionally not replicated; `thread_local` reproduces the
     * same per-thread lifetime/cleanup behavior directly.
     */
    struct TimeBarThreadSlot
    {
      STimeBarThreadInfo* mInfo = nullptr;

      ~TimeBarThreadSlot()
      {
        ReleaseThreadInfo(mInfo);
        mInfo = nullptr;
      }
    };

    thread_local TimeBarThreadSlot gThreadSlot;

    void LinkThreadInfoNoLock(TimeBarState& state, STimeBarThreadInfo* const info) noexcept
    {
      info->ListLinkAfter(&state.mThreadListSentinel);
    }

    [[nodiscard]] STimeBarThreadInfo* GetOrCreateThreadInfo(TimeBarState& state)
    {
      if (gThreadSlot.mInfo) {
        return gThreadSlot.mInfo;
      }

      // TDatListItem's default ctor already self-links info.
      auto* info = new STimeBarThreadInfo{};
      info->mCurrentSection = nullptr;
      info->mColorTag = kDefaultThreadColorTag;

      {
        boost::mutex::scoped_lock guard(state.mLock);
        LinkThreadInfoNoLock(state, info);
      }

      gThreadSlot.mInfo = info;
      return info;
    }

    /**
     * Address: 0x004E70A0 (FUN_004E70A0)
     *
     * What it does:
     * Writes one event record into the current history write slot and advances
     * the ring write index modulo history capacity.
     */
    std::int32_t PushTimeBarHistoryRecordAndAdvanceWriteIndex(
      TimeBarState& state,
      const STimeBarEventRecord& record
    ) noexcept
    {
      const std::int32_t writeIndex = state.mNextHistoryIndex;
      state.mHistory[writeIndex] = record;

      const std::int32_t linearNext = writeIndex + 1;
      state.mNextHistoryIndex = linearNext % kTimeBarHistoryCapacity;
      return linearNext / kTimeBarHistoryCapacity;
    }

    /**
     * Address: 0x004E6A20 (FUN_004E6A20)
     *
     * What it does:
     * Pushes one event record into the fixed-size history ring while holding
     * the time-bar mutex and advancing oldest/newest indices on wrap.
     */
    void PushHistoryRecord(TimeBarState& state, const STimeBarEventRecord& record)
    {
      boost::mutex::scoped_lock guard(state.mLock);

      const std::int32_t nextIndex = (state.mNextHistoryIndex + 1) % kTimeBarHistoryCapacity;
      if (nextIndex == state.mOldestHistoryIndex) {
        state.mOldestHistoryIndex = (state.mOldestHistoryIndex + 1) % kTimeBarHistoryCapacity;
      }

      (void)PushTimeBarHistoryRecordAndAdvanceWriteIndex(state, record);
    }

    [[nodiscard]] CD3DPrimBatcher::Vertex MakeVertex(const float x, const float y, const std::uint32_t colorTag)
    {
      CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = y;
      vertex.mZ = 0.0f;
      vertex.mColor = colorTag;
      vertex.mU = 0.0f;
      vertex.mV = 0.0f;
      return vertex;
    }

    void DrawPanelRect(
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float top,
      const float right,
      const float bottom,
      const std::uint32_t colorTag
    )
    {
      const CD3DPrimBatcher::Vertex topLeft = MakeVertex(left, top, colorTag);
      const CD3DPrimBatcher::Vertex topRight = MakeVertex(right, top, colorTag);
      const CD3DPrimBatcher::Vertex bottomRight = MakeVertex(right, bottom, colorTag);
      const CD3DPrimBatcher::Vertex bottomLeft = MakeVertex(left, bottom, colorTag);
      primBatcher.DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
    }

    void DrawPanelLine(
      CD3DPrimBatcher& primBatcher,
      const float startX,
      const float startY,
      const float endX,
      const float endY,
      const std::uint32_t colorTag
    )
    {
      const CD3DPrimBatcher::Vertex start = MakeVertex(startX, startY, colorTag);
      const CD3DPrimBatcher::Vertex end = MakeVertex(endX, endY, colorTag);
      primBatcher.DrawLine(start, end);
    }

    void BuildEventViews(const msvc8::vector<STimeBarEventRecord>& events, std::vector<TimeBarEventView>& outEventViews)
    {
      outEventViews.clear();
      outEventViews.reserve(events.size());

      for (const STimeBarEventRecord& eventRecord : events) {
        TimeBarEventView view{};
        view.mRecord = &eventRecord;
        view.mStartCycles = CombineCycles(eventRecord.mStartCycleLo, eventRecord.mStartCycleHi);
        view.mEndCycles = CombineCycles(eventRecord.mEndCycleLo, eventRecord.mEndCycleHi);
        outEventViews.push_back(view);
      }
    }

    void BuildTrackLayout(
      CD3DFont& font,
      const std::vector<TimeBarEventView>& eventViews,
      const float top,
      TimeBarTrackMap& outTracks,
      float& outMaxLabelWidth
    )
    {
      outTracks.clear();
      outMaxLabelWidth = 0.0f;

      for (const TimeBarEventView& eventView : eventViews) {
        if (!eventView.mRecord->mName) {
          continue;
        }

        const TimeBarTrackMap::iterator insertPos = outTracks.lower_bound(eventView.mRecord->mName);
        const bool alreadyPresent =
          insertPos != outTracks.end()
          && insertPos->first != nullptr
          && gpg::STR_CompareNoCase(insertPos->first, eventView.mRecord->mName) == 0;

        if (!alreadyPresent) {
          (void)outTracks.insert(
            insertPos,
            {
              eventView.mRecord->mName,
              TimeBarTrackLayout{
                eventView.mRecord->mName,
                0.0f,
              },
            }
          );
        }
      }

      float rowY = top + font.mAscent + 1.0f;
      for (auto& [name, track] : outTracks) {
        track.mName = name;
        track.mRowY = rowY;
        rowY += font.mHeight + font.mExternalLeading;
        outMaxLabelWidth = std::max(outMaxLabelWidth, font.GetAdvance(name, -1) + kLabelPadding);
      }
    }

    void RenderTrackLabels(
      CD3DFont& font,
      CD3DPrimBatcher& primBatcher,
      const float left,
      const float maxLabelWidth,
      const TimeBarTrackMap& tracks
    )
    {
      const Vector3f xAxis{1.0f, 0.0f, 0.0f};
      const Vector3f yAxis{0.0f, 1.0f, 0.0f};
      constexpr std::uint32_t kLabelColor = 0xFFFFFFFFu;
      const float maxAdvance = std::numeric_limits<float>::infinity();

      for (const auto& [name, track] : tracks) {
        if (!name) {
          continue;
        }

        const float labelWidth = font.GetAdvance(name, -1);
        const Vector3f origin{left + maxLabelWidth - labelWidth, track.mRowY, 0.0f};
        (void)font.Render(name, &primBatcher, origin, xAxis, yAxis, kLabelColor, 0.0f, maxAdvance);
      }
    }
  } // namespace

  std::int64_t CTimeBarSection::GetStartCycle() const noexcept
  {
    return CombineCycles(mStartCycleLo, mStartCycleHi);
  }

  void CTimeBarSection::SetStartCycle(const std::int64_t cycles) noexcept
  {
    SplitCycles(cycles, mStartCycleLo, mStartCycleHi);
  }

  /**
   * Address: 0x004E6DF0 (FUN_004E6DF0)
   * Mangled: ??0CTimeBarSection@Moho@@QAE@PBD@Z
   *
   * char const *
   *
   * What it does:
   * Opens a scoped time-bar section on the current thread and snapshots the parent segment.
   */
  CTimeBarSection::CTimeBarSection(const char* const name)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    mName = name;
    mPreviousSection = threadInfo->mCurrentSection;
    threadInfo->mCurrentSection = this;

    const std::int64_t nowCycles = QueryCurrentCycles();
    if (mPreviousSection) {
      STimeBarEventRecord parentSplitRecord{};
      SplitCycles(mPreviousSection->GetStartCycle(), parentSplitRecord.mStartCycleLo, parentSplitRecord.mStartCycleHi);
      SplitCycles(nowCycles, parentSplitRecord.mEndCycleLo, parentSplitRecord.mEndCycleHi);
      parentSplitRecord.mName = mPreviousSection->mName;
      parentSplitRecord.mColorTag = threadInfo->mColorTag;
      PushHistoryRecord(state, parentSplitRecord);
    }

    SetStartCycle(nowCycles);
  }

  /**
   * Address: 0x004E6E90 (FUN_004E6E90)
   * Mangled: ??1CTimeBarSection@Moho@@QAE@XZ
   *
   * void
   *
   * What it does:
   * Closes the current scope, records its elapsed cycle range, and restores the parent section.
   */
  CTimeBarSection::~CTimeBarSection()
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    const std::int64_t nowCycles = QueryCurrentCycles();

    STimeBarEventRecord completedRecord{};
    SplitCycles(GetStartCycle(), completedRecord.mStartCycleLo, completedRecord.mStartCycleHi);
    SplitCycles(nowCycles, completedRecord.mEndCycleLo, completedRecord.mEndCycleHi);
    completedRecord.mName = mName;
    completedRecord.mColorTag = threadInfo->mColorTag;
    PushHistoryRecord(state, completedRecord);

    if (mPreviousSection) {
      mPreviousSection->SetStartCycle(nowCycles);
      threadInfo->mCurrentSection = mPreviousSection;
    } else {
      threadInfo->mCurrentSection = nullptr;
    }
  }

  /**
   * Address: 0x004E6F30 (FUN_004E6F30)
   * Mangled: ?TIME_TimeBarEvent@Moho@@YAXPBD@Z
   *
   * char const *
   *
   * What it does:
   * Emits an instantaneous named marker event into the global time-bar history.
   */
  void TIME_TimeBarEvent(const char* const name)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);

    const std::int64_t nowCycles = QueryCurrentCycles();

    STimeBarEventRecord eventRecord{};
    SplitCycles(nowCycles, eventRecord.mStartCycleLo, eventRecord.mStartCycleHi);
    SplitCycles(nowCycles, eventRecord.mEndCycleLo, eventRecord.mEndCycleHi);
    eventRecord.mName = name;
    eventRecord.mColorTag = threadInfo->mColorTag;
    PushHistoryRecord(state, eventRecord);
  }

  /**
   * Address: 0x004E6FD0 (FUN_004E6FD0)
   *
   * int
   *
   * What it does:
   * Updates the current thread's time-bar color tag used for subsequent samples.
   */
  void TIME_SetTimeBarColor(const std::uint32_t colorTag)
  {
    TimeBarState& state = GetTimeBarState();
    STimeBarThreadInfo* const threadInfo = GetOrCreateThreadInfo(state);
    threadInfo->mColorTag = colorTag;
  }

  /**
   * Address: 0x004E6FA0 (FUN_004E6FA0)
   * Address: 0x004E6AE0 (FUN_004E6AE0)
   *
   * msvc8::vector<moho::STimeBarEventRecord> &,float
   *
   * What it does:
   * Captures active sections plus recent history events into `outEvents`, newest-first.
   */
  void TIME_CollectTimeBarEvents(msvc8::vector<STimeBarEventRecord>& outEvents, const float maxAgeSeconds)
  {
    TimeBarState& state = GetTimeBarState();

    // Match the original behavior: reset output each call before collecting.
    outEvents = msvc8::vector<STimeBarEventRecord>{};

    const std::int64_t nowCycles = QueryCurrentCycles();

    boost::mutex::scoped_lock guard(state.mLock);

    for (auto* node = static_cast<STimeBarThreadInfo*>(state.mThreadListSentinel.mNext); node != &state.mThreadListSentinel;
         node = static_cast<STimeBarThreadInfo*>(node->mNext)) {
      if (!node->mCurrentSection) {
        continue;
      }

      STimeBarEventRecord activeRecord{};
      SplitCycles(node->mCurrentSection->GetStartCycle(), activeRecord.mStartCycleLo, activeRecord.mStartCycleHi);
      SplitCycles(nowCycles, activeRecord.mEndCycleLo, activeRecord.mEndCycleHi);
      activeRecord.mName = node->mCurrentSection->mName;
      activeRecord.mColorTag = node->mColorTag;
      outEvents.push_back(activeRecord);
    }

    std::int32_t historyIndex = state.mNextHistoryIndex;
    while (historyIndex != state.mOldestHistoryIndex) {
      historyIndex = (historyIndex + (kTimeBarHistoryCapacity - 1)) % kTimeBarHistoryCapacity;

      const STimeBarEventRecord& record = state.mHistory[historyIndex];
      if (maxAgeSeconds >= 0.0f) {
        const std::int64_t startCycles = CombineCycles(record.mStartCycleLo, record.mStartCycleHi);
        const float ageSeconds = gpg::time::CyclesToSeconds(nowCycles - startCycles);
        if (ageSeconds > maxAgeSeconds) {
          break;
        }
      }

      outEvents.push_back(record);
    }
  }

  /**
   * Address: 0x004E83A0 (FUN_004E83A0)
   * Mangled: ?TIME_RenderTimeBars@Moho@@YAXPAVCD3DPrimBatcher@1@MMMMM@Z
   *
   * Moho::CD3DPrimBatcher *,float,float,float,float
   *
   * What it does:
   * Renders the time-bar panel background, labels, and clipped event timeline segments.
   */
  void TIME_RenderTimeBars(
    CD3DPrimBatcher* const primBatcher, const float left, const float top, const float width, const float height
  )
  {
    if (!primBatcher) {
      return;
    }

    const float right = left + width;
    const float bottom = top + height;

    const boost::shared_ptr<CD3DBatchTexture> whiteTexture = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
    primBatcher->SetTexture(whiteTexture);
    DrawPanelRect(*primBatcher, left, top, right, bottom, 0xFFFFFFFFu);

    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(kFontPointSize, kFontFaceName);
    const boost::shared_ptr<CD3DFont> font = boost::SharedPtrFromRawRetained(rawFont);
    rawFont.release();

    msvc8::vector<STimeBarEventRecord> events;
    TIME_CollectTimeBarEvents(events, ren_FrameTimeSeconds);

    std::vector<TimeBarEventView> eventViews;
    BuildEventViews(events, eventViews);

    TimeBarTrackMap tracks;
    float maxLabelWidth = 0.0f;
    if (font) {
      BuildTrackLayout(*font, eventViews, top, tracks, maxLabelWidth);
      RenderTrackLabels(*font, *primBatcher, left, maxLabelWidth, tracks);
    }

    primBatcher->SetTexture(whiteTexture);

    DrawPanelLine(*primBatcher, left, top, right, top, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, right, top, right, bottom, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, right, bottom, left, bottom, 0xFFFFFFFFu);
    DrawPanelLine(*primBatcher, left, bottom, left, top, 0xFFFFFFFFu);

    if (eventViews.empty()) {
      return;
    }

    const std::int64_t nowCycles = QueryCurrentCycles();
    const float windowSeconds = std::max(ren_FrameTimeSeconds, kMinWindowSeconds);
    const std::int64_t windowCycles = std::max<std::int64_t>(1, gpg::time::SecondsToCycles(windowSeconds));
    const float timelineLeft = left + maxLabelWidth;
    const float timelineRight = right;
    const float timelineRightClamp = timelineRight - 1.0f;
    const float timelineWidth = std::max(0.0f, width - maxLabelWidth);
    const double cyclesToPixels = static_cast<double>(timelineWidth) / static_cast<double>(windowCycles);
    const double xBase = static_cast<double>(timelineRight) - (cyclesToPixels * static_cast<double>(nowCycles));

    for (const TimeBarEventView& eventView : eventViews) {
      const char* const eventName = eventView.mRecord->mName;
      if (!eventName) {
        continue;
      }

      const TimeBarTrackMap::const_iterator trackIt = tracks.find(eventName);
      if (trackIt == tracks.end()) {
        continue;
      }

      const float rowY = trackIt->second.mRowY;

      float startX = static_cast<float>(xBase + cyclesToPixels * static_cast<double>(eventView.mStartCycles));
      startX = std::min(startX, timelineRightClamp);
      startX = std::max(startX, timelineLeft);

      float endX = static_cast<float>(xBase + cyclesToPixels * static_cast<double>(eventView.mEndCycles));
      endX = std::min(endX, timelineRight);
      endX = std::max(endX, timelineLeft);
      endX = std::max(endX, startX + 1.0f);

      DrawPanelLine(*primBatcher, startX, rowY, endX, rowY, eventView.mRecord->mColorTag);
    }


    // `tracks` goes out of scope here. `~map()` is what the binary runs at
    // this point too, and MSVC emits it; naming it would be a second call.
  }
} // namespace moho
