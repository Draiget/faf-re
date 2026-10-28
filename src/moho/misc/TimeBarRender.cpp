// Engine addition (dedicated-server plan WPL.4, WPR.11): TIME_RenderTimeBars, the time-bar
// panel drawn with the render device's font and batcher, moved unchanged out of TimeBar.cpp,
// which keeps the time-bar sections and events the simulation records.
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

// Engine addition: helpers shared with the file these functions came from.
namespace moho
{
  // Address: 0x00F57E5C (ren_FrameTimeSeconds)
  extern float ren_FrameTimeSeconds;

  namespace
{
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

    constexpr float kLabelPadding = 2.0f;
    struct TimeBarEvent
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
    /**
     * One row per distinct event name, ordered case-insensitively. Node 0x18
     * with colour/nil at `+0x14`/`+0x15` and the `(name*, layout)` pair at
     * `node+0x0C`, which is the ordinary 4-aligned shape for an 0x0C
     * `pair<const char*, TimeBarTrackLayout>`.
     */
    using TimeBarTrackMap = msvc8::map<const char*, TimeBarTrackLayout, CaseInsensitiveCStringLess>;

    void BuildTrackLayout(
      CD3DFont& font,
      const std::vector<TimeBarEvent>& eventViews,
      const float top,
      TimeBarTrackMap& outTracks,
      float& outMaxLabelWidth
    )
    {
      outTracks.clear();
      outMaxLabelWidth = 0.0f;

      for (const TimeBarEvent& eventView : eventViews) {
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
    [[nodiscard]] std::int64_t CombineCycles(const std::uint32_t lo, const std::uint32_t hi) noexcept
    {
      const std::uint64_t value = (static_cast<std::uint64_t>(hi) << 32) | lo;
      return static_cast<std::int64_t>(value);
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

    void BuildEventViews(const msvc8::vector<STimeBarEventRecord>& events, std::vector<TimeBarEvent>& outEventViews)
    {
      outEventViews.clear();
      outEventViews.reserve(events.size());

      for (const STimeBarEventRecord& eventRecord : events) {
        TimeBarEvent view{};
        view.mRecord = &eventRecord;
        view.mStartCycles = CombineCycles(eventRecord.mStartCycleLo, eventRecord.mStartCycleHi);
        view.mEndCycles = CombineCycles(eventRecord.mEndCycleLo, eventRecord.mEndCycleHi);
        outEventViews.push_back(view);
      }
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
    constexpr const char* kFontFaceName = "Times New Roman";
    constexpr std::int32_t kFontPointSize = 10;
    constexpr float kMinWindowSeconds = 0.000001f;
    [[nodiscard]] std::int64_t QueryCurrentCycles()
    {
      const gpg::time::Timer& timer = gpg::time::GetSystemTimer();
      return timer.ElapsedCycles();
    }
  } // namespace
} // namespace moho


namespace moho
{
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

    std::vector<TimeBarEvent> eventViews;
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

    for (const TimeBarEvent& eventView : eventViews) {
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
