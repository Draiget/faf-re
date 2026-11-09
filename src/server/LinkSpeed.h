#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "server/SpeedWatch.h"

// Engine addition, dedicated server (plan WP10.7 step 2): a player whose link can't carry the game's data holds the game,
// as a lockstep peer whose data comes late does; FAF players expect a slow participant to slow the game rather than drop
// out. How long the oldest view a seat hasn't acked has waited (CServerNet's `behindSeconds`; beats behind would count
// for more seconds as the game slows) is looked at every kWindowSeconds. Being behind alone says little (a far link's delay doesn't shrink when the game slows); falling
// further behind does: a link more than kBehindSeconds behind that fell more than kGrowSeconds further behind over the
// window gets a limit one step under the game's speed (one step a window at most). After kCalmWindows windows in a row
// in which it didn't fall behind and was under kBehindSeconds, the limit rises a step, and goes once it reaches the
// requested speed. The server runs at the lowest of the requested speed, each seat's machine limit (step 0) and these.

namespace faf::server
{
  struct SLinkSample
  {
    std::int32_t uid = 0;
    double behindSeconds = 0.0; // how long the oldest view the player hasn't acked has waited
    bool gone = false;
  };

  /** A seat's link limit that changed: the new one, or nothing when it went; how far behind the link was. */
  struct SLinkNews
  {
    std::int32_t uid = 0;
    std::optional<int> limit;
    double behindSeconds = 0.0;
  };

  class CLinkSpeedGovernor
  {
  public:
    static constexpr double kBehindSeconds = 2.0;
    static constexpr double kGrowSeconds = 0.5;
    static constexpr double kWindowSeconds = 10.0;
    static constexpr int kCalmWindows = 3;
    static constexpr int kMinSpeed = -10;

    /** `speed`: the speed the game runs at now; `asked`: the speed requested. Returns the limits that changed. */
    std::vector<SLinkNews> Update(const double now, const int speed, const int asked, const std::span<const SLinkSample> seats)
    {
      std::vector<SLinkNews> news;
      for (const SLinkSample& seat : seats) {
        if (seat.gone) {
          if (const auto found = mLinks.find(seat.uid); found != mLinks.end()) {
            if (found->second.limit) {
              news.push_back(SLinkNews{seat.uid, std::nullopt, 0.0});
            }
            mLinks.erase(found);
          }
          continue;
        }
        SLink& link = mLinks[seat.uid];
        const double behind = seat.behindSeconds;
        if (link.windowAt < 0.0) {
          link.windowAt = now;
          link.windowBehind = behind;
          continue;
        }
        if (now - link.windowAt < kWindowSeconds) {
          continue;
        }
        const double grew = behind - link.windowBehind;
        link.windowAt = now;
        link.windowBehind = behind;
        if (behind > kBehindSeconds && grew > kGrowSeconds) {
          link.calmWindows = 0;
          const int lowered = std::max(kMinSpeed, (link.limit ? std::min(*link.limit, speed) : speed) - 1);
          if (link.limit != lowered) {
            link.limit = lowered;
            news.push_back(SLinkNews{seat.uid, link.limit, behind});
          }
        } else if (grew <= kGrowSeconds / 2.0 && behind <= kBehindSeconds) {
          if (++link.calmWindows >= kCalmWindows && link.limit) {
            link.calmWindows = 0;
            if (*link.limit + 1 >= asked) {
              link.limit.reset();
            } else {
              link.limit = *link.limit + 1;
            }
            news.push_back(SLinkNews{seat.uid, link.limit, behind});
          }
        } else {
          link.calmWindows = 0;
        }
      }
      return news;
    }

    /** The lowest link limit and whose; nothing when no link holds the game. */
    [[nodiscard]] std::optional<std::pair<int, std::int32_t>> Slowest() const
    {
      std::optional<std::pair<int, std::int32_t>> slowest;
      for (const auto& [uid, link] : mLinks) {
        if (link.limit && (!slowest || *link.limit < slowest->first)) {
          slowest.emplace(*link.limit, uid);
        }
      }
      return slowest;
    }

  private:
    struct SLink
    {
      std::optional<int> limit;
      double windowAt = -1.0;
      double windowBehind = 0.0;
      int calmWindows = 0;
    };
    std::map<std::int32_t, SLink> mLinks;
  };
} // namespace faf::server
