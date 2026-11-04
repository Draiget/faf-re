#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "remote/SyncRouting.h"

// Engine addition, server mode (plan WP16.3 and WP6.10), `--spy` with `--lua-routing`: what a spy
// client finds in the Lua lane. Every view's table goes through the wire's encode and decode each
// beat, and then every key and every id in it is checked against the sim:
//
//   - a key the routing policy doesn't list, or an observers-only key not written under the view's
//     own focus, must not arrive;
//   - an id in a field the policy marks (`SyncIdFields`) must be for that field's audience;
//   - a recon blip's or foreign projectile's sim id must not appear anywhere, as those are renumbered
//     for a view (remote/ViewIdMap.h);
//   - any other value that names a live entity of another army is logged as unmarked.
//
// An id is a string of digits or a whole number of at least 2^20. A Lua number below that isn't taken
// for an id, as it could be anything; the ids of army 0's units are that small as numbers, though FA's
// Lua hands ids around as strings.

namespace faf::headless
{
  class CReplaySyncSpy
  {
  public:
    explicit CReplaySyncSpy(const remote::CSyncRouter& router) noexcept
      : mRouter(router)
    {}

    /** Checks every view's payload of this beat. */
    void Check(const moho::Sim& sim);
    /** What must stay 0. Unmarked ids are in `Summary`, for the policy's next audit. */
    [[nodiscard]] std::uint64_t Failures() const noexcept { return mUnknownKeys + mOutsideAudience + mRawRenumbered + mDecodeFailures; }
    [[nodiscard]] std::string Summary() const;

  private:
    struct SWalk;

    bool WalkValue(SWalk& walk, std::string_view field, int depth);
    void CheckId(SWalk& walk, std::uint32_t id, std::string_view field, bool isKey, int depth);
    void Example(const SWalk& walk, const char* what, std::uint32_t id, std::string_view field);

    const remote::CSyncRouter& mRouter;
    std::map<std::string, std::uint64_t, std::less<>> mKeys; // writes seen, by key
    std::uint64_t mViewBeats = 0;
    std::uint64_t mIds = 0;
    std::uint64_t mMarkedIds = 0;
    std::uint64_t mUnknownKeys = 0;
    std::uint64_t mOutsideAudience = 0;
    std::uint64_t mRawRenumbered = 0;
    std::uint64_t mUnmarked = 0;
    std::uint64_t mDecodeFailures = 0;
    std::vector<std::string> mExamples;
  };
} // namespace faf::headless
