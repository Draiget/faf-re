#pragma once
#include <cstdint>
#include <chrono>
#include <limits>

#include "platform/Platform.h"

namespace boost
{
    /**
     * Historic Boost.Thread absolute time structure (CLOCK_REALTIME).
     */
    struct xtime {
        long sec;   // seconds since Unix epoch
        long nsec;  // 0..999'999'999
    };

    /**
     * TIMEUTC clock base for xtime_get (matches historical Boost).
     */
    inline constexpr int kTimeUtc = 1;

    /**
     * Normalize xtime so that 0 <= nsec < 1e9 by carrying into sec.
     */
    inline void xtime_normalize(xtime& x) noexcept {
        // positive overflow
        if (x.nsec >= 1000000000L) {
            long carry = x.nsec / 1000000000L;
            x.sec += carry;
            x.nsec -= carry * 1000000000L;
        }
        // negative underflow
        if (x.nsec < 0) {
            long borrow = (-x.nsec + 999999999L) / 1000000000L;
            x.sec -= borrow;
            x.nsec += borrow * 1000000000L;
        }
    }

    /**
     * Obtain current real-time clock into xtime.
     * Returns TIMEUTC on success, 0 on failure (historical Boost semantics).
     */
    inline int xtime_get(xtime* xt, int base) noexcept {
        if (!xt || base != kTimeUtc) return 0;

#if defined(_WIN32)
        // FILETIME gives 100ns ticks since 1601-01-01.
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER t;
        t.LowPart = ft.dwLowDateTime;
        t.HighPart = ft.dwHighDateTime;

        // Convert to Unix epoch (1970-01-01).
        constexpr std::uint64_t kUnixEpoch_100ns = 11644473600ULL * 10000000ULL;
        if (t.QuadPart < kUnixEpoch_100ns) {
            xt->sec = 0;
            xt->nsec = 0;
            return 0;
        }
        std::uint64_t since_epoch_100ns = t.QuadPart - kUnixEpoch_100ns;
        std::uint64_t ns = since_epoch_100ns * 100ULL;

        xt->sec = static_cast<long>(ns / 1000000000ULL);
        xt->nsec = static_cast<long>(ns % 1000000000ULL);
        return kTimeUtc;
#else
        timespec ts{};
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            xt->sec = 0; xt->nsec = 0;
            return 0;
        }
        xt->sec = static_cast<long>(ts.tv_sec);
        xt->nsec = static_cast<long>(ts.tv_nsec);
        return TIMEUTC;
#endif
    }

    /**
     * Add milliseconds (can be negative) to an xtime and normalize.
     */
    inline void xtime_add(xtime& x, long milliseconds) noexcept {
        x.sec += milliseconds / 1000L;
        x.nsec += (milliseconds % 1000L) * 1000000L;
        xtime_normalize(x);
    }

    /**
     * Add nanoseconds (can be negative) to an xtime and normalize.
     */
    inline void xtime_add_ns(xtime& x, long long nanoseconds) noexcept {
        x.sec += static_cast<long>(nanoseconds / 1000000000LL);
        x.nsec += static_cast<long>(nanoseconds % 1000000000LL);
        xtime_normalize(x);
    }

    /**
     * Construct absolute deadline "now + duration".
     */
    template<class Rep, class Period>
    inline xtime xtime_from_now(const std::chrono::duration<Rep, Period>& d) noexcept {
        using namespace std::chrono;
        xtime out{};
        if (xtime_get(&out, kTimeUtc) != kTimeUtc) {
            out.sec = 0; out.nsec = 0;
            return out;
        }
        const long long ms = duration_cast<milliseconds>(d).count();
        // Clamp to long for historical API
        long ms_clamped;
        if (ms > static_cast<long long>(std::numeric_limits<long>::max())) {
            ms_clamped = std::numeric_limits<long>::max();
        } else if (ms < static_cast<long long>(std::numeric_limits<long>::min())) {
            ms_clamped = std::numeric_limits<long>::min();
        } else {
            ms_clamped = static_cast<long>(ms);
        }
        xtime_add(out, ms_clamped);
        return out;
    }

    /**
     * Compare two xtime values: -1 if a<b, 0 if equal, +1 if a>b.
     */
    inline int xtime_cmp(const xtime& a, const xtime& b) noexcept {
        if (a.sec < b.sec) return -1;
        if (a.sec > b.sec) return +1;
        if (a.nsec < b.nsec) return -1;
        if (a.nsec > b.nsec) return +1;
        return 0;
    }

    /**
     * Return true if a occurs strictly before b.
     */
    inline bool xtime_before(const xtime& a, const xtime& b) noexcept {
        return xtime_cmp(a, b) < 0;
    }

} // namespace boost
