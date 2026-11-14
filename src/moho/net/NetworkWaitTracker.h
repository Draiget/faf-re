#pragma once
#include <algorithm>
#include <cstdint>
#include <deque>

namespace moho {
struct NetworkWaitMetrics {
    double observedSeconds = 0;
    double waitingMs = 0;
    double longestMs = 0;
    double gameSeconds = 0;     // whole-game active seconds
    double gameWaitPercent = 0; // whole-game share waiting on this peer
    std::uint64_t gameWaitEpisodes = 0;
    double gameAverageWaitMs = 0;
};
// Passive wall-clock intervals. Shared waits overlap; pauses are excluded.
class NetworkWaitTracker {
    struct Span { double begin, end; bool active; std::uint64_t peers; };
    std::deque<Span> spans;
    std::uint64_t episodeCounts[64]{};
    std::uint64_t countedEpisodeMask = 0;
public:
    void Observe(double now, bool active, std::uint64_t peers) {
        if (!spans.empty() && now < spans.back().end) {
            spans.clear();
            std::fill_n(episodeCounts, 64, 0);
            countedEpisodeMask = 0;
        }
        // Count only episodes that accumulated real waiting time. Other peers
        // joining/leaving a shared stall must not split this peer's episode.
        if (!spans.empty() && spans.back().active && now > spans.back().end) {
            const auto newlyCounted = spans.back().peers & ~countedEpisodeMask;
            for (unsigned i = 0; i < 64; ++i)
                if (newlyCounted & (std::uint64_t{1} << i)) ++episodeCounts[i];
            countedEpisodeMask |= spans.back().peers;
        }
        countedEpisodeMask &= active ? peers : 0;
        if (!spans.empty()) spans.back().end = now;
        if (spans.empty() || spans.back().active != active || spans.back().peers != peers)
            spans.push_back({now, now, active, peers});
        while (spans.size() > 1 && spans.front().end <= now - 30.0) spans.pop_front();
    }
    NetworkWaitMetrics Read(double now, unsigned peer) const {
        NetworkWaitMetrics result;
        if (peer < 64) result.gameWaitEpisodes = episodeCounts[peer];
        double run = 0;
        for (const auto& span : spans) {
            const double end = &span == &spans.back() ? now : span.end;
            const double seconds = std::max(0.0, end - std::max(span.begin, now - 30.0));
            if (span.active) result.observedSeconds += seconds;
            if (span.active && peer < 64 && (span.peers & (std::uint64_t{1} << peer))) {
                result.waitingMs += seconds * 1000.0;
                run += seconds * 1000.0;
                result.longestMs = std::max(result.longestMs, run);
            } else if (seconds > 0) run = 0;
        }
        return result;
    }
};
}
