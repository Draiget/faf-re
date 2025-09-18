#include "General.h"

#include "CHostManager.h"
using namespace moho;

void SendStampBuffer::ExtractWindow(SendStampView& out, const uint64_t now, const uint64_t window) const {
    // threshold = now - window
    const uint64_t threshold = now - window;

    // Convert u64 -> FILETIME (binary treats FILETIME as raw 64-bit)
    out.from.dwLowDateTime = static_cast<DWORD>(threshold & 0xFFFFFFFFu);
    out.from.dwHighDateTime = static_cast<DWORD>(threshold >> 32);
    out.to.dwLowDateTime = static_cast<DWORD>(now & 0xFFFFFFFFu);
    out.to.dwHighDateTime = static_cast<DWORD>(now >> 32);

    // Logical size of the ring
    uint32_t count;
    if (mStart >= mEnd) {
        count = static_cast<uint32_t>(mStart - mEnd);
    } else {
        count = mStart - mEnd + kCap;
    }

    // Lower_bound by time over [0, count), indexing with (mEnd + idx) % kCap
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        const uint32_t mid = (lo + hi) >> 1;
        const SendStamp& s = mDat[(mEnd + mid) % kCap];
        const uint64_t t =
            (static_cast<uint64_t>(s.when.dwHighDateTime) << 32)
            | static_cast<uint64_t>(s.when.dwLowDateTime);

        if (t >= threshold) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    // Prepare output vector and copy the window
    const uint32_t take = count - lo;
    out.items.clear();
    out.items.reserve(take);
    for (uint32_t i = lo; i < count; ++i) {
        out.items.push_back(mDat[(mEnd + i) % kCap]);
    }
}

void SendStampBuffer::Reset() {
    mEnd = 0;
    mStart = 0;
}

CHostManager* moho::NET_GetHostManager() {
    static CHostManager manager;
    return &manager;
}

msvc8::string moho::NET_GetHostName(const u_long address) {
	const auto manager = NET_GetHostManager();
    return manager->GetHostName(address);
}
