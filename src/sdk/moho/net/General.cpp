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
        count = mStart - mEnd;
    } else {
        count = mStart - mEnd + cap;
    }

    // Lower_bound by time over [0, count), indexing with (mEnd + idx) % kCap
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        const uint32_t mid = (lo + hi) >> 1;
        const SendStamp& s = mDat[(mEnd + mid) % cap];
        const uint64_t t =
            (static_cast<uint64_t>(s.time.dwHighDateTime) << 32)
            | static_cast<uint64_t>(s.time.dwLowDateTime);

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
        out.items.push_back(mDat[(mEnd + i) % cap]);
    }
}

void SendStampBuffer::Reset() {
    mEnd = 0;
    mStart = 0;
}

uint32_t SendStampBuffer::Push(const int dir, const FILETIME timeUs, const int size) noexcept {
    // If advancing start would collide with end, drop the oldest.
    const std::uint32_t next = (mStart + 1u) & static_cast<std::uint32_t>(cap);
    if (next == mEnd) {
        mEnd = (mEnd + 1u) & static_cast<std::uint32_t>(cap);
    }

    // Prepare entry (a1a in the asm)
    SendStamp s;
    s.time = timeUs;
    s.direction = dir;
    s.size = size;

    return EmplaceAndAdvance(s);
}

CHostManager* moho::NET_GetHostManager() {
    static CHostManager manager;
    return &manager;
}

msvc8::string moho::NET_GetHostName(const u_long address) {
	const auto manager = NET_GetHostManager();
    return manager->GetHostName(address);
}

const char* moho::NET_GetWinsockErrorString() noexcept {
#if defined(_WIN32)
    const int e = ::WSAGetLastError();
    if (e == 0) {
        return "NOERROR";
    }

    // DNS/host resolution extended codes first (match original control flow)
    switch (e) {
    case WSAHOST_NOT_FOUND: return "WSAHOST_NOT_FOUND";   // 11001
    case WSATRY_AGAIN:      return "WSATRY_AGAIN";        // 11002
    case WSANO_RECOVERY:    return "WSANO_RECOVERY";      // 11003
    case WSANO_DATA:        return "WSANO_DATA";          // 11004
    }

    // Core Winsock error set mirrored from the original switch
    switch (e) {
    case WSAEINTR:           return "WSAEINTR";            // 10004 (0x2714)
    case WSAEBADF:           return "WSAEBADF";            // 10009 (0x2719)
    case WSAEACCES:          return "WSAEACCES";           // 10013 (0x271D)
    case WSAEFAULT:          return "WSAEFAULT";           // 10014 (0x271E)
    case WSAEINVAL:          return "WSAEINVAL";           // 10022 (0x2726)
    case WSAEMFILE:          return "WSAEMFILE";           // 10024 (0x2728)
    case WSAEWOULDBLOCK:     return "WSAEWOULDBLOCK";      // 10035 (0x2733)
    case WSAEINPROGRESS:     return "WSAEINPROGRESS";      // 10036 (0x2734)
    case WSAEALREADY:        return "WSAEALREADY";         // 10037 (0x2735)
    case WSAENOTSOCK:        return "WSAENOTSOCK";         // 10038 (0x2736)
    case WSAEDESTADDRREQ:    return "WSAEDESTADDRREQ";     // 10039 (0x2737)
    case WSAEMSGSIZE:        return "WSAEMSGSIZE";         // 10040 (0x2738)
    case WSAEPROTOTYPE:      return "WSAEPROTOTYPE";       // 10041 (0x2739)
    case WSAENOPROTOOPT:     return "WSAENOPROTOOPT";      // 10042 (0x273A)
    case WSAEPROTONOSUPPORT: return "WSAEPROTONOSUPPORT";  // 10043 (0x273B)
    case WSAESOCKTNOSUPPORT: return "WSAESOCKTNOSUPPORT";  // 10044 (0x273C)
    case WSAEOPNOTSUPP:      return "WSAEOPNOTSUPP";       // 10045 (0x273D)
    case WSAEPFNOSUPPORT:    return "WSAEPFNOSUPPORT";     // 10046 (0x273E)
    case WSAEAFNOSUPPORT:    return "WSAEAFNOSUPPORT";     // 10047 (0x273F)
    case WSAEADDRINUSE:      return "WSAEADDRINUSE";       // 10048 (0x2740)
    case WSAEADDRNOTAVAIL:   return "WSAEADDRNOTAVAIL";    // 10049 (0x2741)
    case WSAENETDOWN:        return "WSAENETDOWN";         // 10050 (0x2742)
    case WSAENETUNREACH:     return "WSAENETUNREACH";      // 10051 (0x2743)
    case WSAENETRESET:       return "WSAENETRESET";        // 10052 (0x2744)
    case WSAECONNABORTED:    return "WSAECONNABORTED";     // 10053 (0x2745)
    case WSAECONNRESET:      return "WSAECONNRESET";       // 10054 (0x2746)
    case WSAENOBUFS:         return "WSAENOBUFS";          // 10055 (0x2747)
    case WSAEISCONN:         return "WSAEISCONN";          // 10056 (0x2748)
    case WSAENOTCONN:        return "WSAENOTCONN";         // 10057 (0x2749)
    case WSAESHUTDOWN:       return "WSAESHUTDOWN";        // 10058 (0x274A)
    case WSAETOOMANYREFS:    return "WSAETOOMANYREFS";     // 10059 (0x274B)
    case WSAETIMEDOUT:       return "WSAETIMEDOUT";        // 10060 (0x274C)
    case WSAECONNREFUSED:    return "WSAECONNREFUSED";     // 10061 (0x274D)
    case WSAELOOP:           return "WSAELOOP";            // 10062 (0x274E)
    case WSAENAMETOOLONG:    return "WSAENAMETOOLONG";     // 10063 (0x274F)
    case WSAEHOSTDOWN:       return "WSAEHOSTDOWN";        // 10064 (0x2750)
    case WSAEHOSTUNREACH:    return "WSAEHOSTUNREACH";     // 10065 (0x2751)
    case WSAENOTEMPTY:       return "WSAENOTEMPTY";        // 10066 (0x2752)
    case WSAEPROCLIM:        return "WSAEPROCLIM";         // 10067 (0x2753)
    case WSAEUSERS:          return "WSAEUSERS";           // 10068 (0x2754)
    case WSAEDQUOT:          return "WSAEDQUOT";           // 10069 (0x2755)
    case WSAESTALE:          return "WSAESTALE";           // 10070 (0x2756)
    case WSAEREMOTE:         return "WSAEREMOTE";          // 10071 (0x2757)
    case WSASYSNOTREADY:     return "WSASYSNOTREADY";      // 10091 (0x276B)
    case WSAVERNOTSUPPORTED: return "WSAVERNOTSUPPORTED";  // 10092 (0x276C)
    case WSANOTINITIALISED:  return "WSANOTINITIALISED";   // 10093 (0x276D)
    case WSAEDISCON:         return "WSAEDISCON";          // 10101 (0x2775)
    default:                 return "UNKNOWN";
    }
#else
    // Non-Windows build: no Winsock -> stable stub.
    return "NO_WINSOCK";
#endif
}
