#pragma once
#include <list>
#include <map>
#include <mutex>

#include "boost/mutex.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace moho
{
    /**
     * Host entry: intrusive node + cached name + small aux (mVal).
     */
    struct Host :
		TDatListItem<Host, void>
    {
        msvc8::string mName;
        int mVal{ 0 };
    };

    /**
	 * Hostname cache manager: map + intrusive MRU list.
	 * - mHosts: key = IPv4 (host byte order), value = Host (stable address in std::map)
	 * - mHostList: MRU order; front = most recent, back = LRU
	 */
    struct CHostManager
    {
        boost::mutex mLock;
        std::map<unsigned, Host> mHosts;
        TDatList<Host, void> mHostList;

        /**
         * Resolve (or fetch cached) host name for IPv4 address (host byte order).
         */
        msvc8::string GetHostName(u_long host);

        /**
         * Out-parameter variant (drop-in for old code).
         */
        msvc8::string& GetHostName(const u_long host, msvc8::string& out) {
            out = GetHostName(host);
            return out;
        }

    private:
        /** Max entries as in the original binary threshold (0x4C). */
        static constexpr std::size_t kMaxEntries = 0x4C;

        /**
         * Move host to MRU front (no-op if already there).
         */
        void Touch(Host& h) noexcept;

        /**
         * Remove LRU entries until <= capacity.
         */
        void EvictIfNeeded() noexcept;

        /**
         * Linear search: map key for a given Host*. O(N), tolerable for N<=0x4C.
         */
        auto FindByValue(const Host* h) -> std::map<unsigned, Host>::iterator {
            for (auto it = mHosts.begin(); it != mHosts.end(); ++it) {
                if (&it->second == h) return it;
            }
            return mHosts.end();
        }

        /**
         * Reverse DNS via getnameinfo; fallback to dotted IPv4 on failure.
         */
        static msvc8::string ResolveHostName(const u_long host);
    };

    /**
     * Address: 0x004801C5
     * Convert host-order IPv4 (u32) to dotted decimal.
     *
     * @param host 
     * @return 
     */
    msvc8::string NET_GetDottedOctetFromUInt32(u_long host);

    /**
     * Address: 0x00480200
     *
     * @param host 
     * @return 
     */
    uint32_t NET_GetUInt32FromDottedOcted(const msvc8::string& host);

    /**
     * Address: 0x0047FF10
	 * Resolve "host[:port]" to IPv4 address and port using getaddrinfo(AF_INET).
	 * - If no port in the string, uses defaultPort (2nd argument in the original).
	 * - Chooses TCP (SOCK_STREAM/IPPROTO_TCP) or UDP (SOCK_DGRAM/IPPROTO_UDP) by isTCP.
	 * - Writes results in host byte order: addr (u_long), port (u_short).
	 *
     * @param str 
     * @param defaultPort 
     * @param isTcp 
     * @param address 
     * @param port 
     * @return true on success, false on failure.
     */
    bool NET_GetAddrInfo(const char* str, u_short defaultPort, bool isTcp, u_long& address, u_short& port);
}
