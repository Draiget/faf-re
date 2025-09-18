#pragma once
#include <list>
#include <mutex>
#include <unordered_map>

#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"

namespace moho
{
    namespace detail
	{
        /**
         * Convert host-order IPv4 (u32) to dotted decimal using inet_ntop.
         */
        inline msvc8::string DottedFromHostU32(const u_long host) {
            in_addr a{};
            a.s_addr = htonl(host);
            char buf[INET_ADDRSTRLEN]{};

            // Note: make sure WSAStartup() was called earlier on Windows.
            const char* s = ::inet_ntop(AF_INET, &a, buf,
#if defined(_WIN32)
                sizeof(buf)
#else
                sizeof(buf)
#endif
            );

            if (!s) {
                // Fallback: format manually (should be rare).
                // Using host-order bytes to avoid another ntohl/htonl round-trip.
                const std::uint32_t x = host;
                char fb[16];
                std::snprintf(fb, sizeof(fb), "%u.%u.%u.%u",
                    (x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF);
                return msvc8::string(fb);
            }
            return msvc8::string(buf);
        }

        /**
         * Render getnameinfo/gai/WSA error to string for logs.
         */
        inline const char* GaiErrorString(int code) {
#if defined(_WIN32)
            // getnameinfo on Windows returns WSA* error codes; use gai_strerrorA if available
            return gai_strerrorA(code);
#else
            return ::gai_strerror(code);
#endif
        }
    }

    /**
     * Host entry: intrusive node + cached name + small aux (mVal).
     */
    struct Host : TDatListItem<Host, void>
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
        moho::TDatList<Host, void> mHostList;

        /** Resolve (or fetch cached) host name for IPv4 address (host byte order). */
        msvc8::string GetHostName(u_long host) {
            // 1) Try cache under lock
            {
                boost::mutex::scoped_lock g(mLock);
                auto it = mHosts.find(host);
                if (it != mHosts.end()) {
                    Touch(it->second);
                    return it->second.mName;
                }
            }

            // 2) Miss: resolve without holding the lock
            const msvc8::string name = ResolveHostName(host);

            // 3) Insert/update under lock (handle racing inserts)
            {
                boost::mutex::scoped_lock g(mLock);
                auto [it, inserted] = mHosts.emplace(host, Host{});
                Host& h = it->second;
                h.mName = name;

                if (inserted) {
                    // New entry goes to MRU front: pass NODE (object itself)
                    mHostList.push_front(static_cast<moho::TDatListItem<Host, void>*>(&h));
                    EvictIfNeeded();
                } else {
                    // Already present: move to MRU front
                    Touch(h);
                }
                return h.mName;
            }
        }

        /** Out-parameter variant (drop-in for old code). */
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
        void Touch(Host& h) noexcept {
            // Node is the object itself when Host derives the node
            auto& node = static_cast<moho::TDatListItem<Host, void>&>(h);
            node.ListUnlink();
            node.ListLinkAfter(&mHostList);

            if (h.mVal != INT_MAX) ++h.mVal;
        }

        /**
         * Remove LRU entries until <= capacity.
         */
        void EvictIfNeeded() noexcept {
            while (mHosts.size() > kMaxEntries) {
                if (mHostList.empty())
                    break;

                // Take tail node via iterator (end() is sentinel; --end gives last node)
                auto it = mHostList.end();
                --it; // now at last node
                auto* n = it.node(); // node pointer (TDatListItem<Host,void>*)

                // Safety: sentinel check (sentinel is the head itself)
                if (n == static_cast<moho::TDatListItem<Host, void>*>(&mHostList))
                    break;

                Host* lru = static_cast<Host*>(n); // node -> owner when owner derives node

                // Always unlink node first to keep list consistent
                n->ListUnlink();

                // Erase from map by value (linear scan, N <= 0x4C)
                auto mapIt = FindByValue(lru);
                if (mapIt != mHosts.end()) {
                    mHosts.erase(mapIt);
                }
            }
        }

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
        static msvc8::string ResolveHostName(const u_long host) {
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(0);
            sa.sin_addr.s_addr = htonl(host);

            char node[0x401]{}; // 1025 bytes as in the binary
            char serv[0x20]{};  // 32   bytes as in the binary

            const int rv = ::getnameinfo(reinterpret_cast<const sockaddr*>(&sa),
                sizeof(sa),
                node, sizeof(node),
                serv, sizeof(serv),
                NI_NUMERICSERV);
            if (rv != 0) {
                gpg::Logf("NET_GetHostName: getnameinfo() failed: %s", detail::GaiErrorString(rv));
                return detail::DottedFromHostU32(host);
            }
            return msvc8::string{ node };
        }
    };


}
