#pragma once
#include <cstddef>
#include <cstdint>
#include <map>

#include "boost/mutex.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  struct Host : TDatListItem<Host, void>
  {
    // +0x08
    msvc8::string mName;

    // +0x24
    // FA/Moho keep a back-link to a map node/iterator for O(1) erase from the tree.
    // In lifted C++ we keep this as an opaque slot for parity/documentation.
    void* mMapNodeBackLink{nullptr};

    /**
     * Address: 0x0047F8A0 (FUN_0047F8A0, struct_Host::struct_Host)
     *
     * What it does:
     * Initializes intrusive list lanes, copies host name, and clears map-node
     * back-link metadata.
     */
    explicit Host(const msvc8::string& name);

    Host() = default;

    /**
     * Address: 0x0047FBA0 (FUN_0047FBA0)
     *
     * What it does:
     * Clears hostname payload and unlinks this host entry from intrusive MRU
     * list lanes.
     */
    void ResetNameAndUnlink() noexcept;

    /**
     * Address: 0x0047FB50 (FUN_0047FB50, struct_Host::operator delete)
     *
     * What it does:
     * Clears payload, unlinks list lanes, and deletes a heap-allocated host
     * node.
     */
    static void DestroyHeapNode(Host* host) noexcept;
  };

#if defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
  static_assert(sizeof(Host) == 0x28, "Host size must be 0x28");
#endif

  struct CHostManager
  {
    using HostMap = std::map<std::uint32_t, Host*>;

    boost::mutex mLock;
    HostMap mHosts;
    TDatList<Host, void> mHostList;

    /**
     * Address: 0x0047F900 (FUN_0047F900, sHostManager::sHostManager)
     *
     * What it does:
     * Initializes host cache lock/map/list sentinel state.
     */
    CHostManager();

    /**
     * Address: 0x0047FA40 (FUN_0047FA40, sHostManager::~sHostManager)
     *
     * What it does:
     * Clears host cache entries and resets intrusive list/map lanes on teardown.
     */
    ~CHostManager();

    /**
     * Address: 0x0047FBE0 (FUN_0047FBE0)
     *
     * uint32_t
     *
     * What it does:
     * Returns a cached hostname for `host` (host byte order) and updates MRU ordering.
     * On cache miss, resolves with getnameinfo and inserts into the MRU cache.
     */
    msvc8::string GetHostName(std::uint32_t host);

    /**
     * Address: <synthetic overload for lifted call sites>
     *
     * What it does:
     * Compatibility overload that forwards to the value-returning variant.
     */
    msvc8::string& GetHostName(std::uint32_t host, msvc8::string& out);

  private:
    // FA binary: 0x4C entries, Moho binary: 0x0C entries.
    // FAF runtime follows FA behavior.
    static constexpr std::size_t kMaxEntriesFA = 0x4C;
    static constexpr std::size_t kMaxEntriesMoho = 0x0C;
    static constexpr std::size_t kMaxEntries = kMaxEntriesFA;

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
    auto FindByValue(const Host* h) -> HostMap::iterator;

    /**
     * Address: <inlined inside 0x0047FBE0 in FA and 0x1007A1A0 in Moho>
     *
     * What it does:
     * Reverse DNS via getnameinfo; falls back to dotted IPv4 on failure.
     */
    static msvc8::string ResolveHostName(std::uint32_t host);
  };
} // namespace moho
