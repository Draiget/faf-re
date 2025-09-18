#include "CNetUDPConnector.h"

#include "INetNATTraversalProvider.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/TDatList.h"
using namespace moho;

CNetUDPConnector::~CNetUDPConnector() {
    // Drain packet free-list.
    while (mPacketList.mNext != &mPacketList) {
	    if (auto* n = mPacketList.mNext) {
            // Unlink from intrusive list and free
            n->mPrev->mNext = n->mNext;
            n->mNext->mPrev = n->mPrev;
            n->mNext = n;
            n->mPrev = n;
            operator delete(n);
        }
    }

#if defined(_WIN32)
    if (socket_ != INVALID_SOCKET)
        closesocket(socket_);
#endif

    if (mFile) {
        fclose(mFile);
    }

    // SendStamp buffer cleanup (original sub_47D990)
    mBuff.Reset();

    // Clear receive queues (original sub_48C580 on both)
    mPackets2.clear();
    mPackets1.clear();

    // Normalize intrusive lists (both to self-sentinel)
    mPacketList.mPrev->mNext = mPacketList.mNext;
    mPacketList.mNext->mPrev = mPacketList.mPrev;
    mPacketList.mNext = &mPacketList;
    mPacketList.mPrev = &mPacketList;

    mConnections.mPrev->mNext = mConnections.mNext;
    mConnections.mNext->mPrev = mConnections.mPrev;
    mConnections.mNext = &mConnections;
    mConnections.mPrev = &mConnections;

    // Release weak_ptr to NAT traversal provider
    mNatTravProv.reset();
}

void CNetUDPConnector::Destroy() {
    boost::weak_ptr<INetNATTraversalProvider> weakProv;
    weakProv.swap(mNatTravProv);

    if (const auto prov = weakProv.lock())
    {
        // provider->SetHandler(GetLocalPort(), nullptr)
        const int port = this->GetLocalPort();
        boost::shared_ptr<INetNATTraversalHandler> nullHandler{};
        prov->SetHandler(port, &nullHandler);
    }

    {
        gpg::core::SharedReadGuard lock(lock_);
        mNatTravProv.reset();

        // Iterate nodes and call ScheduleDestroy() on owners
        using Node = TDatListItem<CNetUDPConnection, void>;
        for (auto it = mConnections.begin(); it != mConnections.end(); ++it)
        {
            Node* const n = it.node();
            CNetUDPConnection* const conn =
                moho::owner_from_node_with_base<
                CNetUDPConnection,                   // Owner
                CNetUDPConnection,                   // Base that contains the hook
                void,                                // tag
                Node                                 // Hook node type
                >(n, &CNetUDPConnection::mConnList); // pointer-to-member hook

            // Call on the owner
            conn->ScheduleDestroy();
        }

        this->resignalWorker_ = true;
#if defined(_WIN32)
        WSASetEvent(event_);
#endif
    }
}

u_short CNetUDPConnector::GetLocalPort() {
    gpg::core::SharedReadGuard lock(lock_);
    sockaddr_in sa{};
    int nameLen = sizeof(sa);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&sa), &nameLen) == 0) {
        return ntohs(sa.sin_port);
    }
    return 0;
}

CNetUDPConnection* CNetUDPConnector::Connect(const u_long address, const u_short port) {
#if defined(_WIN32)
    gpg::core::SharedReadGuard lock(lock_);
    WSASetEvent(event_);
#endif

    using Node = TDatListItem<CNetUDPConnection, void>;

    for (auto it = mConnections.begin(); it != mConnections.end(); ++it) {
        Node* const n = it.node(); // node pointer
        CNetUDPConnection* const conn =
            moho::owner_from_node_with_base<
            CNetUDPConnection, // Owner
            CNetUDPConnection, // Base that contains the hook
            void,              // tag
            Node               // Hook node type
            >(n, &CNetUDPConnection::mConnList);

        // Match by address/port
        if (conn->GetAddr() != address || conn->GetPort() != port) {
            continue;
        }

        switch (conn->mState)
        {
        case ENetConnectionState::Pending:        // 0 -> 2
            conn->SetState(ENetConnectionState::Answering);
            return conn;

        case ENetConnectionState::Connecting:     // 1 -> 5
        case ENetConnectionState::Answering:      // 2 -> 5
        case ENetConnectionState::Establishing:   // 3 -> 5
            conn->SetState(ENetConnectionState::Errored);
            break;

        case ENetConnectionState::Errored:        // 5 -> no-op
        case ENetConnectionState::TimedOut:       // (not in snippet; keep as-is)
        default:
            GPG_UNREACHABLE()
            break;
        }
    }

    auto* const conn = new CNetUDPConnection(*this, address, port, ENetConnectionState::Connecting);
    return conn;
}

SendStampView& CNetUDPConnector::SnapshotSendStamps(SendStampView& out, const int windowMs) {
    gpg::core::SharedReadGuard lk(lock_);

    // GetTime() returns the same 64-bit tick domain used in the buffer
    const uint64_t now = static_cast<uint64_t>(gpg::time::GetTime());
    const uint64_t window = static_cast<uint64_t>(windowMs) * 1000ull; // ms -> us (as in binary)

    mBuff.ExtractWindow(out, now, window);
    return out;
}

int64_t CNetUDPConnector::GetTime() {
    // Convert elapsed CPU cycles to microseconds
    const uint64_t cycles = mTimer.ElapsedCycles(); // matches Timer::ElapsedCycles(&mTimer)
    const uint64_t elapsedUs = static_cast<uint64_t>(gpg::time::CyclesToMicroseconds(cycles));

    // v14 is used as a 64-bit baseline (stored in a FILETIME-shaped pair of dwords)
    const uint64_t baseUs = (static_cast<uint64_t>(v14.dwHighDateTime) << 32)
        | static_cast<uint64_t>(v14.dwLowDateTime);

    // Candidate = baseline + elapsed
    const uint64_t candidate = baseUs + elapsedUs;

    // Monotonic clamp: never return a value <= previous
    const uint64_t cur = static_cast<uint64_t>(mCurTime);
    const uint64_t next = (candidate > cur) ? candidate : (cur + 1u);

    mCurTime = static_cast<int64_t>(next);
    return mCurTime;
}

void CNetUDPConnector::AddPacket(SPacket* packet) {
    if (!packet) {
        return;
    }

    // Detach from whatever list the packet currently belongs to
    packet->mList.ListUnlink();

    // Pool has a hard cap of 20 packets — delete excess
    if (mPacketPoolSize >= 20u) {
        ::operator delete(packet); // binary used plain operator delete
        return;
    }

    // Push-back into pool list (insert before sentinel = tail)
    packet->mList.ListLinkBefore(&mPacketList);

    ++mPacketPoolSize;
}
