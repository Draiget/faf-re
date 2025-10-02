#include "CNetUDPConnector.h"

#include "INetNATTraversalProvider.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/core/Thread.h"
#include "moho/containers/TDatList.h"
using namespace moho;

extern int32_t net_LogPackets;
extern int32_t net_DebugLevel;

bool net_DebugCrash;

CNetUDPConnector::~CNetUDPConnector() {
    // Drain packet free-list.
    while (mPacketList.mNext != &mPacketList) {
	    if (auto* n = mPacketList.mNext) {
            // Unlink from intrusive list and free
            delete n->ListUnlink();
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
    mNatTraversalProvider.reset();
}

CNetUDPConnector::CNetUDPConnector(SOCKET sock, boost::weak_ptr<INetNATTraversalProvider>& prov) {
}

void CNetUDPConnector::Destroy() {
	if (const boost::shared_ptr<INetNATTraversalProvider> natProvider{ mNatTraversalProvider }) {
        boost::shared_ptr<INetNATTraversalHandler> nullHandler{};
        const int port = GetLocalPort();
        natProvider->SetHandler(port, &nullHandler);
    }

    boost::recursive_mutex::scoped_lock lock{ lock_ };
    for (auto* conn : mConnections.owners()) {
        conn->ScheduleDestroy();
    }

    mClosed = true;
#if defined(_WIN32)
    WSASetEvent(event_);
#endif
}

u_short CNetUDPConnector::GetLocalPort() {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    sockaddr_in sa{};
    int nameLen = sizeof(sa);
    if (getsockname(socket_, reinterpret_cast<sockaddr*>(&sa), &nameLen) == 0) {
        return ntohs(sa.sin_port);
    }
    return 0;
}

CNetUDPConnection* CNetUDPConnector::Connect(const u_long address, const u_short port) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
#if defined(_WIN32)
    WSASetEvent(event_);
#endif

    for (auto* conn : mConnections.owners()) {
		// Match by address/port
        if (conn->GetAddr() != address || conn->GetPort() != port) {
            continue;
        }

        switch (conn->mState)
        {
        case kNetStatePending:        // 0 -> 2
            conn->mState = kNetStateAnswering;
            return conn;

        case kNetStateConnecting:     // 1 -> 5
        case kNetStateAnswering:      // 2 -> 5
        case kNetStateEstablishing:   // 3 -> 5
            conn->mState = kNetStateErrored;
            break;

        case kNetStateErrored:        // 5 -> no-op
        case kNetStateTimedOut:       // (not in snippet; keep as-is)
        default:
            GPG_UNREACHABLE()
            break;
        }
    }

    auto* const conn = new CNetUDPConnection(*this, address, port, kNetStateConnecting);
    return conn;
}

bool CNetUDPConnector::FindNextAddress(u_long& outAddress, u_short& outPort) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    for (auto* connection : mConnections.owners()) {
        if (connection->mState == kNetStatePending && !connection->mScheduleDestroy) {
            outAddress = connection->GetAddr();
            outPort = connection->GetPort();
            return true;
        }
    }
    return false;
}

INetConnection* CNetUDPConnector::Accept(const u_long address, const u_short port) {
    return Connect(address, port);
}

void CNetUDPConnector::Reject(const u_long address, const u_short port) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    for (auto* connection : mConnections.owners()) {
        if (connection->GetAddr() == address && connection->GetPort() == port) {
            connection->ScheduleDestroy();
        }
    }
}

void CNetUDPConnector::Pull() {
    {
        boost::recursive_mutex::scoped_lock lock{ lock_ };
        mIsPulling = true;

        if (!mPackets2.empty()) {
            const boost::shared_ptr<INetNATTraversalProvider> natProvider{ mNatTraversalProvider };

            while (!mPackets2.empty()) {
                const auto [packet, address, port] = mPackets2.front();
                mPackets2.pop_front();

                if (natProvider) {
                    lock.unlock();
                    natProvider->ReceivePacket(
                        address, 
                        port, 
                        reinterpret_cast<const char*>(&packet->header.mEarlyMask),
                        packet->mSize - 1
                    );
                    lock.lock();
                }

                DisposePacket(packet);
            }
        }

        for (auto* connection : mConnections.owners()) {
            if (connection->mDestroyed) {
                delete(connection);
            } else {
                connection->FlushInput();
            }
        }
    }

    for (auto* conn : mConnections.owners()) {
        conn->DispatchFromInput();
    }

    mIsPulling = false;
    if (mClosed) {
#if defined(_WIN32)
        ::WSASetEvent(event_);
#endif
    }
}

void CNetUDPConnector::Push() {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    bool didFlush = false;
    for (auto* conn : mConnections.owners()) {
        if (conn->FlushOutput()) {
            didFlush = true;
        }
    }

    if (didFlush) {
#if defined(_WIN32)
        ::WSASetEvent(event_);
#endif
    }
}

void CNetUDPConnector::SelectEvent(const HANDLE ev) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    mSelectedEvent = ev;
#if defined(_WIN32)
    ::WSASetEvent(event_);
#endif
}

void CNetUDPConnector::Debug() {
}

SSendStampView CNetUDPConnector::SnapshotSendStamps(const uint64_t since) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    return mBuff.GetBetween(1000 * since, GetTime());
}

int64_t CNetUDPConnector::GetTime() {
	const auto cur = mTimer.ElapsedMicroseconds();
	const auto add = initTime_ + cur;
    if (add > mCurTime) {
        mCurTime = add;
    } else {
        ++mCurTime;
    }
    return mCurTime;
}

int32_t CNetUDPConnector::ChooseTimeout(const int32_t current, const int32_t choice) {
    if (current == -1 || choice != -1 && choice < current) {
        return choice;
    }
    return current;
}

int64_t CNetUDPConnector::ReceiveData() {
    struct Acquired {
        SNetPacket* pkt{};
        bool handedOff{ false };
    };

    std::vector<Acquired> acquired;
    acquired.reserve(8);

    while(true) {
        SNetPacket* packet;
        if (mPacketList.mNext == &mPacketList) {
            // Pool empty - allocate
            packet = new SNetPacket();
            if (!packet) {
                // Allocation failed - nothing to receive into; exit the loop.
                break;
            }
            // Ensure embedded list node points to self
            packet->mNext = packet;
            packet->mPrev = packet;
        } else {
            // Pop from pool head
            --mPacketPoolSize;
            packet = reinterpret_cast<SNetPacket*>(mPacketList.mNext);

            // unlink from free-list
            packet->mPrev->mNext = packet->mNext;
            packet->mNext->mPrev = packet->mPrev;
            packet->mNext = packet;
            packet->mPrev = packet;
        }
        acquired.push_back({ packet, /*handed_off*/false });

        // Receive
        sockaddr_in from{};
        int fromLen = sizeof(from);
        const int n = recvfrom(
            socket_,
            static_cast<char*>(packet->GetPayload()),
            512,
            0,
            reinterpret_cast<sockaddr*>(&from),
            &fromLen
        );

        if (n < 0) {
#if defined(_WIN32)
            const int lastErr = WSAGetLastError();
            if (lastErr != WSAEWOULDBLOCK) {
                if (net_DebugLevel) {
                    const char* es = NET_GetWinsockErrorString();
                    gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): recvfrom() failed: %s",
                        GetLocalPort(), es);
                }
            }
#else
            if (errno != EWOULDBLOCK && errno != EAGAIN) {
                if (net_DebugLevel) {
                    gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): recvfrom() failed: errno=%d",
                        GetLocalPort(), errno);
                }
            }
#endif
            // Stop reading - socket drained for now.
            break;
        }

        // Fill packet meta
        packet->mSize = n;

        // Timestamp (us) monotonic
        const auto timeNow = GetTime();
        packet->mSentTime = timeNow;

        // Stamps buffer: 1 = incoming
        mBuff.Push(1, timeNow, n);

        // Source IPv4/port (host order)
        const uint32_t addr_host = ntohl(static_cast<uint32_t>(from.sin_addr.s_addr));
        const uint16_t port_host = ntohs(from.sin_port);

        // .pktlog if enabled
        if (net_LogPackets) {
            // Log from header start; payload = received raw bytes (header+body)
            LogPacket(1, timeNow, addr_host, port_host,
                &packet->header.mState, n);
        }

        // Verbose debug
        if (net_DebugLevel >= 2) {
            auto sPkt = packet->ToString();
            auto host = NET_GetHostName(addr_host);
            auto tstr = gpg::FileTimeToString(timeNow);

            gpg::Debugf("%s:                     recv %s:%hu, %s",
                tstr.c_str(),
                host.c_str(),
                port_host,
                sPkt.c_str());
        }

        // Quick NAT traversal path (packet type == 8)
            // NOTE: adjust field names to your SPacket header structure
        if (n > 0 && packet->header.mState == NATTRAVERSAL) {
            if (auto prov = mNatTraversalProvider.lock()) {
                // Hand off ownership to NAT traversal queue
                SReceivePacket rp{};
                rp.mPacket = packet;
                rp.mAddr = addr_host;
                rp.mPort = port_host;

                mPackets2.push_back(rp);
#if defined(_WIN32)
                if (mSelectedEvent) {
                    SetEvent(mSelectedEvent);
                }
#endif
                acquired.back().handedOff = true;
                continue;
            }
            // If provider is absent - fallthrough to normal handling (ignore).
        }

        // Validate minimum header length
        if (static_cast<unsigned>(n) < 15U) {
            if (net_DebugLevel) {
                auto host = NET_GetHostName(addr_host);
                gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): ignoring short (%d bytes) packet from %s:%hu",
                    GetLocalPort(), n, host.c_str(), port_host);
            }
            continue; // not handed off -> will be pooled/freed after loop
        }

        // Decode header (type/state + payload length and other fields)
        // Replace 'mPayloadLength' with your actual field name
        if (packet->header.mState < NATTRAVERSAL + 1) {
            const int expected = static_cast<int>(packet->header.mPayloadLength) + kNetPacketHeaderSize;
            if (n != expected) {
                if (net_DebugLevel) {
                    auto host = NET_GetHostName(addr_host);
                    gpg::Logf(
                        "CNetUDPConnector<%hu>::ReceiveData(): ignoring packet with payload length mismatch "
                        "(got %d, header says %d) from %s:%hu",
                        GetLocalPort(), n, packet->header.mPayloadLength, host.c_str(), port_host
                    );
                }
                continue;
            }

            // Type 0: connection attempt (CONNECT)
            if (packet->header.mState == 0) {
                // Ownership is passed into ProcessConnect
                ProcessConnect(packet, addr_host, port_host);
                acquired.back().handedOff = true;
                continue;
            }

            // Find connection by (addr,port), only for connections with state < 5 (still handshaking/active)
            CNetUDPConnection* target = nullptr;
            for (auto* connection : mConnections.owners()) {
                if (connection->GetAddr() == addr_host &&
                    connection->GetPort() == port_host &&
                    static_cast<int>(connection->mState) < 5)
                {
                    target = connection;
                    break;
                }
            }

            if (!target) {
                if (net_DebugLevel) {
                    auto host = NET_GetHostName(addr_host);
                    gpg::Logf("CNetUDPConnector<%hu>::ReceiveData(): ignoring packet of type %d from unknown host %s:%hu",
                        GetLocalPort(), packet->header.mState, host.c_str(), port_host);
                }
                continue;
            }

            // Dispatch by type
            switch (packet->header.mState) {
            case ANSWER:
                target->ProcessAnswer(packet);
                acquired.back().handedOff = true;
                break;
            case DATA:
                target->ProcessData(packet);
                acquired.back().handedOff = true;
                break;
            case ACK:
                target->ProcessAck(packet);
                acquired.back().handedOff = true;
                break;
            case KEEPALIVE:
                target->ProcessKeepAlive(packet);
                acquired.back().handedOff = true;
                break;
            case GOODBYE:
                target->ProcessGoodbye(packet);
                acquired.back().handedOff = true;
                break;
            default:
                if (net_DebugLevel) {
                    auto host = NET_GetHostName(addr_host);
                    gpg::Logf(
                        "CNetUDPConnector<%hu>::ReceiveData(): ignoring unimplemented packet of type %d from %s:%hu",
                        GetLocalPort(), packet->header.mState, host.c_str(), port_host
                    );
                }
                break;
            }
        } else {
            if (net_DebugLevel) {
                auto host = NET_GetHostName(addr_host);
                gpg::Logf(
                    "CNetUDPConnector<%hu>::ReceiveData(): ignoring unknown packet type (%d) from %s:%hu",
                    GetLocalPort(), packet->header.mState, host.c_str(), port_host
                );
            }
        }
    }

    // Recycle all not-handed-off packets
    for (auto& [packet, handedOff] : acquired) {
        if (!handedOff) {
            AddPacket(packet);
        }
    }

    // Return last monotonic timestamp (useful to the caller)
    return mCurTime;
}

void CNetUDPConnector::ProcessConnect(const SNetPacket* packet, const u_long address, const u_short port) {
    if (packet->mSize != kNetPacketHeaderSize + sizeof(SPacketBodyConnect)) {
        if (net_DebugLevel) {
	        const auto host = NET_GetHostName(address);
            gpg::Logf(
                "CNetUDPConnector<%hu>::ProcessConnect(): ignoring wrong length CONNECT (got %d bytes, required %d) from %s:%d",
                GetLocalPort(), packet->mSize, 60, host.c_str(), port
            );
        }
        return;
    }

    const auto& connectPacket = packet->As<SPacketBodyConnect>();

    if (connectPacket.protocol != ENetProtocolType::kUdp) {
        if (net_DebugLevel) {
	        const auto host = NET_GetHostName(address);
            gpg::Logf(
                "CNetUDPConnector<%hu>::ProcessConnect(): ignoring connect with wrong protocol (got %d, required %d) from %s:%d",
                GetLocalPort(), connectPacket.protocol, 2, host.c_str(), port
            );
        }
    }
}

void CNetUDPConnector::LogPacket(
	const int direction,
    const std::int64_t timestampUs,
	const std::uint32_t addressHost,
	const std::uint16_t portHost,
    const void* payload,
	const int payloadLen)
{
    if (!net_LogPackets) {
        return;
    }

    // Lazy open
    if (!mFile)
    {
        char* temp = nullptr;
        size_t sz = 0;
        if (_dupenv_s(&temp, &sz, "TEMP") != 0 || temp == nullptr)
        {
            net_LogPackets = 0;
            gpg::Logf("NET: Can't find a place for the packet log -- %%TEMP%% not set!");
            return;
        }

        char host[260] = {};
        if (gethostname(host, sizeof(host) - 1) == -1) {
            net_LogPackets = 0;
            gpg::Logf("NET: Can't figure out a name for the packet log -- gethostname failed.");
            return;
        }

        const unsigned localPort = GetLocalPort();
        std::string path;
        path.reserve(512);
        {
            char buf[512];
            std::snprintf(buf, sizeof(buf), "%s\\%s-%u.pktlog", temp, host, localPort);
            path.assign(buf);
        }

        const auto err = fopen_s(&mFile, path.c_str(), "ab");
        if (err > 0 || !mFile) {
            net_LogPackets = 0;
            gpg::Logf("NET: can't open packet log \"%s\" for writing.", path.c_str());
            return;
        }

        free(temp);
        gpg::Logf("NET: Packet log \"%s\" opened.", path.c_str());

        // Write 16-byte "start" record: {timestamp_us, time64(0), 0, 0}
        PacketLogRecord start;
        start.timestamp_us = timestampUs;
        start.addr = static_cast<std::uint32_t>(_time64(nullptr)); // time64(0)
        start.len_flags = 0;
        start.port = 0;
        std::fwrite(&start, sizeof(start), 1, mFile);
    }

    // Record header
    PacketLogRecord rec;
    rec.timestamp_us = timestampUs;
    rec.addr = addressHost;
    rec.len_flags = static_cast<std::uint16_t>(payloadLen & 0x7FFF);
    if (direction == 1) {
    	rec.len_flags |= 0x8000; // incoming flag
    }
    rec.port = portHost;

    // Write header + payload
    std::fwrite(&rec, sizeof(rec), 1, mFile);
    std::fwrite(payload, 1, static_cast<size_t>(payloadLen), mFile);
}

void CNetUDPConnector::DisposePacket(SNetPacket* packet) {
    if (mPacketPoolSize >= kReceiveUdpPacketPoolSize) {
	    delete(packet);
    } else {
        packet->ListUnlink();
        packet->ListLinkBefore(&mPacketList);
        ++mPacketPoolSize;
    }
}

void CNetUDPConnector::Func1(CMessage* msg) {
    msg->mBuff.Clear();
    char c = 8;
    msg->mBuff.Append(c);
}

void CNetUDPConnector::ReceivePacket(const u_long address, const u_short port, const char* dat, size_t size) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    if (size > kPacketMaxSize) {
        gpg::Logf("Truncating NAT traversal packet from %d to %d bytes", size, kPacketMaxSize);
        size = kPacketMaxSize;
    }

    const auto packet = new SNetPacket();
    memcpy(&packet->header, dat, size);
    packet->mSize = static_cast<int32_t>(size);
    const SReceivePacket r{ packet, address, port };
    mPackets1.push_back(r);

#if defined(_WIN32)
    if (event_) {
        ::WSASetEvent(event_);
    }
#endif
}

SNetPacket* CNetUDPConnector::NewPacket() {
    if (mPacketList.empty()) {
        return new SNetPacket{};
    }

    --mPacketPoolSize;
    SNetPacket* packet = mPacketList.ListGetNext();
    packet->ListUnlink();
    return packet;
}

void CNetUDPConnector::Entry() {
	const msvc8::string name = gpg::STR_Printf("CNetUDPConnector for port %d", GetLocalPort());
    gpg::SetThreadName(0xFFFFFFFF, name.c_str());
    THREAD_SetAffinity(false);
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    while (true) {
        if (!net_LogPackets && mFile != nullptr) {
            ::fclose(mFile);
            mFile = nullptr;
        }
        ReceiveData();
        const LONGLONG timeout = SendData();
        if (mClosed && !mIsPulling) {
            for (const auto* connection : mConnections.owners()) {
                if (connection->mDestroyed) {
                    delete connection;
                }
            }
            if (mConnections.empty()) {
                break;
            }
        }
        lock.unlock();
        if (net_DebugCrash) {
            *static_cast<int*>(0) = 0;
        }

        LONGLONG startTime = 0;
        if (net_DebugLevel >= 3) {
            startTime = GetTime();
            const auto timeStr = gpg::FileTimeToString(startTime);
            gpg::Debugf("%s: waiting, timeout=%dms", timeStr.c_str(), timeout);
        }
        ::WSAWaitForMultipleEvents(1, &event_, false, static_cast<DWORD>(timeout), true);

        if (startTime != 0) {
            const auto time = GetTime();
            const auto timeStr = gpg::FileTimeToString(time);
            gpg::Debugf(
                "%s: wait finished, elapsed=%dms",
                timeStr.c_str(),
                (time - startTime) / 1000
            );
        }
        lock.lock();
        ::WSAResetEvent(event_);
    }
}

int32_t CNetUDPConnector::SendData() {
    int timeout = -1;
    LONGLONG curTime = GetTime();
    while (!mPackets1.empty()) {
        const auto packet = mPackets1.begin();
        sockaddr_in name;
        name.sin_family = AF_INET;
        name.sin_port = ::htons(packet->mPort);
        name.sin_addr.S_un.S_addr = ::htonl(packet->mAddr);

        const auto payload = packet->mPacket->GetPayload();
        const auto payloadSize = packet->mPacket->GetPayloadSize();

        ::sendto(
            socket_, 
            static_cast<const char*>(payload), 
            static_cast<int32_t>(payloadSize), 
            0, 
            reinterpret_cast<SOCKADDR*>(&name), 
            16);

        if (net_LogPackets) {
            LogPacket(0, curTime, packet->mAddr, packet->mPort, payload, packet->mPacket->mSize);
        }

        mBuff.Add(0, curTime, packet->mPacket->mSize);
        if (net_DebugLevel >= 2) {
            msvc8::string packStr = packet->mPacket->ToString();
            msvc8::string hostStr = NET_GetHostName(packet->mAddr);
            curTime = GetTime();
            msvc8::string timeStr = gpg::FileTimeToString(curTime);
            gpg::Debugf("%s: send %s:%d, %s", 
                timeStr.c_str(), 
                hostStr.c_str(), 
                packet->mPort, 
                packStr.c_str());
        }
        mPackets1.pop_front();
        DisposePacket(packet->mPacket);
    }

    for (auto* conn : mConnections.owners()) {
        int conTimeout = 0;
        while (conTimeout == 0) {
            if (!conn->GetBacklogTimeout(curTime, conTimeout)) {
                break;
            }

            conTimeout = ChooseTimeout(static_cast<int32_t>(conn->SendData()), timeout);
        }
        timeout = ChooseTimeout(conTimeout, timeout);
    }

    return timeout;
}

void CNetUDPConnector::AddPacket(SNetPacket* packet) {
    if (!packet) {
        return;
    }

    // Detach from whatever list the packet currently belongs to
    packet->ListUnlink();

    // Pool has a hard cap of 20 packets - delete excess
    if (mPacketPoolSize >= kReceiveUdpPacketPoolSize) {
        operator delete(packet); // binary used plain operator delete
        return;
    }

    // Push-back into pool list (insert before sentinel = tail)
    packet->ListLinkBefore(&mPacketList);

    ++mPacketPoolSize;
}
