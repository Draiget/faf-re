#include "CNetUDPConnector.h"

#include "INetNATTraversalProvider.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/TDatList.h"
using namespace moho;

extern int32_t net_LogPackets;
extern int32_t net_DebugLevel;

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
    mNatTraversalProv.reset();
}

void CNetUDPConnector::Destroy() {
	if (const boost::shared_ptr<INetNATTraversalProvider> natProvider{ mNatTraversalProv }) {
        boost::shared_ptr<INetNATTraversalHandler> nullHandler{};
        const int port = this->GetLocalPort();
        natProvider->SetHandler(port, &nullHandler);
    }

    boost::recursive_mutex::scoped_lock lock{ lock_ };
    for (auto* conn : this->mConnections.owners()) {
        conn->ScheduleDestroy();
    }

    this->mClosed = true;
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

    for (auto* conn : this->mConnections.owners()) {
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
    for (auto* connection : this->mConnections.owners()) {
        if (connection->mState == kNetStatePending && !connection->mScheduleDestroy) {
            outAddress = connection->GetAddr();
            outPort = connection->GetPort();
            return true;
        }
    }
    return false;
}

INetConnection* CNetUDPConnector::Accept(const u_long address, const u_short port) {
    return this->Connect(address, port);
}

void CNetUDPConnector::Reject(const u_long address, const u_short port) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };
    for (auto* connection : this->mConnections.owners()) {
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
	        const boost::shared_ptr<INetNATTraversalHandler*> natProvider{ mNatTraversalProv };

            while (!mPackets2.empty()) {
                const auto [packet, address, port] = mPackets2.front();
                mPackets2.pop_front();

                if (natProvider) {
                    lock.unlock();
                    (*natProvider)->ReceivePacket(
                        address, 
                        port, 
                        &packet->header.mEarlyMask, 
                        packet->mSize - 1
                    );
                    lock.lock();
                }

                DisposePacket(packet);
            }
        }

        for (auto* connection : this->mConnections.owners()) {
            if (connection->mDestroyed) {
                delete(connection);
            } else {
                connection->FlushInput();
            }
        }
    }

    for (auto* conn : this->mConnections.owners()) {
        conn->DispatchFromInput();
    }

    mIsPulling = false;
    if (mClosed) {
#if defined(_WIN32)
        ::WSASetEvent(event_);
#endif
    }
}

SendStampView& CNetUDPConnector::SnapshotSendStamps(SendStampView& out, const int windowMs) {
    boost::recursive_mutex::scoped_lock lock{ lock_ };

    // GetTime() returns the same 64-bit tick domain used in the buffer
    const uint64_t now = static_cast<uint64_t>(gpg::time::GetTime());
    const uint64_t window = static_cast<uint64_t>(windowMs) * 1000ull; // ms -> us (as in binary)

    mBuff.ExtractWindow(out, now, window);
    return out;
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
        const auto ts_us = GetTime();
        packet->mSentTime = ts_us;

        // Stamps buffer: 1 = incoming
        mBuff.Push(1, static_cast<FILETIME>(ts_us), n);

        // Source IPv4/port (host order)
        const uint32_t addr_host = ntohl(static_cast<uint32_t>(from.sin_addr.s_addr));
        const uint16_t port_host = ntohs(from.sin_port);

        // .pktlog if enabled
        if (net_LogPackets) {
            // Log from header start; payload = received raw bytes (header+body)
            LogPacket(1, ts_us, addr_host, port_host,
                &packet->header.mState, n);
        }

        // Verbose debug
        if (net_DebugLevel >= 2) {
            auto sPkt = packet->ToString();
            auto host = NET_GetHostName(addr_host);
            auto tstr = gpg::FileTimeToString(ts_us);

            gpg::Debugf("%s:                     recv %s:%hu, %s",
                tstr.c_str(),
                host.c_str(),
                port_host,
                sPkt.c_str());
        }

        // Quick NAT traversal path (packet type == 8)
            // NOTE: adjust field names to your SPacket header structure
        if (n > 0 && packet->header.mState == NATTRAVERSAL) {
            if (auto prov = mNatTraversalProv.lock()) {
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
            for (auto* connection : this->mConnections.owners()) {
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

    if (connectPacket.protocol != kUdp) {
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
    if (this->mPacketPoolSize >= kReceiveUdpPacketPoolSize) {
	    delete(packet);
    } else {
        packet->ListUnlink();
        packet->ListLinkBefore(&this->mPacketList);
        ++this->mPacketPoolSize;
    }
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
