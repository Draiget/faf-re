#pragma once

#include <span>

#include "General.h"
#include "legacy/containers/String.h"
#include "moho/misc/TDatList.h"

namespace moho
{
    struct SPacket;

#pragma pack(push, 1)
    static constexpr std::size_t kPacketMaxSize = 512;

	/**
	 * Packet container (not a data header, but header).
	 */
	struct SPacketContainer
	{
        TDatList<SPacket, void> mList;
		int64_t mSentTime;
        int32_t mResendCount;
        int32_t mSize;
	};
    static_assert(offsetof(SPacketContainer, mSize) == 20, "SPacketHeader::mSize must be at +20");
    static_assert(sizeof(SPacketContainer) == 24, "SPacketHeader must be 24");

    /**
     * Packet data header & main information.
     */
    struct SPacketHeader
	{
        EPacketState mState;                   // +0 (1)
        std::uint32_t mEarlyMask;              // +1 .. +4
        std::uint16_t mSerialNumber;           // +5 .. +6
        std::uint16_t mInResponseTo;           // +7 .. +8
        std::uint16_t mSequenceNumber;         // +9 .. +10
        std::uint16_t mExpectedSequenceNumber; // +11 .. +12
        std::uint16_t mPayloadLength;          // +13 .. +14
    };
    static_assert(sizeof(SPacketHeader) == 15, "SPacketHeader must be 15 bytes");

    /**
     * Packet header constant size.
     */
    static constexpr std::size_t kNetPacketHeaderSize = sizeof(SPacketHeader);
	static constexpr std::size_t kNetPacketMaxPayload = kPacketMaxSize - kNetPacketHeaderSize; // 497

    /**
     * Network packet structure.
     * Size is dynamic, but typically `recvfrom()` reads 512 bytes only, so max is - 0x200 (512).
     */
    struct SPacket : SPacketContainer
	{
        SPacketHeader header;
        uint8_t data[kNetPacketMaxPayload];

        /**
         * Address: 0x00488BC0
         */
		[[nodiscard]]
		msvc8::string ToString() const;


        /**
         * Pointer to the first payload byte, header and data are the blocks we send
         * over the network except `SPacketContainer` itself.
         */
        void* GetPayload() noexcept {
	        return &header.mState;
        }

        /**
         * Pointer to the first payload byte, header and data are the blocks we send
         * over the network except `SPacketContainer` itself.
         */
        [[nodiscard]]
        const void* GetPayload() const noexcept {
	        return &header.mState;
        }

        /**
         * Get packet size data including header and payload.
         * We added `kNetPacketHeaderSize` when to the mSize when constructing packets, so
         * it's a 'full' packet size.
         */
        [[nodiscard]]
        std::size_t GetPayloadSize() const noexcept {
	        return static_cast<std::size_t>(mSize);
        }

	};
#pragma pack(pop)

#pragma pack(push, 1)
    struct SPacketBodyData
	{
        uint8_t bytes[kNetPacketMaxPayload];
    };
    static_assert(sizeof(SPacketBodyData) == kNetPacketMaxPayload, "SPacketBodyData must fill wire area");
#pragma pack(pop)

    /**
     * A typed packet that shares the exact SPacket layout.
     * It adds only helper methods to access/construct the body.
     * Safe to place into TPairList<SPacket,...> and pass as SPacket*.
     */
    template<class Body>
    struct SPacketOf : SPacket
    {
        static_assert(std::is_trivially_copyable<Body>::value, "Body must be trivially copyable");
        static_assert(sizeof(Body) <= sizeof(static_cast<SPacket*>(nullptr)->data), "Body too large for wire area");

        Body* body() { return reinterpret_cast<Body*>(data); }
        const Body& body() const { return *reinterpret_cast<const Body*>(data); }

        /**
         * Fill common header (does not touch container meta).
         */
        SPacketOf& SetCommon(
            const EPacketState st,
            const uint32_t mask,
            const uint16_t serial,
            const uint16_t inResp,
            const uint16_t seq,
            const uint16_t expected)
        {
            header.mState = st;
            header.mEarlyMask = mask;
            header.mSerialNumber = serial;
            header.mInResponseTo = inResp;
            header.mSequenceNumber = seq;
            header.mExpectedSequenceNumber = expected;
            return *this;
        }

        /**
         * Set wire size after body is written.
         * @param payloadBytes - bytes starting at &hdr
         */
        SPacketOf& finalize_size(const std::uint16_t payloadBytes)
        {
            header.mPayloadLength = payloadBytes;
            mSize = static_cast<std::int32_t>(kNetPacketHeaderSize + payloadBytes);
            return *this;
        }
    };

    /**
     * Packet structure definitions.
     */

#pragma pack(push, 1)
    struct SPacketBodyConnect
	{
        std::uint32_t protocol; // must be 2
        int64_t time;
        ENetCompressionMethod comp;
        char nonceA[32]; // Sender nonce
    };
    static_assert(sizeof(SPacketBodyConnect) == 45, "SPacketBodyConnect must be 73 bytes");

    struct SPacketBodyAnswer
    {
        std::uint32_t protocol; // must be 2
        int64_t time;
        ENetCompressionMethod comp;
        char nonceA[32];
        char nonceB[32]; // Receiver nonce
    };
    static_assert(sizeof(SPacketBodyAnswer) == 77, "SPacketBodyAnswer must be 77 bytes");
#pragma pack(pop)

    /**
     * Packet aliases
     */

    using SPacketDataPkt = SPacketOf<SPacketBodyData>;
    using SPacketConnectPkt = SPacketOf<SPacketBodyConnect>;
    using SPacketAnswerPkt = SPacketOf<SPacketBodyAnswer>;
}
