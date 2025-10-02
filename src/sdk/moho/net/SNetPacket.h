#pragma once

#include <span>

#include "Common.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"

namespace moho
{
    struct SNetPacket;

    static constexpr std::size_t kPacketMaxSize = 512;

    /**
     * Base constraint for typed packet bodies on the wire
     */
    template<class T>
    concept PacketBody =
        std::is_trivially_copyable_v<T> &&
        sizeof(T) <= kPacketMaxSize;


#pragma pack(push, 1)
	/**
	 * Packet container (not a data header, but header).
	 */
	struct SNetPacketMetadata
	{
		int64_t mSentTime;
        int32_t mResendCount;
        int32_t mSize;
	};
    static_assert(offsetof(SNetPacketMetadata, mSize) == 12, "SPacketMeta::mSize must be at +12");
    static_assert(sizeof(SNetPacketMetadata) == 16, "SPacketMeta must be 24");

    /**
     * Packet data header & main information.
     */
    struct SNetPacketHeader
	{
        EPacketState mState;                   // +0 (1)
        uint32_t mEarlyMask;              // +1 .. +4
        uint16_t mSerialNumber;           // +5 .. +6
        uint16_t mInResponseTo;           // +7 .. +8
        uint16_t mSequenceNumber;         // +9 .. +10
        uint16_t mExpectedSequenceNumber; // +11 .. +12
        uint16_t mPayloadLength;          // +13 .. +14
    };
    static_assert(sizeof(SNetPacketHeader) == 15, "SPacketHeader must be 15 bytes");

    /**
     * Packet header constant size.
     */
    static constexpr std::size_t kNetPacketHeaderSize = sizeof(SNetPacketHeader);
	static constexpr std::size_t kNetPacketMaxPayload = kPacketMaxSize - kNetPacketHeaderSize; // 497

    /**
     * Non-owning wire body of arbitrary bytes.
     */
    struct SPacketBodyData
    {
        std::uint8_t bytes[kNetPacketMaxPayload];
    };
    static_assert(sizeof(SPacketBodyData) == kNetPacketMaxPayload, 
        "SPacketBodyData size should fit 512 - <header>(15) = 497");

    /**
     * CRTP mixin that provides ergonomic accessors without changing layout.
     */
    template<class Derived>
    struct INetPacketOps
    {
        /**
         * Get mutable pointer to the first wire byte (header start)
         */
        void* GetPayload() noexcept {
            auto& self = *static_cast<Derived*>(this);
            return &self.header.mState;
        }

        /**
         * Get const pointer to the first wire byte (header start)
         */
        [[nodiscard]]
    	const void* GetPayload() const noexcept {
            auto& self = *static_cast<const Derived*>(this);
            return &self.header.mState;
        }

        /**
         * Get wire payload bytes span (just payload, not including header)
         */
        std::span<std::byte> GetPayloadSpan() noexcept {
            auto& self = *static_cast<Derived*>(this);
            return { reinterpret_cast<std::byte*>(self.data), self.header.mPayloadLength };
        }

        /**
         * Get wire payload bytes span (const)
         */
        [[nodiscard]]
        std::span<const std::byte> GetPayloadSpan() const noexcept {
            auto& self = *static_cast<const Derived*>(this);
            return { reinterpret_cast<const std::byte*>(self.data), self.header.mPayloadLength };
        }

        /**
         * Get total wire size including header and payload
         */
        [[nodiscard]]
        std::size_t GetPayloadSize() const noexcept {
            auto& self = *static_cast<const Derived*>(this);
            return static_cast<std::size_t>(self.mSize);
        }

        /**
         * Set total payload length and recompute wire size
         */
        void SetPayloadSize(std::uint16_t payloadBytes) noexcept {
            auto& self = *static_cast<Derived*>(this);
            self.header.mPayloadLength = payloadBytes;
            self.mSize = static_cast<std::int32_t>(kNetPacketHeaderSize + payloadBytes);
        }

        /**
	     * Return typed body by reference
	     */
        template<PacketBody T>
        T& As() noexcept {
            auto& self = *static_cast<Derived*>(this);
            static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
            return *reinterpret_cast<T*>(self.data);
        }

        /**
         * Return typed body by const reference
         */
        template<PacketBody T>
        const T& As() const noexcept {
            auto& self = *static_cast<const Derived*>(this);
            static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
            return *reinterpret_cast<const T*>(self.data);
        }

        /**
         * Return typed body pointer
         */
        template<PacketBody T>
        T* AsPtr() noexcept {
            auto& self = *static_cast<Derived*>(this);
            static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
            return reinterpret_cast<T*>(self.data);
        }

        /**
         * Return typed body const pointer
         */
        template<PacketBody T>
        const T* AsPtr() const noexcept {
            auto& self = *static_cast<const Derived*>(this);
            static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
            return reinterpret_cast<const T*>(self.data);
        }

        /**
         * Write typed body and set sizes accordingly
         */
        template<PacketBody T>
        void WriteBody(const T& b) noexcept {
            auto& self = *static_cast<Derived*>(this);
            static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large for packet");
            std::memcpy(self.data, &b, sizeof(T));
            SetPayloadSize(static_cast<std::uint16_t>(sizeof(T)));
        }

        /**
         * Fill common header fields (does not touch meta)
         */
        Derived& SetMetadata(
            EPacketState st,
            std::uint32_t mask,
            std::uint16_t serial,
            std::uint16_t inResp,
            std::uint16_t seq,
            std::uint16_t expected) noexcept
        {
            auto& self = *static_cast<Derived*>(this);
            self.header.mState = st;
            self.header.mEarlyMask = mask;
            self.header.mSerialNumber = serial;
            self.header.mInResponseTo = inResp;
            self.header.mSequenceNumber = seq;
            self.header.mExpectedSequenceNumber = expected;
            return self;
        }
    };

    /**
     * Network packet structure.
     * Size is dynamic, but typically `recvfrom()` reads 512 bytes only, so max is - 0x200 (512).
     */
    struct SNetPacket : TDatList<SNetPacket, void>, SNetPacketMetadata, INetPacketOps<SNetPacket>
	{
        SNetPacketHeader header;
        uint8_t data[kNetPacketMaxPayload];

        /**
         * Address: 0x00488BC0
         */
		[[nodiscard]]
		msvc8::string ToString() const;

        /**
         * Address: 0x00487A30
         */
		void LogPacket(const char* dirType, int64_t receiveOrSentTime) const;
	};
#pragma pack(pop)

    /**
     * Strongly typed packet that shares the exact SPacket layout.
     */
    template<PacketBody Body>
    struct SPacketOf : SNetPacket
    {
        static_assert(sizeof(Body) <= sizeof(static_cast<SNetPacket*>(nullptr)->data),
            "Body too large for packet");

        /**
         * Mutable typed body view
         */
        Body* GetBody() noexcept {
	        return reinterpret_cast<Body*>(data);
        }

        /**
         * Const typed body view
         */
        const Body& GetBody() const noexcept {
	        return *reinterpret_cast<const Body*>(data);
        }

        /**
         * Finalize sizes when body is already written
         */
        SPacketOf& FinalizeSize(const std::uint16_t payloadBytes) noexcept {
            this->SetPayloadSize(payloadBytes);
            return *this;
        }
    };

    /**
     * Packet structure definitions.
     */

#pragma pack(push, 1)
    struct SPacketBodyConnect
	{
        ENetProtocolType protocol; // must be 2
        int64_t time;
        ENetCompressionMethod comp;
        char nonceA[32]; // Sender nonce
    };
    static_assert(sizeof(SPacketBodyConnect) == 45, "SPacketBodyConnect must be 73 bytes");

    struct SPacketBodyAnswer
    {
        ENetProtocolType protocol; // must be 2
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

    using SNetPacketGameData = SPacketOf<SPacketBodyData>;
    using SNetPacketGameConnect = SPacketOf<SPacketBodyConnect>;
    using SNetPacketGameAnswer = SPacketOf<SPacketBodyAnswer>;
}
