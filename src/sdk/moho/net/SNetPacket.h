#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

#include "EnumByte.h"
#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "NetTransportEnums.h"

namespace moho
{
  struct SNetPacket;

  /**
   * Packet type byte wrapper.
   *
   * Host-build convenience over the 1-byte wire `SNetPacketHeader::mType` field.
   * No direct engine symbol for this wrapper (synthetic helper).
   */
  struct PacketTypeByte : EnumByte
  {
    using EnumByte::EnumByte;
    PacketTypeByte() noexcept = default;
  };
  static_assert(sizeof(PacketTypeByte) == 0x1, "PacketTypeByte size must be 0x1");

  static constexpr std::size_t kPacketMaxSize = 512;

  typedef uint32_t EarlyPayloadMask;

  /**
   * Base constraint for typed packet bodies on the wire
   */
  template <class T>
  concept PacketBody = std::is_trivially_copyable_v<T> && sizeof(T) <= kPacketMaxSize;

#pragma pack(push, 1)
  /**
   * Packet container (not a data header, but header).
   */
  struct SNetPacketMetadata
  {
    int64_t mSentTime{0};
    int32_t mResendCount{0};
    int32_t mSize{0};
  };
  static_assert(offsetof(SNetPacketMetadata, mSize) == 12, "SPacketMeta::mSize must be at +12");
  static_assert(sizeof(SNetPacketMetadata) == 16, "SNetPacketMetadata size must be 0x10");

  /**
   * Packet data header & main information.
   */
  struct SNetPacketHeader
  {
    EPacketType mType{PT_Connect};       // +0 (1)
    EarlyPayloadMask mEarlyMask{0};      // +1 .. +4
    uint16_t mSerialNumber{0};           // +5 .. +6
    uint16_t mInResponseTo{0};           // +7 .. +8
    uint16_t mSequenceNumber{0};         // +9 .. +10
    uint16_t mExpectedSequenceNumber{0}; // +11 .. +12
    uint16_t mPayloadLength{0};          // +13 .. +14
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
    std::uint8_t bytes[kNetPacketMaxPayload]{};
  };
  static_assert(
    sizeof(SPacketBodyData) == kNetPacketMaxPayload, "SPacketBodyData size should fit 512 - <header>(15) = 497"
  );

  /**
   * CRTP mixin with typed packet-field helpers.
   *
   * These helpers are intentionally synthetic for host-side readability and do not map
   * to standalone engine symbols in FA/Moho binaries.
   */
  template <class Derived>
  struct INetPacketOps
  {
    /**
     * Get mutable pointer to the first wire byte (header start)
     */
    void* GetPayload() noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      return &self.header.mType;
    }

    /**
     * Get const pointer to the first wire byte (header start)
     */
    [[nodiscard]]
    const void* GetPayload() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      return &self.header.mType;
    }

    /**
     * Get packet type as strongly-typed one-byte wrapper.
     */
    [[nodiscard]]
    PacketTypeByte GetTypeByte() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      return PacketTypeByte{self.header.mType};
    }

    /**
     * Set packet type from one-byte wrapper.
     */
    void SetTypeByte(const PacketTypeByte type) noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      self.header.mType = static_cast<EPacketType>(type);
    }

    /**
     * Get wire payload bytes span (just payload, not including header)
     */
    std::span<std::byte> GetPayloadSpan() noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      return {reinterpret_cast<std::byte*>(self.data), self.header.mPayloadLength};
    }

    /**
     * Get wire payload bytes span (const)
     */
    [[nodiscard]]
    std::span<const std::byte> GetPayloadSpan() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      return {reinterpret_cast<const std::byte*>(self.data), self.header.mPayloadLength};
    }

    /**
     * Get total wire size including header and payload
     */
    [[nodiscard]]
    std::size_t GetPayloadSize() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      return static_cast<std::size_t>(self.mSize);
    }

    /**
     * Set total payload length and recompute wire size
     */
    void SetPayloadSize(std::uint16_t payloadBytes) noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      self.header.mPayloadLength = payloadBytes;
      self.mSize = static_cast<std::int32_t>(kNetPacketHeaderSize + payloadBytes);
    }

    /**
     * Return typed body by reference
     */
    template <PacketBody T>
    T& As() noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
      return *reinterpret_cast<T*>(self.data);
    }

    /**
     * Return typed body by const reference
     */
    template <PacketBody T>
    const T& As() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
      return *reinterpret_cast<const T*>(self.data);
    }

    /**
     * Return typed body pointer
     */
    template <PacketBody T>
    T* AsPtr() noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
      return reinterpret_cast<T*>(self.data);
    }

    /**
     * Return typed body const pointer
     */
    template <PacketBody T>
    const T* AsPtr() const noexcept
    {
      auto& self = *static_cast<const Derived*>(this);
      static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large");
      return reinterpret_cast<const T*>(self.data);
    }

    /**
     * Write typed body and set sizes accordingly
     */
    template <PacketBody T>
    void WriteBody(const T& b) noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      static_assert(sizeof(T) <= kNetPacketMaxPayload, "Body too large for packet");
      std::memcpy(self.data, &b, sizeof(T));
      SetPayloadSize(static_cast<std::uint16_t>(sizeof(T)));
    }

    /**
     * Fill common header fields (does not touch meta)
     */
    Derived& SetMetadata(
      EPacketType st,
      std::uint32_t mask,
      std::uint16_t serial,
      std::uint16_t inResp,
      std::uint16_t seq,
      std::uint16_t expected
    ) noexcept
    {
      auto& self = *static_cast<Derived*>(this);
      self.header.mType = st;
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
    SNetPacketHeader header{};
    uint8_t data[kNetPacketMaxPayload]{};

    /**
     * Address: 0x00488BC0 (FUN_00488BC0)
     * Address: 0x100825E0 (sub_100825E0)
     *
     * SNetPacket const &
     *
     * IDA signature (FA):
     * std::string *__usercall Moho::SPacket::ToString@<eax>(Moho::SPacket *a1@<esi>, std::string *a2);
     *
     * IDA signature (MohoEngine):
     * int __usercall sub_100825E0@<eax>(int a1@<esi>, int a2);
     *
     * What it does:
     * Formats packet metadata/type for debug logs and optionally dumps first bytes
     * of NAT-traversal packets.
     */
    [[nodiscard]]
    msvc8::string ToString() const;

    /**
     * Address: 0x00487A30 (FUN_00487A30)
     * Address: 0x10081450 (sub_10081450)
     *
     * const char *, __int64
     *
     * IDA signature (FA, unnamed export):
     * int __usercall nullsub_513_0@<eax>(const char *a1@<edx>, int a2@<esi>, __int64 a3);
     *
     * IDA signature (MohoEngine):
     * void __usercall sub_10081450(const char *a1@<edx>, int a2@<esi>, __int64 a3);
     *
     * What it does:
     * Emits detailed packet diagnostics (size/resend/type/sequence/payload length).
     */
    void LogPacket(const char* dirType, int64_t receiveOrSentTime) const;
  };
  static_assert(sizeof(SNetPacket) == 0x218, "SNetPacket size must be 0x218");
#pragma pack(pop)

  /**
   * Strongly typed packet view that shares exact `SNetPacket` layout.
   *
   * Host-only typed convenience over raw packet payload bytes.
   */
  template <PacketBody Body>
  struct SPacketOf : SNetPacket
  {
    static_assert(sizeof(Body) <= sizeof(static_cast<SNetPacket*>(nullptr)->data), "Body too large for packet");

    /**
     * Mutable typed body view
     */
    Body* GetBody() noexcept
    {
      return reinterpret_cast<Body*>(data);
    }

    /**
     * Const typed body view
     */
    const Body& GetBody() const noexcept
    {
      return *reinterpret_cast<const Body*>(data);
    }

    /**
     * Finalize sizes when body is already written
     */
    SPacketOf& FinalizeSize(const std::uint16_t payloadBytes) noexcept
    {
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
    ENetProtocolType protocol{ENetProtocolType::kUdp}; // must be 2
    int64_t time{0};
    ENetCompressionMethod comp{NETCOMP_None};
    char senderNonce[32]{}; // Sender nonce
  };
  static_assert(sizeof(SPacketBodyConnect) == 45, "SPacketBodyConnect size must be 45 bytes");

  struct SPacketBodyAnswer
  {
    ENetProtocolType protocol{ENetProtocolType::kUdp}; // must be 2
    int64_t time{0};
    ENetCompressionMethod comp{NETCOMP_None};
    char senderNonce[32]{};
    char receiverNonce[32]{}; // Receiver nonce
  };
  static_assert(sizeof(SPacketBodyAnswer) == 77, "SPacketBodyAnswer size must be 77 bytes");
#pragma pack(pop)

  /**
   * Packet aliases
   */

  using SNetPacketGameData = SPacketOf<SPacketBodyData>;
  using SNetPacketGameConnect = SPacketOf<SPacketBodyConnect>;
  using SNetPacketGameAnswer = SPacketOf<SPacketBodyAnswer>;
} // namespace moho
