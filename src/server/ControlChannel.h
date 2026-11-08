#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// Engine addition, dedicated server (plan WP17.2, design research/WP17.2-control-api.md): the control API's channel,
// without sockets. The control service (and only it) connects over TCP; both sides hold one 32-byte control key.
//
// Handshake, each side the same: send a 24-byte random nonce; with the peer's, send a 32-byte proof,
// BLAKE2b-keyed(key, label | server nonce | service nonce), the label "faf-control server" or "faf-control service"
// by the sender's role; check the peer's. Then one key per direction, BLAKE2b-keyed(key, "faf-control s2c" or
// "faf-control c2s" | both nonces), and every message is a frame: a 4-byte little-endian length of what follows,
// then the message sealed with XChaCha20-Poly1305 (Monocypher's `crypto_aead_lock`: the cipher text, then the 16-byte
// tag), the nonce the frame's counter in that direction (8 bytes little-endian, then zeros), the length its additional
// data. Go has both: `blake2b.New(32, key)`, `chacha20poly1305.NewX`.

namespace faf::server
{
  using ControlKey = std::array<std::uint8_t, 32>;
  using ControlNonce = std::array<std::uint8_t, 24>;
  using ControlProof = std::array<std::uint8_t, 32>;

  inline constexpr std::size_t kControlTagBytes = 16;
  inline constexpr std::size_t kControlLengthBytes = 4;
  /** The longest message either side may send: a status of a full lobby is a few KB. */
  inline constexpr std::size_t kMaxControlMessageBytes = 256u * 1024u;

  enum class EControlRole : std::uint8_t
  {
    Server,
    Service,
  };

  /** The control key file's text: 64 hex digits, white space around them allowed. */
  [[nodiscard]] bool ReadControlKey(std::string_view text, ControlKey& out) noexcept;

  class CControlChannel
  {
  public:
    /** `ownNonce`: random, from the caller (`remote::net::FillRandom`), so tests can fix it. */
    CControlChannel(const ControlKey& key, EControlRole role, const ControlNonce& ownNonce) noexcept;
    ~CControlChannel();
    CControlChannel(const CControlChannel&) = delete;
    CControlChannel& operator=(const CControlChannel&) = delete;

    [[nodiscard]] const ControlNonce& OwnNonce() const noexcept { return mOwnNonce; }
    /** The peer's nonce has come: the proof to send it. */
    [[nodiscard]] ControlProof Proof(const ControlNonce& peerNonce) noexcept;
    /** The peer's proof: true when it holds the key, and from then on messages go both ways. */
    [[nodiscard]] bool CheckPeerProof(const ControlProof& proof) noexcept;
    [[nodiscard]] bool Ready() const noexcept { return mReady; }

    /** One message as a frame for the peer; empty before `Ready` or past `kMaxControlMessageBytes`. */
    [[nodiscard]] std::vector<std::uint8_t> Seal(std::span<const std::uint8_t> message);
    /**
     * Bytes from the peer, as they came. False: a frame too long, or one that doesn't open (a wrong key, changed or
     * reordered bytes): the connection should go. Whole messages wait for `Take`.
     */
    [[nodiscard]] bool Feed(std::span<const std::uint8_t> bytes);
    [[nodiscard]] bool Take(std::vector<std::uint8_t>& message);

  private:
    [[nodiscard]] const ControlNonce& ServerNonce() const noexcept;
    [[nodiscard]] const ControlNonce& ServiceNonce() const noexcept;
    void Derive(std::string_view label, std::uint8_t* out) const noexcept;

    ControlKey mKey;
    EControlRole mRole;
    ControlNonce mOwnNonce;
    ControlNonce mPeerNonce{};
    bool mHavePeerNonce = false;
    bool mReady = false;
    ControlKey mSendKey{};
    ControlKey mReceiveKey{};
    std::uint64_t mSent = 0;
    std::uint64_t mReceived = 0;
    std::vector<std::uint8_t> mInbox;   // bytes of a frame not yet whole
    std::vector<std::vector<std::uint8_t>> mMessages;
  };
} // namespace faf::server
