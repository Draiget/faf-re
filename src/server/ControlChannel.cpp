#include "server/ControlChannel.h"

#include <cstring>

#include "monocypher.h"

// Engine addition, dedicated server: see ControlChannel.h.

namespace faf::server
{
  namespace
  {
    [[nodiscard]] int HexDigit(const char c) noexcept
    {
      if (c >= '0' && c <= '9') {
        return c - '0';
      }
      if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
      }
      if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
      }
      return -1;
    }

    [[nodiscard]] bool IsSpace(const char c) noexcept
    {
      return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    [[nodiscard]] std::array<std::uint8_t, 24> FrameNonce(const std::uint64_t counter) noexcept
    {
      std::array<std::uint8_t, 24> nonce{};
      for (int i = 0; i < 8; ++i) {
        nonce[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(counter >> (8 * i));
      }
      return nonce;
    }

    constexpr std::string_view kServerProof = "faf-control server";
    constexpr std::string_view kServiceProof = "faf-control service";
    constexpr std::string_view kServerToService = "faf-control s2c";
    constexpr std::string_view kServiceToServer = "faf-control c2s";
  } // namespace

  bool ReadControlKey(std::string_view text, ControlKey& out) noexcept
  {
    while (!text.empty() && IsSpace(text.front())) {
      text.remove_prefix(1);
    }
    while (!text.empty() && IsSpace(text.back())) {
      text.remove_suffix(1);
    }
    if (text.size() != 2u * out.size()) {
      return false;
    }
    for (std::size_t i = 0; i < out.size(); ++i) {
      const int high = HexDigit(text[2 * i]);
      const int low = HexDigit(text[2 * i + 1]);
      if (high < 0 || low < 0) {
        return false;
      }
      out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
  }

  CControlChannel::CControlChannel(const ControlKey& key, const EControlRole role, const ControlNonce& ownNonce) noexcept
    : mKey(key)
    , mRole(role)
    , mOwnNonce(ownNonce)
  {}

  CControlChannel::~CControlChannel()
  {
    crypto_wipe(mKey.data(), mKey.size());
    crypto_wipe(mSendKey.data(), mSendKey.size());
    crypto_wipe(mReceiveKey.data(), mReceiveKey.size());
  }

  const ControlNonce& CControlChannel::ServerNonce() const noexcept
  {
    return mRole == EControlRole::Server ? mOwnNonce : mPeerNonce;
  }

  const ControlNonce& CControlChannel::ServiceNonce() const noexcept
  {
    return mRole == EControlRole::Service ? mOwnNonce : mPeerNonce;
  }

  void CControlChannel::Derive(const std::string_view label, std::uint8_t* const out) const noexcept
  {
    // label | server nonce | service nonce, keyed with the control key, 32 bytes.
    std::array<std::uint8_t, 32 + 2 * 24> input{};
    std::memcpy(input.data(), label.data(), label.size());
    std::memcpy(input.data() + label.size(), ServerNonce().data(), 24);
    std::memcpy(input.data() + label.size() + 24, ServiceNonce().data(), 24);
    crypto_blake2b_keyed(out, 32, mKey.data(), mKey.size(), input.data(), label.size() + 48);
    crypto_wipe(input.data(), input.size());
  }

  ControlProof CControlChannel::Proof(const ControlNonce& peerNonce) noexcept
  {
    mPeerNonce = peerNonce;
    mHavePeerNonce = true;
    ControlProof proof{};
    Derive(mRole == EControlRole::Server ? kServerProof : kServiceProof, proof.data());
    return proof;
  }

  bool CControlChannel::CheckPeerProof(const ControlProof& proof) noexcept
  {
    if (!mHavePeerNonce || mReady) {
      return false;
    }
    ControlProof expected{};
    Derive(mRole == EControlRole::Server ? kServiceProof : kServerProof, expected.data());
    const bool same = crypto_verify32(expected.data(), proof.data()) == 0;
    crypto_wipe(expected.data(), expected.size());
    if (!same) {
      return false;
    }
    const bool server = mRole == EControlRole::Server;
    Derive(server ? kServerToService : kServiceToServer, mSendKey.data());
    Derive(server ? kServiceToServer : kServerToService, mReceiveKey.data());
    mReady = true;
    return true;
  }

  std::vector<std::uint8_t> CControlChannel::Seal(const std::span<const std::uint8_t> message)
  {
    if (!mReady || message.size() > kMaxControlMessageBytes) {
      return {};
    }
    const std::size_t sealed = message.size() + kControlTagBytes;
    std::vector<std::uint8_t> frame(kControlLengthBytes + sealed);
    for (std::size_t i = 0; i < kControlLengthBytes; ++i) {
      frame[i] = static_cast<std::uint8_t>(sealed >> (8u * i));
    }
    const auto nonce = FrameNonce(mSent++);
    std::uint8_t* const cipher = frame.data() + kControlLengthBytes;
    crypto_aead_lock(cipher, cipher + message.size(), mSendKey.data(), nonce.data(), frame.data(), kControlLengthBytes, message.data(), message.size());
    return frame;
  }

  bool CControlChannel::Feed(const std::span<const std::uint8_t> bytes)
  {
    if (!mReady) {
      return false;
    }
    mInbox.insert(mInbox.end(), bytes.begin(), bytes.end());
    std::size_t at = 0;
    while (mInbox.size() - at >= kControlLengthBytes) {
      std::size_t sealed = 0;
      for (std::size_t i = 0; i < kControlLengthBytes; ++i) {
        sealed |= static_cast<std::size_t>(mInbox[at + i]) << (8u * i);
      }
      if (sealed < kControlTagBytes || sealed > kMaxControlMessageBytes + kControlTagBytes) {
        return false;
      }
      if (mInbox.size() - at - kControlLengthBytes < sealed) {
        break; // the rest of this frame is still on its way
      }
      const std::uint8_t* const header = mInbox.data() + at;
      const std::uint8_t* const cipher = header + kControlLengthBytes;
      const std::size_t size = sealed - kControlTagBytes;
      std::vector<std::uint8_t> plain(size);
      const auto nonce = FrameNonce(mReceived);
      if (crypto_aead_unlock(plain.data(), cipher + size, mReceiveKey.data(), nonce.data(), header, kControlLengthBytes, cipher, size) != 0) {
        return false;
      }
      ++mReceived;
      mMessages.push_back(std::move(plain));
      at += kControlLengthBytes + sealed;
    }
    mInbox.erase(mInbox.begin(), mInbox.begin() + static_cast<std::ptrdiff_t>(at));
    return true;
  }

  bool CControlChannel::Take(std::vector<std::uint8_t>& message)
  {
    if (mMessages.empty()) {
      return false;
    }
    message = std::move(mMessages.front());
    mMessages.erase(mMessages.begin());
    return true;
  }
} // namespace faf::server
