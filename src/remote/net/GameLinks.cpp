#include "remote/net/GameLinks.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

#include "remote/net/Datagram.h"

namespace faf::remote::net
{
  namespace
  {
    // Larger than any datagram either end sends: a bigger one is cut, and then fails its checks.
    constexpr std::size_t kReceiveBuffer = 2048;
    // In one pass, so a flood can't keep the channels from being served.
    constexpr int kMaxDatagramsPerPump = 4096;
  } // namespace

  CServerLinks::CServerLinks(const ChannelConfig& channel)
    : mChannelConfig(channel)
  {}

  bool CServerLinks::Open(const SEndpoint& local, std::string& error)
  {
    if (!mCookies.Init() || !FillRandom(&mAddressSalt, sizeof(mAddressSalt))) {
      error = "the system gave no random secret for the handshake";
      return false;
    }
    return mSocket.Open(local, error);
  }

  void CServerLinks::AllowAddress(const std::uint32_t ip)
  {
    mAllowlistOn = true;
    mAllowed.insert(ip);
  }

  bool CServerLinks::TakeAddressBudget(const std::uint32_t ip, const std::uint64_t nowUs) noexcept
  {
    // Salted, so a flood can't pick addresses that share a player's bucket.
    const std::uint64_t mixed = (static_cast<std::uint64_t>(ip) ^ mAddressSalt) * 0x9E3779B97F4A7C15ull;
    SAddressBucket& bucket = mAddressBuckets[static_cast<std::size_t>(mixed >> 52) % kAddressBuckets];
    if (nowUs > bucket.lastUs) {
      bucket.tokens = std::min(kHandshakeBurstPerAddress, bucket.tokens + static_cast<double>(nowUs - bucket.lastUs) * 1e-6 * kHandshakesPerAddressPerSecond);
      bucket.lastUs = nowUs;
    }
    if (bucket.tokens < 1.0) {
      ++mStats.addressLimited;
      return false;
    }
    bucket.tokens -= 1.0;
    return true;
  }

  bool CServerLinks::TakeUnlistedBudget(const std::uint64_t nowUs) noexcept
  {
    if (nowUs > mUnlistedBudgetUs) {
      mUnlistedBudget = std::min(kUnlistedHandshakesPerSecond, mUnlistedBudget + static_cast<double>(nowUs - mUnlistedBudgetUs) * 1e-6 * kUnlistedHandshakesPerSecond);
      mUnlistedBudgetUs = nowUs;
    }
    if (mUnlistedBudget < 1.0) {
      ++mStats.unlistedDropped;
      return false;
    }
    mUnlistedBudget -= 1.0;
    return true;
  }

  void CServerLinks::AddPlayer(const std::int32_t uid, const Token& token)
  {
    mPlayers[uid].token = token;
  }

  void CServerLinks::RemovePlayer(const std::int32_t uid)
  {
    const auto found = mPlayers.find(uid);
    if (found == mPlayers.end()) {
      return;
    }
    if (found->second.channel) {
      mByAddress.erase(found->second.from.Key());
    }
    mPlayers.erase(found);
  }

  bool CServerLinks::TakeHandshakeBudget(const std::uint64_t nowUs) noexcept
  {
    if (nowUs > mHandshakeBudgetUs) {
      mHandshakeBudget = std::min(kHandshakesPerSecond, mHandshakeBudget + static_cast<double>(nowUs - mHandshakeBudgetUs) * 1e-6 * kHandshakesPerSecond);
      mHandshakeBudgetUs = nowUs;
    }
    if (mHandshakeBudget < 1.0) {
      ++mStats.handshakesLimited;
      return false;
    }
    mHandshakeBudget -= 1.0;
    return true;
  }

  void CServerLinks::HandleConnect(const std::uint8_t* const data, const std::size_t size, const SEndpoint& from, const std::uint64_t nowUs, IEvents& events)
  {
    SConnectRequest request;
    if (!ReadConnect(data, size, request)) {
      ++mStats.strangersDropped;
      return;
    }
    if (!mCookies.Check(request.cookie, from.Key(), nowUs)) {
      ++mStats.badCookies;
      return;
    }

    const auto found = mPlayers.find(request.uid);
    if (found == mPlayers.end()) {
      ++mStats.refused;
      const auto reject = WriteReject(EHandshakeRefusal::NotAdmitted);
      (void)mSocket.SendTo(reject.data(), reject.size(), from);
      return;
    }
    SPlayer& player = found->second;

    // The Accept was lost: the same one again, as the keys behind it are already in use.
    if (player.channel && player.clientPublic == request.clientPublic && player.from == from) {
      (void)mSocket.SendTo(player.accept.data(), player.accept.size(), from);
      return;
    }
    // An old Connect sent again by someone else must not knock out the live channel.
    if (std::find(player.usedPublics.begin(), player.usedPublics.end(), request.clientPublic) != player.usedPublics.end()) {
      ++mStats.refused;
      return;
    }

    std::optional<SServerSession> session = AnswerConnect(request, player.token);
    if (!session) {
      ++mStats.refused;
      const auto reject = WriteReject(EHandshakeRefusal::NotAdmitted);
      (void)mSocket.SendTo(reject.data(), reject.size(), from);
      return;
    }

    const bool returning = player.channel != nullptr;
    if (returning) {
      mByAddress.erase(player.from.Key());
    }
    player.channel = std::make_unique<NetChannel>(mChannelConfig);
    (void)player.channel->SetKeys(session->keys);
    WipeKey(session->keys.send);
    WipeKey(session->keys.receive);
    player.from = from;
    player.clientPublic = request.clientPublic;
    player.usedPublics.push_back(request.clientPublic);
    player.accept = std::move(session->accept);
    player.lost = false;
    // A valid token lists its address (plan WPR.48): a player behind a VPN comes in once and then as any other.
    if (mAllowlistOn) {
      mAllowed.insert(from.ip);
    }

    // Someone else's channel at this address, as when one machine restarts a game on the port another left.
    if (const auto other = mByAddress.find(from.Key()); other != mByAddress.end() && other->second != request.uid) {
      if (const auto otherPlayer = mPlayers.find(other->second); otherPlayer != mPlayers.end()) {
        otherPlayer->second.channel.reset();
      }
    }
    mByAddress[from.Key()] = request.uid;

    (void)mSocket.SendTo(player.accept.data(), player.accept.size(), from);
    events.OnJoined(request.uid, from, returning);
  }

  void CServerLinks::HandleDatagram(const std::uint8_t* const data, const std::size_t size, const SEndpoint& from, const std::uint64_t nowUs, IEvents& events)
  {
    if (size == 0u) {
      ++mStats.strangersDropped;
      return;
    }
    if (data[0] == kDatagramTag) {
      const auto address = mByAddress.find(from.Key());
      if (address == mByAddress.end()) {
        ++mStats.strangersDropped;
        return;
      }
      const auto player = mPlayers.find(address->second);
      if (player == mPlayers.end() || !player->second.channel) {
        ++mStats.strangersDropped;
        return;
      }
      (void)player->second.channel->Receive(data, size, nowUs);
      return;
    }

    const std::optional<EHandshakeType> type = HandshakeTypeOf(data, size);
    if (type != EHandshakeType::Hello && type != EHandshakeType::Connect) {
      ++mStats.strangersDropped;
      return;
    }
    // An address off the allowlist shares one small budget, then its own; a listed one has its own. The global
    // budget last, so what one address sends can't spend it.
    const bool listed = !mAllowlistOn || mAllowed.contains(from.ip);
    if ((!listed && !TakeUnlistedBudget(nowUs)) || !TakeAddressBudget(from.ip, nowUs) || !TakeHandshakeBudget(nowUs)) {
      return;
    }
    if (type == EHandshakeType::Hello) {
      const auto answer = AnswerHello(data, size, mCookies, from.Key(), nowUs);
      if (!answer.empty()) {
        (void)mSocket.SendTo(answer.data(), answer.size(), from);
      }
    } else {
      HandleConnect(data, size, from, nowUs, events);
    }
  }

  void CServerLinks::Pump(const std::uint64_t nowUs, IEvents& events)
  {
    std::array<std::uint8_t, kReceiveBuffer> buffer{};
    SEndpoint from;
    for (int count = 0; count < kMaxDatagramsPerPump; ++count) {
      const int size = mSocket.ReceiveFrom(buffer.data(), buffer.size(), from);
      if (size < 0) {
        break;
      }
      ++mStats.datagramsIn;
      HandleDatagram(buffer.data(), static_cast<std::size_t>(size), from, nowUs, events);
    }

    for (auto& [uid, player] : mPlayers) {
      if (!player.channel) {
        continue;
      }
      while (player.channel && player.channel->TakeReliable(mMessage)) {
        events.OnMessage(uid, mMessage);
      }
      if (!player.channel) {
        continue;
      }
      mOut.clear();
      player.channel->Poll(nowUs, mOut);
      for (const std::vector<std::uint8_t>& datagram : mOut) {
        (void)mSocket.SendTo(datagram.data(), datagram.size(), player.from);
      }
      const ChannelState state = player.channel->State();
      if (!player.lost && (state == ChannelState::TimedOut || state == ChannelState::Failed)) {
        player.lost = true;
        events.OnLost(uid);
      }
    }
  }

  bool CServerLinks::SendReliable(const std::int32_t uid, const void* const data, const std::size_t size)
  {
    const auto found = mPlayers.find(uid);
    return found != mPlayers.end() && found->second.channel && found->second.channel->SendReliable(data, size);
  }

  void CServerLinks::SendUnreliableToAll(const void* const data, const std::size_t size)
  {
    for (auto& [uid, player] : mPlayers) {
      if (player.channel && !player.lost) {
        (void)player.channel->SendUnreliable(data, size);
      }
    }
  }

  const ChannelStats* CServerLinks::StatsOf(const std::int32_t uid) const
  {
    const auto found = mPlayers.find(uid);
    return found != mPlayers.end() && found->second.channel ? &found->second.channel->Stats() : nullptr;
  }

  std::uint64_t CServerLinks::ReliableUnacked(const std::int32_t uid) const
  {
    const auto found = mPlayers.find(uid);
    return found != mPlayers.end() && found->second.channel ? found->second.channel->ReliableUnacked() : 0u;
  }

  CClientLink::CClientLink(const std::int32_t uid, const Token& token, const SEndpoint& server, const ChannelConfig& channel)
    : mUid(uid)
    , mToken(token)
    , mServer(server)
    , mChannelConfig(channel)
    , mHandshake(std::make_unique<CClientHandshake>(uid, token))
  {}

  bool CClientLink::Open(std::string& error)
  {
    return mSocket.Open(SEndpoint{}, error);
  }

  void CClientLink::Reconnect()
  {
    mHandshake = std::make_unique<CClientHandshake>(mUid, mToken);
    mChannel.reset();
    mConnect.clear();
    mState = EState::Connecting;
    mRefusal.reset();
    mNextSendUs = 0;
  }

  void CClientLink::Pump(const std::uint64_t nowUs)
  {
    std::array<std::uint8_t, kReceiveBuffer> buffer{};
    SEndpoint from;
    for (int count = 0; count < kMaxDatagramsPerPump; ++count) {
      const int received = mSocket.ReceiveFrom(buffer.data(), buffer.size(), from);
      if (received < 0) {
        break;
      }
      const auto size = static_cast<std::size_t>(received);
      if (!(from == mServer) || size == 0u) {
        continue;
      }
      if (buffer[0] == kDatagramTag) {
        if (mChannel) {
          (void)mChannel->Receive(buffer.data(), size, nowUs);
        }
        continue;
      }
      if (mState != EState::Connecting) {
        continue;
      }
      const std::optional<EHandshakeType> type = HandshakeTypeOf(buffer.data(), size);
      if (type == EHandshakeType::Challenge) {
        std::vector<std::uint8_t> connect = mHandshake->OnChallenge(buffer.data(), size);
        if (!connect.empty()) {
          mConnect = std::move(connect);
          (void)mSocket.SendTo(mConnect.data(), mConnect.size(), mServer);
          mNextSendUs = nowUs + kRetryUs;
        }
      } else if (type == EHandshakeType::Accept) {
        std::optional<ChannelKeys> keys = mHandshake->OnAccept(buffer.data(), size);
        if (keys) {
          mChannel = std::make_unique<NetChannel>(mChannelConfig);
          (void)mChannel->SetKeys(*keys);
          WipeKey(keys->send);
          WipeKey(keys->receive);
          mState = EState::Connected;
        }
      } else if (type == EHandshakeType::Reject && size == kRejectSize) {
        mRefusal = static_cast<EHandshakeRefusal>(buffer[2]);
        mState = EState::Refused;
      }
    }

    if (mState == EState::Connecting && nowUs >= mNextSendUs) {
      const std::vector<std::uint8_t> hello = WriteHello();
      // A cookie goes stale, so it's asked for again until an Accept comes.
      if (mConnect.empty()) {
        (void)mSocket.SendTo(hello.data(), hello.size(), mServer);
      } else {
        (void)mSocket.SendTo(mConnect.data(), mConnect.size(), mServer);
        (void)mSocket.SendTo(hello.data(), hello.size(), mServer);
      }
      mNextSendUs = nowUs + kRetryUs;
    }

    if (mChannel) {
      mOut.clear();
      mChannel->Poll(nowUs, mOut);
      for (const std::vector<std::uint8_t>& datagram : mOut) {
        (void)mSocket.SendTo(datagram.data(), datagram.size(), mServer);
      }
      if (mState == EState::Connected && (mChannel->State() == ChannelState::TimedOut || mChannel->State() == ChannelState::Failed)) {
        mState = EState::Lost;
      }
    }
  }

  bool CClientLink::SendReliable(const void* const data, const std::size_t size)
  {
    return mChannel && mChannel->SendReliable(data, size);
  }

  bool CClientLink::TakeUnreliable(std::vector<std::uint8_t>& out)
  {
    return mChannel && mChannel->TakeUnreliable(out);
  }

  bool CClientLink::TakeReliable(std::vector<std::uint8_t>& out)
  {
    return mChannel && mChannel->TakeReliable(out);
  }
} // namespace faf::remote::net
