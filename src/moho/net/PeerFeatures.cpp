#include "PeerFeatures.h"

#include <algorithm>
#include <cstring>

#include "CClientManagerImpl.h"
#include "CMessage.h"
#include "CMessageStream.h"
#include "CNetClient.h"
#include "CRejoinFeed.h"
#include "EClientMsg.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/SimDriver.h"
#include "NetConVars.h"

using namespace moho;

namespace
{
  // kind, format, mask. A build name follows; a later format adds fields after it.
  constexpr std::uint8_t kAnnounceFormat = 1;
  constexpr std::size_t kAnnounceFixedBytes = 2u + sizeof(std::uint64_t);

  // Loading a large map shows no progress for a while, so this is generous.
  constexpr std::chrono::seconds kRejoinSilenceSeconds{60};
  // The other stages report every second.
  constexpr std::chrono::seconds kRejoinReportingSilenceSeconds{20};
} // namespace

void moho::WritePeerAnnouncement(CMessageStream& stream, const std::uint64_t mask)
{
  const char* const build = gpg::diag::BuildCommitShort();
  stream.Write(kPeerKindAnnounce);
  stream.Write(kAnnounceFormat);
  stream.Write(mask);
  stream.Write(build, std::strlen(build) + 1u);
}

bool moho::ReadPeerAnnouncement(const char* const payload, const std::size_t size, SPeerAnnouncement& out)
{
  if (size < kAnnounceFixedBytes || static_cast<std::uint8_t>(payload[0]) != kPeerKindAnnounce) {
    return false;
  }
  std::memcpy(&out.mask, payload + 2, sizeof(out.mask));
  const char* const build = payload + kAnnounceFixedBytes;
  const std::size_t buildBytes = size - kAnnounceFixedBytes;
  out.build.assign(build, strnlen(build, buildBytes));
  return true;
}

CPeerFeatures::CPeerFeatures(const std::size_t clientCount)
  : mPeers(clientCount)
{}

std::uint64_t CPeerFeatures::LocalMask(const CClientManagerImpl& manager)
{
  std::uint64_t mask = 0;
  if (manager.mStreamCheck != nullptr) {
    mask |= PeerFeatureBit(EPeerFeature::OrderStreamCheck);
  }
  if (wld_SkewCorrection != 0) {
    mask |= PeerFeatureBit(EPeerFeature::SkewCorrection);
  }
  if (NET_FastRetransmitEnabled()) {
    mask |= PeerFeatureBit(EPeerFeature::FastAck);
  }
  if (net_RejoinAccept != 0) {
    mask |= PeerFeatureBit(EPeerFeature::Rejoin);
  }
  return mask;
}

void CPeerFeatures::SendKeyTo(CClientManagerImpl& manager, CNetClient& peer)
{
  const auto index = static_cast<std::size_t>(peer.GetIndex());
  if (index >= mPeers.size() || mPeers[index].keySent || !REJOIN_HasKey() ||
      (LocalMask(manager) & PeerFeatureBit(EPeerFeature::Rejoin)) == 0u) {
    return;
  }
  mPeers[index].keySent = true;
  CMessage message(EClientMsg::CLIMSG_PeerFeatures);
  CMessageStream stream(message);
  stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinKey));
  const SRejoinPublicKey& key = REJOIN_PublicKey();
  stream.Write(reinterpret_cast<const char*>(key.data()), key.size());
  peer.Process(message);
}

void CPeerFeatures::Announce(CClientManagerImpl& manager)
{
  if (net_PeerFeatures == 0) {
    return;
  }
  // Saved before a peer can hear of it. A client restarted with /rejoin already holds its key.
  if ((LocalMask(manager) & PeerFeatureBit(EPeerFeature::Rejoin)) != 0u && manager.mRejoinFeed == nullptr) {
    (void)REJOIN_CreateKey();
  }
  for (CClientBase* const client : manager.mClients) {
    if (auto* const peer = dynamic_cast<CNetClient*>(client)) {
      AnnounceTo(manager, *peer);
      const auto index = static_cast<std::size_t>(peer->GetIndex());
      if (index < mPeers.size() && (mPeers[index].announcement.mask & PeerFeatureBit(EPeerFeature::Rejoin)) != 0u) {
        SendKeyTo(manager, *peer);
      }
    }
  }
  gpg::Logf("PEERS: announced features %016llx, build %s", static_cast<unsigned long long>(LocalMask(manager)), gpg::diag::BuildCommitShort());
}

void CPeerFeatures::AnnounceTo(CClientManagerImpl& manager, CNetClient& peer) const
{
  if (net_PeerFeatures == 0) {
    return;
  }
  const std::uint64_t mask = LocalMask(manager);

  CMessage message(EClientMsg::CLIMSG_PeerFeatures);
  CMessageStream stream(message);
  WritePeerAnnouncement(stream, mask);
  peer.Process(message);
}

void CPeerFeatures::Receive(CClientManagerImpl& manager, CNetClient& client, CMessage& message)
{
  const auto index = static_cast<std::size_t>(client.GetIndex());
  const auto size = static_cast<std::size_t>(message.GetMessageSize());
  const char* const payload = message.mBuff.start_ + 3;
  if (size < 1u) {
    return;
  }

  const auto kind = static_cast<EPeerMessageKind>(payload[0]);
  if (kind == EPeerMessageKind::RejoinInfo && (LocalMask(manager) & PeerFeatureBit(EPeerFeature::Rejoin)) != 0) {
    REJOIN_HandlePeerMessage(manager, client, message);
    return;
  }
  if (kind == EPeerMessageKind::RejoinKey && index < mPeers.size() && size >= 1u + sizeof(SRejoinPublicKey)) {
    // The first one stays: a key is a seat's, and nothing may replace it later.
    SPeer& keyed = mPeers[index];
    if (!keyed.keyKnown) {
      std::memcpy(keyed.key.data(), payload + 1, keyed.key.size());
      keyed.keyKnown = true;
      gpg::Logf("REJOIN: client %d:%s gave its seat's key", client.GetIndex(), client.GetNickname().c_str());
    }
    return;
  }
  if (kind == EPeerMessageKind::RejoinProgress && index < mPeers.size() && size >= 2u + sizeof(float)) {
    const auto stage = static_cast<ERejoinStage>(payload[1]);
    if (stage >= ERejoinStage::Transfer && stage <= ERejoinStage::Back) {
      SPeer& rejoining = mPeers[index];
      rejoining.rejoin.stage = stage;
      std::memcpy(&rejoining.rejoin.progress, payload + 2, sizeof(float));
      rejoining.rejoinNoted = std::chrono::steady_clock::now();
    }
    return;
  }
  if (kind != EPeerMessageKind::Announce || index >= mPeers.size()) {
    return;
  }

  SPeer& peer = mPeers[index];
  if (!ReadPeerAnnouncement(payload, size, peer.announcement)) {
    return;
  }
  peer.announced = true;

  if ((peer.announcement.mask & PeerFeatureBit(EPeerFeature::Rejoin)) != 0u) {
    SendKeyTo(manager, client);
  }

  gpg::Logf(
    "PEERS: client %d:%s announced features %016llx, build %s", client.GetIndex(), client.GetNickname().c_str(),
    static_cast<unsigned long long>(peer.announcement.mask), peer.announcement.build.c_str()
  );
  gpg::Logf(
    "PEERS: everyone supports OrderStreamCheck: %s", EveryoneSupports(manager, EPeerFeature::OrderStreamCheck) ? "yes" : "no"
  );
  if ((peer.announcement.mask & PeerFeatureBit(EPeerFeature::OrderStreamCheck)) != 0u) {
    // CClientBase compares this client's order stream reports from now on.
    gpg::Logf("PEERS: client %d:%s's order stream reports are compared", client.GetIndex(), client.GetNickname().c_str());
  }
  OfferRejoinToLauncher(manager);
}

void CPeerFeatures::OfferRejoinToLauncher(CClientManagerImpl& manager)
{
  // A game coming back makes none: its launcher has one from the first start.
  if (mRejoinOffered || !EveryoneSupports(manager, EPeerFeature::Rejoin) || !CFG_GetArgOption(gpg::StrArg{"/rejoinoffer"}, 0u, nullptr) ||
      CFG_GetArgOption(gpg::StrArg{"/rejoin"}, 0u, nullptr)) {
    return;
  }
  mRejoinOffered = true;

  fa::string seats;
  for (const CClientBase* const client : manager.mClients) {
    if (client != nullptr) {
      if (!seats.empty()) {
        seats = seats + ",";
      }
      seats += gpg::STR_Printf("%d=%d", client->GetOwnerId(), client->GetIndex());
    }
  }
  manager.mInterface->NoteRejoinOffer(gpg::STR_Printf("%d", manager.mLocalClient->GetIndex()), seats);
  gpg::Logf("REJOIN: told the launcher this client could come back: source %d, %s", manager.mLocalClient->GetIndex(), seats.c_str());
}

void CPeerFeatures::NoteRejoinEjected(const int clientIndex, const std::uint32_t address, const std::uint16_t port)
{
  SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
  peer.ejected = true;
  peer.ejectedAddress = address;
  peer.ejectedPort = port;
}

int CPeerFeatures::FindEjectedSeat(const std::uint32_t address, const std::uint16_t port) const
{
  for (std::size_t index = 0; index < mPeers.size(); ++index) {
    const SPeer& peer = mPeers[index];
    if (peer.ejected && peer.ejectedAddress == address && peer.ejectedPort == port) {
      return static_cast<int>(index);
    }
  }
  return -1;
}

bool CPeerFeatures::HasRejoinKey(const int clientIndex) const
{
  return clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size() &&
    mPeers[static_cast<std::size_t>(clientIndex)].keyKnown;
}

SRejoinNonce CPeerFeatures::StartRejoinChallenge(const int clientIndex)
{
  SRejoinNonce nonce = REJOIN_MakeNonce();
  if (clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size()) {
    SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
    peer.nonce = nonce;
    peer.challenged = true;
  }
  return nonce;
}

bool CPeerFeatures::CheckRejoinProof(const int clientIndex, const int localIndex, const SRejoinSignature& signature)
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return false;
  }
  SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
  if (!peer.keyKnown || !peer.challenged) {
    return false;
  }
  peer.challenged = false;
  const bool good = REJOIN_CheckProof(peer.key, peer.nonce, clientIndex, localIndex, signature);
  peer.proven = peer.proven || good;
  return good;
}

bool CPeerFeatures::RejoinProven(const int clientIndex) const
{
  return clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size() &&
    mPeers[static_cast<std::size_t>(clientIndex)].proven;
}

void CPeerFeatures::NoteRejoinLost(const int clientIndex)
{
  if (clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size()) {
    mPeers[static_cast<std::size_t>(clientIndex)].rejoin = SRejoinStatus{ERejoinStage::Lost, -1.0f};
  }
}

void CPeerFeatures::NoteRejoinStarted(const int clientIndex)
{
  if (clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size()) {
    SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
    peer.rejoin = SRejoinStatus{ERejoinStage::Transfer, -1.0f};
    peer.rejoinNoted = std::chrono::steady_clock::now();
    // The process behind this link holds none of this client's key.
    peer.keySent = false;
  }
}

SRejoinStatus CPeerFeatures::RejoinStatus(const int clientIndex) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return {};
  }
  const SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
  const auto silence = std::chrono::steady_clock::now() - peer.rejoinNoted;
  switch (peer.rejoin.stage) {
    case ERejoinStage::None:
    case ERejoinStage::Lost:
      return peer.rejoin;
    case ERejoinStage::Back:
      return silence > kRejoinBackSeconds ? SRejoinStatus{} : peer.rejoin;
    case ERejoinStage::Loading:
      return silence > kRejoinSilenceSeconds ? SRejoinStatus{ERejoinStage::Lost, -1.0f} : peer.rejoin;
    default:
      return silence > kRejoinReportingSilenceSeconds ? SRejoinStatus{ERejoinStage::Lost, -1.0f} : peer.rejoin;
  }
}

float CPeerFeatures::RejoinSilenceSeconds(const int clientIndex) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return 0.0f;
  }
  const auto silence = std::chrono::steady_clock::now() - mPeers[static_cast<std::size_t>(clientIndex)].rejoinNoted;
  return std::chrono::duration<float>(silence).count();
}

const char* moho::RejoinStageName(const ERejoinStage stage)
{
  switch (stage) {
    case ERejoinStage::Lost:
      return "lost";
    case ERejoinStage::Transfer:
      return "transfer";
    case ERejoinStage::Loading:
      return "loading";
    case ERejoinStage::CatchingUp:
      return "catchingUp";
    case ERejoinStage::Back:
      return "back";
    default:
      return "";
  }
}

bool CPeerFeatures::PeerSupports(const int clientIndex, const EPeerFeature feature) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return false;
  }
  const SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
  return peer.announced && (peer.announcement.mask & PeerFeatureBit(feature)) != 0;
}

std::int32_t CPeerFeatures::PeerAckDelayMs(const int clientIndex) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size() ||
      !mPeers[static_cast<std::size_t>(clientIndex)].announced) {
    return NET_AckDelayMs();
  }
  return PeerSupports(clientIndex, EPeerFeature::FastAck) ? std::min(net_AckDelay, net_FastAckDelay) : net_AckDelay;
}

void CPeerFeatures::NoteReady(const int clientIndex, const std::int64_t handledUs)
{
  if (clientIndex >= 0 && static_cast<std::size_t>(clientIndex) < mPeers.size() &&
      mPeers[static_cast<std::size_t>(clientIndex)].readyUs == 0) {
    mPeers[static_cast<std::size_t>(clientIndex)].readyUs = handledUs;
  }
}

std::int64_t CPeerFeatures::ReadyUs(const int clientIndex) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return 0;
  }
  return mPeers[static_cast<std::size_t>(clientIndex)].readyUs;
}

bool CPeerFeatures::EveryoneSupports(CClientManagerImpl& manager, const EPeerFeature feature) const
{
  if ((LocalMask(manager) & PeerFeatureBit(feature)) == 0) {
    return false;
  }
  for (const CClientBase* const client : manager.mClients) {
    if (client == nullptr || client == manager.mLocalClient || client->mEjected || client->mEjectPending) {
      continue;
    }
    if (!PeerSupports(client->GetIndex(), feature)) {
      return false;
    }
  }
  return true;
}
