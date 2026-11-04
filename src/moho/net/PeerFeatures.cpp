#include "PeerFeatures.h"

#include <cstring>

#include "CClientManagerImpl.h"
#include "CMessage.h"
#include "CMessageStream.h"
#include "CNetClient.h"
#include "EClientMsg.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "NetConVars.h"

using namespace moho;

namespace
{
  // The first payload byte of `CLIMSG_PeerFeatures`. Other values are feature
  // traffic; a client that does not know one ignores it.
  constexpr std::uint8_t kKindAnnounce = 0;

  // kind, format, mask. A build name follows; a later format adds fields after it.
  constexpr std::uint8_t kAnnounceFormat = 1;
  constexpr std::size_t kAnnounceFixedBytes = 2u + sizeof(std::uint64_t);

  [[nodiscard]] constexpr std::uint64_t Bit(const EPeerFeature feature) noexcept
  {
    return std::uint64_t{1} << static_cast<std::uint8_t>(feature);
  }
} // namespace

CPeerFeatures::CPeerFeatures(const std::size_t clientCount)
  : mPeers(clientCount)
{}

std::uint64_t CPeerFeatures::LocalMask(const CClientManagerImpl& manager)
{
  std::uint64_t mask = 0;
  if (manager.mStreamCheck != nullptr) {
    mask |= Bit(EPeerFeature::OrderStreamCheck);
  }
  return mask;
}

void CPeerFeatures::Announce(CClientManagerImpl& manager) const
{
  if (net_PeerFeatures == 0) {
    return;
  }

  const std::uint64_t mask = LocalMask(manager);
  const char* const build = gpg::diag::BuildCommitShort();

  CMessage message(EClientMsg::CLIMSG_PeerFeatures);
  CMessageStream stream(message);
  stream.Write(kKindAnnounce);
  stream.Write(kAnnounceFormat);
  stream.Write(mask);
  stream.Write(build, std::strlen(build) + 1u);

  for (CClientBase* const client : manager.mClients) {
    if (auto* const peer = dynamic_cast<CNetClient*>(client)) {
      peer->Process(message);
    }
  }
  gpg::Logf("PEERS: announced features %016llx, build %s", static_cast<unsigned long long>(mask), build);
}

void CPeerFeatures::Receive(CClientManagerImpl& manager, const CNetClient& client, CMessage& message)
{
  const auto index = static_cast<std::size_t>(client.GetIndex());
  const auto size = static_cast<std::size_t>(message.GetMessageSize());
  const char* const payload = message.mBuff.start_ + 3;
  if (index >= mPeers.size() || size < kAnnounceFixedBytes || static_cast<std::uint8_t>(payload[0]) != kKindAnnounce) {
    return;
  }

  SPeer& peer = mPeers[index];
  peer.announced = true;
  std::memcpy(&peer.mask, payload + 2, sizeof(peer.mask));
  const char* const build = payload + kAnnounceFixedBytes;
  const std::size_t buildBytes = size - kAnnounceFixedBytes;
  peer.build.assign(build, strnlen(build, buildBytes));

  gpg::Logf(
    "PEERS: client %d:%s announced features %016llx, build %s", client.GetIndex(), client.GetNickname().c_str(),
    static_cast<unsigned long long>(peer.mask), peer.build.c_str()
  );
  gpg::Logf(
    "PEERS: everyone supports OrderStreamCheck: %s", EveryoneSupports(manager, EPeerFeature::OrderStreamCheck) ? "yes" : "no"
  );
}

bool CPeerFeatures::PeerSupports(const int clientIndex, const EPeerFeature feature) const
{
  if (clientIndex < 0 || static_cast<std::size_t>(clientIndex) >= mPeers.size()) {
    return false;
  }
  const SPeer& peer = mPeers[static_cast<std::size_t>(clientIndex)];
  return peer.announced && (peer.mask & Bit(feature)) != 0;
}

bool CPeerFeatures::EveryoneSupports(CClientManagerImpl& manager, const EPeerFeature feature) const
{
  if ((LocalMask(manager) & Bit(feature)) == 0) {
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
