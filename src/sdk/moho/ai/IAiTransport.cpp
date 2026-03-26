#include "moho/ai/IAiTransport.h"

using namespace moho;

gpg::RType* IAiTransport::sType = nullptr;

IAiTransportEventListener* IAiTransportEventListener::FromListenerLink(Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<IAiTransportEventListener, Broadcaster, &IAiTransportEventListener::mListenerLink>(
    link
  );
}

const IAiTransportEventListener* IAiTransportEventListener::FromListenerLink(const Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<IAiTransportEventListener, Broadcaster, &IAiTransportEventListener::mListenerLink>(
    link
  );
}

/**
 * Address: 0x005E3C70 (FUN_005E3C70, scalar deleting thunk target)
 *
 * What it does:
 * Unlinks IAiTransport from broadcaster chain and restores self-linked node.
 */
IAiTransport::~IAiTransport()
{
  ListUnlink();
}

/**
 * What it does:
 * Sync-facing alias for teleport-beacon lookup.
 */
Unit* IAiTransport::TransportGetTeleportBeaconForSync() const
{
  return TransportGetTeleportBeacon();
}
