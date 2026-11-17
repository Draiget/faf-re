#pragma once
// Engine addition, game channel (net_GameChannel), not in the binary.
//
// Between two players whose links both offer it (the "s+" mark in the ICE ufrag, NetPeerTransport.h), a connection's
// stream travels on a net channel (src/remote/net, docs/NET_CHANNEL.md) once the shipped handshake is done, in place of
// the shipped DATA packets: one layer of acks with RTT-based loss detection, each new range repeated in the next two
// datagrams until acked so a lost datagram rarely costs a resend wait, no 32-packet window and no 2 KB/s rate cap. The
// bytes are the same stream, deflated as before, so what arrives, and in which order, does not change. The connection
// keeps the binary's layout; its channel lives in a table here.

namespace moho
{
  class CNetUDPConnection;

  /// Drops a connection's game channel (its destructor).
  void NET_ForgetGameChannel(const CNetUDPConnection* connection);
} // namespace moho
