#include "CNetNullConnector.h"

using namespace moho;

/**
 * Address: 0x0047EC40 (FUN_0047EC40)
 *
 * What it does:
 * Constructor lane that installs the CNetNullConnector vtable.
 */
CNetNullConnector::CNetNullConnector() = default;

/**
 * Address: 0x0047EC50 (FUN_0047EC50, ??1CNetNullConnector@Moho@@QAE@XZ)
 *
 * What it does:
 * Runs deleting-destructor behavior and restores base connector vtable.
 */
CNetNullConnector::~CNetNullConnector() = default;

/**
 * Address: 0x0047EB20 (FUN_0047EB20)
 *
 * What it does:
 * Deletes this connector instance.
 */
void CNetNullConnector::Destroy()
{
  delete this;
}

/**
 * Address: 0x0047EB30 (FUN_0047EB30)
 *
 * What it does:
 * Returns `ENetProtocolType::kNone`.
 */
ENetProtocolType CNetNullConnector::GetProtocol()
{
  return ENetProtocolType::kNone;
}

/**
 * Address: 0x0047EB40 (FUN_0047EB40)
 *
 * What it does:
 * Returns local port `0`.
 */
u_short CNetNullConnector::GetLocalPort()
{
  return 0;
}

/**
 * Address: 0x0047EB50 (FUN_0047EB50)
 *
 * What it does:
 * No-op connect path; always returns null.
 */
INetConnection* CNetNullConnector::Connect(const u_long address, const u_short port)
{
  (void)address;
  (void)port;
  return nullptr;
}

/**
 * Address: 0x0047EB60 (FUN_0047EB60, emit `Func2`)
 *
 * What it does:
 * Null connector has no pending peers; always returns false.
 */
bool CNetNullConnector::FindNextAddress(u_long& outAddress, u_short& outPort)
{
  (void)outAddress;
  (void)outPort;
  return false;
}

/**
 * Address: 0x0047EB70 (FUN_0047EB70)
 *
 * What it does:
 * No-op accept path; always returns null.
 */
INetConnection* CNetNullConnector::Accept(const u_long address, const u_short port)
{
  (void)address;
  (void)port;
  return nullptr;
}

/**
 * Address: 0x0047EB80 (FUN_0047EB80)
 *
 * What it does:
 * No-op reject path.
 */
void CNetNullConnector::Reject(const u_long address, const u_short port)
{
  (void)address;
  (void)port;
}

/**
 * Address: 0x0047EB90 (FUN_0047EB90)
 */
void CNetNullConnector::Pull() {}

/**
 * Address: 0x0047EBA0 (FUN_0047EBA0)
 */
void CNetNullConnector::Push() {}

/**
 * Address: 0x0047EBB0 (FUN_0047EBB0)
 */
void CNetNullConnector::SelectEvent(HANDLE ev)
{
  (void)ev;
}

/**
 * Address: 0x0047EBC0 (FUN_0047EBC0, emit `Func3`)
 *
 * What it does:
 * Returns an empty send-stamp snapshot (`items` empty, duration/end = 0).
 */
SSendStampView CNetNullConnector::SnapshotSendStamps(const int32_t since)
{
  (void)since;
  return {0u, 0u};
}
