#include "CLocalClient.h"

#include <mutex>

#include "CClientManagerImpl.h"
#include "CMessage.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

/**
 * Address: <synthetic host-build wrapper>
 *
 * Binary evidence:
 * - 0x0053E180 (FUN_0053E180, CClientManagerImpl::CreateLocalClient)
 * - 0x1012B540 (sub_1012B540, MohoEngine CreateLocalClient equivalent)
 *
 * What it does:
 * Wraps `CClientBase` construction for local client objects; in FA/Moho the
 * derived-constructor sequence is inlined inside `CreateLocalClient`.
 */
CLocalClient::CLocalClient(
  int32_t index,
  CClientManagerImpl* manager,
  const char* name,
  const int32_t ownerId,
  BVIntSet& commandSources,
  uint32_t sourceId
)
  : CClientBase(index, manager, name, ownerId, commandSources, sourceId)
{}

/**
 * Address: 0x0053BA00 (FUN_0053BA00)
 * Address: 0x10129280 (sub_10129280)
 *
 * float ()
 *
 * IDA signature (FA):
 * double sub_53BA00();
 *
 * IDA signature (MohoEngine):
 * double sub_10129280();
 *
 * What it does:
 * Returns constant `0.0f` for local clients.
 */
float CLocalClient::GetStatusMetricA()
{
  return 0.0f;
}

/**
 * Address: 0x0053BA10 (FUN_0053BA10)
 * Address: 0x10129290 (sub_10129290)
 *
 * float ()
 *
 * IDA signature (FA):
 * double Moho::CLocalClient::Func3();
 *
 * IDA signature (MohoEngine):
 * double sub_10129290();
 *
 * What it does:
 * Returns constant `0.0f` for local clients.
 */
float CLocalClient::GetStatusMetricB()
{
  return 0.0f;
}

/**
 * Address: 0x0053D190 (FUN_0053D190)
 * Address: 0x1012A920 (sub_1012A920)
 *
 * CMessage &
 *
 * IDA signature (FA):
 * void __thiscall Moho::CLocalClient::Process(Moho::CLocalClient *this, CMessage *msg);
 *
 * IDA signature (MohoEngine):
 * void __thiscall sub_1012A920(_DWORD *this, int a2);
 *
 * What it does:
 * Takes manager lock, runs shared base incoming-message processing, and
 * signals current manager event when marshaller has no bound manager.
 */
void CLocalClient::Process(CMessage& msg)
{
  std::scoped_lock lock(mManager->mLock);
  CClientBase::Process(msg);
  if (mManager->mCurrentEvent != nullptr && mManager->mMarshaller.mClientManager == nullptr) {
    SetEvent(mManager->mCurrentEvent);
  }
}

/**
 * Address: 0x0053D220 (FUN_0053D220)
 * Address: 0x1012A9B0 (sub_1012A9B0)
 *
 * void ()
 *
 * IDA signature (FA):
 * int __thiscall sub_53D220(void *this, int a2);
 *
 * IDA signature (MohoEngine):
 * int __thiscall sub_1012A9B0(const char *this, int a2);
 *
 * What it does:
 * Logs local client banner then forwards to `CClientBase::Debug()`.
 */
void CLocalClient::Debug()
{
  gpg::Logf("    CLocalClient 0x%08x:", this);
  CClientBase::Debug();
}
