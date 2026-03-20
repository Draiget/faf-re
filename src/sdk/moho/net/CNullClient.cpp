#include "CNullClient.h"

#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: <synthetic host-build wrapper>
 *
 * Binary evidence:
 * - 0x0053E330 (FUN_0053E330, CClientManagerImpl::CreateCNullClient)
 *
 * What it does:
 * Wraps `CClientBase` construction for null-client objects; in FA the
 * derived constructor sequence is inlined in manager creation.
 */
CNullClient::CNullClient(
  const int32_t index,
  CClientManagerImpl* manager,
  const char* name,
  LaunchInfoBase* launchInfo,
  BVIntSet& commandSources,
  const uint32_t sourceId
)
  : CClientBase(index, manager, name, launchInfo, commandSources, sourceId)
{}

/**
 * Address: 0x0053B9A0 (FUN_0053B9A0)
 */
CNullClient::~CNullClient() = default;

/**
 * Address: 0x0053B970 (FUN_0053B970)
 */
float CNullClient::GetStatusMetricA()
{
  return 0.0f;
}

/**
 * Address: 0x0053B980 (FUN_0053B980)
 */
float CNullClient::GetStatusMetricB()
{
  return 0.0f;
}

/**
 * Address: 0x0053B990 (FUN_0053B990)
 */
void CNullClient::Process(CMessage& msg)
{
  (void)msg;
}

/**
 * Address: 0x0053D170 (FUN_0053D170)
 */
void CNullClient::Debug()
{
  gpg::Logf("    CNullClient 0x%08x:", this);
  CClientBase::Debug();
}
