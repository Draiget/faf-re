#include "CClientManagerImpl.h"
using namespace moho;

CClientManagerImpl::~CClientManagerImpl() {
}

// 0x0053E180
IClient* CClientManagerImpl::CreateLocalClient(
	const char* name,
	const int32_t index,
	LaunchInfoBase* launchInfo,
	const uint32_t sourceId)
{
	BVIntSet commandSources{};
	commandSources.Add(sourceId);

	const auto client = new CLocalClient(index, this, name, launchInfo, commandSources, sourceId);
	mClients[index] = client;
	return client;
}

CLocalClient::CLocalClient(
	int32_t index, 
	CClientManagerImpl* manager, 
	const char* name,
	LaunchInfoBase* launchInfo, 
	BVIntSet& commandSources,
	uint32_t sourceId
) :
	CClientBase(index, manager, name, launchInfo, commandSources, sourceId)
{
}
