#include "IClient.h"
using namespace moho;

IClient::IClient(const char* name, const int index, LaunchInfoBase* launchInfo) :
	mNickname(name),
	mIndex(index),
	mLaunchInfo(launchInfo)
{
}
