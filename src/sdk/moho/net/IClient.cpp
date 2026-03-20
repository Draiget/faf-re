#include "IClient.h"
using namespace moho;

/**
 * Address: 0x0053B5E0 (FUN_0053B5E0)
 */
IClient::IClient(const char* name, const int index, LaunchInfoBase* launchInfo)
  : mNickname(name)
  , mIndex(index)
  , mLaunchInfo(launchInfo)
{}
