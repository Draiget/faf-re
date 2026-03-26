#include "IClient.h"
using namespace moho;

/**
 * Address: 0x0053B5E0 (FUN_0053B5E0)
 */
IClient::IClient(const char* name, const int index, const int32_t ownerId)
  : mNickname(name)
  , mIndex(index)
  , mOwnerId(ownerId)
{}
