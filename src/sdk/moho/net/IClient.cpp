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

/**
 * Address: 0x0053B5C0 (FUN_0053B5C0)
 *
 * What it does:
 * Returns the client index lane stored in this record.
 */
int IClient::GetIndex() const
{
  return mIndex;
}

/**
 * Address: 0x0053B5D0 (FUN_0053B5D0)
 *
 * What it does:
 * Returns the owner-id lane stored in this record.
 */
int32_t IClient::GetOwnerId() const
{
  return mOwnerId;
}
