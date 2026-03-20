#include "IMessageReceiver.h"

#include <algorithm>
#include <cstddef>

using namespace moho;

/**
 * Address: 0x0047C360 (FUN_0047C360)
 */
void CMessageDispatcher::PushReceiver(const unsigned int lower, const unsigned int upper, IMessageReceiver* rec)
{
  auto* const linkage = new SMsgReceiverLinkage{lower, upper, rec, this};

  linkage->TDatListItem<SMsgReceiverLinkage, void>::ListLinkBefore(this);
  linkage->TDatListItem<IMessageReceiver, void>::ListLinkBefore(rec);

  if (lower < upper) {
    std::fill_n(&mReceivers[lower], upper - lower, rec);
  }
}

/**
 * Address: 0x0047C450 (FUN_0047C450)
 */
void CMessageDispatcher::RemoveLinkage(SMsgReceiverLinkage* linkage)
{
  auto* const listEnd = static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(this);
  auto* const nextLink = static_cast<SMsgReceiverLinkage*>(linkage->TDatListItem<SMsgReceiverLinkage, void>::mNext);

  for (unsigned val = linkage->mLower; val < linkage->mUpper; ++val) {
    auto& receiverSlot = mReceivers[val];
    if (receiverSlot != linkage->mReceiver) {
      continue;
    }

    receiverSlot = nullptr;
    for (auto* it = nextLink; static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(it) != listEnd;
         it = static_cast<SMsgReceiverLinkage*>(it->TDatListItem<SMsgReceiverLinkage, void>::mNext)) {
      if (it->mLower <= val && val < it->mUpper) {
        receiverSlot = it->mReceiver;
      }
    }
  }

  linkage->TDatListItem<IMessageReceiver, void>::ListUnlink();
  linkage->TDatListItem<SMsgReceiverLinkage, void>::ListUnlink();
  delete linkage;
}

/**
 * Address: 0x0047C4D0 (FUN_0047C4D0)
 */
bool CMessageDispatcher::Dispatch(CMessage* msg)
{
  const uint8_t idx = *msg->mBuff.start_;

  IMessageReceiver* rec = mReceivers[idx];
  if (!rec) {
    return false;
  }

  rec->ReceiveMessage(msg, this);
  return true;
}

/**
 * Address: 0x0047C4F0 (FUN_0047C4F0)
 */
IMessageReceiver::~IMessageReceiver()
{
  auto* const head = static_cast<TDatListItem<IMessageReceiver, void>*>(this);
  while (head->mNext != head) {
    auto* const nextNode = head->mNext;
    auto* const receiverBase = reinterpret_cast<IMessageReceiver*>(reinterpret_cast<std::byte*>(nextNode) - 0x4);
    auto* const linkage = static_cast<SMsgReceiverLinkage*>(receiverBase);
    linkage->mDispatcher->RemoveLinkage(linkage);
  }

  head->ListUnlink();
}

/**
 * Address: 0x0047C37A (inlined in FUN_0047C360)
 */
SMsgReceiverLinkage::SMsgReceiverLinkage(
  const unsigned int lower, const unsigned int upper, IMessageReceiver* rec, CMessageDispatcher* dispatcher
)
  : IMessageReceiver()
  , mLower(lower)
  , mUpper(upper)
  , mReceiver(rec)
  , mDispatcher(dispatcher)
{}

void SMsgReceiverLinkage::ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher)
{
  (void)message;
  (void)dispatcher;
}
