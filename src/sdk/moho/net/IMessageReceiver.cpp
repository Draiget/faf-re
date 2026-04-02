#include "IMessageReceiver.h"

#include <algorithm>
#include <cstddef>
#include <new>

#include "gpg/core/utils/Global.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x0047C320 (FUN_0047C320)
   *
   * What it does:
   * Unlinks one `SMsgReceiverLinkage` from both intrusive list lanes
   * (dispatcher lane and receiver lane) without deleting storage.
   */
  TDatListItem<SMsgReceiverLinkage, void>* UnlinkReceiverLinkageNodes(SMsgReceiverLinkage* const linkage)
  {
    auto* const receiverNode =
      static_cast<TDatListItem<IMessageReceiver, void>*>(static_cast<IMessageReceiver*>(linkage));
    receiverNode->ListUnlink();

    auto* const dispatcherNode = static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(linkage);
    return dispatcherNode->ListUnlink();
  }

  /**
   * Address: 0x0047C2E0 (FUN_0047C2E0)
   *
   * What it does:
   * Unlinks one `SMsgReceiverLinkage` from both intrusive list lanes and
   * then releases the allocation with scalar `operator delete`.
   */
  SMsgReceiverLinkage* DestroyReceiverLinkageNodes(SMsgReceiverLinkage* const linkage)
  {
    UnlinkReceiverLinkageNodes(linkage);
    ::operator delete(linkage);
    return linkage;
  }
} // namespace

/**
 * Address: 0x0047C240 (FUN_0047C240, Moho::CMessageDispatcher::CMessageDispatcher)
 *
 * What it does:
 * Initializes receiver-linkage sentinel and clears 256-byte receiver table.
 */
CMessageDispatcher::CMessageDispatcher()
{
  TDatListItem<SMsgReceiverLinkage, void>::ListResetLinks();
  std::fill_n(mReceivers, std::size(mReceivers), nullptr);
}

/**
 * Address: 0x0047C280 (FUN_0047C280, Moho::CMessageDispatcher::~CMessageDispatcher)
 *
 * What it does:
 * Unlinks and deletes all receiver linkages owned by this dispatcher.
 */
CMessageDispatcher::~CMessageDispatcher()
{
  auto* const head = static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(this);
  while (head->mNext != head) {
    auto* const linkage = static_cast<SMsgReceiverLinkage*>(head->mNext);
    DestroyReceiverLinkageNodes(linkage);
  }

  head->ListUnlink();
}

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
 * Address: 0x0047C400 (FUN_0047C400, Moho::CMessageDispatcher::RemoveReceiver)
 *
 * What it does:
 * Finds and removes one range receiver linkage matching `(lower, upper, rec)`.
 */
void CMessageDispatcher::RemoveReceiver(const unsigned int lower, const unsigned int upper, IMessageReceiver* rec)
{
  auto* const listEnd = static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(this);
  auto* linkage = static_cast<SMsgReceiverLinkage*>(listEnd->mNext);
  while (static_cast<TDatListItem<SMsgReceiverLinkage, void>*>(linkage) != listEnd) {
    if (linkage->mLower == lower && linkage->mUpper == upper && linkage->mReceiver == rec) {
      RemoveLinkage(linkage);
      return;
    }
    linkage = static_cast<SMsgReceiverLinkage*>(linkage->TDatListItem<SMsgReceiverLinkage, void>::mNext);
  }

  gpg::HandleAssertFailure("Reached the supposably unreachable.", 241, "c:\\work\\rts\\main\\code\\src\\core\\Message.cpp");
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

  UnlinkReceiverLinkageNodes(linkage);
  ::operator delete(linkage);
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
 * Address: 0x0047BC90 (FUN_0047BC90)
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

/**
 * Address: 0x0047C320 (FUN_0047C320, non-deleting destructor lane)
 * Address: 0x0047C2E0 (FUN_0047C2E0, deleting-destructor thunk)
 *
 * What it does:
 * Unlinks receiver-linkage node from receiver and dispatcher intrusive rings.
 */
SMsgReceiverLinkage::~SMsgReceiverLinkage()
{
  TDatListItem<IMessageReceiver, void>::ListUnlink();
  TDatListItem<SMsgReceiverLinkage, void>::ListUnlink();
}

void SMsgReceiverLinkage::ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher)
{
  (void)message;
  (void)dispatcher;
}
