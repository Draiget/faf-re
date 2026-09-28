#include "IMessageReceiver.h"

#include <algorithm>
#include <cstddef>
#include <new>

#include "gpg/core/utils/Global.h"

using namespace moho;

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
 * Deletes all receiver linkages owned by this dispatcher. The trailing
 * unlink at 0x0047C2C9 is the `TDatListItem` base's destructor.
 */
CMessageDispatcher::~CMessageDispatcher()
{
  while (mNext != this) {
    delete static_cast<SMsgReceiverLinkage*>(mNext);
  }
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
 * `CLobby::LaunchGame` inlines it twice (0x007C4B36, 0x007C4B68); both copies
 * share this body's Message.cpp line-241 assert at 0x007C4E4D.
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
 * Address: 0x0053BC60 (FUN_0053BC60)
 */
IMessageReceiver::IMessageReceiver()
{
  TDatListItem<IMessageReceiver, void>::ListResetLinks();
}

/**
 * Address: 0x0047C4F0 (FUN_0047C4F0)
 */
IMessageReceiver::~IMessageReceiver()
{
  while (mNext != this) {
    auto* const linkage = static_cast<SMsgReceiverLinkage*>(static_cast<IMessageReceiver*>(mNext));
    linkage->mDispatcher->RemoveLinkage(linkage);
  }
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
 *
 * In the binary these two unlinks are the two `TDatListItem` destructors
 * alone (inlined at 0x0047C49A in `RemoveLinkage`), with no vptr store and no
 * ring walk, so the second base there is not `IMessageReceiver`. Here it is,
 * and `~IMessageReceiver` walks its ring and removes every linkage on it. The
 * body therefore has to unlink first, until that base is resolved.
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
