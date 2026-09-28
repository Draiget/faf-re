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
  std::fill_n(mReceivers, std::size(mReceivers), nullptr);
}

/**
 * Address: 0x0047C280 (FUN_0047C280, Moho::CMessageDispatcher::~CMessageDispatcher)
 *
 * What it does:
 * Deletes all receiver linkages owned by this dispatcher. The trailing
 * unlink at 0x0047C2C9 is `mLinkages`' destructor.
 */
CMessageDispatcher::~CMessageDispatcher()
{
  while (!mLinkages.empty()) {
    delete mLinkages.mNext->Get();
  }
}

/**
 * Address: 0x0047C360 (FUN_0047C360)
 */
void CMessageDispatcher::PushReceiver(const unsigned int lower, const unsigned int upper, IMessageReceiver* rec)
{
  auto* const linkage = new SMsgReceiverLinkage{lower, upper, rec, this};

  mLinkages.push_back(linkage);
  rec->mLinkages.push_back(linkage);

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
  for (SMsgReceiverLinkage* const linkage : mLinkages) {
    if (linkage->mLower == lower && linkage->mUpper == upper && linkage->mReceiver == rec) {
      RemoveLinkage(linkage);
      return;
    }
  }

  gpg::HandleAssertFailure("Reached the supposably unreachable.", 241, "c:\\work\\rts\\main\\code\\src\\core\\Message.cpp");
}

/**
 * Address: 0x0047C450 (FUN_0047C450)
 *
 * What it does:
 * Hands each message type this linkage answered to the newest linkage pushed
 * after it that also covers the type, or to nobody, then deletes it. The scan
 * starts at the linkage's own successor (0x0047C457), so older linkages never
 * win a slot back.
 */
void CMessageDispatcher::RemoveLinkage(SMsgReceiverLinkage* linkage)
{
  using LinkageList = decltype(mLinkages);
  const LinkageList::iterator later{static_cast<SMsgReceiverLinkage::DispatcherLink*>(linkage)->mNext, &mLinkages};

  for (unsigned val = linkage->mLower; val < linkage->mUpper; ++val) {
    auto& receiverSlot = mReceivers[val];
    if (receiverSlot != linkage->mReceiver) {
      continue;
    }

    receiverSlot = nullptr;
    for (auto it = later; it != mLinkages.end(); ++it) {
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
 *
 * What it does:
 * Installs the interface vtable; `mLinkages`' constructor self-links the ring.
 */
IMessageReceiver::IMessageReceiver() = default;

/**
 * Address: 0x0047C4F0 (FUN_0047C4F0)
 *
 * What it does:
 * Removes every linkage still routing to this receiver, through the
 * dispatcher that owns it. The trailing unlink at 0x0047C51C is `mLinkages`'
 * destructor.
 */
IMessageReceiver::~IMessageReceiver()
{
  while (!mLinkages.empty()) {
    SMsgReceiverLinkage* const linkage = mLinkages.mNext->Get();
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
  : mLower(lower)
  , mUpper(upper)
  , mReceiver(rec)
  , mDispatcher(dispatcher)
{}
