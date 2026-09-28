#pragma once

#include <cstddef>

#include "CMessage.h"
#include "gpg/core/containers/DList.h"

namespace moho
{
  class IMessageReceiver;
  struct SMsgReceiverLinkage;

  /**
   * Routes each message to the receiver registered for its type byte.
   *
   * Not polymorphic and with no bases: `CNetTCPConnection`'s RTTI lists
   * `CMessageDispatcher` at mdisp 4 and nothing under it, so the linkage ring
   * at +0x00 is a member. It is a `gpg::DList`: the connection's own
   * `DListItem` base lands at +0x410 rather than +0x40C, which only an empty
   * `noncopyable` inside this ring produces.
   */
  class CMessageDispatcher
  {
  public:
    /**
     * Address: 0x0047C240 (FUN_0047C240, Moho::CMessageDispatcher::CMessageDispatcher)
     *
     * What it does:
     * Initializes receiver-linkage sentinel and clears 256-byte receiver table.
     */
    CMessageDispatcher();

    /**
     * Address: 0x0047C280 (FUN_0047C280, Moho::CMessageDispatcher::~CMessageDispatcher)
     *
     * What it does:
     * Unlinks and deletes all receiver linkages owned by this dispatcher.
     */
    ~CMessageDispatcher();

    /**
     * Address: 0x0047C360
     * @param lower
     * @param upper
     * @param rec
     */
    void PushReceiver(unsigned int lower, unsigned int upper, IMessageReceiver* rec);

    /**
     * Address: 0x0047C450
     * @param linkage
     */
    void RemoveLinkage(SMsgReceiverLinkage* linkage);

    /**
     * Address: 0x0047C400 (FUN_0047C400, Moho::CMessageDispatcher::RemoveReceiver)
     *
     * What it does:
     * Finds and removes one range receiver linkage matching `(lower, upper, rec)`.
     */
    void RemoveReceiver(unsigned int lower, unsigned int upper, IMessageReceiver* rec);

    /**
     * Address: 0x0047C4D0
     * @param msg
     * @return
     */
    bool Dispatch(CMessage* msg);

  public:
    /// Every linkage pushed onto this dispatcher, oldest first.
    gpg::DList<SMsgReceiverLinkage, CMessageDispatcher> mLinkages; // +0x00
    /// The receiver currently answering each message type.
    IMessageReceiver* mReceivers[256];                             // +0x08
  };
  static_assert(offsetof(CMessageDispatcher, mReceivers) == 0x08, "CMessageDispatcher::mReceivers offset must be 0x08");
  static_assert(sizeof(CMessageDispatcher) == 0x408, "CMessageDispatcher size must be 0x408");

  /**
   * VFTABLE: 0x00E03BE4 (one slot, `ReceiveMessage`; no virtual destructor)
   *
   * RTTI lists no base under `IMessageReceiver`, so the ring at +0x04 is a
   * member: the linkages that route messages to this receiver.
   */
  class IMessageReceiver
  {
  public:
    /**
     * Address: 0x0053BC60 (FUN_0053BC60)
     *
     * What it does:
     * Installs the interface vtable and self-links the linkage ring.
     */
    IMessageReceiver();

    virtual void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) = 0;

    /**
     * Address: 0x0047C4F0 (FUN_0047C4F0)
     *
     * What it does:
     * Removes all attached dispatch linkages registered under this receiver.
     */
    ~IMessageReceiver();

  public:
    gpg::DList<SMsgReceiverLinkage, IMessageReceiver> mLinkages; // +0x04
  };
  static_assert(offsetof(IMessageReceiver, mLinkages) == 0x04, "IMessageReceiver::mLinkages offset must be 0x04");
  static_assert(sizeof(IMessageReceiver) == 0x0C, "IMessageReceiver size should be 0x0C");

  /**
   * One `[mLower, mUpper)` message-type range routed to `mReceiver`, linked
   * into both the dispatcher's ring (first base, +0x00) and the receiver's
   * ring (second base, +0x0C).
   *
   * No vtable: neither the out-of-line ctor (0x0047BC90) nor the one inlined
   * in `PushReceiver` stores a vptr. The second base sits at +0x0C, not +0x08,
   * because both bases are `gpg::DListItem`s and each carries a `noncopyable`.
   */
  struct SMsgReceiverLinkage
    : gpg::DListItem<SMsgReceiverLinkage, CMessageDispatcher>
    , gpg::DListItem<SMsgReceiverLinkage, IMessageReceiver>
  {
    using DispatcherLink = gpg::DListItem<SMsgReceiverLinkage, CMessageDispatcher>;
    using ReceiverLink = gpg::DListItem<SMsgReceiverLinkage, IMessageReceiver>;

    /**
     * Address: 0x0047BC90 (FUN_0047BC90)
     * Address: 0x0047C37A (inlined ctor lane in FUN_0047C360)
     *
     * @param lower
     * @param upper
     * @param rec
     * @param dispatcher
     */
    SMsgReceiverLinkage(unsigned int lower, unsigned int upper, IMessageReceiver* rec, CMessageDispatcher* dispatcher);

    /**
     * Address: 0x0047C320 (FUN_0047C320)
     * Address: 0x0047C2E0 (FUN_0047C2E0, the same body followed by operator delete)
     *
     * What it does:
     * The two base destructors, the receiver link (+0x0C) first. Both copies
     * are reached from nowhere; `RemoveLinkage` (0x0047C497) and
     * `~CMessageDispatcher` (0x0047C28D) inline it.
     */
    ~SMsgReceiverLinkage() = default;

    unsigned int mLower;             // +0x14
    unsigned int mUpper;             // +0x18
    IMessageReceiver* mReceiver;     // +0x1C
    CMessageDispatcher* mDispatcher; // +0x20
  };
  static_assert(offsetof(SMsgReceiverLinkage, mLower) == 0x14, "SMsgReceiverLinkage::mLower offset must be 0x14");
  static_assert(
    offsetof(SMsgReceiverLinkage, mDispatcher) == 0x20, "SMsgReceiverLinkage::mDispatcher offset must be 0x20"
  );
  static_assert(sizeof(SMsgReceiverLinkage) == 0x24, "SMsgReceiverLinkage size must be 0x24");
} // namespace moho
