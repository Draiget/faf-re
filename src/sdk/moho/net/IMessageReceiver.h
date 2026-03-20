#pragma once

#include "CMessage.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class IMessageReceiver;
  class SMsgReceiverLinkage;

  class CMessageDispatcher : public TDatListItem<SMsgReceiverLinkage, void>
  {
  public:
    IMessageReceiver* mReceivers[256]{};

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
     * Address: 0x0047C4D0
     * @param msg
     * @return
     */
    bool Dispatch(CMessage* msg);
  };
  static_assert(sizeof(CMessageDispatcher) == 0x408, "CMessageDispatcher size must be 0x408");

  class IMessageReceiver : public TDatListItem<IMessageReceiver, void>
  {
  public:
    virtual void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) = 0;

    /**
     * Address: 0x0047C4F0 (FUN_0047C4F0)
     *
     * What it does:
     * Removes all attached dispatch linkages registered under this receiver.
     */
    ~IMessageReceiver();
  };
  static_assert(sizeof(IMessageReceiver) == 0x0C, "IMessageReceiver size should be 0x0C");

  class SMsgReceiverLinkage : public TDatListItem<SMsgReceiverLinkage, void>, public IMessageReceiver
  {
  public:
    /**
     * Address: 0x0047C37A
     * NOTE: Inlined
     *
     * @param lower
     * @param upper
     * @param rec
     * @param dispatcher
     */
    SMsgReceiverLinkage(unsigned int lower, unsigned int upper, IMessageReceiver* rec, CMessageDispatcher* dispatcher);

    void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) override;

  public:
    unsigned int mLower{0};
    unsigned int mUpper{0};
    IMessageReceiver* mReceiver{nullptr};
    CMessageDispatcher* mDispatcher{nullptr};
  };
  static_assert(sizeof(SMsgReceiverLinkage) == 0x24, "IMessageReceiver size should be 0x24");
} // namespace moho
