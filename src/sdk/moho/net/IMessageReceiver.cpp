#include "IMessageReceiver.h"
using namespace moho;

void CMessageDispatcher::PushReceiver(const unsigned int lower, const unsigned int upper, IMessageReceiver* rec) {
    using LNode = TDatListItem<SMsgReceiverLinkage, void>;
    using RNode = TDatListItem<IMessageReceiver, void>;

    const auto linkage = new SMsgReceiverLinkage{ lower, upper, rec, this };

    auto* linkNode = static_cast<LNode*>(linkage);
    const auto* head = static_cast<LNode*>(this);
    linkNode->ListLinkAfter(head->mPrev);

    auto* linkageReceiverNode = static_cast<RNode*>(static_cast<IMessageReceiver*>(linkage));
    const auto* recNode = static_cast<RNode*>(rec);
    linkageReceiverNode->ListLinkAfter(recNode->mPrev);

    if (lower < upper) {
        for (unsigned code = lower; code < upper; ++code) {
            mReceivers[code] = rec;
        }
    }
}

SMsgReceiverLinkage::SMsgReceiverLinkage(
	const unsigned int lower,
	const unsigned int upper, 
    IMessageReceiver* rec,
	CMessageDispatcher* dispatcher
) :
	mLower(lower),
	mUpper(upper),
	mReceiver(rec),
	mDispatcher(dispatcher)
{
}

void SMsgReceiverLinkage::Receive(CMessage* message, CMessageDispatcher* dispatcher) {
}
