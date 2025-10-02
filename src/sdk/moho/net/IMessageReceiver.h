#pragma once

#include "CMessage.h"
#include "moho/containers/TDatList.h"

namespace moho
{
	class IMessageReceiver;
	class SMsgReceiverLinkage;

	struct struct_filler4
	{
		int filler;
	};

    class CMessageDispatcher : public TDatListItem<SMsgReceiverLinkage, void>
    {
    public:
        IMessageReceiver* mReceivers[256];

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

	class IMessageReceiver : public TDatListItem<IMessageReceiver, void>
    {
    public:
        virtual void Receive(CMessage* message, CMessageDispatcher* dispatcher) = 0;

        /**
         * In binary:
         *
         * PDB address: 0x0047C4F0
         * VFTable SLOT: 0
         */
        ~IMessageReceiver() = default;
    };
    static_assert(sizeof(IMessageReceiver) == 0x0C, "IMessageReceiver size should be 0x0C");

    class SMsgReceiverLinkage :
        public TDatListItem<SMsgReceiverLinkage, void>,
        public struct_filler4,
        public IMessageReceiver
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
        SMsgReceiverLinkage(
            unsigned int lower, 
            unsigned int upper, 
            IMessageReceiver* rec, 
            CMessageDispatcher* dispatcher
        );

        void Receive(CMessage* message, CMessageDispatcher* dispatcher) override;

    public:
        unsigned int mLower;
        unsigned int mUpper;
        IMessageReceiver* mReceiver;
        CMessageDispatcher* mDispatcher;
    };
}
