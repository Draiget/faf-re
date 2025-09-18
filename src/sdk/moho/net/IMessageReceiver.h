#pragma once

#include "moho/misc/TDatList.h"
#include "CMessage.h"

namespace moho
{
	class SMsgReceiverLinkage;

	struct struct_filler4
	{
		int filler;
	};

    class CMessageDispatcher : TDatListItem<SMsgReceiverLinkage, void>
    {

    };

	class IMessageReceiver : public TDatListItem<IMessageReceiver, void>
    {
    public:
        virtual void Receive(CMessage*, CMessageDispatcher*) = 0;

        /**
         * In binary:
         *
         * PDB address: 0x0047C4F0
         * VFTable SLOT: 0
         */
        ~IMessageReceiver() = default;
    };

    class SMsgReceiverLinkage : public
        TDatListItem<SMsgReceiverLinkage, void>,
        struct_filler4,
        TDatListItem<IMessageReceiver, void>
    {

    };
}
