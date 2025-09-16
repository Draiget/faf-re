#pragma once

#include "CMessage.h"
#include "CMessageDispatcher.h"
#include "moho/misc/TDatListItem.h"

namespace moho
{
    class IMessageReceiver : public TDatListItem<IMessageReceiver>
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
}
