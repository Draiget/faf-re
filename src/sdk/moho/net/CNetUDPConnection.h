#pragma once
#include "INetConnection.h"
#include "gpg/core/utils/BoostUtils.h"

namespace moho
{
	class CNetUDPConnection : public INetConnection, boost::noncopyable_::noncopyable
	{
        // Primary vftable (8 entries)
    public:
        /**
         * In binary: 
         *
         * PDB address: 0x485BE0
         * VFTable SLOT: 0
         */
        virtual void sub_485BE0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x485BF0
         * VFTable SLOT: 1
         */
        virtual void sub_485BF0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x489550
         * VFTable SLOT: 2
         */
        virtual void sub_489550() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x489590
         * VFTable SLOT: 3
         */
        virtual void sub_489590() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x489130
         * VFTable SLOT: 4
         */
        virtual void sub_489130() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x4893F0
         * VFTable SLOT: 5
         */
        virtual void sub_4893F0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x4894C0
         * VFTable SLOT: 6
         */
        virtual void sub_4894C0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x489660
         * VFTable SLOT: 7
         */
        virtual void sub_489660() = 0;

	public:
        // ...
        // +0x410  ListEntry linkInConnector
        // +0x42C  uint32_t state            // 0=Idle, 1=Init, 2=Active, 3=Closing?, 5=Retired
        // +0xE40  uint8_t  flagBusy         // used as "not busy" filter
        // +0xE41  uint8_t  flagDeleteNow    // immediate shutdown signal/flag
        // vtable[0]: uint32_t RemoteAddrBE() const
        // vtable[1]: uint16_t RemotePort()  const
        // vtable[7]: void CloseOrRelease()
	};
}
