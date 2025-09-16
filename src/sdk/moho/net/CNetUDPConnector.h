#pragma once
#include <cstdint>

#include "CNetUDPConnection.h"
#include "INetConnector.h"
#include "INetNATTraversalHandler.h"
#include "gpg/core/containers/IntrusiveLink.h"
#include "gpg/core/utils/Sync.h"

namespace moho
{
    enum class NetConnectorType : int32_t
	{
        TCP = 1, // guess
        UDP = 2  // confirmed by GetType()
    };

    enum EPacketState
    {
        CONNECT,
        ANSWER,
        RESETSERIAL,
        SERIALRESET,
        DATA,
        ACK,
        KEEPALIVE,
        GOODBYE,
        NATTRAVERSAL,
    };

    /*
     * Game Types:
     *
     * Multiplayer - CLobby::LaunchGame
     * Replay - VCR_SetupReplaySession
     * SinglePlayer - WLD_SetupSessionInfo
     * Saved Game - CSavedGame::CreateSinglePlayerSession
     *
     * Session State
     * 0 - None?
     * 1 - Loading?
     * 2 - Started?
     * 3 - SIM Initialized
     * 4 - SIM Started
     * 5 - Game Started
     * 7 - Restart Requested
     * 8 - Session Halted
     */

	class CNetUDPConnector : public INetConnector, public INetNATTraversalHandler
	{
        // Primary vftable (13 entries)
	public:
        /**
         * In binary: dtor
         *
         * PDB address: 0x4899E0
         * VFTable SLOT: 0
         */
        void ~CNetUDPConnector() = default;

        /**
         * In binary:
         *
         * PDB address: 0x489D20
         * VFTable SLOT: 1
         */
        virtual void Shutdown() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x485CA0
         * VFTable SLOT: 2
         */
        virtual NetConnectorType GetType() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B250
         * VFTable SLOT: 3
         */
        virtual uint16_t GetLocalPort() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B2B0
         * VFTable SLOT: 4
         */
        virtual CNetUDPConnection* AcceptConnection(uint32_t address, uint16_t port) = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B410
         * VFTable SLOT: 5
         */
        virtual bool TryGetIdlePeer(uint32_t& outAddress, uint16_t& outPort) = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B4F0
         * VFTable SLOT: 6
         */
        virtual void sub_48B4F0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B500
         * VFTable SLOT: 7
         */
        virtual int CloseIdlePeer(uint32_t address, uint16_t port) = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B5C0
         * VFTable SLOT: 8
         */
        virtual void sub_48B5C0() = 0; 

        /**
         * In binary:
         *
         * PDB address: 0x48B7F0
         * VFTable SLOT: 9
         */
        virtual void sub_48B7F0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B9A0
         * VFTable SLOT: 10
         */
        virtual void sub_48B9A0() = 0; 

        /**
         * In binary:
         *
         * PDB address: 0x48B8E0
         * VFTable SLOT: 11
         */
        virtual void sub_48B8E0() = 0;

        /**
         * In binary:
         *
         * PDB address: 0x48B9E0
         * VFTable SLOT: 12
         */
        virtual void sub_48B9E0() = 0;

    // Secondary vftable at subobject offset 4 (2 entries)
    public:
        void sub_A82547() override = 0; // 0x48BA80
        void sub_A82547_1() override = 0; // 0x48BAE0

	public:
        // +0x00  vptr(INetConnector)
        // +0x04  vptr(INetNATTraversalHandler)

        // at 0x08
        gpg::core::Mutex sync_;

        // at 0x14
        SOCKET socket_;

        // at 0x24
        gpg::core::IntrusiveLink<CNetUDPConnection*> connections_;

        // +0x1C  void*  currentToken_    // cleared in Shutdown()
        // +0x20  RefCounted* rcToken_    // released in Shutdown()
	    // +0x24  ListEntry connections_; // sentinel
	    // +0x28  connections_.Flink
	    // ...
	    // +0x2C  free-list anchor for small packet pool (this+44)
	    // +0x38  smallPoolHead_ (this[11])
	    // +0x34  smallPoolCount_ (this[13])
	    //
	    // Outbound ring (ring buffer of pending sends):
	    // +0x6C  void** outRingItems_    // this[27]
	    // +0x70  uint32_t outRingCap_    // this[28]
	    // +0x74  uint32_t outRingHead_   // this[29]
	    // +0x78  uint32_t outRingCount_  // this[30]
	    //
	    // +0x50  uint8_t resignalWorkerFlag_ // this[80]
	    // +0x51  uint8_t inPumpFlag_         // this[81]
	};
}
