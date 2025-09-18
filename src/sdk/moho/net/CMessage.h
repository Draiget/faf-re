#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/Stream.h"
#include "platform/Platform.h"

namespace moho
{
    enum class ECmdStreamOp : uint8_t
    {
	    /**
	     * Data payload:
	     * - uint32_t - number of beats to advance in simulation
	     */
	    CMDST_Advance = 0,

	    /**
	     * Data payload:
	     * - uint8_t - command source id
	     */
	    CMDST_SetCommandSource = 1,

        /**
         * Data payload:
         * - (nothing)
         */
        CMDST_CommandSourceTerminated = 2,

        /**
         * Data payload:
         * - MD5Digest - checksum
         * - uint32_t - beat number
         */
        CMDST_VerifyChecksum = 3,

        /**
         * Data payload:
         * - (nothing)
         */
        CMDST_RequestPause = 4,

        /**
         * Data payload:
         * - (nothing)
         */
        CMDST_Resume = 5,

        /**
         * Data payload:
         * - (nothing)
         */
        CMDST_SingleStep = 6,

        /**
         * Data payload:
         * - uint8_t - army index
         * - string - blueprint id
         * - float - x
         * - float - z
         * - float - heading
         */
        CMDST_CreateUnit = 7,

        /**
         * Data payload:
         * - string - blueprint id
         * - Vec3f - location
         */
        CMDST_CreateProp = 8,

        /**
         * Data payload:
         * - int32_t - entity id
         */
        CMDST_DestroyEntity = 9,

        /**
         * Data payload:
         * - int32_t - entity id
         * - VTransform - new entity transform
         */
        CMDST_WarpEntity = 10,

        /**
         * Data payload:
         * - int32_t - entity id
         * - string - anything, argument 0?
         * - string - anything, argument 1?
         */
        CMDST_ProcessInfoPair = 11,

        /**
         * Data payload:
         * - uint32 - number of units
         * - set<int32_t> - set of unit id's
         * - CmdData - command data
         * - uint8_t - clear queue flag
         */
        CMDST_IssueCommand = 12,

        /**
         * Data payload:
         * - uint32 - number of factories
         * - set<int32_t> - set of factory id's
         * - CmdData - command data
         * - uint8_t - clear queue flag
         */
        CMDST_IssueFactoryCommand = 13,

        /**
         * Data payload:
         * - CmdId - command id
         * - int32_t - count delta
         */
        CMDST_IncreaseCommandCount = 14,

        /**
         * Data payload:
         * - CmdId - command id
         * - int32_t - count delta
         */
        CMDST_DecreaseCommandCount = 15,

        /**
         * Data payload:
         * - CmdId - command id
         * - STITarget - target
         */
        CMDST_SetCommandTarget = 16,

        /**
         * Data payload:
         * - CmdId - command id
         * - EUnitCommandType - type
         */
        CMDST_SetCommandType = 17,

        /**
         * Data payload:
         * - CmdId - command id
         * - ListOfCells - list of cells
         * - Vec3f - pos
         */
        CMDST_SetCommandCells = 18,

        /**
         * Data payload:
         * - CmdId - command id
         * - int32_t - unit id
         */
        CMDST_RemoveCommandFromQueue = 19,

        /**
         * Data payload:
         * - string - the debug command string
         * - Vec3f - mouse pos (in world coords)
         * - uint8_t - focus army index
         * - set<int32_t> - set of selected entity id's
         */
        CMDST_DebugCommand = 20,

        /**
         * Data payload:
         * - string - lua string to exec in sim state
         */
        CMDST_ExecuteLuaInSim = 21,

        /**
         * Data payload:
         * - string - callback function name
         * - LuaObject - table of function arguments
         */
        CMDST_LuaSimCallback = 22,

        /**
         * Data payload:
         * - (nothing)
         * Disconnect function triggers to send this as well.
         */
        CMDST_EndGame = 23,

        /**
         * Data payload:
         * - uint8_t - client index
         * - uint32_t - queued beat
         *
         * Referenced in:
         *  Moho::CReplayClient::Process (0x0053D900)
         *  Moho::CReplayClient::Start 
         */
        Replay_Process0 = 50,

        /**
         * Answer packet to `Replay_ClientOnLoad` (id = 52).
         * Data payload:
         * - ?
         *
         * Referenced in:
         *  Moho::CReplayClient::Process (0x0053D900)
         */
        Replay_Process1 = 51,

        /**
         * Answer packet to `Replay_ClientOnLoad` (id = 52).
         * Data payload:
         * - uint32_t - available beat
         *
         * Referenced in:
         *  Moho::CClientManagerImpl::OnLoad (0x0053EB9A) - Near ++*p_mAvailableBeat
         */
        Replay_ClientOnLoad = 52,

        /**
         * Data payload:
         * - (nothing)
         *
         * Referenced in:
         *  Moho::CClientManagerImpl::Cleanup (0x0053E51A)
         */
        Replay_Cleanup = 53,

        /**
         * Data payload:
         * - uint8_t - clientIndex
         * - uint32 - queued beat
         *
         * Referenced in:
         *  Moho::CClientBase::Eject,
         *  > sub_53F2C0 (0x0053F2C0)
         */
        Replay_EjectClient = 54,

        /**
         * Data payload:
         * - (raw bytes of CMessage based on capacity)
         *
         * Referenced in:
         *  Moho::CClientBase::Func7 (0x0053C9CB)
         */
        Replay_BlobData = 55,

        /**
         * Data payload:
         * - uint32_t - current clock? (clock+1)
         * - int32_t - simulation rate
         *
         * Referenced in:
         *  Moho::CClientManagerImpl::SetSimRate (0x0053E5EC)
         */
        Replay_SetSimRate = 56,

        /**
         * Data payload:
         * - uint32_t - ?
         *
         * Referenced in:
         *  Moho::CClientManagerImpl::Func1 (0x0053E89C)
         */
        ClientMgr_IntParam = 57,

	    /**
         * Data payload:
         * - uint32_t - player id?
         * - string - player name
         *
         * Referenced in:
         *  Moho::CLobby::ConnectionMade (0x007C5CA0)
	     */
	    ConnectionMade = 100,

        /**
         * Data payload:
         * - string - reason
         *
         * Referenced in:
         *  Moho::CLobby::PeerJoined (0x007C64C0)
         *  > Kicks client with 'LobbyFull' for e.g.
         */
    	ConnectionReject = 101,

        /**
         * Data payload:
         * - uint32_t - player name size
         * - uint32_t - player UUID
         * - uint32_t - ? (lobby->v37, 4 bytes)
         *
         * Referenced in:
         *  Moho::CLobby::PeerJoined (0x007C64C0)
         *  > Kicks client with 'LobbyFull' for e.g.
         */
        PeerJoined = 102,

	    PeerInfo = 103, // 0x007C8146
	    PeerDisconnected = 104, // 0x007C78BF
	    PollTask = 105, // 0x007C56B0
	    BroadcastData = 106, // 0x007C2235
	    SendScriptData = 107, // 0x007C24C0

        DiscoveryRequest = 110, // 0x7BFA60, broadcast to UDP/15000
        DiscoveryResponse = 111, // 0x7C5840, payload: header bytes + Lua-serialized GameConfig

        ConnectionFailed = 200, // 0x00483E18, CNetTCPConnection<%s:%d>::Pull()
        Answering = 201, // 0x004853D0, when state = ENetConnectionState::Establishing
        Errored = 202, // 0x00487971, when state == ENetConnectionState::Errored
        EndOfInput = 203, // 0x0048799E, else (end of input from client?)
    };

    struct CMessage
    {
        gpg::core::FastVectorN<char, 64> mBuf;
        int mPos;

        /**
         * PDB address: 0x00483490
         */
        CMessage(int size, char type);

        /**
         * PDB address: 0x0047BE62
         */
        void SetSize(const size_t size) {
            this->mBuf[1] = LOBYTE(size);
            this->mBuf[2] = HIBYTE(size);
        }

        /**
         * PDB address: 0x0047BF4C
         */
        unsigned short GetSize() {
            // return *(unsigned short *)(&this->mBuf[1]);
            return MAKEWORD(this->mBuf[1], this->mBuf[2]);
        }

        /**
         * PDB address: 0x0047BEE5
         */
        [[nodiscard]]
    	bool HasReadLength() const {
            return this->mPos >= 3;
        }

        /**
         * PDB address: 0x007BFB97
         */
        char GetType() {
            return this->mBuf[0];
        }

        /**
         * PDB address: 0x004834E9
         */
        void SetType(const char type) {
            this->mBuf[0] = type;
        }

        /**
         * PDB address: 0x0047BE90
         */
        int GetMessageSize();

        /**
         * PDB address: 0x0047BD40
         */
        bool ReadMessage(gpg::Stream* stream);

        /**
         * PDB address: 0x0047BEE0
         */
        bool Read(gpg::Stream* stream);

        /**
         * PDB address: 0x0047BDE0
         */
        unsigned int Append(const char* ptr, size_t size);

        /**
         * PDB address: <inlined>
         */
        void inline Clear() noexcept;
    };
}