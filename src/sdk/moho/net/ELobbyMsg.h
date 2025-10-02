#pragma once
#include <cstdint>

namespace moho
{
	/**
	 * NOTE: Real enum name came from 0x007C774E
	 */
	enum class ELobbyMsg : uint8_t
	{
		/**
		 * ASM: 0x64
		 *
		 * Data payload:
		 *  - msvc8::string - player name
		 *  - int32_t       - requested UUID
		 *
         * Referenced in:
         *  - Moho::CLobby::ConnectionMade (0x007C5CA0)
		 */
		LOBMSG_Join = 100,

		/**
		 * ASM: 0x65
		 *
		 * Data payload:
		 *  - msvc8::string - reason
		 *
         * Referenced in:
         *  - Moho::CLobby::PeerJoined (0x007C64C0)
		 */
		LOBMSG_Rejected = 101,

		/**
		 * ASM: 0x66
		 *
		 * Data payload:
		 *  - msvc8::string - host display name
		 *  - int32_t       - host UUID
		 *  - int32_t       - assigned player UUID
		 *  - msvc8::string - rename self to (new player name)
		 *  - int32_t       - ? (lobby->v39, 4 bytes)
		 *
		 * References:
         *  - Moho::CLobby::PeerJoined (0x007C64C0)
		 */
		LOBMSG_Welcome = 102,

		/**
		 * ASM: 0x67
		 *
		 * Data payload:
		 *  - string  - peer name
		 *  - u_long  - address
		 *  - u_short - port
		 *  - int32_t - UUID
		 *
		 * References:
		 *  - 0x007C8146
		 */
		LOBMSG_NewPeer = 103,

		/**
		 * ASM: 0x68
		 *
		 * Data payload:
		 *  - int32_t - UUID
		 *
		 * References:
         *  - Moho::CLobby::PeerDisconnected (0x007C78BF)
		 */
		LOBMSG_DeletePeer = 104,

		/**
		 * ASM: 0x69
		 *
		 * Data payload:
		 *  - int32_t[X] - UUID
		 *  - int32_t    - -1 (array end marker)
		 *
		 * References:
         *  - Moho::CLobby::PullTask (0x007C56B0)
		 */
		LOBMSG_EstablishedPeers = 105,

		/**
		 * ASM: 0x6A
		 * Notes:
		 *  - Used to broadcast script data to everyone.
		 *
		 * References:
         *  - Moho::CLobby::BroadcastScriptData (0x007C2210)
         *
         * Data payload: 
		 *  - LuaObject - Script object
		 */
		LOBMSG_BroadcastScriptData = 106,

		/**
		 * ASM: 0x6B
		 * Notes:
		 *  - Used to send script data to direct peer(s).
		 *
		 * References:
         *  - Moho::CLobby::SendScriptData (0x007C24C0)
         *
         * Data payload: 
		 *  - LuaObject - Script object
		 */
		LOBMSG_DirectScriptData = 107,

		/**
		 * ASM: 0x6E
		 * Notes:
		 *  - Lobby related, broadcast to UDP/15000.
		 *
		 * References:
		 *  - 0x007BFA60
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_DiscoveryRequest = 110,

		/**
		 * ASM: 0x6F
		 * Notes:
		 *  - Lobby related, broadcast to UDP/15000.
		 *
		 * References:
		 *  - 0x007C5840
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_DiscoveryResponse = 111,

		/**
		 * ASM: 0x78
		 * Notes:
		 *  - marked as last for `ConnectionMade` packet id's receivers;
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_HandshakeLast = 120,

		/**
		 * ASM: 0xC8
		 * Address: 0x00483E18
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_ConnFailed = 200,

		/**
		 * ASM: 0xC9
		 * Address: 0x004853D0
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_ConnMade = 201,

		/**
		 * ASM: 0xCA
		 * Address: 0x004876A0
		 *
         * Data payload: <nothing>
		 */
		LOBMSG_ConnLostErrored = 202,

		/**
		 * ASM: 0xCB
         * Address: 0x004876A0
         *
         * Data payload: <nothing>
		 */
		LOBMSG_ConnLostEof = 203,

		LOBMSG_Unknown0 = 204,
		LOBMSG_Unknown1 = 205,
		LOBMSG_Unknown2 = 206,
		LOBMSG_Unknown3 = 207,
		LOBMSG_Unknown4 = 208,
		LOBMSG_Unknown5 = 209,
		LOBMSG_Unknown6 = 210,
	};
}
