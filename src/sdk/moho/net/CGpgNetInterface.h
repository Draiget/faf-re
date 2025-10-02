#pragma once
#include "INetNATTraversalProvider.h"
#include "boost/enable_shared_from_this.h"
#include "boost/mutex.h"
#include "boost/recursive_mutex.h"
#include "boost/thread.h"
#include "boost/weak_ptr.h"
#include "gpg/core/utils/Sync.h"
#include "legacy/containers/Deque.h"
#include "moho/task/CTask.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"

namespace moho
{
	class INetTCPSocket;
	class INetTCPServer;

	struct SNetCommandArg
    {
        enum EType
        {
            NETARG_Num = 0x0,
            NETARG_String = 0x1,
            NETARG_Data = 0x2,
        };

        EType mType;
        int32_t mNum;
        msvc8::string mStr{};

        explicit SNetCommandArg(const int32_t num) :
            mType{ NETARG_Num },
            mNum{ num }
        {
        }

        explicit SNetCommandArg(const msvc8::string& str) :
            mType{ NETARG_String },
            mNum{ 0 },
            mStr{ str }
        {
        }
    };

	struct SNetCommand
	{
		msvc8::string mName;
		msvc8::vector<SNetCommandArg> mArgs;
		int mVal;
	};

	class CGpgNetInterface :
		public CPullTask<CGpgNetInterface>,
		public INetNATTraversalProvider,
        public boost::enable_shared_from_this<CGpgNetInterface>
	{
	public:
		/**
		 * Address: 0x007B6800
		 */
		CGpgNetInterface();

		/**
		 * Address: 0x007B68C0
		 * Slot: 2
		 */
		~CGpgNetInterface() override;

		/**
		 * Address: 0x007B9070
		 * Slot: 0
		 *
		 * @param port 
		 * @param handler 
		 */
		void SetHandler(int port, boost::shared_ptr<INetNATTraversalHandler>* handler) override;

		/**
		 * Address: 0x007B9160
		 * Slot: 1
		 *
		 * @param address 
		 * @param port 
		 * @param dat 
		 * @param size 
		 */
		void ReceivePacket(u_long address, u_short port, const char* dat, size_t size) override;

		/**
		 * Address: 0x007BB250
		 * Slot: 3
		 *
		 * @return 
		 */
		int Execute() override;

		/**
		 * Address: 0x007B65C0
		 */
		void ExpectedInt() noexcept(false);

		/**
		 * Address: 0x007B66B0
		 */
		void ExpectedData() noexcept(false);

		/**
		 * Address: 0x007B67A0
		 *
		 * @param str 
		 * @param val 
		 */
		void EnqueueCommand0(const char* str, int val);

		/**
		 * Address: 0x007B6A30
		 *
		 * @param address 
		 * @param port 
		 */
		void Connect(u_long address, u_short port);

		/**
		 * Address: 0x007B6DB0
		 *
		 * @param name 
		 * @param args 
		 */
		void WriteCommand(const char* name, std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B6F00
		 */
		void SendBottleneckCleared();

		/**
		 * Address: 0x007B6FF0
		 *
		 * @param name 
		 * @param arg 
		 */
		void WriteCommand1(const char* name, SNetCommandArg* arg);

		/**
		 * Address: 0x007B70F0
		 *
		 * @param name 
		 * @param arg1 
		 * @param arg2 
		 */
		void WriteCommand2(const char* name, SNetCommandArg* arg1, SNetCommandArg* arg2);

		/**
		 * Address: 0x007B7200
		 *
		 * @param name 
		 * @param arg1 
		 * @param arg2 
		 * @param arg3 
		 */
		void WriteCommand3(const char* name, SNetCommandArg* arg1, SNetCommandArg* arg2, SNetCommandArg* arg3);

		/**
		 * Address: 0x007B7310
		 *
		 * @param name 
		 * @param arg1 
		 * @param arg2 
		 * @param arg3 
		 * @param arg4 
		 */
		void WriteCommand4(const char* name, SNetCommandArg* arg1, SNetCommandArg* arg2, SNetCommandArg* arg3, SNetCommandArg* arg4);

		/**
		 * Address: 0x007B7420
		 *
		 * @param name 
		 */
		void WriteCommandName(const char* name);

		/**
		 * Address: 0x007B74A0
		 *
		 * @param str 
		 */
		void WriteString(const char* str);

		/**
		 * Address: 0x007B7520
		 *
		 * @param arg 
		 */
		void WriteArg(SNetCommandArg* arg);

		/**
		 * Address: 0x007B7710
		 */
		void Process();

		/**
		 * Address: 0x007B7A30
		 *
		 * @param args 
		 */
		void Test(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B7C50
		 *
		 * @param args 
		 */
		void Connected(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B7DE0
		 *
		 * @param args 
		 */
		void CreateLobby(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B81D0
		 *
		 * @param args 
		 */
		void HostGame(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B83C0
		 *
		 * @param args 
		 */
		void JoinGame(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B85A0
		 *
		 * @param args 
		 */
		void ConnectToPeer(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B8780
		 *
		 * @param args
		 */
		void DisconnectFromPeer(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B8920
		 *
		 * @param args
		 */
		void HasSupCom(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B8A70
		 *
		 * @param args
		 */
		void HasForgedAlliance(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B8BC0
		 *
		 * @param args
		 */
		void SendNatPacket(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007B8E20
		 *
		 * @param args
		 */
		void EjectPlayer(std::vector<SNetCommandArg>& args);

		/**
		 * Address: 0x007BA5E0
		 *
		 * @param address
		 * @param port
		 */
		void ConnectThread(u_long address, u_short port);

		/**
		 * Address: 0x007BA880
		 */
		void ReadFromSocket();

		/**
		 * Address: 0x007BAE50
		 *
		 * @param name
		 * @param args
		 * @param val
		 */
		void EnqueueCommand(const char* name, std::vector<SNetCommandArg>& args, int val);

	private:
        // boost::shared_ptr<CGpgNetInterface> mSelf;
        boost::mutex mLock;
        DWORD mState;
        INetTCPServer* mServer;
        INetTCPSocket* mSocket;
        msvc8::deque<SNetCommand> mCommands;
        HANDLE mEvent;
        boost::thread* mNATHandlerThread;
        LuaPlus::LuaObject mLObj;
        boost::weak_ptr<INetNATTraversalHandler> mNATHandler;
	};
    static_assert(sizeof(CGpgNetInterface) == 0x70, "CGpgNetInterface size must be 0x70");
}
