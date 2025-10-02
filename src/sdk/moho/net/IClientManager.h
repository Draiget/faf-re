#pragma once

#include "CClientBase.h"
#include "Common.h"
#include "IMessageReceiver.h"
#include "legacy/containers/Vector.h"

namespace moho
{
	class INetConnector;
	struct BVIntSet;
	class IClient;
	class LaunchInfoBase;
	class IClientMgrUIInterface;

	/**
     * VFTABLE: 0x00E16AF4
     * COL:  0x00E6AF74
     */
    class IClientManager :
		public CMessageDispatcher
    {
    public:
        /**
         * Address: 0x0053B680
         * Slot: 0
         * Demangled: Moho::IClientManager::dtr
         */
        virtual ~IClientManager();

        /**
         * Address: 0x00A82547
         * Slot: 1
         * Demangled: _purecall
         */
        virtual IClient* CreateLocalClient(const char* name, int idx, LaunchInfoBase* info, unsigned int sourceId) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 2
         * Demangled: _purecall
         */
        virtual IClient* CreateNetClient(const char* name, int idx, LaunchInfoBase* info, unsigned int sourceId, int val) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 3
         * Demangled: _purecall
         */
        virtual IClient* CreateReplayClient(int*, BVIntSet*) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual IClient* CreateNullClient(const char* name, int idx, LaunchInfoBase* info, unsigned int sourceId) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual INetConnector* GetConnector() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 6
         * Demangled: _purecall
         */
        virtual size_t NumberOfClients() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual IClient* GetClient(int idx) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual IClient* GetClientWithData(LaunchInfoBase* info) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual IClient* GetLocalClient() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void SetUIInterface(IClientMgrUIInterface*) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void Cleanup() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual bool IsEveryoneReady() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 13
         * Demangled: _purecall
         */
        virtual void SetSimRate(int rate) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 14
         * Demangled: _purecall
         */
        virtual int GetSimRate() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 15
         * Demangled: _purecall
         */
        virtual int GetSimRateRequested() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 16
         * Demangled: _purecall
         */
        virtual void Func1(int) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 17
         * Demangled: _purecall
         */
        virtual void ProcessClients(CMessage& msg) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 18
         * Demangled: _purecall
         */
        virtual void DoBeat() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 19
         * Demangled: _purecall
         */
        virtual void SelectEvent(HANDLE ev) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 20
         * Demangled: _purecall
         */
        virtual void GetPartiallyQueuedBeat(int& out) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 21
         * Demangled: _purecall
         */
        virtual void GetAvailableBeat(int& out) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 22
         * Demangled: _purecall
         */
        virtual void UpdateStates(int beat) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 23
         * Demangled: _purecall
         */
        virtual SSendStampView GetBetween(int since) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 24
         * Demangled: _purecall
         */
        virtual SClientBottleneckInfo GetBottleneckInfo() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 25
         * Demangled: _purecall
         */
        virtual void Debug() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 26
         * Demangled: _purecall
         */
        virtual void Disconnect() = 0;
    };
} // namespace Moho
