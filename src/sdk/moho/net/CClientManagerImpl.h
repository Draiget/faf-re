// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include "IClientManager.h"
#include "boost/recursive_mutex.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/time/Timer.h"
#include "legacy/containers/Vector.h"

namespace moho
{
	class INetConnector;
	class CClientBase;

    class CMarshaller
    {
    public:
        CClientManagerImpl* mClientManager;
    };

	/**
     * VFTABLE: 0x00E16B64
     * COL:  0x00E6AF24
     */
    class CClientManagerImpl :
		public IClientManager
	{
    public:
        /**
         * Address: 0x0053E050
         * Slot: 0
         */
        virtual ~CClientManagerImpl();

        /**
         * Address: 0x0053E180
         * Slot: 1
         */
        virtual IClient* CreateLocalClient(
            const char* name, 
            int32_t index, 
            LaunchInfoBase* launchInfo, 
            unsigned int sourceId
        );

        /**
         * Address: 0x0053E260
         * Slot: 2
         */
        virtual IClient * CreateNetClient(
            const char* name, 
            int32_t index, 
            LaunchInfoBase* info, 
            uint32_t sourceId,
            int val
        ) = 0;

        /**
         * Address: 0x0053E400
         * Slot: 3
         */
        virtual IClient* CreateReplayClient(int*, BVIntSet* set) = 0;

        /**
         * Address: 0x0053E330
         * Slot: 4
         */
        virtual IClient* CreateNullClient(
            const char* name, 
            int32_t index, 
            LaunchInfoBase* info, 
            uint32_t sourceId
        ) = 0;

        /**
         * Address: 0x0053BCB0
         * Slot: 5
         */
        virtual INetConnector* GetConnector() = 0;

        /**
         * Address: 0x0053BCC0
         * Slot: 6
         */
        virtual size_t NumberOfClients() = 0;

        /**
         * Address: 0x0053BCE0
         * Slot: 7
         */
        virtual IClient* GetClient(int idx) = 0;

        /**
         * Address: 0x0053E470
         * Slot: 8
         */
        virtual IClient* GetClientWithData(LaunchInfoBase* info) = 0;

        /**
         * Address: 0x0053BD10
         * Slot: 9
         */
        virtual IClient* GetLocalClient() = 0;

        /**
         * Address: 0x0053BD20
         * Slot: 10
         */
        virtual void SetUIInterface(IClientMgrUIInterface*) = 0;

        /**
         * Address: 0x0053E4B0
         * Slot: 11
         */
        virtual void Cleanup() = 0;

        /**
         * Address: 0x0053E560
         * Slot: 12
         */
        virtual bool IsEveryoneReady() = 0;

        /**
         * Address: 0x0053E590
         * Slot: 13
         */
        virtual void SetSimRate(int rate) = 0;

        /**
         * Address: 0x0053E720
         * Slot: 14
         */
        virtual int GetSimRate() = 0;

        /**
         * Address: 0x0053E7E0
         * Slot: 15
         */
        virtual int GetSimRateRequested() = 0;

        /**
         * Address: 0x0053E850
         * Slot: 16
         */
        virtual void Func1(int) = 0;

        /**
         * Address: 0x0053E990
         * Slot: 17
         */
        virtual void ProcessClients(CMessage& msg) = 0;

        /**
         * Address: 0x0053EA30
         * Slot: 18
         */
        virtual void DoBeat() = 0;

        /**
         * Address: 0x0053EDA0
         * Slot: 19
         */
        virtual void SelectEvent(HANDLE ev) = 0;

        /**
         * Address: 0x0053EF90
         * Slot: 20
         */
        virtual void GetPartiallyQueuedBeat(int& out) = 0;

        /**
         * Address: 0x0053EFD0
         * Slot: 21
         */
        virtual void GetAvailableBeat(int& out) = 0;

        /**
         * Address: 0x0053F010
         * Slot: 22
         */
        virtual void UpdateStates(int beat) = 0;

        /**
         * Address: 0x0053F4C0
         * Slot: 23
         * Demangled: Moho::CClientManagerImpl::Func3
         */
        virtual SSendStampView GetBetween(int since) = 0;

        /**
         * Address: 0x0053F5A0
         * Slot: 24
         * Demangled: Moho::CClientManagerImpl::Func4
         */
        virtual SClientBottleneckInfo GetBottleneckInfo() = 0;

        /**
         * Address: 0x0053F920
         * Slot: 25
         */
        virtual void Debug() = 0;

        /**
         * Address: 0x0053F830
         * Slot: 26
         */
        virtual void Disconnect() = 0;

    public:
        boost::recursive_mutex mLock;
        IClientMgrUIInterface* mInterface;
        msvc8::vector<CClientBase*> mClients;
        INetConnector* mConnector;
        CClientBase* mLocalClient;
        bool mWeAreReady;
        bool mEveryoneIsReady;
        int mDispatchedBeat;
        int mAvailableBeat;
        int mFullyQueuedBeat;
        int mPartiallyQueuedBeat;
        int mGameSpeedClock;
        int mGameSpeedRequester;
        int mGameSpeed;
        bool mAdjustableGameSpeed;
        HANDLE mCurrentEvent;
        int gap;
        gpg::time::Timer mTimer3;
        SSendStampBuffer mStampBuffer;
        gpg::PipeStream mStream;
        CMarshaller mMarshaller;
        gpg::time::Timer mDispatchedTimer;
        gpg::time::Timer mTimer2;
    };

    /**
     * VFTABLE: 0x00E16C64
     * COL:     0x00E6AE38
     */
    class CLocalClient :
		public CClientBase
    {
    public:
	    /**
	     * Address: 0x0053BD40
	     *
	     * @param index 
	     * @param manager 
	     * @param name 
	     * @param launchInfo 
	     * @param commandSources 
	     * @param sourceId 
	     */
	    CLocalClient(
            int32_t index, 
            CClientManagerImpl* manager, 
            const char* name, 
            LaunchInfoBase* launchInfo, 
            BVIntSet& commandSources,
            uint32_t sourceId
        );

		void OnAttach() override {}
        void OnDetach() override {}
        void Process(CMessage& msg) override {}
        void CollectPendingIds(msvc8::vector<int>& out) override {}
        void Debug() override {}
    };
    static_assert(sizeof(CLocalClient) == 0xD8, "CLocalClient must be 0xD8");
} 
