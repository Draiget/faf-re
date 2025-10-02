#pragma once

#include "IClient.h"
#include "gpg/core/containers/Set.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/PipeStream.h"
#include "moho/containers/BVIntSet.h"
#include "moho/sim/SSyncFilter.h"
#include "platform/Platform.h"

namespace moho
{
	class CClientBase;
    class CClientManagerImpl;

#pragma pack(push, 4)

    struct SEjectRequest
    {
        CClientBase* mRequester;
        int mAfterBeat;
    };

    struct SClientBottleneckInfo
    {
        enum Type
        {
            Nothing = 0,
            Readiness = 1,
            Data = 2,
            Ack = 3,
        };

        Type mType;
        int mVal;
        BVIntSet mSubobj;
        float mFloat;
    };

	/**
     * VFTABLE: 0x00E16BD4
     * COL:     0x00E6AED8
     */
    class MOHO_EMPTY_BASES CClientBase :
		public IClient
	{
    public:
        /**
         * Address: 0053B930
         * Slot: 0
         */
        BVIntSet* GetValidCommandSources() override;

        /**
         * Address: 0x0053C960
         * Slot: 1
         */
        bool NoEjectionPending() override;

        /**
         * Address: 0x00A82547
         * Slot: 2
         */
        void OnAttach() override = 0;

        /**
         * Address: 0x00A82547
         * Slot: 3
         */
        void OnDetach() override = 0;

        /**
         * Return pointer to latest-acks vector payload (implementation detail).
         *
         * Address: 0x0053CA60
         * Slot: 4
         */
        const msvc8::vector<int32_t>* GetLatestAcksVector() override;

        /**
         * Address: 0x0053CA90
         * Slot: 5
         */
        void GetLatestBeatDispatchedRemote(uint32_t& out) override;

        /**
         * Output available remote beat counter.
         *
         * Address: 0x0053CAD0
         * Slot: 6
         */
        void GetAvailableBeatRemote(uint32_t& out) override;

        /**
         * Address: 0x00A82547
         * Slot: 7
         */
        void Process(CMessage& msg) override = 0;

        /**
         * Build a message from raw span and forward to Process(...).
         *
         * Address: 0x0053C9A0
         * Slot: 8
         */
        void ReceiveChat(gpg::MemBuffer<const char> data) override;

        /**
         * Output queued beat number.
         *
         * Address: 0x0053CA20
         * Slot: 9
         * Demangled: _purecall
         */
        void GetQueuedBeat(uint32_t& out) override;

        /**
         * Schedule ejection sequence; see CClientBase::Eject().
         *
         * Address: 0x0053CB10
         * Slot: 10
         * Demangled: _purecall
         */
        void Eject() override;

        /**
         * Copy pending IDs from EjectRequests vector into out.
         *
         * Address: 0x0053CC60
         * Slot: 11
         * Demangled: _purecall
         */
        void CollectPendingIds(msvc8::vector<int>& out) override = 0;

        /**
         * Return small numeric property (client id, channel, etc.).
         *
         * Address: 0x0053CDC0
         * Slot: 12
         */
        int32_t GetSimRate() override;

        /**
         * Address: 0x0053B930
         * Slot: 13
         * Demangled: Moho::CClientBase::dtr
         */
        virtual ~CClientBase() = default;

        /**
         * Address: 0x0053B910
         * Slot: 14
         * Demangled: Moho::CClientBase::Open
         */
        virtual void Open() {}

        /**
         * Address: 0x00A82547
         * Slot: 15
         * Demangled: _purecall
         */
        virtual void Debug() = 0;

        /**
         * Address: 0x0053BD40
         */
        CClientBase(
            int clientIndex, 
            CClientManagerImpl* manager, 
            const char* name, 
            LaunchInfoBase* launchInfo, 
            BVIntSet& commandSources,
            uint32_t sourceId
        );

        /**
         * Address: 0x0053F2C0
         * @param manager 
         * @param beat 
         */
        void ProcessEject(CClientManagerImpl* manager, uint32_t beat) const;

        /**
         * Address: 0x0053CD50
         * @param requester
         */
        void RemoveEjectRequestsByRequester(const CClientBase* requester);

    public:
        CClientManagerImpl* mManager;
        int32_t gap;
        BVIntSet mValidCommandSources;
        uint32_t mCommandSourceId;
        bool mReady;
        gpg::PipeStream mPipe;
        uint32_t mQueuedBeat;
        uint32_t mDispatchedBeat;
        uint32_t mAvailableBeatRemote;
        msvc8::vector<int32_t> mLatestAckReceived;
        int32_t mLatestBeatDispatchedRemote;
        bool mEjectPending;
        bool mEjected;
        msvc8::vector<SEjectRequest*> mEjectRequests;
        int32_t mSimRate;
    };
    static_assert(sizeof(CClientBase) == 0xD8, "CLocalClient size must be 0xD8");
#pragma pack(pop)
}

