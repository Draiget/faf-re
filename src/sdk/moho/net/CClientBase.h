#pragma once

#include "IClient.h"
#include "gpg/core/containers/Set.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/PipeStream.h"
#include "moho/sim/SSyncFilter.h"
#include "platform/Platform.h"

namespace moho
{
	class CClientManagerImpl;

    struct EjectRequest
    {
        gpg::StrArg* mRequester;
        int mAfterBeat;
    };

	/**
     * VFTABLE: 0x00E16BD4
     * COL:  0x00E6AED8
     */
    class CClientBase : public IClient
	{
    public:
        /**
         * Address: 
         * Slot: 0
         * Demangled: 
         */
        virtual Set* GetValidCommandSources() = 0;

        /**
         * True if no ejection is pending.
         *
         * Address: 0x0053C960
         * Slot: 1
         * Demangled: _purecall
         */
        virtual bool NoEjectionPending();

        /**
         * TODO: name/semantics unknown (pure).
         *
         * Address: 0x00A82547
         * Slot: 2
         * Demangled: _purecall
         */
        virtual void OnAttach() = 0;

        /**
         * TODO: name/semantics unknown (pure).
         *
         * Address: 0x00A82547
         * Slot: 3
         * Demangled: _purecall
         */
        virtual void OnDetach() = 0;

        /**
         * Return pointer to latest-acks vector payload (implementation detail).
         *
         * Address: 0x0053CA60
         * Slot: 4
         * Demangled: _purecall
         */
        virtual const void* GetLatestAcksVector() = 0;

        /**
         * Output the latest beat dispatched to remote peer.
         *
         * Address: 0x0053CA90
         * Slot: 5
         * Demangled: _purecall
         */
        virtual void GetLatestBeatDispatchedRemote(uint32_t& out) = 0;

        /**
         * Output available remote beat counter.
         *
         * Address: 0x0053CAD0
         * Slot: 6
         * Demangled: _purecall
         */
        virtual void GetAvailableBeatRemote(uint32_t& out) = 0;

        /**
         * Core message processor invoked by CClientBase::DispatchRawBuffer.
         *
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual void Process(CMessage& msg, int a, int b) = 0;

        /**
         * Build a message from raw span and forward to Process(...).
         *
         * Address: 0x0053C9A0
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void DispatchRawBuffer(const gpg::ByteSpan& span) = 0;

        /**
         * Output queued beat number.
         *
         * Address: 0x0053CA20
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void GetQueuedBeat(uint32_t& out) = 0;

        /**
         * Schedule ejection sequence; see CClientBase::Eject().
         *
         * Address: 0x0053CB10
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void Eject() = 0;

        /**
         * Copy pending IDs from EjectRequests vector into out.
         *
         * Address: 0x0053CC60
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void CollectPendingIds(msvc8::vector<int>& out) = 0;

        /**
         * Return small numeric property (client id, channel, etc.).
         *
         * Address: 0x0053CDC0
         * Slot: 12
         * Demangled: _purecall
         */
        virtual int GetClientNumeric() = 0;

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

    public:
        CClientManagerImpl* mManager;
        BYTE gap2C[4];
        SSyncFilter::Subobj1 mValidCommandSources;
        BYTE gap44[12];
        DWORD mCommandSource;
        BYTE mReady;
        gpg::PipeStream mPipe;
        DWORD mQueuedBeat;
        DWORD mDispatchedBeat;
        DWORD mAvailableBeatRemote;
        msvc8::vector<void*> mLatestAckReceived;
        DWORD mLatestBeatDispatchedRemote;
        BYTE mEjectPending;
        BYTE mEjected;
        msvc8::vector<EjectRequest*> mEjectRequests;
        int v1;
    };
} // namespace moho
