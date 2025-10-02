// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <cstdint>

#include "CMessageStream.h"
#include "gpg/core/containers/ByteSpan.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/Vector.h"

namespace moho
{
	class LaunchInfoBase;
	struct BVIntSet;

	/**
     * VFTABLE: 0x00E16ABC
     * COL:  0x00E6AFC0
     */
    class IClient
	{
    public:
        /**
         * Address: 0x00A82547
         * Slot: 0
         * Demangled: _purecall
         */
        virtual BVIntSet* GetValidCommandSources() = 0;

        /**
         * True if no ejection is pending.
         *
         * Address: 0x00A82547
         * Slot: 1
         * Demangled: _purecall
         */
        virtual bool NoEjectionPending() = 0;

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
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual const msvc8::vector<int32_t>* GetLatestAcksVector() = 0;

        /**
         * Output the latest beat dispatched to remote peer.
         *
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual void GetLatestBeatDispatchedRemote(uint32_t& out) = 0;

        /**
         * Output available remote beat counter.
         *
         * Address: 0x00A82547
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
        virtual void Process(CMessage& msg) = 0;

        /**
         * Build a message from raw span and forward to Process(...).
         *
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void ReceiveChat(gpg::MemBuffer<const char> data) = 0;

        /**
         * Output queued beat number.
         *
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void GetQueuedBeat(uint32_t& out) = 0;

        /**
         * Schedule ejection sequence; see CClientBase::Eject().
         *
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void Eject() = 0;

        /**
         * Copy pending IDs from EjectRequests vector into out.
         *
         * Address: 0x00A82547
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void CollectPendingIds(msvc8::vector<int>& out) = 0;

        /**
         * Return small numeric property (client id, channel, etc.).
         *
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual int GetSimRate() = 0;

        /**
         * Address: 0x0053B5E0
         */
        IClient(const char* name, int index, LaunchInfoBase* launchInfo);

    protected:
        msvc8::string mNickname;
        int mIndex;
        LaunchInfoBase* mLaunchInfo;
    };
    static_assert(sizeof(IClient) == 0x28, "IClient size must be 0x28");
}
