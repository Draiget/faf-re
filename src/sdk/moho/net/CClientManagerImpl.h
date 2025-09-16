// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho
{
    /**
     * VFTABLE: 0x00E16B64
     * COL:  0x00E6AF24
     */
    class CClientManagerImpl {
    public:
        /**
         * Address: 0x0053E050
         * Slot: 0
         * Demangled: Moho::CClientManagerImpl::dtr
         */
        virtual ~CClientManagerImpl();
        /**
         * Address: 0x0053E180
         * Slot: 1
         * Demangled: Moho::CClientManagerImpl::CreateCLocalClient
         */
        virtual void CreateCLocalClient() = 0;
        /**
         * Address: 0x0053E260
         * Slot: 2
         * Demangled: Moho::CClientManagerImpl::CreateCNetClient
         */
        virtual void CreateCNetClient() = 0;
        /**
         * Address: 0x0053E400
         * Slot: 3
         * Demangled: Moho::CClientManagerImpl::CreateCReplayClient
         */
        virtual void CreateCReplayClient() = 0;
        /**
         * Address: 0x0053E330
         * Slot: 4
         * Demangled: Moho::CClientManagerImpl::CreateCNullClient
         */
        virtual void CreateCNullClient() = 0;
        /**
         * Address: 0x0053BCB0
         * Slot: 5
         * Demangled: Moho::CClientManagerImpl::GetConnector
         */
        virtual void GetConnector() = 0;
        /**
         * Address: 0x0053BCC0
         * Slot: 6
         * Demangled: Moho::CClientManagerImpl::NumberOfClients
         */
        virtual void NumberOfClients() = 0;
        /**
         * Address: 0x0053BCE0
         * Slot: 7
         * Demangled: Moho::CClientManagerImpl::GetClient
         */
        virtual void GetClient() = 0;
        /**
         * Address: 0x0053E470
         * Slot: 8
         * Demangled: Moho::CClientManagerImpl::GetClientWithData
         */
        virtual void GetClientWithData() = 0;
        /**
         * Address: 0x0053BD10
         * Slot: 9
         * Demangled: Moho::CClientManagerImpl::GetLocalClient
         */
        virtual void GetLocalClient() = 0;
        /**
         * Address: 0x0053BD20
         * Slot: 10
         * Demangled: Moho::CClientManagerImpl::SetUIInterface
         */
        virtual void SetUIInterface() = 0;
        /**
         * Address: 0x0053E4B0
         * Slot: 11
         * Demangled: Moho::CClientManagerImpl::Cleanup
         */
        virtual void Cleanup() = 0;
        /**
         * Address: 0x0053E560
         * Slot: 12
         * Demangled: Moho::CClientManagerImpl::IsEveryoneReady
         */
        virtual void IsEveryoneReady() = 0;
        /**
         * Address: 0x0053E590
         * Slot: 13
         * Demangled: Moho::CClientManagerImpl::SetSimRate
         */
        virtual void SetSimRate() = 0;
        /**
         * Address: 0x0053E720
         * Slot: 14
         * Demangled: Moho::CClientManagerImpl::GetSimRate
         */
        virtual void GetSimRate() = 0;
        /**
         * Address: 0x0053E7E0
         * Slot: 15
         * Demangled: Moho::CClientManagerImpl::GetSimRateRequested
         */
        virtual void GetSimRateRequested() = 0;
        /**
         * Address: 0x0053E850
         * Slot: 16
         * Demangled: Moho::CClientManagerImpl::Func1
         */
        virtual void Func1() = 0;
        /**
         * Address: 0x0053E990
         * Slot: 17
         * Demangled: Moho::CClientManagerImpl::ProcessClients
         */
        virtual void ProcessClients() = 0;
        /**
         * Address: 0x0053EA30
         * Slot: 18
         * Demangled: Moho::CClientManagerImpl::OnLoad
         */
        virtual void OnLoad() = 0;
        /**
         * Address: 0x0053EDA0
         * Slot: 19
         * Demangled: Moho::CClientManagerImpl::SelectEvent
         */
        virtual void SelectEvent() = 0;
        /**
         * Address: 0x0053EF90
         * Slot: 20
         * Demangled: Moho::CClientManagerImpl::GetPartiallyQueuedBeat
         */
        virtual void GetPartiallyQueuedBeat() = 0;
        /**
         * Address: 0x0053EFD0
         * Slot: 21
         * Demangled: Moho::CClientManagerImpl::GetAvailableBeat
         */
        virtual void GetAvailableBeat() = 0;
        /**
         * Address: 0x0053F010
         * Slot: 22
         * Demangled: Moho::CClientManagerImpl::UpdatePipelineStream
         */
        virtual void UpdatePipelineStream() = 0;
        /**
         * Address: 0x0053F4C0
         * Slot: 23
         * Demangled: Moho::CClientManagerImpl::Func3
         */
        virtual void Func3() = 0;
        /**
         * Address: 0x0053F5A0
         * Slot: 24
         * Demangled: Moho::CClientManagerImpl::Func4
         */
        virtual void Func4() = 0;
        /**
         * Address: 0x0053F920
         * Slot: 25
         * Demangled: Moho::CClientManagerImpl::Debug
         */
        virtual void Debug() = 0;
        /**
         * Address: 0x0053F830
         * Slot: 26
         * Demangled: Moho::CClientManagerImpl::Disconnect
         */
        virtual void Disconnect() = 0;
    };
} // namespace moho
