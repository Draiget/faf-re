#pragma once

#include "gpg/core/containers/Set.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/PipeStream.h"
#include "IClient.h"
#include "moho/containers/BVIntSet.h"
#include "moho/sim/SSyncFilter.h"
#include "platform/Platform.h"

#if defined(_MSVC_LANG)
#define MOHO_NET_LANG_STANDARD _MSVC_LANG
#else
#define MOHO_NET_LANG_STANDARD __cplusplus
#endif

#if MOHO_NET_LANG_STANDARD >= 201103L
#define MOHO_NET_STATIC_ASSERT(expr, message) static_assert((expr), message)
#else
#define MOHO_NET_STATIC_ASSERT(expr, message)
#endif

namespace moho
{
  class CClientBase;
  class CClientManagerImpl;

  struct SEjectRequest
  {
    const CClientBase* mRequester{nullptr};
    int mAfterBeat{0};
  };
  MOHO_NET_STATIC_ASSERT(sizeof(SEjectRequest) == 0x8, "SEjectRequest size must be 0x8");

  struct SClientBottleneckInfo
  {
    enum Type
    {
      Nothing = 0,
      Readiness = 1,
      Data = 2,
      Ack = 3,
    };

    Type mType{Nothing};
    int mVal{0};
    BVIntSet mSubobj;
    float mFloat{0.0f};
  };

  /**
   * VFTABLE: 0x00E16BD4
   * COL:     0x00E6AED8
   */
  class MOHO_EMPTY_BASES CClientBase : public IClient
  {
  public:
    /**
     * Address: 0x0053B930 (FUN_0053B930)
     * Slot: 0
     */
    BVIntSet* GetValidCommandSources() override;

    /**
     * Address: 0x0053C960 (FUN_0053C960)
     * Slot: 1
     */
    bool NoEjectionPending() override;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    float GetStatusMetricA() override = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    float GetStatusMetricB() override = 0;

    /**
     * Address: 0x0053CA60 (FUN_0053CA60)
     * Slot: 4
     */
    const msvc8::vector<int32_t>* GetLatestAcksVector() override;

    /**
     * Address: 0x0053CA90 (FUN_0053CA90)
     * Slot: 5
     */
    void GetLatestBeatDispatchedRemote(uint32_t& out) override;

    /**
     * Address: 0x0053CAD0 (FUN_0053CAD0)
     * Slot: 6
     */
    void GetAvailableBeatRemote(uint32_t& out) override;

    /**
     * Address: 0x00A82547 (_purecall in CClientBase vtable slot)
     * Address: 0x0053BF30 (FUN_0053BF30, out-of-line base body)
     * Slot: 7
     *
     * What it does:
     * Pure-virtual slot for per-client processing; concrete clients override this
     * and may delegate inbound handling to `CClientBase::Process(...)`.
     */
    void Process(CMessage& msg) override = 0;

    /**
     * Address: 0x0053C9A0 (FUN_0053C9A0)
     * Slot: 8
     */
    void ReceiveChat(gpg::MemBuffer<const char> data) override;

    /**
     * Address: 0x0053CA20 (FUN_0053CA20)
     * Slot: 9
     */
    void GetQueuedBeat(uint32_t& out) override;

    /**
     * Address: 0x0053CB10 (FUN_0053CB10)
     * Slot: 10
     */
    void Eject() override;

    /**
     * Address: 0x0053CC60 (FUN_0053CC60)
     * Slot: 11
     */
    void CollectPendingIds(msvc8::vector<int>& out) override;

    /**
     * Address: 0x0053CDC0 (FUN_0053CDC0)
     * Slot: 12
     */
    int32_t GetSimRate() override;

    /**
     * Address: 0x0053BE30 (FUN_0053BE30)
     * Slot: 13
     */
    virtual ~CClientBase();

    /**
     * Address: 0x0053B910 (FUN_0053B910)
     * Slot: 14
     */
    virtual void Open();

    /**
     * Address: 0x0053CDF0 (FUN_0053CDF0)
     * Slot: 15
     *
     * What it does:
     * Pure virtual in the base interface, but with a shared debug-dump body
     * used by concrete client debug implementations.
     */
    virtual void Debug() = 0;

    /**
     * Address: 0x0053BD40 (FUN_0053BD40)
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
     * Address: 0x0053CBB0 (FUN_0053CBB0)
     *
     * What it does:
     * Adds or updates an eject request authored by `requester`.
     */
    void AddOrUpdateEjectRequest(const CClientBase* requester, int afterBeat);

    /**
     * Address: 0x0053CC20 (FUN_0053CC20)
     *
     * What it does:
     * Returns the earliest beat among pending eject requests, or `mQueuedBeat` when none exist.
     *
     * Note:
     * Caller is expected to hold `mManager->mLock`.
     */
    void GetMostExpiredEjectRequest(int& outBeat) const;

    /**
     * Address: 0x0053CD50 (FUN_0053CD50)
     *
     * What it does:
     * Removes all eject requests created by `requester`.
     *
     * Note:
     * Caller is expected to hold `mManager->mLock`.
     */
    void RemoveEjectRequestsByRequester(const CClientBase* requester);

    /**
     * Address: 0x0053C3E0 (FUN_0053C3E0)
     *
     * What it does:
     * Returns whether this client is considered ready to advance to `beat`
     * under current ACK/eject state.
     *
     * Note:
     * Caller is expected to hold `mManager->mLock`.
     */
    bool IsReadyForBeat(int beat) const;

    /**
     * Address: 0x0053F2C0 (FUN_0053F2C0)
     */
    void ProcessEject(CClientManagerImpl* manager, uint32_t beat) const;

  private:
    /**
     * Address: 0x0053F440 (FUN_0053F440)
     * Address: 0x1012C6E0 (sub_1012C6E0)
     *
     * What it does:
     * Resolves requester index to a client pointer, records the eject request,
     * and notifies UI for non-local targets.
     */
    void HandleIncomingEjectRequest(uint8_t requesterClientIndex, int32_t afterBeat);

    /**
     * Address: 0x0053E810 (FUN_0053E810)
     * Address: 0x1012BB50 (sub_1012BB50)
     *
     * What it does:
     * Applies inbound adjustable-speed arbitration. Newer clocks win; ties are
     * broken by lower requester index.
     */
    void ApplyIncomingGameSpeedRequest(int32_t speedClock, int32_t requestedSimRate);

  public:
    CClientManagerImpl* mManager{nullptr};       // 0x028
    int32_t mUnknown2C{0};                       // 0x02C
    BVIntSet mValidCommandSources;               // 0x030
    uint32_t mCommandSourceId{0};                // 0x050
    bool mReady{false};                          // 0x054
    gpg::PipeStream mPipe;                       // 0x058
    uint32_t mQueuedBeat{0};                     // 0x0A0
    uint32_t mDispatchedBeat{0};                 // 0x0A4
    uint32_t mAvailableBeatRemote{0};            // 0x0A8
    msvc8::vector<int32_t> mLatestAckReceived;   // 0x0AC
    int32_t mLatestBeatDispatchedRemote{0};      // 0x0BC
    bool mEjectPending{false};                   // 0x0C0
    bool mEjected{false};                        // 0x0C1
    msvc8::vector<SEjectRequest> mEjectRequests; // 0x0C4
    int32_t mSimRate{0};                         // 0x0D4
  };
  MOHO_NET_STATIC_ASSERT(sizeof(CClientBase) == 0xD8, "CClientBase size must be 0xD8");
} // namespace moho

#undef MOHO_NET_STATIC_ASSERT
#undef MOHO_NET_LANG_STANDARD
