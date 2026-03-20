#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/condition.h"
#include "boost/thread.h"
#include "CClientBase.h"
#include "CMessage.h"

namespace gpg
{
  class Stream;
}

namespace moho
{
  class CClientManagerImpl;

  /**
   * VFTABLE: 0x00E16CAC
   * COL:     0x00E6ADE8
   */
  class CReplayClient : public CClientBase
  {
  public:
    /**
     * Address: 0x0053BA50 (FUN_0053BA50)
     *
     * CClientManagerImpl *, BVIntSet &, gpg::Stream *&
     *
     * What it does:
     * Builds a replay-backed client (`index=0`, nickname `"Replay"`) and
     * takes ownership of the replay stream pointer from `replayStream`.
     */
    CReplayClient(CClientManagerImpl* manager, BVIntSet& commandSources, gpg::Stream*& replayStream);

    /**
     * Address: 0x0053BB40 (FUN_0053BB40)
     * Slot: 13
     *
     * What it does:
     * Scalar-deleting virtual teardown entry.
     */
    ~CReplayClient() override;

    /**
     * Address: 0x0053BB20 (FUN_0053BB20)
     * Slot: 2
     *
     * What it does:
     * Returns constant `0.0f`.
     */
    float GetStatusMetricA() override;

    /**
     * Address: 0x0053BB30 (FUN_0053BB30)
     * Slot: 3
     *
     * What it does:
     * Returns constant `0.0f`.
     */
    float GetStatusMetricB() override;

    /**
     * Address: 0x0053D900 (FUN_0053D900)
     * Slot: 7
     *
     * CMessage &
     *
     * What it does:
     * Handles replay-control opcodes (`0`, `51`, `52`, `53`) and forwards
     * synthesized client messages through shared `CClientBase` processing.
     */
    void Process(CMessage& msg) override;

    /**
     * Address: 0x0053DC00 (FUN_0053DC00)
     * Slot: 15
     *
     * What it does:
     * Dumps replay-client state and forwards the base debug dump.
     */
    void Debug() override;

    /**
     * Address: 0x0053D360 (FUN_0053D360)
     *
     * What it does:
     * Drains replay stream messages into `CClientBase::Process(...)`,
     * handles replay EOF shutdown flow, and schedules/alerts replay worker.
     */
    void Start();

  private:
    /**
     * Address: 0x0053D240 (FUN_0053D240)
     *
     * What it does:
     * Non-deleting teardown body used by scalar-deleting destructor path.
     */
    void DestroyNonDeleting();

    /**
     * Address: 0x0053D7A0 (FUN_0053D7A0, func_ReplayThread)
     *
     * What it does:
     * Worker loop that polls replay stream readiness and signals manager event.
     */
    static void ReplayThreadMain(CReplayClient* self);

  public:
    gpg::Stream* mReplayStream{nullptr};     // 0x0D8
    CMessage mReplayMessage;                 // 0x0E0
    std::uint32_t mReserved134{0};           // 0x134
    std::int32_t mReplayBeat{0};             // 0x138
    bool mCurrentSourceAllowed{false};       // 0x13C
    std::uint8_t mReserved13D[3]{};          // 0x13D
    boost::thread* mReplayThread{nullptr};   // 0x140
    boost::condition mReplayWorkerCondition; // 0x144
    bool mReplayPollRequested{false};        // 0x15C
    bool mReplayThreadStopRequested{false};  // 0x15D
    std::uint8_t mReserved15E[2]{};          // 0x15E
  };

#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(offsetof(CReplayClient, mReplayStream) == 0x0D8, "CReplayClient::mReplayStream offset must be 0x0D8");
  static_assert(offsetof(CReplayClient, mReplayMessage) == 0x0E0, "CReplayClient::mReplayMessage offset must be 0x0E0");
  static_assert(offsetof(CReplayClient, mReplayBeat) == 0x138, "CReplayClient::mReplayBeat offset must be 0x138");
  static_assert(
    offsetof(CReplayClient, mCurrentSourceAllowed) == 0x13C, "CReplayClient::mCurrentSourceAllowed offset must be 0x13C"
  );
  static_assert(offsetof(CReplayClient, mReplayThread) == 0x140, "CReplayClient::mReplayThread offset must be 0x140");
  static_assert(
    offsetof(CReplayClient, mReplayWorkerCondition) == 0x144,
    "CReplayClient::mReplayWorkerCondition offset must be 0x144"
  );
  static_assert(
    offsetof(CReplayClient, mReplayPollRequested) == 0x15C, "CReplayClient::mReplayPollRequested offset must be 0x15C"
  );
  static_assert(
    offsetof(CReplayClient, mReplayThreadStopRequested) == 0x15D,
    "CReplayClient::mReplayThreadStopRequested offset must be 0x15D"
  );
  static_assert(sizeof(CReplayClient) == 0x160, "CReplayClient size must be 0x160");
#endif
} // namespace moho
