#pragma once
#include <cstdint>

#include "CMessageStream.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  struct BVIntSet;

  /**
   * VFTABLE: 0x00E16ABC
   * COL:     0x00E6AFC0
   */
  class IClient
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     */
    virtual BVIntSet* GetValidCommandSources() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     *
     * What it does:
     * Returns true when no ejection is pending for this client.
     */
    virtual bool NoEjectionPending() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     *
     * What it does:
     * Returns an auxiliary status metric. Exact semantics are still unresolved.
     * Local clients return 0 in FA; net clients query their transport peer.
     */
    virtual float GetStatusMetricA() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     *
     * What it does:
     * Returns a second auxiliary status metric. Exact semantics are unresolved.
     * Local clients return 0 in FA; net clients return -1 when no peer exists.
     */
    virtual float GetStatusMetricB() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     */
    virtual const msvc8::vector<int32_t>* GetLatestAcksVector() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 5
     */
    virtual void GetLatestBeatDispatchedRemote(uint32_t& out) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 6
     */
    virtual void GetAvailableBeatRemote(uint32_t& out) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 7
     */
    virtual void Process(CMessage& msg) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 8
     */
    virtual void ReceiveChat(gpg::MemBuffer<const char> data) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 9
     */
    virtual void GetQueuedBeat(uint32_t& out) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 10
     */
    virtual void Eject() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 11
     */
    virtual void CollectPendingIds(msvc8::vector<int>& out) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 12
     */
    virtual int GetSimRate() = 0;

    /**
     * Address: 0x0053B5E0 (FUN_0053B5E0)
     */
    IClient(const char* name, int index, int32_t ownerId);

    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Exposes the per-owner id lane tracked by this client record.
     */
    [[nodiscard]]
    int32_t GetOwnerId() const
    {
      return mOwnerId;
    }

  protected:
    msvc8::string mNickname;
    int mIndex{0};
    int32_t mOwnerId{0};
  };
  static_assert(sizeof(IClient) == 0x28, "IClient size must be 0x28");
} // namespace moho
