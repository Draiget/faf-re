#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace moho
{
  class CUnitCommandQueue;

  enum ETaskStatus : std::int32_t;

  /**
   * VFTABLE: 0x00E1B3AC
   * COL:  0x00E70540
   *
   * RTTI hierarchy evidence:
   * - base `CCommandTask` at +0x00 (FUN_005998B0).
   * - base `IAiCommandDispatch` at +0x30 (FUN_00599910).
   * - base `Listener<EUnitCommandQueueStatus>` at +0x34 (FUN_00599970).
   */
  class IAiCommandDispatchImpl : public CCommandTask, public IAiCommandDispatch, public Listener<EUnitCommandQueueStatus>
  {
  public:
    /**
     * Address: 0x005990F0 (FUN_005990F0, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    ~IAiCommandDispatchImpl() override;

    /**
     * Address: 0x00598E80 (FUN_00598E80, ?TaskTick@IAiCommandDispatchImpl@Moho@@UAE?AW4ETaskStatus@2@XZ)
     *
     * VFTable SLOT: 1
     */
    virtual ETaskStatus TaskTick() = 0;

  public:
    static gpg::RType* sType;

    std::uint8_t mLastQueueStatus; // +0x40
    std::uint8_t mPadding41[3]{};
    CUnitCommandQueue* mCommandQueue; // +0x44
  };

  static_assert(sizeof(IAiCommandDispatchImpl) == 0x48, "IAiCommandDispatchImpl size must be 0x48");
  static_assert(
    offsetof(IAiCommandDispatchImpl, mLastQueueStatus) == 0x40, "IAiCommandDispatchImpl::mLastQueueStatus offset must be 0x40"
  );
  static_assert(
    offsetof(IAiCommandDispatchImpl, mCommandQueue) == 0x44, "IAiCommandDispatchImpl::mCommandQueue offset must be 0x44"
  );
} // namespace moho

