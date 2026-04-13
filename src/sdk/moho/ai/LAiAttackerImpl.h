#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/task/CTask.h"

namespace moho
{
  class CAiAttackerImpl;

  /**
   * VFTABLE: 0x00E1EA88
   * COL:  0x00E759EC
   *
   * RTTI hierarchy evidence:
   * - Base `CTask` at +0x00.
   * - Size: 0x20 bytes.
   * - `CAiAttackerImpl*` lane at +0x1C (serializer/runtime evidence).
   */
  class LAiAttackerImpl : public CTask
  {
  public:
    /**
     * Address: 0x005D5F30 (FUN_005D5F30, Moho::LAiAttackerImpl::LAiAttackerImpl)
     *
     * What it does:
     * Initializes one detached AI attacker task shell and binds the owning
     * `CAiAttackerImpl` lane.
     */
    explicit LAiAttackerImpl(CAiAttackerImpl* owner);

    /**
     * Address: 0x005D5FD0 (FUN_005D5FD0, Moho::LAiAttackerImpl::dtr)
     * Address: 0x005D5FF0 (FUN_005D5FF0, destructor body helper)
     * Slot: 0
     *
     * What it does:
     * Decrements the LAiAttackerImpl instance-counter stat and tears down the
     * base `CTask`.
     */
    ~LAiAttackerImpl() override;

    /**
     * Address: 0x005D5FB0 (FUN_005D5FB0, Moho::LAiAttackerImpl::TaskTick)
     * Slot: 1
     *
     * What it does:
     * Advances one frame on the owning attacker task-stage and returns
     * completion code `1`.
     */
    int Execute() override;

  public:
    std::uint32_t mReserved18; // +0x18
    CAiAttackerImpl* cImpl;    // +0x1C
  };

  static_assert(offsetof(LAiAttackerImpl, cImpl) == 0x1C, "LAiAttackerImpl::cImpl offset must be 0x1C");
  static_assert(sizeof(LAiAttackerImpl) == 0x20, "LAiAttackerImpl size must be 0x20");
} // namespace moho
