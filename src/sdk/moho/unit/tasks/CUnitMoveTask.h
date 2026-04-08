#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  class CUnitMoveTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x00618A70 (FUN_00618A70, Moho::CUnitMoveTask::OnEvent)
     *
     * What it does:
     * Issues a follow-up call-transport task once for the owning unit when
     * ferry-assigned transport context is valid, and unlinks the navigator
     * listener lane before dispatching.
     */
    int OnEvent();

  public:
    std::uint32_t mUnknown0030; // 0x30
    std::uint32_t mNavigatorListenerVftable; // 0x34
    Broadcaster mNavigatorListenerLink; // 0x38
    std::uint8_t mPad_0040_0060[0x20]; // 0x40
    CCommandTask* mDispatchTask; // 0x60
    std::uint8_t mPad_0064_0091[0x2D]; // 0x64
    std::uint8_t mRequiresTransportCategoryCheck; // 0x91
    std::uint8_t mResetLinkOnDispatch; // 0x92
    std::uint8_t mTransportDispatchIssued; // 0x93
  };

  static_assert(offsetof(CUnitMoveTask, mNavigatorListenerVftable) == 0x34, "CUnitMoveTask::mNavigatorListenerVftable offset must be 0x34");
  static_assert(offsetof(CUnitMoveTask, mNavigatorListenerLink) == 0x38, "CUnitMoveTask::mNavigatorListenerLink offset must be 0x38");
  static_assert(offsetof(CUnitMoveTask, mDispatchTask) == 0x60, "CUnitMoveTask::mDispatchTask offset must be 0x60");
  static_assert(
    offsetof(CUnitMoveTask, mRequiresTransportCategoryCheck) == 0x91,
    "CUnitMoveTask::mRequiresTransportCategoryCheck offset must be 0x91"
  );
  static_assert(
    offsetof(CUnitMoveTask, mTransportDispatchIssued) == 0x93,
    "CUnitMoveTask::mTransportDispatchIssued offset must be 0x93"
  );
} // namespace moho
