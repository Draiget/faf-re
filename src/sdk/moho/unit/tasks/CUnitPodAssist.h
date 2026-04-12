#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class Unit;

  /**
   * Task lane used when command-dispatch issues pod assist behavior.
   */
  class CUnitPodAssist : public CCommandTask
  {
  public:
    /**
     * Address: 0x0061D3B0 (FUN_0061D3B0, ??0CUnitPodAssist@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes pod-assist task state, marks the owning unit with
     * `UNITSTATE_AssistingCommander`, binds creator weak-target lane, and
     * transitions task state to waiting.
     */
    explicit CUnitPodAssist(CCommandTask* dispatchTask);

    /**
     * Address: 0x0061D7D0 (FUN_0061D7D0, Moho::CUnitPodAssist::operator new)
     *
     * What it does:
     * Allocates one pod-assist task and runs the dispatch-bound constructor.
     */
    [[nodiscard]] static CUnitPodAssist* Create(CCommandTask* dispatchTask);

    int Execute() override;

    /**
     * Address: 0x0061E970 (FUN_0061E970, Moho::CUnitPodAssist::MemberDeserialize)
     *
     * What it does:
     * Reads the CCommandTask base via the cached `CCommandTask` RType, then
     * reads the dispatch-task pointer (`mDispatchTask`) and the assist-target
     * `WeakPtr<Unit>` from the archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0061EA10 (FUN_0061EA10, Moho::CUnitPodAssist::MemberSerialize)
     *
     * What it does:
     * Writes the CCommandTask base, then writes the dispatch-task as an
     * UNOWNED raw pointer ref, then writes the assist-target weak ref.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    CCommandTask* mDispatchTask;   // 0x30
    WeakPtr<Unit> mAssistTarget;   // 0x34
  };

  static_assert(sizeof(CUnitPodAssist) == 0x3C, "CUnitPodAssist size must be 0x3C");
  static_assert(offsetof(CUnitPodAssist, mDispatchTask) == 0x30, "CUnitPodAssist::mDispatchTask offset must be 0x30");
  static_assert(offsetof(CUnitPodAssist, mAssistTarget) == 0x34, "CUnitPodAssist::mAssistTarget offset must be 0x34");
} // namespace moho
