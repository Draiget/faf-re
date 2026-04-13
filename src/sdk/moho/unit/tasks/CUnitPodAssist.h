#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class RType;
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
    static gpg::RType* sType;

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

    /**
     * Address: 0x0061D4F0 (FUN_0061D4F0, ??1CUnitPodAssist@Moho@@QAE@@Z)
     *
     * What it does:
     * Executes pod-assist teardown by calling `Kill`, clearing the assisting
     * unit-state bit, unlinking assist-target weak-chain ownership, and
     * delegating final cleanup to `CCommandTask`.
     */
    ~CUnitPodAssist() override;

    int Execute() override;

    /**
     * Address: 0x0061D820 (FUN_0061D820, Moho::CUnitPodAssist::Kill)
     *
     * What it does:
     * Terminates active pod-assist transport linkage, detaches/removes pickup
     * reservations as needed, stops owner unit motion, and returns the task to
     * preparing state.
     */
    void Kill();

    /**
     * Address: 0x0061D9C0 (FUN_0061D9C0, Moho::CUnitPodAssist::HasNextCommand)
     *
     * What it does:
     * Returns true when owner command queue has at least two entries and the
     * next queued command weak slot resolves to a live command object.
     */
    [[nodiscard]] bool HasNextCommand() const;

    /**
     * Address: 0x0061DA00 (FUN_0061DA00)
     *
     * What it does:
     * For station-assist pod auto mode, scans nearby allied units in guard
     * radius, chooses the nearest eligible assist target, then dispatches
     * repair or reclaim follow-up work.
     */
    [[nodiscard]] bool TryIssueNearbyAssistTask();

    /**
     * Address: 0x0061DE50 (FUN_0061DE50)
     *
     * What it does:
     * For non-station pod assist lanes, evaluates current assist-target/focus
     * state and dispatches repair or reclaim follow-up work when possible.
     */
    [[nodiscard]] bool TryIssueFocusedAssistTask();

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

namespace gpg
{
  /**
   * Address: 0x0061E7C0 (FUN_0061E7C0, gpg::RRef_CUnitPodAssist)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitPodAssist*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitPodAssist(gpg::RRef* outRef, moho::CUnitPodAssist* value);
} // namespace gpg
