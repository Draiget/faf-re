#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAiResult.h"

namespace moho
{
  class Unit;
  class Sim;

  class CCommandTask : public CTask, public InstanceCounter<CCommandTask>
  {
  public:
    /**
     * Address: 0x00608DF0 (FUN_00608DF0)
     *
     * What it does:
     * Saves this object's members.
     */
    void MemberSerialize(gpg::WriteArchive* archive, int version, const gpg::RRef& ownerRef);

    /**
     * Address: 0x00608DE0 (FUN_00608DE0)
     *
     * What it does:
     * Loads this object's members.
     */
    void MemberDeserialize(gpg::ReadArchive* archive, int version, const gpg::RRef& ownerRef);

    /**
     * Address: 0x00598B30 (FUN_00598B30, scalar deleting thunk)
     * Address: 0x00608E90 (FUN_00608E90, non-deleting body)
     *
     * IDA signature:
     * volatile signed __int32 *__stdcall sub_608E90(Moho::CTask *a1);
     *
     * What it does:
     * Base teardown only: `InstanceCounter<CCommandTask>`'s -1, then `CTask`.
     */
    ~CCommandTask() override;

    /**
     * VFTable SLOT: 1 (CTask::Execute)
     *
     * What it does:
     * Default body for the `CCommandTask` vtable slot. Concrete task
     * subclasses (e.g. `CUnitMeleeAttackTargetTask`) override this with
     * real per-tick logic; the binary's `CCommandTask` vtable slot 1 is
     * `_purecall`, and reaching this fallback in a recovered build means
     * the derived vtable pointer was not written into `mCommandTaskStorage`.
     * Matches that intent by terminating.
     */
    int Execute() override;

    /**
     * Address: 0x00598A20 (FUN_00598A20, ??0CCommandTask@Moho@@QAE@@Z_0)
     *
     * Unit *, Sim *
     *
     * IDA signature:
     * Moho::CCommandTask *__stdcall Moho::CCommandTask::CCommandTask(
     *   Moho::CCommandTask *this, Moho::Unit *unit, Moho::Sim *sim);
     *
     * What it does:
     * Initializes a detached command task with explicit unit/sim context.
     */
    CCommandTask(Unit* unit, Sim* sim);

    /**
     * Address: 0x00598AB0 (FUN_00598AB0, ??0CCommandTask@Moho@@QAE@@Z_1)
     *
     * IDA signature:
     * Moho::CCommandTask *__stdcall Moho::CCommandTask::CCommandTask(Moho::CCommandTask *this);
     *
     * What it does:
     * Initializes a detached command task with null context.
     */
    CCommandTask();

    /**
     * Address: 0x005F08D0 (FUN_005F08D0, ??0CCommandTask@Moho@@QAE@@Z)
     *
     * CCommandTask *
     *
     * What it does:
     * Initializes one child command task from `parent` task context, inheriting
     * task-thread/unit/sim lanes and chaining dispatch-result storage.
     */
    explicit CCommandTask(CCommandTask* parent);

    /**
     * Address: 0x005F24B0 (FUN_005F24B0)
     *
     * What it does:
     * Returns the bound command-task unit lane pointer.
     */
    [[nodiscard]] Unit* GetUnit() const noexcept;

  public:
    static gpg::RType* sType;

    // 0x18: reserved/unknown dword (all observed constructors clear it to zero).
    std::uint32_t mReserved18;
    Unit* mUnit;                  // 0x1C
    Sim* mSim;                    // 0x20
    ETaskState mTaskState;        // 0x24
    EAiResult* mDispatchResult;   // 0x28
    EAiResult mLinkResult;        // 0x2C
  };

  class CCommandTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00608D30 (FUN_00608D30, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CCommandTaskTypeInfo() override;

    /**
     * Address: 0x0060C210 (FUN_0060C210, Moho::CCommandTaskTypeInfo::AddBase_CTask)
     *
     * What it does:
     * Registers `CTask` as the primary base at offset 0.
     */
    static void AddBase_CTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00608D20 (FUN_00608D20, ?GetName@CCommandTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00608D00 (FUN_00608D00, ?Init@CCommandTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CCommandTask) == 0x30, "CCommandTask size must be 0x30");
  static_assert(offsetof(CCommandTask, mReserved18) == 0x18, "CCommandTask::mReserved18 offset must be 0x18");
  static_assert(offsetof(CCommandTask, mUnit) == 0x1C, "CCommandTask::mUnit offset must be 0x1C");
  static_assert(offsetof(CCommandTask, mSim) == 0x20, "CCommandTask::mSim offset must be 0x20");
  static_assert(offsetof(CCommandTask, mTaskState) == 0x24, "CCommandTask::mTaskState offset must be 0x24");
  static_assert(
    offsetof(CCommandTask, mDispatchResult) == 0x28, "CCommandTask::mDispatchResult offset must be 0x28"
  );
  static_assert(offsetof(CCommandTask, mLinkResult) == 0x2C, "CCommandTask::mLinkResult offset must be 0x2C");
  static_assert(sizeof(CCommandTaskTypeInfo) == 0x64, "CCommandTaskTypeInfo size must be 0x64");

  // Six command tasks register their `Listener<ECommandEvent>` at +0x34, not
  // +0x30 where `CCommandTask` ends (CUnitCaptureTask, CUnitGuardTask,
  // CUnitMobileBuildTask, CUnitReclaimTask, CUnitRepairTask,
  // CUnitSacrificeTask). The compiler puts it there: `CCommandTask` ends with
  // an empty base (`InstanceCounter<CCommandTask>`, followed only by scalar
  // members) and `Listener`'s node starts with `boost::noncopyable`, and MSVC
  // pads between two such bases. `IAiCommandDispatchImpl` and
  // `CUnitScriptTask` put a vptr-led base there instead, with no gap.
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x005F22F0 (FUN_005F22F0, gpg::RRef_CCommandTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CCommandTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CCommandTask(gpg::RRef* outRef, moho::CCommandTask* value);
} // namespace gpg
