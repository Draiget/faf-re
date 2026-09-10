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

  class CCommandTask : public CTask
  {
  public:
    /**
     * Address: 0x00598B30 (FUN_00598B30, scalar deleting thunk)
     * Address: 0x00608E90 (FUN_00608E90, non-deleting body)
     *
     * IDA signature:
     * volatile signed __int32 *__stdcall sub_608E90(Moho::CTask *a1);
     *
     * What it does:
     * Resets `CCommandTask` vtable, decrements command-task instance counter
     * bookkeeping, then runs `CTask` teardown.
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

  class CCommandTaskSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD0590 (FUN_00BD0590, dynamic initializer for the global
     * `CCommandTaskSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CCommandTaskSerializer();

    /**
     * Address: 0x00BF9B40 (FUN_00BF9B40, Moho::CCommandTaskSerializer::~CCommandTaskSerializer)
     */
    ~CCommandTaskSerializer();

    /**
     * Address: 0x00608DE0 (FUN_00608DE0, Moho::CCommandTaskSerializer::Deserialize)
     *
     * What it does:
     * Loads base-task state, unit/sim pointers, task state, and dispatch-result
     * lanes while pre-tracking the in-object result value pointer.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00608DF0 (FUN_00608DF0, Moho::CCommandTaskSerializer::Serialize)
     *
     * What it does:
     * Saves base-task state, unit/sim pointers, task state, and dispatch-result
     * lanes while pre-registering the in-object result value pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0060BA20 (FUN_0060BA20, sub_60BA20)
     *
     * What it does:
     * Binds load/save serializer callbacks into CCommandTask RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  static_assert(
    offsetof(CCommandTaskSerializer, mSerLoadFunc) == 0x0C, "CCommandTaskSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CCommandTaskSerializer, mSerSaveFunc) == 0x10, "CCommandTaskSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(CCommandTaskSerializer) == 0x14, "CCommandTaskSerializer size must be 0x14");

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

  /**
   * `CCommandTask` plus the four-byte slot that sits between it and the
   * `Listener<ECommandEvent>` subobject of every command task that listens for
   * its own command's events.
   *
   * Six task types register that listener at +0x34 rather than +0x30, which is
   * where `CCommandTask` ends: `AddBase` stores the literal in
   * CUnitCaptureTask (0x005F1B90-family), CUnitGuardTask, CUnitMobileBuildTask,
   * CUnitReclaimTask, CUnitRepairTask and CUnitSacrificeTask. The two command
   * tasks with a differently-shaped second base register it at +0x30 with no
   * gap - `IAiCommandDispatchImpl` puts `IAiCommandDispatch` there
   * (0x00596E00) and `CUnitScriptTask` puts `CScriptObject` there
   * (0x00623E30) - so the four bytes belong to those six derived types, not to
   * `CCommandTask` itself.
   *
   * The slot used to be modelled as a separate empty-ish base declared between
   * `CCommandTask` and the listener in each of the six. That does not survive a
   * modern MSVC: it lays every polymorphic base out ahead of every
   * non-polymorphic one, so the pad was moved past the listener to the tail of
   * the class and the listener slid back to +0x30 - measured with
   * `/d1reportSingleClassLayout` on all six. Folding the slot into a
   * polymorphic intermediate keeps it where the binary puts it, because the
   * intermediate introduces no vfptr of its own and inherits `CCommandTask`'s
   * position.
   */
  class CCommandTaskWithListenerSlot : public CCommandTask
  {
  public:
    using CCommandTask::CCommandTask;

    /// +0x30. Never read; no command-task path in the binary touches it.
    std::uint32_t mListenerPad{0};
  };

  static_assert(
    sizeof(CCommandTaskWithListenerSlot) == 0x34, "CCommandTaskWithListenerSlot size must be 0x34"
  );
  static_assert(
    offsetof(CCommandTaskWithListenerSlot, mListenerPad) == 0x30,
    "CCommandTaskWithListenerSlot::mListenerPad offset must be 0x30"
  );
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
