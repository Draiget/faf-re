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

  class CCommandTaskSerializer
  {
  public:
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

  public:
    /**
     * Address: 0x0060BA20 (FUN_0060BA20, sub_60BA20)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CCommandTask RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
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
  static_assert(sizeof(CCommandTaskSerializer) == 0x14, "CCommandTaskSerializer size must be 0x14");
  static_assert(sizeof(CCommandTaskTypeInfo) == 0x64, "CCommandTaskTypeInfo size must be 0x64");
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
