#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "gpg/core/reflection/Reflection.h"

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

  public:
    static gpg::RType* sType;

    // 0x18: reserved/unknown dword (all observed constructors clear it to zero).
    std::uint32_t mReserved18;
    Unit* mUnit;                       // 0x1C
    Sim* mSim;                         // 0x20
    ETaskState mTaskState;             // 0x24
    CCommandTask** mDispatchLinkOwner; // 0x28
    CCommandTask* mDispatchLinkNext;   // 0x2C
  };

  class CCommandTaskSerializer
  {
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
    offsetof(CCommandTask, mDispatchLinkOwner) == 0x28, "CCommandTask::mDispatchLinkOwner offset must be 0x28"
  );
  static_assert(
    offsetof(CCommandTask, mDispatchLinkNext) == 0x2C, "CCommandTask::mDispatchLinkNext offset must be 0x2C"
  );
  static_assert(sizeof(CCommandTaskSerializer) == 0x14, "CCommandTaskSerializer size must be 0x14");
  static_assert(sizeof(CCommandTaskTypeInfo) == 0x64, "CCommandTaskTypeInfo size must be 0x64");
} // namespace moho
