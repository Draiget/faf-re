#include "CCommandTask.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

using namespace moho;

namespace
{
  gpg::RType* CachedCCommandTaskType()
  {
    if (!CCommandTask::sType) {
      CCommandTask::sType = gpg::LookupRType(typeid(CCommandTask));
    }
    return CCommandTask::sType;
  }

  gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  void AddCTaskBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const taskType = CachedCTaskType();
    gpg::RField baseField{};
    baseField.mName = taskType->GetName();
    baseField.mType = taskType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

gpg::RType* CCommandTask::sType = nullptr;

/**
 * Address: 0x00608E90 (FUN_00608E90, non-deleting body)
 *
 * IDA signature:
 * volatile signed __int32 *__stdcall sub_608E90(Moho::CTask *a1);
 *
 * What it does:
 * Resets `CCommandTask` vtable, decrements command-task instance counter
 * bookkeeping, then runs `CTask` teardown.
 */
CCommandTask::~CCommandTask() = default;

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
CCommandTask::CCommandTask(Unit* const unit, Sim* const sim)
  : CTask(nullptr, false)
  , mReserved18(0)
  , mUnit(unit)
  , mSim(sim)
  , mTaskState(TASKSTATE_Preparing)
  , mDispatchLinkOwner(nullptr)
  , mDispatchLinkNext(nullptr)
{}

/**
 * Address: 0x00598AB0 (FUN_00598AB0, ??0CCommandTask@Moho@@QAE@@Z_1)
 *
 * IDA signature:
 * Moho::CCommandTask *__stdcall Moho::CCommandTask::CCommandTask(Moho::CCommandTask *this);
 *
 * What it does:
 * Initializes a detached command task with null context.
 */
CCommandTask::CCommandTask()
  : CTask(nullptr, false)
  , mReserved18(0)
  , mUnit(nullptr)
  , mSim(nullptr)
  , mTaskState(TASKSTATE_Preparing)
  , mDispatchLinkOwner(nullptr)
  , mDispatchLinkNext(nullptr)
{}

/**
 * Address: 0x0060BA20 (FUN_0060BA20, sub_60BA20)
 */
void CCommandTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCCommandTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x00608D30 (FUN_00608D30, scalar deleting destructor thunk)
 */
CCommandTaskTypeInfo::~CCommandTaskTypeInfo() = default;

/**
 * Address: 0x00608D20 (FUN_00608D20, ?GetName@CCommandTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CCommandTaskTypeInfo::GetName() const
{
  return "CCommandTask";
}

/**
 * Address: 0x00608D00 (FUN_00608D00, ?Init@CCommandTaskTypeInfo@Moho@@UAEXXZ)
 */
void CCommandTaskTypeInfo::Init()
{
  size_ = sizeof(CCommandTask);
  gpg::RType::Init();
  AddCTaskBaseToTypeInfo(this);
  Finish();
}
