#include "CCommandTask.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  alignas(CCommandTaskSerializer) unsigned char gCCommandTaskSerializerStorage[sizeof(CCommandTaskSerializer)]{};
  bool gCCommandTaskSerializerConstructed = false;

  alignas(CCommandTaskTypeInfo) unsigned char gCCommandTaskTypeInfoStorage[sizeof(CCommandTaskTypeInfo)]{};
  bool gCCommandTaskTypeInfoConstructed = false;

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mNext);
  }

  template <class TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mNext = self;
    serializer.mPrev = self;
  }

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mNext != nullptr && serializer.mPrev != nullptr) {
      static_cast<gpg::SerHelperBase*>(serializer.mNext)->mPrev = static_cast<gpg::SerHelperBase*>(serializer.mPrev);
      static_cast<gpg::SerHelperBase*>(serializer.mPrev)->mNext = static_cast<gpg::SerHelperBase*>(serializer.mNext);
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mPrev = self;
    serializer.mNext = self;
    return self;
  }

  [[nodiscard]] CCommandTaskSerializer* AcquireCCommandTaskSerializer()
  {
    if (!gCCommandTaskSerializerConstructed) {
      new (gCCommandTaskSerializerStorage) CCommandTaskSerializer();
      gCCommandTaskSerializerConstructed = true;
    }

    return reinterpret_cast<CCommandTaskSerializer*>(gCCommandTaskSerializerStorage);
  }

  [[nodiscard]] CCommandTaskTypeInfo* AcquireCCommandTaskTypeInfo()
  {
    if (!gCCommandTaskTypeInfoConstructed) {
      auto* const typeInfo = new (gCCommandTaskTypeInfoStorage) CCommandTaskTypeInfo();
      gpg::PreRegisterRType(typeid(CCommandTask), typeInfo);
      gCCommandTaskTypeInfoConstructed = true;
    }

    return reinterpret_cast<CCommandTaskTypeInfo*>(gCCommandTaskTypeInfoStorage);
  }

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

  gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Unit));
    }
    return cached;
  }

  gpg::RType* CachedSimType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Sim));
    }
    return cached;
  }

  gpg::RType* CachedEAiResultType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiResult));
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

  template <class TObject>
  gpg::RRef MakeDerivedRef(TObject* object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  gpg::RRef MakeEAiResultRef(EAiResult* const value)
  {
    gpg::RRef out{};
    out.mObj = value;
    out.mType = CachedEAiResultType();
    return out;
  }

  template <class TObject>
  TObject* ReadTypedPointer(
    gpg::ReadArchive* const archive, const gpg::RRef& ownerRef, gpg::RType* const expectedType, const char* const expectedName
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.type == expectedType) {
      return static_cast<TObject*>(tracked.object);
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    if (expectedType != nullptr && tracked.type != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
      if (upcast.mObj) {
        return static_cast<TObject*>(upcast.mObj);
      }
    }

    const char* const expectedTypeName = expectedType ? expectedType->GetName() : expectedName;
    const char* const actualTypeName = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedTypeName ? expectedTypeName : expectedName,
      actualTypeName ? actualTypeName : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  /**
   * Address: 0x00BF9AE0 (FUN_00BF9AE0, sub_BF9AE0)
   *
   * What it does:
   * Tears down static `CCommandTaskTypeInfo` storage at process exit.
   */
  void cleanup_CCommandTaskTypeInfo()
  {
    if (!gCCommandTaskTypeInfoConstructed) {
      return;
    }

    AcquireCCommandTaskTypeInfo()->~CCommandTaskTypeInfo();
    gCCommandTaskTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF9B40 (FUN_00BF9B40, CCommandTaskSerializer dtor/unlink)
   *
   * What it does:
   * Unlinks static `CCommandTaskSerializer` helper node from intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CCommandTaskSerializer()
  {
    if (!gCCommandTaskSerializerConstructed) {
      return nullptr;
    }
    return UnlinkSerializerNode(*AcquireCCommandTaskSerializer());
  }

  void cleanup_CCommandTaskSerializer_atexit()
  {
    (void)cleanup_CCommandTaskSerializer();
  }

  /**
   * Address: 0x00608CA0 (FUN_00608CA0, sub_608CA0)
   *
   * What it does:
   * Constructs and preregisters static RTTI descriptor storage for `CCommandTask`.
   */
  gpg::RType* construct_CCommandTaskTypeInfo()
  {
    return AcquireCCommandTaskTypeInfo();
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
  , mDispatchResult(nullptr)
  , mLinkResult(static_cast<EAiResult>(0))
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
  , mDispatchResult(nullptr)
  , mLinkResult(static_cast<EAiResult>(0))
{}

/**
 * Address: 0x00608DE0 (FUN_00608DE0, Moho::CCommandTaskSerializer::Deserialize)
 * Address: 0x0060CFC0 (FUN_0060CFC0, shared callback body)
 */
void CCommandTaskSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  auto* const task = reinterpret_cast<CCommandTask*>(static_cast<std::uintptr_t>(objectPtr));
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(task != nullptr);
  if (!archive || !task) {
    return;
  }

  const gpg::RRef owner{};
  archive->TrackPointer(MakeEAiResultRef(&task->mLinkResult));

  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = CachedCTaskType();
    CTask::sType = taskType;
  }
  archive->Read(taskType, static_cast<CTask*>(task), owner);

  task->mUnit = ReadTypedPointer<Unit>(archive, owner, CachedUnitType(), "Unit");
  task->mSim = ReadTypedPointer<Sim>(archive, owner, CachedSimType(), "Sim");

  int taskState = 0;
  archive->ReadInt(&taskState);
  task->mTaskState = static_cast<ETaskState>(taskState);

  gpg::RType* aiResultType = CachedEAiResultType();
  archive->Read(aiResultType, &task->mLinkResult, owner);
  task->mDispatchResult = ReadTypedPointer<EAiResult>(archive, owner, aiResultType, "EAiResult");
}

/**
 * Address: 0x00608DF0 (FUN_00608DF0, Moho::CCommandTaskSerializer::Serialize)
 * Address: 0x0060D0C0 (FUN_0060D0C0, shared callback body)
 */
void CCommandTaskSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  auto* const task = reinterpret_cast<CCommandTask*>(static_cast<std::uintptr_t>(objectPtr));
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(task != nullptr);
  if (!archive || !task) {
    return;
  }

  const gpg::RRef owner{};
  archive->PreCreatedPtr(MakeEAiResultRef(&task->mLinkResult));

  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = CachedCTaskType();
    CTask::sType = taskType;
  }
  archive->Write(taskType, static_cast<const CTask*>(task), owner);

  gpg::WriteRawPointer(archive, MakeDerivedRef(task->mUnit, CachedUnitType()), gpg::TrackedPointerState::Unowned, owner);
  gpg::WriteRawPointer(archive, MakeDerivedRef(task->mSim, CachedSimType()), gpg::TrackedPointerState::Unowned, owner);
  archive->WriteInt(static_cast<int>(task->mTaskState));

  gpg::RType* const aiResultType = CachedEAiResultType();
  archive->Write(aiResultType, &task->mLinkResult, owner);
  gpg::WriteRawPointer(
    archive, MakeEAiResultRef(task->mDispatchResult), gpg::TrackedPointerState::Unowned, owner
  );
}

/**
 * Address: 0x0060BA20 (FUN_0060BA20, sub_60BA20)
 */
void CCommandTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCCommandTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc ? mSerLoadFunc : &CCommandTaskSerializer::Deserialize;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc ? mSerSaveFunc : &CCommandTaskSerializer::Serialize;
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

namespace moho
{
  /**
   * Address: 0x00BD0570 (FUN_00BD0570, sub_BD0570)
   *
   * What it does:
   * Ensures `CCommandTask` RTTI descriptor storage is preregistered and
   * schedules process-exit teardown.
   */
  int register_CCommandTaskTypeInfo()
  {
    (void)construct_CCommandTaskTypeInfo();
    return std::atexit(&cleanup_CCommandTaskTypeInfo);
  }

  /**
   * Address: 0x00BD0590 (FUN_00BD0590, register_CCommandTaskSerializer)
   *
   * What it does:
   * Initializes serializer helper storage and binds load/save callbacks onto
   * `CCommandTask` reflected type metadata.
   */
  void register_CCommandTaskSerializer()
  {
    CCommandTaskSerializer* const serializer = AcquireCCommandTaskSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mSerLoadFunc = &CCommandTaskSerializer::Deserialize;
    serializer->mSerSaveFunc = &CCommandTaskSerializer::Serialize;
    serializer->RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_CCommandTaskSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct CCommandTaskReflectionBootstrap
  {
    CCommandTaskReflectionBootstrap()
    {
      (void)moho::register_CCommandTaskTypeInfo();
      moho::register_CCommandTaskSerializer();
    }
  };

  CCommandTaskReflectionBootstrap gCCommandTaskReflectionBootstrap;
} // namespace
