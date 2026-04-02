#include "moho/script/CUnitScriptTask.h"

#include <exception>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/CUnitCommand.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    if (!CUnitScriptTask::sType) {
      CUnitScriptTask::sType = gpg::LookupRType(typeid(CUnitScriptTask));
    }
    return CUnitScriptTask::sType;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* cached = CCommandTask::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    return CScriptObject::StaticGetClass();
  }

  [[nodiscard]] gpg::RType* CachedLuaObjectType()
  {
    gpg::RType* cached = LuaPlus::LuaObject::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    gpg::RType* cached = CUnitCommand::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CUnitCommand));
      CUnitCommand::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitScriptTaskRef(CUnitScriptTask* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCUnitScriptTaskType();
    return ref;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCommandRef(CUnitCommand* command)
  {
    gpg::RRef ref{};
    ref.mObj = nullptr;
    ref.mType = CachedCUnitCommandType();
    if (!command) {
      return ref;
    }

    gpg::RType* dynamicType = ref.mType;
    try {
      dynamicType = gpg::LookupRType(typeid(*command));
    } catch (...) {
      dynamicType = ref.mType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && ref.mType != nullptr && dynamicType->IsDerivedFrom(ref.mType, &baseOffset);
    if (!isDerived) {
      ref.mObj = command;
      ref.mType = dynamicType;
      return ref;
    }

    ref.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(command) - static_cast<std::uintptr_t>(baseOffset));
    ref.mType = dynamicType;
    return ref;
  }

  [[nodiscard]] CUnitCommand* ReadTrackedCUnitCommandPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandType());
    if (upcast.mObj) {
      return static_cast<CUnitCommand*>(upcast.mObj);
    }

    const char* const expected = CachedCUnitCommandType() ? CachedCUnitCommandType()->GetName() : "CUnitCommand";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "CUnitCommand",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  [[nodiscard]] CScriptObject* ResolveWarningObject(const WeakObject::ScopedWeakLinkGuard& guard)
  {
    const WeakObject::WeakLinkSlot* const ownerLinkSlot = guard.OwnerLinkSlotAddress();
    if (!ownerLinkSlot) {
      return nullptr;
    }

    return WeakPtr<CScriptObject>::DecodeOwnerObject(
      reinterpret_cast<void*>(const_cast<WeakObject::WeakLinkSlot*>(ownerLinkSlot))
    );
  }
} // namespace

gpg::RType* CUnitScriptTask::sType = nullptr;

/**
 * Address: 0x00622810 (FUN_00622810, default ctor)
 */
CUnitScriptTask::CUnitScriptTask()
  : CCommandTask()
  , CScriptObject()
  , Listener<ECommandEvent>()
  , mSourceCommand(nullptr)
  , mSourceLuaObj()
  , mTaskClassLua()
  , mTaskScriptPath()
{}

/**
 * Address: 0x00623140 (FUN_00623140, non-deleting body)
 */
CUnitScriptTask::~CUnitScriptTask()
{
  CallbackStr("OnDestroy");
  mListenerLink.ListUnlink();
}

/**
 * Address: 0x006227D0 (FUN_006227D0, ?GetClass@CUnitScriptTask@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CUnitScriptTask::GetClass() const
{
  return CachedCUnitScriptTaskType();
}

/**
 * Address: 0x006227F0 (FUN_006227F0, ?GetDerivedObjectRef@CUnitScriptTask@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CUnitScriptTask::GetDerivedObjectRef()
{
  return MakeCUnitScriptTaskRef(this);
}

/**
 * Address: 0x00624450 (FUN_00624450, Moho::CUnitScriptTask::MemberDeserialize)
 */
void CUnitScriptTask::MemberDeserialize(gpg::ReadArchive* const archive, CUnitScriptTask* const task, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version of CUnitScriptTask");
  }

  gpg::RRef owner{};
  archive->Read(CachedCCommandTaskType(), task, owner);

  CScriptObject* const scriptObject = task ? static_cast<CScriptObject*>(task) : nullptr;
  gpg::RRef scriptOwner{};
  archive->Read(CachedCScriptObjectType(), scriptObject, scriptOwner);

  gpg::RRef pointerOwner{};
  task->mSourceCommand = ReadTrackedCUnitCommandPointer(archive, pointerOwner);

  gpg::RRef luaOwner{};
  archive->Read(CachedLuaObjectType(), &task->mSourceLuaObj, luaOwner);
}

/**
 * Address: 0x00624550 (FUN_00624550, Moho::CUnitScriptTask::MemberSerialize)
 */
void CUnitScriptTask::MemberSerialize(CUnitScriptTask* const task, gpg::WriteArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version of CUnitScriptTask");
  }

  gpg::RRef owner{};
  archive->Write(CachedCCommandTaskType(), task, owner);

  CScriptObject* const scriptObject = task ? static_cast<CScriptObject*>(task) : nullptr;
  gpg::RRef scriptOwner{};
  archive->Write(CachedCScriptObjectType(), scriptObject, scriptOwner);

  const gpg::RRef sourceCommandRef = MakeCUnitCommandRef(task->mSourceCommand);
  gpg::WriteRawPointer(archive, sourceCommandRef, gpg::TrackedPointerState::Unowned, scriptOwner);

  gpg::RRef luaOwner{};
  archive->Write(CachedLuaObjectType(), &task->mSourceLuaObj, luaOwner);
}

/**
 * Address: 0x00622FC0 (FUN_00622FC0, CUnitScriptTask primary-slot update)
 */
int CUnitScriptTask::Execute()
{
  WeakObject::ScopedWeakLinkGuard weakGuard(static_cast<WeakObject*>(static_cast<CScriptObject*>(this)));

  try {
    return CScriptObject::TaskTick();
  } catch (const std::exception& ex) {
    LogScriptWarning(ResolveWarningObject(weakGuard), mTaskScriptPath.c_str(), ex.what());
  } catch (...) {
    LogScriptWarning(ResolveWarningObject(weakGuard), mTaskScriptPath.c_str(), "unknown exception");
  }

  return -1;
}

void CUnitScriptTask::OnEvent(const ECommandEvent)
{
  (void)Execute();
}
