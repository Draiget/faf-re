#include "moho/script/CUnitScriptTask.h"

#include <exception>
#include <typeinfo>

#include "moho/misc/WeakPtr.h"

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

  [[nodiscard]] gpg::RRef MakeCUnitScriptTaskRef(CUnitScriptTask* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCUnitScriptTaskType();
    return ref;
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

