#include "moho/task/CTaskThreadWeakPtrReflection.h"

#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/task/CTaskThread.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCTaskThreadType()
  {
    gpg::RType* cached = moho::CTaskThread::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CTaskThread));
      moho::CTaskThread::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCTaskThreadRef(moho::CTaskThread* thread)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedCTaskThreadType();
    if (!thread) {
      return out;
    }

    gpg::RType* dynamicType = CachedCTaskThreadType();
    try {
      dynamicType = gpg::LookupRType(typeid(*thread));
    } catch (...) {
      dynamicType = CachedCTaskThreadType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(CachedCTaskThreadType(), &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mObj = thread;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(thread) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
    * Alias of FUN_0040C4A0 (non-canonical helper lane).
   */
  [[nodiscard]] moho::CTaskThread* ReadPointerCTaskThread(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskThreadType());
    if (upcast.mObj) {
      return static_cast<moho::CTaskThread*>(upcast.mObj);
    }

    const char* const expected = CachedCTaskThreadType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "CTaskThread",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  alignas(moho::RWeakPtrType<moho::CTaskThread>)
    std::byte gWeakPtrCTaskThreadTypeStorage[sizeof(moho::RWeakPtrType<moho::CTaskThread>)]{};
  bool gWeakPtrCTaskThreadTypeConstructed = false;

  [[nodiscard]] moho::RWeakPtrType<moho::CTaskThread>& WeakPtrCTaskThreadTypeSlot()
  {
    return *reinterpret_cast<moho::RWeakPtrType<moho::CTaskThread>*>(gWeakPtrCTaskThreadTypeStorage);
  }
} // namespace

/**
 * Address: 0x0040B200 (FUN_0040B200, sub_40B200)
 *
 * What it does:
 * Rebinds one `WeakPtr<CTaskThread>` node to the intrusive owner chain of the
 * provided thread object.
 */
moho::WeakPtr<moho::CTaskThread>* moho::RelinkWeakPtrCTaskThread(
  moho::WeakPtr<moho::CTaskThread>* const weak, moho::CTaskThread* const thread
)
{
  if (!weak) {
    return nullptr;
  }

  weak->ResetFromObject(thread);
  return weak;
}

/**
 * Address: 0x0040BA70 (FUN_0040BA70, ??0RWeakPtrType_CTaskThread@Moho@@QAE@@Z)
 */
moho::RWeakPtrType<moho::CTaskThread>::RWeakPtrType()
  : gpg::RType()
  , gpg::RIndexed()
{
  gpg::PreRegisterRType(typeid(moho::WeakPtr<moho::CTaskThread>), this);
}

/**
 * Address: 0x0040BB50 (FUN_0040BB50, Moho::RWeakPtrType_CTaskThread::dtr)
 */
moho::RWeakPtrType<moho::CTaskThread>::~RWeakPtrType() = default;

/**
 * Address: 0x0040A300 (FUN_0040A300, Moho::RWeakPtrType_CTaskThread::GetName)
 */
const char* moho::RWeakPtrType<moho::CTaskThread>::GetName() const
{
  static msvc8::string cachedName;
  if (cachedName.empty()) {
    const char* const taskThreadTypeName = CachedCTaskThreadType()->GetName();
    cachedName = gpg::STR_Printf("WeakPtr<%s>", taskThreadTypeName ? taskThreadTypeName : "CTaskThread");
  }
  return cachedName.c_str();
}

/**
 * Address: 0x0040A3A0 (FUN_0040A3A0, Moho::RWeakPtrType_CTaskThread::Init)
 */
void moho::RWeakPtrType<moho::CTaskThread>::Init()
{
  size_ = 0x08;
  version_ = 1;
  serLoadFunc_ = &moho::WeakPtr_CTaskThread::Deserialize;
  serSaveFunc_ = &moho::WeakPtr_CTaskThread::Serialize;
}

/**
 * Address: 0x0040A3C0 (FUN_0040A3C0, Moho::RWeakPtrType_CTaskThread::GetLexical)
 */
msvc8::string moho::RWeakPtrType<moho::CTaskThread>::GetLexical(const gpg::RRef& ref) const
{
  auto* const weak = static_cast<const moho::WeakPtr<moho::CTaskThread>*>(ref.mObj);
  if (!weak || !weak->HasValue()) {
    return msvc8::string("NULL");
  }

  const gpg::RRef pointee = MakeCTaskThreadRef(weak->GetObjectPtr());
  if (!pointee.mObj) {
    return msvc8::string("NULL");
  }

  const msvc8::string inner = pointee.GetLexical();
  return gpg::STR_Printf("[%s]", inner.c_str());
}

/**
 * Address: 0x0040A550 (FUN_0040A550, Moho::RWeakPtrType_CTaskThread::IsIndexed)
 */
const gpg::RIndexed* moho::RWeakPtrType<moho::CTaskThread>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x0040A560 (FUN_0040A560, Moho::RWeakPtrType_CTaskThread::IsPointer)
 */
const gpg::RIndexed* moho::RWeakPtrType<moho::CTaskThread>::IsPointer() const
{
  return this;
}

/**
 * Address: 0x0040A570 (FUN_0040A570, Moho::RWeakPtrType_CTaskThread::GetCount)
 */
size_t moho::RWeakPtrType<moho::CTaskThread>::GetCount(void* obj) const
{
  auto* const weak = static_cast<moho::WeakPtr<moho::CTaskThread>*>(obj);
  if (!weak) {
    return 0u;
  }
  return weak->HasValue() ? 1u : 0u;
}

/**
 * Address: 0x0040A5A0 (FUN_0040A5A0, Moho::RWeakPtrType_CTaskThread::SubscriptIndex)
 */
gpg::RRef moho::RWeakPtrType<moho::CTaskThread>::SubscriptIndex(void* const obj, const int ind) const
{
  GPG_ASSERT(ind == 0);
  if (ind != 0) {
    return MakeCTaskThreadRef(nullptr);
  }

  auto* const weak = static_cast<moho::WeakPtr<moho::CTaskThread>*>(obj);
  if (!weak) {
    return MakeCTaskThreadRef(nullptr);
  }

  return MakeCTaskThreadRef(weak->GetObjectPtr());
}

/**
 * Address: 0x0040AD50 (FUN_0040AD50, Moho::WeakPtr_CTaskThread::Deserialize)
 */
void moho::WeakPtr_CTaskThread::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, int /*version*/, gpg::RRef* ownerRef
)
{
  auto* const weak = reinterpret_cast<moho::WeakPtr<moho::CTaskThread>*>(objectPtr);
  GPG_ASSERT(weak != nullptr);

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  RelinkWeakPtrCTaskThread(weak, ReadPointerCTaskThread(archive, owner));
}

/**
 * Address: 0x0040AD80 (FUN_0040AD80, Moho::WeakPtr_CTaskThread::Serialize)
 */
void moho::WeakPtr_CTaskThread::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, int /*version*/, gpg::RRef* ownerRef
)
{
  auto* const weak = reinterpret_cast<moho::WeakPtr<moho::CTaskThread>*>(objectPtr);
  GPG_ASSERT(weak != nullptr);

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const gpg::RRef objectRef = MakeCTaskThreadRef(weak ? weak->GetObjectPtr() : nullptr);
  gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
}

namespace moho
{
  /**
   * Address: 0x00BEE620 (FUN_00BEE620, ??1RWeakPtrType_CTaskThread@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for startup `RWeakPtrType<CTaskThread>`
   * storage.
   */
  void cleanup_RWeakPtrType_CTaskThread()
  {
    if (!gWeakPtrCTaskThreadTypeConstructed) {
      return;
    }

    WeakPtrCTaskThreadTypeSlot().~RWeakPtrType();
    gWeakPtrCTaskThreadTypeConstructed = false;
  }

  /**
   * Address: 0x00BC3120 (FUN_00BC3120, register_RWeakPtrType_CTaskThread)
   *
   * What it does:
   * Materializes startup `RWeakPtrType<CTaskThread>` storage and registers
   * process-exit teardown.
   */
  void register_RWeakPtrType_CTaskThread()
  {
    if (!gWeakPtrCTaskThreadTypeConstructed) {
      ::new (static_cast<void*>(&WeakPtrCTaskThreadTypeSlot())) RWeakPtrType<CTaskThread>();
      gWeakPtrCTaskThreadTypeConstructed = true;
    }

    (void)std::atexit(&cleanup_RWeakPtrType_CTaskThread);
  }
} // namespace moho

namespace
{
  struct WeakPtrCTaskThreadReflectionBootstrap
  {
    WeakPtrCTaskThreadReflectionBootstrap()
    {
      moho::register_RWeakPtrType_CTaskThread();
    }
  };

  [[maybe_unused]] WeakPtrCTaskThreadReflectionBootstrap gWeakPtrCTaskThreadReflectionBootstrap;
} // namespace
