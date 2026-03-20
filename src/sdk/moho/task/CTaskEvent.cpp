#include "CTaskEvent.h"

#include <stdexcept>
#include <typeinfo>

#include "CTaskThread.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

using namespace moho;

namespace gpg
{
  enum class TrackedPointerState : int
  {
    Unowned = 1,
    Owned = 2,
  };

  struct TrackedPointerInfo
  {
    void* object;
    gpg::RType* type;
  };

  TrackedPointerInfo ReadRawPointer(ReadArchive* archive, const gpg::RRef& ownerRef);
  void WriteRawPointer(
    WriteArchive* archive, const gpg::RRef& objectRef, TrackedPointerState state, const gpg::RRef& ownerRef
  );
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
} // namespace gpg

namespace
{
  gpg::RType* CachedCTaskEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTaskEvent));
    }
    return cached;
  }

  gpg::RType* CachedSTaskEventLinkageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(STaskEventLinkage));
    }
    return cached;
  }

  gpg::RRef MakeSTaskEventLinkageRef(STaskEventLinkage* linkage)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedSTaskEventLinkageType();
    if (!linkage) {
      return out;
    }

    gpg::RType* dynamicType = CachedSTaskEventLinkageType();
    try {
      dynamicType = gpg::LookupRType(typeid(*linkage));
    } catch (...) {
      dynamicType = CachedSTaskEventLinkageType();
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(CachedSTaskEventLinkageType(), &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = linkage;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(linkage) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  STaskEventLinkage* ReadOwnedSTaskEventLinkagePointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTaskEventLinkageType());
    if (upcast.mObj) {
      return static_cast<STaskEventLinkage*>(upcast.mObj);
    }

    const char* const expected = CachedSTaskEventLinkageType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "STaskEventLinkage",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  /**
   * Address: 0x00406EC0 (FUN_00406EC0, Moho::CTaskEventSerializer::Deserialize)
   *
   * What it does:
   * Loads trigger flag and event wait-link intrusive list.
   */
  void DeserializeCTaskEvent(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const event = reinterpret_cast<CTaskEvent*>(objectPtr);
    GPG_ASSERT(event != nullptr);
    archive->ReadBool(&event->mTriggered);
    event->DeserializeWaitLinks(archive);
  }

  /**
   * Address: 0x00406EF0 (FUN_00406EF0, Moho::CTaskEventSerializer::Serialize)
   *
   * What it does:
   * Saves trigger flag and event wait-link intrusive list.
   */
  void SerializeCTaskEvent(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const event = reinterpret_cast<CTaskEvent*>(objectPtr);
    GPG_ASSERT(event != nullptr);
    archive->WriteBool(event->mTriggered);
    event->SerializeWaitLinks(archive);
  }
} // namespace

/**
 * Address: 0x00406D30 (FUN_00406D30, ??1STaskEventLinkage@Moho@@QAE@XZ)
 *
 * What it does:
 * Unbinds weak references from both directions and unlinks this node from the
 * parent event wait-list.
 */
STaskEventLinkage::~STaskEventLinkage()
{
  mThreadRef.ResetFromObject(nullptr);

  for (WeakPtr<STaskEventLinkage>* node = mOwnerWeakRefHead; node != nullptr;) {
    WeakPtr<STaskEventLinkage>* const next = node->nextInOwner;
    node->ownerLinkSlot = nullptr;
    node->nextInOwner = nullptr;
    node = next;
  }
  mOwnerWeakRefHead = nullptr;

  ListUnlink();
}

/**
 * Address: 0x00406C70 (FUN_00406C70, ??1CTaskEvent@Moho@@UAE@XZ)
 *
 * What it does:
 * Destroys all wait-link nodes, destroys their waiting threads when still
 * valid, then unlinks this event from its owner list.
 */
CTaskEvent::~CTaskEvent()
{
  while (mWaitLinks.mNext != &mWaitLinks) {
    auto* const link = static_cast<STaskEventLinkage*>(mWaitLinks.mNext);
    CTaskThread* const waitingThread = link->mThreadRef.GetObjectPtr();
    delete link;
    if (waitingThread != nullptr) {
      waitingThread->Destroy();
    }
  }

  mWaitLinks.ListUnlink();
}

/**
 * Address: 0x00406E20 (FUN_00406E20, ?EventWait@CTaskEvent@Moho@@QAEPAUSTaskEventLinkage@2@PAVCTaskThread@2@@Z)
 *
 * What it does:
 * Stages the provided thread when needed, allocates a new wait-link node,
 * binds its thread weak-link, then appends it to this event wait-list.
 */
STaskEventLinkage* CTaskEvent::EventWait(CTaskThread* const thread)
{
  if (mTriggered) {
    return nullptr;
  }

  if (!thread->mStaged) {
    thread->Stage();
  }

  auto* const linkage = new STaskEventLinkage();
  linkage->mThreadRef.ResetFromObject(thread);
  linkage->ListLinkBefore(&mWaitLinks);
  return linkage;
}

/**
 * Address: 0x00406D90 (FUN_00406D90, ?EventSetSignaled@CTaskEvent@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Applies signaled state; when set to true, drains all wait links, clears
 * pending-frame throttles, and unstages waiting threads.
 */
void CTaskEvent::EventSetSignaled(const bool signaled)
{
  if (signaled) {
    while (mWaitLinks.mNext != &mWaitLinks) {
      auto* const linkage = static_cast<STaskEventLinkage*>(mWaitLinks.mNext);
      CTaskThread* const thread = linkage->mThreadRef.GetObjectPtr();

      delete linkage;

      if (thread) {
        thread->mPendingFrames = 0;
        if (thread->mStaged) {
          thread->Unstage();
        }
      }
    }
  }

  mTriggered = signaled;
}

/**
 * Address: 0x00407020 (FUN_00407020, ?SerThreads@CTaskEvent@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 */
void CTaskEvent::DeserializeWaitLinks(gpg::ReadArchive* const archive)
{
  const gpg::RRef owner{};
  while (true) {
    STaskEventLinkage* const linkage = ReadOwnedSTaskEventLinkagePointer(archive, owner);
    if (!linkage) {
      return;
    }
    linkage->ListLinkBefore(&mWaitLinks);
  }
}

/**
 * Address: 0x00406FB0 (FUN_00406FB0, ?SerThreads@CTaskEvent@Moho@@ABEXAAVWriteArchive@gpg@@H@Z)
 */
void CTaskEvent::SerializeWaitLinks(gpg::WriteArchive* const archive) const
{
  const gpg::RRef owner{};
  auto* const listEnd = reinterpret_cast<const STaskEventLinkage*>(&mWaitLinks);
  for (auto* node = static_cast<STaskEventLinkage*>(mWaitLinks.mNext); node != listEnd;
       node = static_cast<STaskEventLinkage*>(node->mNext)) {
    const gpg::RRef objectRef = MakeSTaskEventLinkageRef(node);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Owned, owner);
  }

  const gpg::RRef nullRef = MakeSTaskEventLinkageRef(nullptr);
  gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Unowned, owner);
}

/**
 * Address: 0x00407620 (FUN_00407620, ?Init@CTaskEventSerializer@Moho@@UAEXXZ)
 *
 * What it does:
 * Installs CTaskEvent RTTI serialization callbacks.
 */
void CTaskEventSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCTaskEventType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCTaskEvent;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCTaskEvent;
}

/**
 * Address: 0x00406B60 (FUN_00406B60, scalar deleting destructor thunk)
 */
CTaskEventTypeInfo::~CTaskEventTypeInfo() = default;

/**
 * Address: 0x00406B50 (FUN_00406B50, ?GetName@CTaskEventTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CTaskEventTypeInfo::GetName() const
{
  return "CTaskEvent";
}

/**
 * Address: 0x00406B30 (FUN_00406B30, ?Init@CTaskEventTypeInfo@Moho@@UAEXXZ)
 */
void CTaskEventTypeInfo::Init()
{
  size_ = sizeof(CTaskEvent);
  gpg::RType::Init();
  Finish();
}
