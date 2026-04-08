#include "CTaskEvent.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "CTaskThread.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"

using namespace moho;

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

  gpg::RType* CachedWeakPtrCTaskThreadType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakPtr<CTaskThread>));
    }
    return cached;
  }

  alignas(moho::STaskEventLinkageTypeInfo)
    std::byte gSTaskEventLinkageTypeInfoStorage[sizeof(moho::STaskEventLinkageTypeInfo)]{};
  alignas(moho::STaskEventLinkageSerializer)
    std::byte gSTaskEventLinkageSerializerStorage[sizeof(moho::STaskEventLinkageSerializer)]{};
  alignas(moho::CTaskEventTypeInfo) std::byte gCTaskEventTypeInfoStorage[sizeof(moho::CTaskEventTypeInfo)]{};
  bool gSTaskEventLinkageTypeInfoConstructed = false;
  bool gSTaskEventLinkageSerializerConstructed = false;
  bool gCTaskEventTypeInfoConstructed = false;

  [[nodiscard]] moho::STaskEventLinkageTypeInfo& STaskEventLinkageTypeInfoSlot()
  {
    return *reinterpret_cast<moho::STaskEventLinkageTypeInfo*>(gSTaskEventLinkageTypeInfoStorage);
  }

  [[nodiscard]] moho::STaskEventLinkageSerializer& STaskEventLinkageSerializerSlot()
  {
    return *reinterpret_cast<moho::STaskEventLinkageSerializer*>(gSTaskEventLinkageSerializerStorage);
  }

  [[nodiscard]] moho::CTaskEventTypeInfo& CTaskEventTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CTaskEventTypeInfo*>(gCTaskEventTypeInfoStorage);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper* const helper)
  {
    return reinterpret_cast<gpg::SerHelperBase*>(helper);
  }

  template <typename THelper>
  void ResetHelperIntrusiveLinks(THelper* const helper)
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper->mNext = self;
    helper->mPrev = self;
  }

  template <typename THelper>
  void UnlinkHelperIntrusiveLinks(THelper* const helper)
  {
    if (helper->mNext != nullptr && helper->mPrev != nullptr) {
      helper->mNext->mPrev = helper->mPrev;
      helper->mPrev->mNext = helper->mNext;
    }

    ResetHelperIntrusiveLinks(helper);
  }

  [[nodiscard]] moho::STaskEventLinkageSerializer* InitializeSTaskEventLinkageSerializerHelper(
    moho::STaskEventLinkageSerializer* const serializer
  )
  {
    ResetHelperIntrusiveLinks(serializer);
    serializer->mSerLoadFunc = &moho::STaskEventLinkageSerializer::Deserialize;
    serializer->mSerSaveFunc = &moho::STaskEventLinkageSerializer::Serialize;
    return serializer;
  }

  [[nodiscard]] gpg::RType* InitializeSTaskEventLinkageTypeInfoStorage()
  {
    if (!gSTaskEventLinkageTypeInfoConstructed) {
      ::new (static_cast<void*>(&STaskEventLinkageTypeInfoSlot())) moho::STaskEventLinkageTypeInfo();
      gSTaskEventLinkageTypeInfoConstructed = true;
    }

    return &STaskEventLinkageTypeInfoSlot();
  }

  [[nodiscard]] gpg::RType* InitializeCTaskEventTypeInfoStorage()
  {
    if (!gCTaskEventTypeInfoConstructed) {
      ::new (static_cast<void*>(&CTaskEventTypeInfoSlot())) moho::CTaskEventTypeInfo();
      gCTaskEventTypeInfoConstructed = true;
    }

    return &CTaskEventTypeInfoSlot();
  }

  /**
   * Address: 0x00408000 (FUN_00408000, gpg::RRef::Upcast_STaskEventLinkage)
   *
   * What it does:
   * Upcasts a reflected object lane to `STaskEventLinkage` when compatible.
   */
  [[nodiscard]] STaskEventLinkage* UpcastSTaskEventLinkage(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTaskEventLinkageType());
    return static_cast<STaskEventLinkage*>(upcast.mObj);
  }

  /**
   * Address: 0x00408040 (FUN_00408040, gpg::RRef_STaskEventLinkage)
   *
   * What it does:
   * Builds reflected object reference for `STaskEventLinkage` and preserves
   * most-derived complete-object pointer semantics.
   */
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

  /**
   * Address: 0x004081E0 (FUN_004081E0, gpg::ReadArchive::ReadPointer_STaskEventLinkage)
   *
   * What it does:
   * Reads one tracked pointer lane and upcasts it to `STaskEventLinkage`
   * without changing ownership state.
   */
  [[nodiscard]] STaskEventLinkage* ReadPointerSTaskEventLinkage(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    if (STaskEventLinkage* const linkage = UpcastSTaskEventLinkage(source)) {
      return linkage;
    }

    const char* const expected = CachedSTaskEventLinkageType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "STaskEventLinkage",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  /**
   * Address: 0x00407A50 (FUN_00407A50, gpg::ReadArchive::ReadPointerOwned_STaskEventLinkage)
   *
   * What it does:
   * Reads one pointer lane, enforces owned-pointer transition
   * (`Unowned -> Owned`), and upcasts to `STaskEventLinkage`.
   */
  STaskEventLinkage* ReadOwnedSTaskEventLinkagePointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.state != gpg::TrackedPointerState::Unowned) {
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    if (STaskEventLinkage* const linkage = UpcastSTaskEventLinkage(source)) {
      tracked.state = gpg::TrackedPointerState::Owned;
      return linkage;
    }

    const char* const expected = CachedSTaskEventLinkageType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "STaskEventLinkage",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  // Shared callback body used by FUN_004069A0 and FUN_00407900.
  void DeserializeSTaskEventLinkageThreadRef(gpg::ReadArchive* archive, int objectPtr)
  {
    auto* const linkage = reinterpret_cast<STaskEventLinkage*>(objectPtr);
    GPG_ASSERT(linkage != nullptr);

    const gpg::RRef owner{};
    archive->Read(CachedWeakPtrCTaskThreadType(), &linkage->mThreadRef, owner);
  }

  // Shared callback body used by FUN_004069F0 and FUN_00407950.
  void SerializeSTaskEventLinkageThreadRef(gpg::WriteArchive* archive, int objectPtr)
  {
    auto* const linkage = reinterpret_cast<STaskEventLinkage*>(objectPtr);
    GPG_ASSERT(linkage != nullptr);

    const gpg::RRef owner{};
    archive->Write(CachedWeakPtrCTaskThreadType(), &linkage->mThreadRef, owner);
  }

  /**
   * Address: 0x00407710 (FUN_00407710)
   *
   * What it does:
   * Loads one weak pointer lane targeting `STaskEventLinkage` and binds this
   * weak-link node to the decoded owner object.
   */
  void LoadWeakPtrSTaskEventLinkage(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<STaskEventLinkage>*>(objectPtr);
    GPG_ASSERT(weak != nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    weak->ResetFromObject(ReadPointerSTaskEventLinkage(archive, owner));
  }

  /**
   * Address: 0x00407740 (FUN_00407740)
   *
   * What it does:
   * Saves one weak pointer lane targeting `STaskEventLinkage` as an unowned
   * tracked pointer entry.
   */
  void SaveWeakPtrSTaskEventLinkage(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<STaskEventLinkage>*>(objectPtr);
    GPG_ASSERT(weak != nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef objectRef = MakeSTaskEventLinkageRef(weak ? weak->GetObjectPtr() : nullptr);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
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

  CTaskEventSerializer gCTaskEventSerializer{};
  RWeakPtrType<STaskEventLinkage> gRWeakPtrTypeSTaskEventLinkage{};

  /**
   * Address: 0x00BC2F50 (FUN_00BC2F50, register_CTaskEventSerializer)
   *
   * What it does:
   * Initializes the global CTaskEvent serializer helper and binds load/save
   * callbacks into reflected type metadata.
   */
  void RegisterCTaskEventSerializerBootstrap()
  {
    ResetHelperIntrusiveLinks(&gCTaskEventSerializer);
    gCTaskEventSerializer.mSerLoadFunc = &DeserializeCTaskEvent;
    gCTaskEventSerializer.mSerSaveFunc = &SerializeCTaskEvent;
    gCTaskEventSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00BC2F90 (FUN_00BC2F90, register_RWeakPtrType_STaskEventLinkage)
   *
   * What it does:
   * Materializes the global weak-pointer reflection type for
   * `WeakPtr<STaskEventLinkage>`.
   */
  void RegisterWeakTaskEventLinkagePointerTypeBootstrap()
  {
    (void)gRWeakPtrTypeSTaskEventLinkage;
  }

} // namespace

/**
 * Address: 0x004069A0 (FUN_004069A0, Moho::STaskEventLinkageSerializer::Deserialize)
 * Alias:   0x00407900 (FUN_00407900, duplicate callback body)
 */
void STaskEventLinkageSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
)
{
  DeserializeSTaskEventLinkageThreadRef(archive, objectPtr);
}

/**
 * Address: 0x004069F0 (FUN_004069F0, Moho::STaskEventLinkageSerializer::Serialize)
 * Alias:   0x00407950 (FUN_00407950, duplicate callback body)
 */
void STaskEventLinkageSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
)
{
  SerializeSTaskEventLinkageThreadRef(archive, objectPtr);
}

/**
 * Address: 0x00407240 (FUN_00407240, Moho::STaskEventLinkageSerializer::Init)
 */
void STaskEventLinkageSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSTaskEventLinkageType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc ? mSerLoadFunc : &STaskEventLinkageSerializer::Deserialize;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc ? mSerSaveFunc : &STaskEventLinkageSerializer::Serialize;
}

/**
 * Address: 0x00406840 (FUN_00406840, Moho::STaskEventLinkageTypeInfo::STaskEventLinkageTypeInfo)
 */
STaskEventLinkageTypeInfo::STaskEventLinkageTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(STaskEventLinkage), this);
}

/**
 * Address: 0x004068F0 (FUN_004068F0, Moho::STaskEventLinkageTypeInfo::dtr)
 */
STaskEventLinkageTypeInfo::~STaskEventLinkageTypeInfo() = default;

/**
 * Address: 0x004068E0 (FUN_004068E0, Moho::STaskEventLinkageTypeInfo::GetName)
 */
const char* STaskEventLinkageTypeInfo::GetName() const
{
  return "STaskEventLinkage";
}

/**
 * Address: 0x004068A0 (FUN_004068A0, Moho::STaskEventLinkageTypeInfo::Init)
 */
void STaskEventLinkageTypeInfo::Init()
{
  size_ = sizeof(STaskEventLinkage);
  newRefFunc_ = &STaskEventLinkageTypeInfo::NewRef;
  ctorRefFunc_ = &STaskEventLinkageTypeInfo::CtrRef;
  deleteFunc_ = &STaskEventLinkageTypeInfo::Delete;
  dtrFunc_ = &STaskEventLinkageTypeInfo::Destruct;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x004077F0 (FUN_004077F0)
 */
gpg::RRef STaskEventLinkageTypeInfo::NewRef()
{
  auto* const linkage = new (std::nothrow) STaskEventLinkage();
  return MakeSTaskEventLinkageRef(linkage);
}

/**
 * Address: 0x00407860 (FUN_00407860)
 */
gpg::RRef STaskEventLinkageTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const linkage = static_cast<STaskEventLinkage*>(objectStorage);
  if (linkage) {
    new (linkage) STaskEventLinkage();
  }
  return MakeSTaskEventLinkageRef(linkage);
}

/**
 * Address: 0x00407840 (FUN_00407840)
 */
void STaskEventLinkageTypeInfo::Delete(void* const objectStorage)
{
  auto* const linkage = static_cast<STaskEventLinkage*>(objectStorage);
  if (!linkage) {
    return;
  }

  linkage->~STaskEventLinkage();
  ::operator delete(linkage);
}

/**
 * Address: 0x004078A0 (FUN_004078A0)
 */
void STaskEventLinkageTypeInfo::Destruct(void* const objectStorage)
{
  auto* const linkage = static_cast<STaskEventLinkage*>(objectStorage);
  if (!linkage) {
    return;
  }

  linkage->~STaskEventLinkage();
}

/**
 * Address: 0x00407EC0 (FUN_00407EC0, Moho::RWeakPtrType_STaskEventLinkage::dtr)
 */
RWeakPtrType<STaskEventLinkage>::~RWeakPtrType() = default;

/**
 * Address: 0x004072B0 (FUN_004072B0, Moho::RWeakPtrType_STaskEventLinkage::GetName)
 */
const char* RWeakPtrType<STaskEventLinkage>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const char* const linkageTypeName = CachedSTaskEventLinkageType()->GetName();
    sName = gpg::STR_Printf("WeakPtr<%s>", linkageTypeName ? linkageTypeName : "STaskEventLinkage");
  }
  return sName.c_str();
}

/**
 * Address: 0x00407370 (FUN_00407370, Moho::RWeakPtrType_STaskEventLinkage::GetLexical)
 */
msvc8::string RWeakPtrType<STaskEventLinkage>::GetLexical(const gpg::RRef& ref) const
{
  auto* const weak = static_cast<const WeakPtr<STaskEventLinkage>*>(ref.mObj);
  if (!weak || !weak->HasValue()) {
    return msvc8::string("NULL");
  }

  const gpg::RRef linkageRef = MakeSTaskEventLinkageRef(weak->GetObjectPtr());
  if (!linkageRef.mObj) {
    return msvc8::string("NULL");
  }

  const msvc8::string inner = linkageRef.GetLexical();
  return gpg::STR_Printf("[%s]", inner.c_str());
}

/**
 * Address: 0x00407500 (FUN_00407500, Moho::RWeakPtrType_STaskEventLinkage::IsIndexed)
 */
const gpg::RIndexed* RWeakPtrType<STaskEventLinkage>::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00407510 (FUN_00407510, Moho::RWeakPtrType_STaskEventLinkage::IsPointer)
 */
const gpg::RIndexed* RWeakPtrType<STaskEventLinkage>::IsPointer() const
{
  return this;
}

/**
 * Address: 0x00407350 (FUN_00407350, Moho::RWeakPtrType_STaskEventLinkage::Init)
 */
void RWeakPtrType<STaskEventLinkage>::Init()
{
  size_ = 0x08;
  version_ = 1;
  serLoadFunc_ = &LoadWeakPtrSTaskEventLinkage;
  serSaveFunc_ = &SaveWeakPtrSTaskEventLinkage;
}

/**
 * Address: 0x00407550 (FUN_00407550, Moho::RWeakPtrType_STaskEventLinkage::SubscriptIndex)
 */
gpg::RRef RWeakPtrType<STaskEventLinkage>::SubscriptIndex(void* const obj, const int ind) const
{
  GPG_ASSERT(ind == 0);
  if (ind != 0) {
    return MakeSTaskEventLinkageRef(nullptr);
  }

  auto* const weak = static_cast<WeakPtr<STaskEventLinkage>*>(obj);
  if (!weak) {
    return MakeSTaskEventLinkageRef(nullptr);
  }

  return MakeSTaskEventLinkageRef(weak->GetObjectPtr());
}

/**
 * Address: 0x00407520 (FUN_00407520, Moho::RWeakPtrType_STaskEventLinkage::GetCount)
 */
size_t RWeakPtrType<STaskEventLinkage>::GetCount(void* const obj) const
{
  auto* const weak = static_cast<WeakPtr<STaskEventLinkage>*>(obj);
  if (!weak) {
    return 0u;
  }
  return weak->HasValue() ? 1u : 0u;
}

/**
 * Address: 0x00406C10 (FUN_00406C10, ??0CTaskEvent@Moho@@QAE@XZ)
 */
CTaskEvent::CTaskEvent()
  : mTriggered(false)
  , mAlignmentPad05{}
  , mWaitLinks()
{}

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
 * Address: 0x00406AD0 (FUN_00406AD0, Moho::CTaskEventTypeInfo::CTaskEventTypeInfo)
 */
CTaskEventTypeInfo::CTaskEventTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CTaskEvent), this);
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

namespace moho
{
  /**
   * Address: 0x00BEE0E0 (FUN_00BEE0E0, ??1STaskEventLinkageTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for startup `STaskEventLinkageTypeInfo`
   * storage.
   */
  void cleanup_STaskEventLinkageTypeInfo()
  {
    if (!gSTaskEventLinkageTypeInfoConstructed) {
      return;
    }

    STaskEventLinkageTypeInfoSlot().~STaskEventLinkageTypeInfo();
    gSTaskEventLinkageTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BEE140 (FUN_00BEE140, ??1STaskEventLinkageSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks startup `STaskEventLinkageSerializer` helper lanes and resets them
   * to a self-linked singleton state.
   */
  void cleanup_STaskEventLinkageSerializer()
  {
    if (!gSTaskEventLinkageSerializerConstructed) {
      return;
    }

    UnlinkHelperIntrusiveLinks(&STaskEventLinkageSerializerSlot());
    STaskEventLinkageSerializerSlot().~STaskEventLinkageSerializer();
    gSTaskEventLinkageSerializerConstructed = false;
  }

  /**
   * Address: 0x00BEE170 (FUN_00BEE170, ??1CTaskEventTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for startup `CTaskEventTypeInfo` storage.
   */
  void cleanup_CTaskEventTypeInfo()
  {
    if (!gCTaskEventTypeInfoConstructed) {
      return;
    }

    CTaskEventTypeInfoSlot().~CTaskEventTypeInfo();
    gCTaskEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC2ED0 (FUN_00BC2ED0, register_STaskEventLinkageTypeInfo)
   *
   * What it does:
   * Materializes startup `STaskEventLinkageTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_STaskEventLinkageTypeInfo()
  {
    (void)InitializeSTaskEventLinkageTypeInfoStorage();
    (void)std::atexit(&cleanup_STaskEventLinkageTypeInfo);
  }

  /**
   * Address: 0x00BC2EF0 (FUN_00BC2EF0, register_STaskEventLinkageSerializer)
   *
   * What it does:
   * Initializes startup `STaskEventLinkageSerializer` helper callback lanes and
   * registers process-exit intrusive-link cleanup.
   */
  void register_STaskEventLinkageSerializer()
  {
    if (!gSTaskEventLinkageSerializerConstructed) {
      ::new (static_cast<void*>(&STaskEventLinkageSerializerSlot())) STaskEventLinkageSerializer();
      gSTaskEventLinkageSerializerConstructed = true;
    }

    InitializeSTaskEventLinkageSerializerHelper(&STaskEventLinkageSerializerSlot());
    (void)std::atexit(&cleanup_STaskEventLinkageSerializer);
  }

  /**
   * Address: 0x00BC2F30 (FUN_00BC2F30, register_CTaskEventTypeInfo)
   *
   * What it does:
   * Materializes startup `CTaskEventTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_CTaskEventTypeInfo()
  {
    (void)InitializeCTaskEventTypeInfoStorage();
    (void)std::atexit(&cleanup_CTaskEventTypeInfo);
  }
} // namespace moho

namespace
{
  struct CTaskEventReflectionBootstrap
  {
    CTaskEventReflectionBootstrap()
    {
      moho::register_STaskEventLinkageTypeInfo();
      moho::register_STaskEventLinkageSerializer();
      moho::register_CTaskEventTypeInfo();
      RegisterCTaskEventSerializerBootstrap();
      RegisterWeakTaskEventLinkagePointerTypeBootstrap();
    }
  };

  [[maybe_unused]] CTaskEventReflectionBootstrap gCTaskEventReflectionBootstrap;
} // namespace
