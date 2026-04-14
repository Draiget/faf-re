#include "moho/ai/IAiAttacker.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/ai/EAiAttackerEventTypeInfo.h"
#include "moho/ai/IAiAttackerSerializer.h"
#include "moho/ai/IAiAttackerTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/Listener.h"
#include "moho/unit/core/UnitWeapon.h"

using namespace moho;

gpg::RType* Broadcaster_EAiAttackerEvent::sType = nullptr;
gpg::RType* IAiAttacker::sType = nullptr;

namespace moho
{
  class RBroadcasterRType_EAiAttackerEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005DC400 (FUN_005DC400, Moho::RBroadcasterRType_EAiAttackerEvent::SerLoad)
     *
     * What it does:
     * Deserializes one intrusive `Broadcaster<EAiAttackerEvent>` lane by
     * reading listener pointers until a null sentinel and relinking each
     * listener node into the broadcaster ring.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC470 (FUN_005DC470, Moho::RBroadcasterRType_EAiAttackerEvent::SerSave)
     *
     * What it does:
     * Serializes one intrusive `Broadcaster<EAiAttackerEvent>` lane by writing
     * each listener pointer as `UNOWNED`, terminated by one null pointer.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      serLoadFunc_ = &RBroadcasterRType_EAiAttackerEvent::SerLoad;
      serSaveFunc_ = &RBroadcasterRType_EAiAttackerEvent::SerSave;
      Finish();
    }
  };

  class RListenerRType_EAiAttackerEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005DF8C0 (FUN_005DF8C0, moho::RListenerRType_EAiAttackerEvent::RListenerRType_EAiAttackerEvent)
     *
     * What it does:
     * Pre-registers `Listener<EAiAttackerEvent>` RTTI during object construction.
     */
    RListenerRType_EAiAttackerEvent();

    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Listener<EAiAttackerEvent>);
      Finish();
    }
  };
} // namespace moho

namespace gpg
{
  class RVectorType_UnitWeaponPtr final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005DB9A0 (FUN_005DB9A0, gpg::RVectorType_UnitWeapon_P::GetLexical)
     *
     * What it does:
     * Appends `size=<count>` suffix to the base lexical representation for
     * one `vector<UnitWeapon*>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_CAcquireTargetTaskPtr final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005DBB50 (FUN_005DBB50, gpg::RVectorType_CAcquireTargetTask_P::GetLexical)
     *
     * What it does:
     * Appends `size=<count>` suffix to the base lexical representation for
     * one `vector<CAcquireTargetTask*>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;

    /**
     * Address: 0x005DC660 (FUN_005DC660, gpg::RVectorType_CAcquireTargetTask_P::SerLoad)
     *
     * What it does:
     * Deserializes one `msvc8::vector<moho::CAcquireTargetTask*>` payload from
     * archive count + pointer lanes.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC770 (FUN_005DC770, gpg::RVectorType_CAcquireTargetTask_P::SerSave)
     *
     * What it does:
     * Serializes one `msvc8::vector<moho::CAcquireTargetTask*>` payload as
     * count + unowned reflected pointer lanes.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };
} // namespace gpg

namespace
{
  using BroadcasterAttackerType = moho::RBroadcasterRType_EAiAttackerEvent;
  using ListenerAttackerType = moho::RListenerRType_EAiAttackerEvent;
  using UnitWeaponPtrVectorType = gpg::RVectorType_UnitWeaponPtr;
  using CAcquireTargetTaskPtrVectorType = gpg::RVectorType_CAcquireTargetTaskPtr;

  struct CachedTypeName
  {
    msvc8::string value;
    bool initialized = false;
  };

  using UnitWeaponPtrVector = msvc8::vector<moho::UnitWeapon*>;
  using CAcquireTargetTaskPtrVector = msvc8::vector<moho::CAcquireTargetTask*>;

  template <class TObject>
  [[nodiscard]] TObject* PointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  alignas(BroadcasterAttackerType) unsigned char gBroadcasterAttackerTypeStorage[sizeof(BroadcasterAttackerType)];
  bool gBroadcasterAttackerTypeConstructed = false;

  alignas(ListenerAttackerType) unsigned char gListenerAttackerTypeStorage[sizeof(ListenerAttackerType)];
  bool gListenerAttackerTypeConstructed = false;

  alignas(UnitWeaponPtrVectorType) unsigned char gUnitWeaponPtrVectorTypeStorage[sizeof(UnitWeaponPtrVectorType)];
  bool gUnitWeaponPtrVectorTypeConstructed = false;

  alignas(CAcquireTargetTaskPtrVectorType)
    unsigned char gCAcquireTargetTaskPtrVectorTypeStorage[sizeof(CAcquireTargetTaskPtrVectorType)];
  bool gCAcquireTargetTaskPtrVectorTypeConstructed = false;

  [[nodiscard]] BroadcasterAttackerType* AcquireBroadcasterAttackerType()
  {
    if (!gBroadcasterAttackerTypeConstructed) {
      new (gBroadcasterAttackerTypeStorage) BroadcasterAttackerType();
      gBroadcasterAttackerTypeConstructed = true;
    }

    return reinterpret_cast<BroadcasterAttackerType*>(gBroadcasterAttackerTypeStorage);
  }

  [[nodiscard]] ListenerAttackerType* AcquireListenerAttackerType()
  {
    if (!gListenerAttackerTypeConstructed) {
      new (gListenerAttackerTypeStorage) ListenerAttackerType();
      gListenerAttackerTypeConstructed = true;
    }

    return reinterpret_cast<ListenerAttackerType*>(gListenerAttackerTypeStorage);
  }

  [[nodiscard]] UnitWeaponPtrVectorType* AcquireUnitWeaponPtrVectorType()
  {
    if (!gUnitWeaponPtrVectorTypeConstructed) {
      new (gUnitWeaponPtrVectorTypeStorage) UnitWeaponPtrVectorType();
      gUnitWeaponPtrVectorTypeConstructed = true;
    }

    return reinterpret_cast<UnitWeaponPtrVectorType*>(gUnitWeaponPtrVectorTypeStorage);
  }

  [[nodiscard]] CAcquireTargetTaskPtrVectorType* AcquireCAcquireTargetTaskPtrVectorType()
  {
    if (!gCAcquireTargetTaskPtrVectorTypeConstructed) {
      new (gCAcquireTargetTaskPtrVectorTypeStorage) CAcquireTargetTaskPtrVectorType();
      gCAcquireTargetTaskPtrVectorTypeConstructed = true;
    }

    return reinterpret_cast<CAcquireTargetTaskPtrVectorType*>(gCAcquireTargetTaskPtrVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveUnitWeaponPtrType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::UnitWeapon*));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("UnitWeapon *");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveCAcquireTargetTaskPtrType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAcquireTargetTask*));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("CAcquireTargetTask *");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveEAiAttackerEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiAttackerEvent));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("EAiAttackerEvent");
      }
    }
    return cached;
  }

  [[nodiscard]] CachedTypeName& CachedBroadcasterEAiAttackerEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedListenerEAiAttackerEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedUnitWeaponPtrVectorTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedCAcquireTargetTaskPtrVectorTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  template <class TVector>
  [[nodiscard]] msvc8::string MakeVectorLexical(const gpg::RType* const ownerType, const gpg::RRef& ref, const TVector* vec)
  {
    const msvc8::string base = ownerType != nullptr ? ownerType->gpg::RType::GetLexical(ref) : msvc8::string("vector");
    const int size = vec ? static_cast<int>(vec->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
  }

  void cleanup_RBroadcasterRType_EAiAttackerEvent()
  {
    if (!gBroadcasterAttackerTypeConstructed) {
      return;
    }

    AcquireBroadcasterAttackerType()->~BroadcasterAttackerType();
    gBroadcasterAttackerTypeConstructed = false;
  }

  void cleanup_RListenerRType_EAiAttackerEvent()
  {
    if (!gListenerAttackerTypeConstructed) {
      return;
    }

    AcquireListenerAttackerType()->~ListenerAttackerType();
    gListenerAttackerTypeConstructed = false;
  }

  void cleanup_RBroadcasterRType_EAiAttackerEvent_GetName()
  {
    CachedTypeName& cache = CachedBroadcasterEAiAttackerEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RListenerRType_EAiAttackerEvent_GetName()
  {
    CachedTypeName& cache = CachedListenerEAiAttackerEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_UnitWeaponPtr_GetName()
  {
    CachedTypeName& cache = CachedUnitWeaponPtrVectorTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_CAcquireTargetTaskPtr_GetName()
  {
    CachedTypeName& cache = CachedCAcquireTargetTaskPtrVectorTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_UnitWeaponPtr()
  {
    if (!gUnitWeaponPtrVectorTypeConstructed) {
      return;
    }

    AcquireUnitWeaponPtrVectorType()->~UnitWeaponPtrVectorType();
    gUnitWeaponPtrVectorTypeConstructed = false;
  }

  void cleanup_RVectorType_CAcquireTargetTaskPtr()
  {
    if (!gCAcquireTargetTaskPtrVectorTypeConstructed) {
      return;
    }

    AcquireCAcquireTargetTaskPtrVectorType()->~CAcquireTargetTaskPtrVectorType();
    gCAcquireTargetTaskPtrVectorTypeConstructed = false;
  }
} // namespace

/**
 * Address: 0x005DF8C0 (FUN_005DF8C0, moho::RListenerRType_EAiAttackerEvent::RListenerRType_EAiAttackerEvent)
 *
 * What it does:
 * Pre-registers `Listener<EAiAttackerEvent>` RTTI during object construction.
 */
moho::RListenerRType_EAiAttackerEvent::RListenerRType_EAiAttackerEvent()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiAttackerEvent>), this);
}

/**
 * Address: 0x005DB790 (FUN_005DB790, Moho::RBroadcasterRType_EAiAttackerEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Broadcaster<EAiAttackerEvent>`
 * using the registered enum reflection type name.
 */
const char* moho::RBroadcasterRType_EAiAttackerEvent::GetName() const
{
  CachedTypeName& cache = CachedBroadcasterEAiAttackerEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiAttackerEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiAttackerEvent";
    cache.value = gpg::STR_Printf("Broadcaster<%s>", eventTypeName ? eventTypeName : "EAiAttackerEvent");
    (void)std::atexit(&cleanup_RBroadcasterRType_EAiAttackerEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005DB850 (FUN_005DB850, Moho::RListenerRType_EAiAttackerEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Listener<EAiAttackerEvent>`
 * using the registered enum reflection type name.
 */
const char* moho::RListenerRType_EAiAttackerEvent::GetName() const
{
  CachedTypeName& cache = CachedListenerEAiAttackerEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiAttackerEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiAttackerEvent";
    cache.value = gpg::STR_Printf("Listener<%s>", eventTypeName ? eventTypeName : "EAiAttackerEvent");
    (void)std::atexit(&cleanup_RListenerRType_EAiAttackerEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005DC400 (FUN_005DC400, Moho::RBroadcasterRType_EAiAttackerEvent::SerLoad)
 *
 * What it does:
 * Reads listener pointers until a null sentinel and relinks each listener's
 * intrusive broadcaster node before the destination broadcaster sentinel.
 */
void moho::RBroadcasterRType_EAiAttackerEvent::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const broadcaster = PointerFromArchiveInt<moho::Broadcaster>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(broadcaster != nullptr);
  if (!archive || !broadcaster) {
    return;
  }

  moho::Listener<moho::EAiAttackerEvent>* listener = nullptr;
  archive->ReadPointer_Listener_EAiAttackerEvent(&listener, ownerRef);
  while (listener != nullptr) {
    listener->mListenerLink.ListLinkBefore(broadcaster);
    archive->ReadPointer_Listener_EAiAttackerEvent(&listener, ownerRef);
  }
}

/**
 * Address: 0x005DC470 (FUN_005DC470, Moho::RBroadcasterRType_EAiAttackerEvent::SerSave)
 *
 * What it does:
 * Serializes one intrusive `Broadcaster<EAiAttackerEvent>` lane by writing
 * each linked listener as an unowned pointer and terminating with one null
 * pointer record.
 */
void moho::RBroadcasterRType_EAiAttackerEvent::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const broadcaster = PointerFromArchiveInt<moho::Broadcaster_EAiAttackerEvent>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(broadcaster != nullptr);
  if (!archive || !broadcaster) {
    return;
  }

  const gpg::RRef nullOwner{};
  gpg::RRef pointerRef{};

  for (
    moho::Broadcaster* node = static_cast<moho::Broadcaster*>(broadcaster->mNext);
    node != broadcaster;
    node = static_cast<moho::Broadcaster*>(node->mNext)
  ) {
    moho::Listener<moho::EAiAttackerEvent>* listener = nullptr;
    if (node != nullptr) {
      auto* const bytePtr = reinterpret_cast<std::uint8_t*>(node);
      listener = reinterpret_cast<moho::Listener<moho::EAiAttackerEvent>*>(
        bytePtr - offsetof(moho::Listener<moho::EAiAttackerEvent>, mListenerLink)
      );
    }

    (void)gpg::RRef_Listener_EAiAttackerEvent(&pointerRef, listener);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  (void)gpg::RRef_Listener_EAiAttackerEvent(&pointerRef, nullptr);
  gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x005DB900 (FUN_005DB900, gpg::RVectorType_UnitWeapon_P::GetName)
 *
 * What it does:
 * Lazily formats and caches the reflected type name for
 * `msvc8::vector<moho::UnitWeapon*>`.
 */
const char* gpg::RVectorType_UnitWeaponPtr::GetName() const
{
  CachedTypeName& cache = CachedUnitWeaponPtrVectorTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    const gpg::RType* const elementType = ResolveUnitWeaponPtrType();
    const char* const elementName = elementType ? elementType->GetName() : "UnitWeapon *";
    cache.value = gpg::STR_Printf("vector<%s>", elementName ? elementName : "UnitWeapon *");
    (void)std::atexit(&cleanup_RVectorType_UnitWeaponPtr_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005DB9A0 (FUN_005DB9A0, gpg::RVectorType_UnitWeapon_P::GetLexical)
 *
 * What it does:
 * Appends `size=<count>` suffix to the base lexical representation for one
 * `vector<UnitWeapon*>` payload.
 */
msvc8::string gpg::RVectorType_UnitWeaponPtr::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const UnitWeaponPtrVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_UnitWeaponPtr::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_UnitWeaponPtr::Init()
{
  size_ = sizeof(UnitWeaponPtrVector);
  version_ = 1;
}

gpg::RRef gpg::RVectorType_UnitWeaponPtr::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<UnitWeaponPtrVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveUnitWeaponPtrType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_UnitWeaponPtr::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const UnitWeaponPtrVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_UnitWeaponPtr::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<UnitWeaponPtrVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), nullptr);
}

/**
 * Address: 0x005DBAB0 (FUN_005DBAB0, gpg::RVectorType_CAcquireTargetTask_P::GetName)
 *
 * What it does:
 * Lazily formats and caches the reflected type name for
 * `msvc8::vector<moho::CAcquireTargetTask*>`.
 */
const char* gpg::RVectorType_CAcquireTargetTaskPtr::GetName() const
{
  CachedTypeName& cache = CachedCAcquireTargetTaskPtrVectorTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    const gpg::RType* const elementType = ResolveCAcquireTargetTaskPtrType();
    const char* const elementName = elementType ? elementType->GetName() : "CAcquireTargetTask *";
    cache.value = gpg::STR_Printf("vector<%s>", elementName ? elementName : "CAcquireTargetTask *");
    (void)std::atexit(&cleanup_RVectorType_CAcquireTargetTaskPtr_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005DBB50 (FUN_005DBB50, gpg::RVectorType_CAcquireTargetTask_P::GetLexical)
 *
 * What it does:
 * Appends `size=<count>` suffix to the base lexical representation for one
 * `vector<CAcquireTargetTask*>` payload.
 */
msvc8::string gpg::RVectorType_CAcquireTargetTaskPtr::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const CAcquireTargetTaskPtrVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_CAcquireTargetTaskPtr::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_CAcquireTargetTaskPtr::Init()
{
  size_ = sizeof(CAcquireTargetTaskPtrVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_CAcquireTargetTaskPtr::SerLoad;
  serSaveFunc_ = &RVectorType_CAcquireTargetTaskPtr::SerSave;
}

/**
 * Address: 0x005DC660 (FUN_005DC660, gpg::RVectorType_CAcquireTargetTask_P::SerLoad)
 *
 * What it does:
 * Deserializes one `vector<CAcquireTargetTask*>` payload from archive count +
 * pointer lanes and replaces destination storage in one assignment.
 */
void gpg::RVectorType_CAcquireTargetTaskPtr::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const storage = PointerFromArchiveInt<CAcquireTargetTaskPtrVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  unsigned int count = 0;
  archive->ReadUInt(&count);

  CAcquireTargetTaskPtrVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));
  for (unsigned int i = 0; i < count; ++i) {
    moho::CAcquireTargetTask* value = nullptr;
    archive->ReadPointer_CAcquireTargetTask(&value, ownerRef);
    loaded.push_back(value);
  }

  *storage = loaded;
}

/**
 * Address: 0x005DC770 (FUN_005DC770, gpg::RVectorType_CAcquireTargetTask_P::SerSave)
 *
 * What it does:
 * Serializes one `vector<CAcquireTargetTask*>` payload as count + unowned
 * reflected pointer entries.
 */
void gpg::RVectorType_CAcquireTargetTaskPtr::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const storage = PointerFromArchiveInt<const CAcquireTargetTaskPtrVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  const unsigned int count = static_cast<unsigned int>(storage->size());
  archive->WriteUInt(count);

  const gpg::RRef nullOwner{};
  gpg::RRef pointerRef{};
  for (unsigned int i = 0; i < count; ++i) {
    (void)gpg::RRef_CAcquireTargetTask(&pointerRef, (*storage)[static_cast<std::size_t>(i)]);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }
}

gpg::RRef gpg::RVectorType_CAcquireTargetTaskPtr::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<CAcquireTargetTaskPtrVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveCAcquireTargetTaskPtrType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_CAcquireTargetTaskPtr::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const CAcquireTargetTaskPtrVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_CAcquireTargetTaskPtr::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<CAcquireTargetTaskPtrVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), nullptr);
}

/**
 * Address: 0x005D5780 (FUN_005D5780)
 */
IAiAttacker::~IAiAttacker()
{
  Broadcaster* const link = static_cast<Broadcaster*>(&mListeners);
  link->ListUnlink();
}

/**
 * Address: 0x00BCEAA0 (FUN_00BCEAA0, sub_BCEAA0)
 *
 * What it does:
 * Registers the broadcaster reflection lane for `EAiAttackerEvent` and
 * installs process-exit cleanup.
 */
int moho::register_RBroadcasterRType_EAiAttackerEvent()
{
  auto* const type = AcquireBroadcasterAttackerType();
  gpg::PreRegisterRType(typeid(moho::Broadcaster_EAiAttackerEvent), type);
  return std::atexit(&cleanup_RBroadcasterRType_EAiAttackerEvent);
}

/**
 * Address: 0x00BCEAC0 (FUN_00BCEAC0, register_RListenerRType_EAiAttackerEvent)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiAttackerEvent` and installs
 * process-exit cleanup.
 */
int moho::register_RListenerRType_EAiAttackerEvent()
{
  (void)AcquireListenerAttackerType();
  return std::atexit(&cleanup_RListenerRType_EAiAttackerEvent);
}

/**
 * Address: 0x00BCEAE0 (FUN_00BCEAE0, sub_BCEAE0)
 *
 * What it does:
 * Registers `msvc8::vector<UnitWeapon*>` reflection metadata and installs
 * process-exit cleanup.
 */
int moho::register_RVectorType_UnitWeaponPtr()
{
  auto* const type = AcquireUnitWeaponPtrVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::UnitWeapon*>), type);
  return std::atexit(&cleanup_RVectorType_UnitWeaponPtr);
}

/**
 * Address: 0x00BCEB00 (FUN_00BCEB00, sub_BCEB00)
 *
 * What it does:
 * Registers `msvc8::vector<CAcquireTargetTask*>` reflection metadata and
 * installs process-exit cleanup.
 */
int moho::register_RVectorType_CAcquireTargetTaskPtr()
{
  auto* const type = AcquireCAcquireTargetTaskPtrVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::CAcquireTargetTask*>), type);
  return std::atexit(&cleanup_RVectorType_CAcquireTargetTaskPtr);
}

namespace
{
  struct IAiAttackerReflectionBootstrap
  {
    IAiAttackerReflectionBootstrap()
    {
      (void)moho::register_EAiAttackerEventTypeInfo();
      (void)moho::register_EAiAttackerEventPrimitiveSerializer();
      (void)moho::register_IAiAttackerTypeInfo();
      (void)moho::register_IAiAttackerSerializer();
      (void)moho::register_RBroadcasterRType_EAiAttackerEvent();
      (void)moho::register_RListenerRType_EAiAttackerEvent();
      (void)moho::register_RVectorType_UnitWeaponPtr();
      (void)moho::register_RVectorType_CAcquireTargetTaskPtr();
    }
  };

  [[maybe_unused]] IAiAttackerReflectionBootstrap gIAiAttackerReflectionBootstrap;
} // namespace
