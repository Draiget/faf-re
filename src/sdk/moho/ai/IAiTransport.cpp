#include "moho/ai/IAiTransport.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiTransportImpl.h"
#include "moho/ai/CAiTransportImplConstruct.h"
#include "moho/ai/CAiTransportImplSerializer.h"
#include "moho/ai/CAiTransportImplTypeInfo.h"
#include "moho/ai/EAiTransportEventTypeInfo.h"
#include "moho/ai/IAiTransportSerializer.h"
#include "moho/ai/IAiTransportTypeInfo.h"
#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/ai/SAiReservedTransportBoneSerializer.h"
#include "moho/ai/SAiReservedTransportBoneTypeInfo.h"
#include "moho/ai/SAttachPointSerializer.h"
#include "moho/ai/SAttachPointTypeInfo.h"
#include "moho/ai/STransportPickUpInfoSerializer.h"
#include "moho/ai/STransportPickUpInfoTypeInfo.h"
#include "moho/misc/Listener.h"

using namespace moho;

/**
 * Address: 0x005E87E0 (FUN_005E87E0, ?AI_CreateTransport@Moho@@YAPAVIAiTransport@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiTransportImpl` bound to `unit` and returns it through the
 * `IAiTransport` interface lane.
 */
IAiTransport* moho::AI_CreateTransport(Unit* const unit)
{
  auto* const impl = new (std::nothrow) CAiTransportImpl(unit);
  return impl ? static_cast<IAiTransport*>(impl) : nullptr;
}

namespace moho
{
  class RBroadcasterRType_EAiTransportEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E9E40 (FUN_005E9E40, moho::RBroadcasterRType_EAiTransportEvent::SerLoad)
     *
     * What it does:
     * Deserializes one intrusive `Broadcaster<EAiTransportEvent>` lane by
     * reading listener pointers until a null sentinel and relinking each
     * listener node into the broadcaster ring.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E9EB0 (FUN_005E9EB0, moho::RBroadcasterRType_EAiTransportEvent::SerSave)
     *
     * What it does:
     * Serializes one intrusive `Broadcaster<EAiTransportEvent>` lane by writing
     * each linked listener pointer as `UNOWNED` and terminating with one null
     * pointer record.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005ECC40 (FUN_005ECC40, moho::RBroadcasterRType_EAiTransportEvent::RBroadcasterRType_EAiTransportEvent)
     *
     * What it does:
     * Constructs and preregisters the broadcaster RTTI lane for
     * `BroadcasterEventTag<EAiTransportEvent>`.
     */
    RBroadcasterRType_EAiTransportEvent();

    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      serLoadFunc_ = &RBroadcasterRType_EAiTransportEvent::SerLoad;
      serSaveFunc_ = &RBroadcasterRType_EAiTransportEvent::SerSave;
      Finish();
    }
  };

  class RListenerRType_EAiTransportEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005ECCA0 (FUN_005ECCA0, moho::RListenerRType_EAiTransportEvent::RListenerRType_EAiTransportEvent)
     *
     * What it does:
     * Constructs and preregisters the listener RTTI lane for
     * `Listener<EAiTransportEvent>`.
     */
    RListenerRType_EAiTransportEvent();

    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Listener<EAiTransportEvent>);
      Finish();
    }
  };
} // namespace moho

namespace gpg
{
  class RVectorType_int final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005ECD00 (FUN_005ECD00, gpg::RVectorType_int::RVectorType_int)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for
     * `msvc8::vector<int>`.
     */
    RVectorType_int();

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E8E30 (FUN_005E8E30, gpg::RVectorType_int::GetLexical)
     *
     * What it does:
     * Appends `size=<count>` suffix to the base lexical representation for
     * one `vector<int>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005E8E10 (FUN_005E8E10, gpg::RVectorType_int::Init)
     *
     * What it does:
     * Initializes vector<int> RTTI metadata lanes including ser callbacks.
     */
    void Init() override;

    /**
     * Address: 0x005E9F20 (FUN_005E9F20, gpg::RVectorType_int::SerLoad)
     *
     * What it does:
     * Deserializes one `msvc8::vector<int>` payload from archive lanes.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005EA020 (FUN_005EA020, gpg::RVectorType_int::SerSave)
     *
     * What it does:
     * Serializes one `msvc8::vector<int>` payload into archive lanes.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_SAiReservedTransportBone final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005ECD70 (FUN_005ECD70, gpg::RVectorType_SAiReservedTransportBone::RVectorType_SAiReservedTransportBone)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for
     * `msvc8::vector<SAiReservedTransportBone>`.
     */
    RVectorType_SAiReservedTransportBone();

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E90A0 (FUN_005E90A0, gpg::RVectorType_SAiReservedTransportBone::GetLexical)
     *
     * What it does:
     * Appends `size=<count>` suffix to the base lexical representation for
     * one `vector<SAiReservedTransportBone>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005E9080 (FUN_005E9080, gpg::RVectorType_SAiReservedTransportBone::Init)
     *
     * What it does:
     * Initializes `vector<SAiReservedTransportBone>` RTTI metadata lanes.
     */
    void Init() override;

    /**
     * Address: 0x005EA070 (FUN_005EA070, gpg::RVectorType_SAiReservedTransportBone::SerLoad)
     *
     * What it does:
     * Deserializes one `vector<SAiReservedTransportBone>` payload.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005EA1E0 (FUN_005EA1E0, gpg::RVectorType_SAiReservedTransportBone::SerSave)
     *
     * What it does:
     * Serializes one `vector<SAiReservedTransportBone>` payload.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_SAttachPoint final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005ECDE0 (FUN_005ECDE0, gpg::RVectorType_SAttachPoint::RVectorType_SAttachPoint)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for
     * `msvc8::vector<SAttachPoint>`.
     */
    RVectorType_SAttachPoint();

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E9310 (FUN_005E9310, gpg::RVectorType_SAttachPoint::GetLexical)
     *
     * What it does:
     * Appends `size=<count>` suffix to the base lexical representation for
     * one `vector<SAttachPoint>` payload.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005E92F0 (FUN_005E92F0, gpg::RVectorType_SAttachPoint::Init)
     *
     * What it does:
     * Initializes `vector<SAttachPoint>` RTTI metadata lanes.
     */
    void Init() override;

    /**
     * Address: 0x005EA260 (FUN_005EA260, gpg::RVectorType_SAttachPoint::SerLoad)
     *
     * What it does:
     * Deserializes one `vector<SAttachPoint>` payload.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005EA370 (FUN_005EA370, gpg::RVectorType_SAttachPoint::SerSave)
     *
     * What it does:
     * Serializes one `vector<SAttachPoint>` payload.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };
} // namespace gpg

namespace
{
  using BroadcasterTransportType = moho::RBroadcasterRType_EAiTransportEvent;
  using ListenerTransportType = moho::RListenerRType_EAiTransportEvent;
  using IntVectorType = gpg::RVectorType_int;
  using ReservedTransportBoneVectorType = gpg::RVectorType_SAiReservedTransportBone;
  using AttachPointVectorType = gpg::RVectorType_SAttachPoint;

  struct CachedTypeName
  {
    msvc8::string value;
    bool initialized = false;
  };

  using IntVector = msvc8::vector<int>;
  using ReservedTransportBoneVector = msvc8::vector<moho::SAiReservedTransportBone>;
  using AttachPointVector = msvc8::vector<moho::SAttachPoint>;

  alignas(BroadcasterTransportType) unsigned char gBroadcasterTransportTypeStorage[sizeof(BroadcasterTransportType)];
  bool gBroadcasterTransportTypeConstructed = false;

  alignas(ListenerTransportType) unsigned char gListenerTransportTypeStorage[sizeof(ListenerTransportType)];
  bool gListenerTransportTypeConstructed = false;

  alignas(IntVectorType) unsigned char gIntVectorTypeStorage[sizeof(IntVectorType)];
  bool gIntVectorTypeConstructed = false;

  alignas(ReservedTransportBoneVectorType)
    unsigned char gReservedTransportBoneVectorTypeStorage[sizeof(ReservedTransportBoneVectorType)];
  bool gReservedTransportBoneVectorTypeConstructed = false;

  alignas(AttachPointVectorType) unsigned char gAttachPointVectorTypeStorage[sizeof(AttachPointVectorType)];
  bool gAttachPointVectorTypeConstructed = false;

  [[nodiscard]] BroadcasterTransportType* AcquireBroadcasterTransportType()
  {
    if (!gBroadcasterTransportTypeConstructed) {
      new (gBroadcasterTransportTypeStorage) BroadcasterTransportType();
      gBroadcasterTransportTypeConstructed = true;
    }

    return reinterpret_cast<BroadcasterTransportType*>(gBroadcasterTransportTypeStorage);
  }

  [[nodiscard]] ListenerTransportType* AcquireListenerTransportType()
  {
    if (!gListenerTransportTypeConstructed) {
      new (gListenerTransportTypeStorage) ListenerTransportType();
      gListenerTransportTypeConstructed = true;
    }

    return reinterpret_cast<ListenerTransportType*>(gListenerTransportTypeStorage);
  }

  [[nodiscard]] IntVectorType* AcquireIntVectorType()
  {
    if (!gIntVectorTypeConstructed) {
      new (gIntVectorTypeStorage) IntVectorType();
      gIntVectorTypeConstructed = true;
    }

    return reinterpret_cast<IntVectorType*>(gIntVectorTypeStorage);
  }

  [[nodiscard]] ReservedTransportBoneVectorType* AcquireReservedTransportBoneVectorType()
  {
    if (!gReservedTransportBoneVectorTypeConstructed) {
      new (gReservedTransportBoneVectorTypeStorage) ReservedTransportBoneVectorType();
      gReservedTransportBoneVectorTypeConstructed = true;
    }

    return reinterpret_cast<ReservedTransportBoneVectorType*>(gReservedTransportBoneVectorTypeStorage);
  }

  [[nodiscard]] AttachPointVectorType* AcquireAttachPointVectorType()
  {
    if (!gAttachPointVectorTypeConstructed) {
      new (gAttachPointVectorTypeStorage) AttachPointVectorType();
      gAttachPointVectorTypeConstructed = true;
    }

    return reinterpret_cast<AttachPointVectorType*>(gAttachPointVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("int");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveEAiTransportEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiTransportEvent));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("EAiTransportEvent");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveReservedTransportBoneType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SAiReservedTransportBone));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("SAiReservedTransportBone");
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveAttachPointType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SAttachPoint));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("SAttachPoint");
      }
    }
    return cached;
  }

  [[nodiscard]] CachedTypeName& CachedBroadcasterEAiTransportEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedListenerEAiTransportEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedRVectorTypeIntName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedRVectorTypeSAiReservedTransportBoneName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedRVectorTypeSAttachPointName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  template <class TObject>
  [[nodiscard]] TObject* PointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  template <class TObject>
  [[nodiscard]] const TObject* ConstPointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<const TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  template <class TVector>
  [[nodiscard]] msvc8::string MakeVectorLexical(const gpg::RType* const ownerType, const gpg::RRef& ref, const TVector* vec)
  {
    const msvc8::string base = ownerType != nullptr ? ownerType->gpg::RType::GetLexical(ref) : msvc8::string("vector");
    const int size = vec ? static_cast<int>(vec->size()) : 0;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
  }

  void cleanup_RBroadcasterRType_EAiTransportEvent()
  {
    if (!gBroadcasterTransportTypeConstructed) {
      return;
    }

    AcquireBroadcasterTransportType()->~BroadcasterTransportType();
    gBroadcasterTransportTypeConstructed = false;
  }

  void cleanup_RListenerRType_EAiTransportEvent()
  {
    if (!gListenerTransportTypeConstructed) {
      return;
    }

    AcquireListenerTransportType()->~ListenerTransportType();
    gListenerTransportTypeConstructed = false;
  }

  void cleanup_RVectorType_int()
  {
    if (!gIntVectorTypeConstructed) {
      return;
    }

    AcquireIntVectorType()->~IntVectorType();
    gIntVectorTypeConstructed = false;
  }

  void cleanup_RVectorType_SAiReservedTransportBone()
  {
    if (!gReservedTransportBoneVectorTypeConstructed) {
      return;
    }

    AcquireReservedTransportBoneVectorType()->~ReservedTransportBoneVectorType();
    gReservedTransportBoneVectorTypeConstructed = false;
  }

  void cleanup_RVectorType_SAttachPoint()
  {
    if (!gAttachPointVectorTypeConstructed) {
      return;
    }

    AcquireAttachPointVectorType()->~AttachPointVectorType();
    gAttachPointVectorTypeConstructed = false;
  }

  void cleanup_RBroadcasterRType_EAiTransportEvent_GetName()
  {
    CachedTypeName& cache = CachedBroadcasterEAiTransportEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RListenerRType_EAiTransportEvent_GetName()
  {
    CachedTypeName& cache = CachedListenerEAiTransportEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_int_GetName()
  {
    CachedTypeName& cache = CachedRVectorTypeIntName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_SAiReservedTransportBone_GetName()
  {
    CachedTypeName& cache = CachedRVectorTypeSAiReservedTransportBoneName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RVectorType_SAttachPoint_GetName()
  {
    CachedTypeName& cache = CachedRVectorTypeSAttachPointName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }
} // namespace

/**
 * Address: 0x005E8C00 (FUN_005E8C00, Moho::RBroadcasterRType_EAiTransportEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name
 * `Broadcaster<EAiTransportEvent>` using the registered enum type name.
 */
const char* moho::RBroadcasterRType_EAiTransportEvent::GetName() const
{
  CachedTypeName& cache = CachedBroadcasterEAiTransportEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiTransportEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiTransportEvent";
    cache.value = gpg::STR_Printf("Broadcaster<%s>", eventTypeName ? eventTypeName : "EAiTransportEvent");
    (void)std::atexit(&cleanup_RBroadcasterRType_EAiTransportEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005E9E40 (FUN_005E9E40, moho::RBroadcasterRType_EAiTransportEvent::SerLoad)
 *
 * What it does:
 * Reads listener pointers until a null sentinel and relinks each listener's
 * intrusive broadcaster node before the destination broadcaster sentinel.
 */
void moho::RBroadcasterRType_EAiTransportEvent::SerLoad(
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

  moho::Listener<moho::EAiTransportEvent>* listener = nullptr;
  archive->ReadPointer_Listener_EAiTransportEvent(&listener, ownerRef);
  while (listener != nullptr) {
    listener->mListenerLink.ListLinkBefore(broadcaster);
    archive->ReadPointer_Listener_EAiTransportEvent(&listener, ownerRef);
  }
}

/**
 * Address: 0x005E9EB0 (FUN_005E9EB0, moho::RBroadcasterRType_EAiTransportEvent::SerSave)
 *
 * What it does:
 * Serializes one intrusive broadcaster lane by writing each listener pointer
 * as `UNOWNED` and appending a null sentinel pointer.
 */
void moho::RBroadcasterRType_EAiTransportEvent::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const broadcaster = PointerFromArchiveInt<moho::Broadcaster>(objectPtr);
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
    moho::Listener<moho::EAiTransportEvent>* listener = nullptr;
    if (node != nullptr) {
      moho::IAiTransportEventListener* const eventListener = moho::IAiTransportEventListener::FromListenerLink(node);
      listener = reinterpret_cast<moho::Listener<moho::EAiTransportEvent>*>(eventListener);
    }

    (void)gpg::RRef_Listener_EAiTransportEvent(&pointerRef, listener);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  (void)gpg::RRef_Listener_EAiTransportEvent(&pointerRef, nullptr);
  gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x005E8CC0 (FUN_005E8CC0, Moho::RListenerRType_EAiTransportEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name
 * `Listener<EAiTransportEvent>` using the registered enum type name.
 */
const char* moho::RListenerRType_EAiTransportEvent::GetName() const
{
  CachedTypeName& cache = CachedListenerEAiTransportEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiTransportEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiTransportEvent";
    cache.value = gpg::STR_Printf("Listener<%s>", eventTypeName ? eventTypeName : "EAiTransportEvent");
    (void)std::atexit(&cleanup_RListenerRType_EAiTransportEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005ECC40 (FUN_005ECC40, moho::RBroadcasterRType_EAiTransportEvent::RBroadcasterRType_EAiTransportEvent)
 *
 * What it does:
 * Constructs and preregisters the broadcaster RTTI lane for
 * `BroadcasterEventTag<EAiTransportEvent>`.
 */
moho::RBroadcasterRType_EAiTransportEvent::RBroadcasterRType_EAiTransportEvent()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(moho::BroadcasterEventTag<moho::EAiTransportEvent>), this);
}

/**
 * Address: 0x005ECCA0 (FUN_005ECCA0, moho::RListenerRType_EAiTransportEvent::RListenerRType_EAiTransportEvent)
 *
 * What it does:
 * Constructs and preregisters the listener RTTI lane for
 * `Listener<EAiTransportEvent>`.
 */
moho::RListenerRType_EAiTransportEvent::RListenerRType_EAiTransportEvent()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiTransportEvent>), this);
}

/**
 * Address: 0x005ECD00 (FUN_005ECD00, gpg::RVectorType_int::RVectorType_int)
 *
 * What it does:
 * Constructs and preregisters reflection metadata for
 * `msvc8::vector<int>`.
 */
gpg::RVectorType_int::RVectorType_int()
{
  gpg::PreRegisterRType(typeid(msvc8::vector<int>), this);
}

/**
 * Address: 0x005E8D70 (FUN_005E8D70, gpg::RVectorType_int::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `vector<int>` using the
 * currently registered `int` reflection type.
 */
const char* gpg::RVectorType_int::GetName() const
{
  CachedTypeName& cache = CachedRVectorTypeIntName();
  if (!cache.initialized) {
    cache.initialized = true;
    const gpg::RType* const elementType = ResolveIntType();
    const char* const elementName = elementType ? elementType->GetName() : "int";
    cache.value = gpg::STR_Printf("vector<%s>", elementName ? elementName : "int");
    (void)std::atexit(&cleanup_RVectorType_int_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005E8E30 (FUN_005E8E30, gpg::RVectorType_int::GetLexical)
 *
 * What it does:
 * Appends `size=<count>` suffix to the base lexical representation for one
 * `vector<int>` payload.
 */
msvc8::string gpg::RVectorType_int::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const IntVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_int::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x005E8E10 (FUN_005E8E10, gpg::RVectorType_int::Init)
 *
 * What it does:
 * Initializes vector<int> RTTI metadata lanes including ser callbacks.
 */
void gpg::RVectorType_int::Init()
{
  size_ = sizeof(IntVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_int::SerLoad;
  serSaveFunc_ = &RVectorType_int::SerSave;
}

/**
 * Address: 0x005E9F20 (FUN_005E9F20, gpg::RVectorType_int::SerLoad)
 *
 * What it does:
 * Deserializes one integer vector from archive lanes and replaces destination
 * storage in one assignment.
 */
void gpg::RVectorType_int::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const storage = PointerFromArchiveInt<IntVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  unsigned int count = 0;
  archive->ReadUInt(&count);

  IntVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));
  for (unsigned int i = 0; i < count; ++i) {
    int value = 0;
    archive->ReadInt(&value);
    loaded.push_back(value);
  }

  *storage = loaded;
}

/**
 * Address: 0x005EA020 (FUN_005EA020, gpg::RVectorType_int::SerSave)
 *
 * What it does:
 * Serializes one integer vector payload element-by-element.
 */
void gpg::RVectorType_int::SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  const auto* const storage = ConstPointerFromArchiveInt<IntVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  const unsigned int count = static_cast<unsigned int>(storage->size());
  archive->WriteUInt(count);
  for (unsigned int i = 0; i < count; ++i) {
    archive->WriteInt((*storage)[static_cast<std::size_t>(i)]);
  }
}

gpg::RRef gpg::RVectorType_int::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<IntVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveIntType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_int::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const IntVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_int::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<IntVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count), 0);
}

/**
 * Address: 0x005ECD70 (FUN_005ECD70, gpg::RVectorType_SAiReservedTransportBone::RVectorType_SAiReservedTransportBone)
 *
 * What it does:
 * Constructs and preregisters reflection metadata for
 * `msvc8::vector<SAiReservedTransportBone>`.
 */
gpg::RVectorType_SAiReservedTransportBone::RVectorType_SAiReservedTransportBone()
{
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SAiReservedTransportBone>), this);
}

/**
 * Address: 0x005E8FE0 (FUN_005E8FE0, gpg::RVectorType_SAiReservedTransportBone::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name for
 * `vector<SAiReservedTransportBone>`.
 */
const char* gpg::RVectorType_SAiReservedTransportBone::GetName() const
{
  CachedTypeName& cache = CachedRVectorTypeSAiReservedTransportBoneName();
  if (!cache.initialized) {
    cache.initialized = true;
    const gpg::RType* const elementType = ResolveReservedTransportBoneType();
    const char* const elementName = elementType ? elementType->GetName() : "SAiReservedTransportBone";
    cache.value = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SAiReservedTransportBone");
    (void)std::atexit(&cleanup_RVectorType_SAiReservedTransportBone_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005E90A0 (FUN_005E90A0, gpg::RVectorType_SAiReservedTransportBone::GetLexical)
 *
 * What it does:
 * Appends `size=<count>` suffix to the base lexical representation for one
 * `vector<SAiReservedTransportBone>` payload.
 */
msvc8::string gpg::RVectorType_SAiReservedTransportBone::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const ReservedTransportBoneVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_SAiReservedTransportBone::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x005E9080 (FUN_005E9080, gpg::RVectorType_SAiReservedTransportBone::Init)
 *
 * What it does:
 * Initializes reserved-bone vector RTTI metadata lanes including ser callbacks.
 */
void gpg::RVectorType_SAiReservedTransportBone::Init()
{
  size_ = sizeof(ReservedTransportBoneVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_SAiReservedTransportBone::SerLoad;
  serSaveFunc_ = &RVectorType_SAiReservedTransportBone::SerSave;
}

/**
 * Address: 0x005EA070 (FUN_005EA070, gpg::RVectorType_SAiReservedTransportBone::SerLoad)
 *
 * What it does:
 * Deserializes reserved-transport-bone vector payload and replaces destination
 * storage.
 */
void gpg::RVectorType_SAiReservedTransportBone::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const storage = PointerFromArchiveInt<ReservedTransportBoneVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  unsigned int count = 0;
  archive->ReadUInt(&count);

  ReservedTransportBoneVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));

  gpg::RType* const elementType = ResolveReservedTransportBoneType();
  GPG_ASSERT(elementType != nullptr);
  if (!elementType) {
    return;
  }

  const gpg::RRef elementOwner{};
  for (unsigned int i = 0; i < count; ++i) {
    moho::SAiReservedTransportBone entry{};
    archive->Read(elementType, &entry, elementOwner);
    loaded.push_back(entry);
  }

  *storage = loaded;
}

/**
 * Address: 0x005EA1E0 (FUN_005EA1E0, gpg::RVectorType_SAiReservedTransportBone::SerSave)
 *
 * What it does:
 * Serializes reserved-transport-bone vector payload element-by-element.
 */
void gpg::RVectorType_SAiReservedTransportBone::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const storage = ConstPointerFromArchiveInt<ReservedTransportBoneVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  const unsigned int count = static_cast<unsigned int>(storage->size());
  archive->WriteUInt(count);

  gpg::RType* const elementType = ResolveReservedTransportBoneType();
  GPG_ASSERT(elementType != nullptr);
  if (!elementType) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0; i < count; ++i) {
    archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
  }
}

gpg::RRef gpg::RVectorType_SAiReservedTransportBone::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<ReservedTransportBoneVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveReservedTransportBoneType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_SAiReservedTransportBone::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const ReservedTransportBoneVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_SAiReservedTransportBone::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<ReservedTransportBoneVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count));
}

/**
 * Address: 0x005ECDE0 (FUN_005ECDE0, gpg::RVectorType_SAttachPoint::RVectorType_SAttachPoint)
 *
 * What it does:
 * Constructs and preregisters reflection metadata for
 * `msvc8::vector<SAttachPoint>`.
 */
gpg::RVectorType_SAttachPoint::RVectorType_SAttachPoint()
{
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SAttachPoint>), this);
}

/**
 * Address: 0x005E9250 (FUN_005E9250, gpg::RVectorType_SAttachPoint::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name for `vector<SAttachPoint>`.
 */
const char* gpg::RVectorType_SAttachPoint::GetName() const
{
  CachedTypeName& cache = CachedRVectorTypeSAttachPointName();
  if (!cache.initialized) {
    cache.initialized = true;
    const gpg::RType* const elementType = ResolveAttachPointType();
    const char* const elementName = elementType ? elementType->GetName() : "SAttachPoint";
    cache.value = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SAttachPoint");
    (void)std::atexit(&cleanup_RVectorType_SAttachPoint_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005E9310 (FUN_005E9310, gpg::RVectorType_SAttachPoint::GetLexical)
 *
 * What it does:
 * Appends `size=<count>` suffix to the base lexical representation for one
 * `vector<SAttachPoint>` payload.
 */
msvc8::string gpg::RVectorType_SAttachPoint::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const AttachPointVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_SAttachPoint::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x005E92F0 (FUN_005E92F0, gpg::RVectorType_SAttachPoint::Init)
 *
 * What it does:
 * Initializes attach-point vector RTTI metadata lanes including ser callbacks.
 */
void gpg::RVectorType_SAttachPoint::Init()
{
  size_ = sizeof(AttachPointVector);
  version_ = 1;
  serLoadFunc_ = &RVectorType_SAttachPoint::SerLoad;
  serSaveFunc_ = &RVectorType_SAttachPoint::SerSave;
}

/**
 * Address: 0x005EA260 (FUN_005EA260, gpg::RVectorType_SAttachPoint::SerLoad)
 *
 * What it does:
 * Deserializes attach-point vector payload and replaces destination storage.
 */
void gpg::RVectorType_SAttachPoint::SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const storage = PointerFromArchiveInt<AttachPointVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  unsigned int count = 0;
  archive->ReadUInt(&count);

  AttachPointVector loaded{};
  loaded.reserve(static_cast<std::size_t>(count));

  gpg::RType* const elementType = ResolveAttachPointType();
  GPG_ASSERT(elementType != nullptr);
  if (!elementType) {
    return;
  }

  const gpg::RRef elementOwner{};
  for (unsigned int i = 0; i < count; ++i) {
    moho::SAttachPoint point{};
    archive->Read(elementType, &point, elementOwner);
    loaded.push_back(point);
  }

  *storage = loaded;
}

/**
 * Address: 0x005EA370 (FUN_005EA370, gpg::RVectorType_SAttachPoint::SerSave)
 *
 * What it does:
 * Serializes attach-point vector payload element-by-element.
 */
void gpg::RVectorType_SAttachPoint::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const storage = ConstPointerFromArchiveInt<AttachPointVector>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(storage != nullptr);
  if (!archive || !storage) {
    return;
  }

  const unsigned int count = static_cast<unsigned int>(storage->size());
  archive->WriteUInt(count);

  gpg::RType* const elementType = ResolveAttachPointType();
  GPG_ASSERT(elementType != nullptr);
  if (!elementType) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0; i < count; ++i) {
    archive->Write(elementType, &(*storage)[static_cast<std::size_t>(i)], owner);
  }
}

gpg::RRef gpg::RVectorType_SAttachPoint::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<AttachPointVector*>(obj);
  gpg::RRef out{};
  out.mObj = nullptr;
  out.mType = ResolveAttachPointType();
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  out.mObj = &(*storage)[static_cast<std::size_t>(ind)];
  return out;
}

size_t gpg::RVectorType_SAttachPoint::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const AttachPointVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType_SAttachPoint::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<AttachPointVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count));
}

gpg::RType* IAiTransport::sType = nullptr;

IAiTransportEventListener* IAiTransportEventListener::FromListenerLink(Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<IAiTransportEventListener, Broadcaster, &IAiTransportEventListener::mListenerLink>(
    link
  );
}

const IAiTransportEventListener* IAiTransportEventListener::FromListenerLink(const Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<IAiTransportEventListener, Broadcaster, &IAiTransportEventListener::mListenerLink>(
    link
  );
}

/**
 * Address: 0x005E3C70 (FUN_005E3C70, scalar deleting thunk target)
 *
 * What it does:
 * Unlinks IAiTransport from broadcaster chain and restores self-linked node.
 */
IAiTransport::~IAiTransport()
{
  ListUnlink();
}

/**
 * What it does:
 * Sync-facing alias for teleport-beacon lookup.
 */
Unit* IAiTransport::TransportGetTeleportBeaconForSync() const
{
  return TransportGetTeleportBeacon();
}

/**
 * Address: 0x00BCEFA0 (FUN_00BCEFA0, register_RBroadcasterRType_EAiTransportEvent)
 *
 * What it does:
 * Registers the broadcaster reflection lane for `EAiTransportEvent` and
 * installs process-exit cleanup.
 */
int moho::register_RBroadcasterRType_EAiTransportEvent()
{
  (void)AcquireBroadcasterTransportType();
  return std::atexit(&cleanup_RBroadcasterRType_EAiTransportEvent);
}

/**
 * Address: 0x00BCEFC0 (FUN_00BCEFC0, register_RListenerRType_EAiTransportEvent)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiTransportEvent` and installs
 * process-exit cleanup.
 */
int moho::register_RListenerRType_EAiTransportEvent()
{
  (void)AcquireListenerTransportType();
  return std::atexit(&cleanup_RListenerRType_EAiTransportEvent);
}

/**
 * Address: 0x00BCEFE0 (FUN_00BCEFE0, register_RVectorType_int)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<int>` reflection type and
 * installs process-exit cleanup.
 */
int moho::register_RVectorType_int()
{
  (void)AcquireIntVectorType();
  return std::atexit(&cleanup_RVectorType_int);
}

/**
 * Address: 0x00BCF000 (FUN_00BCF000, register_RVectorType_SAiReservedTransportBone)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<SAiReservedTransportBone>`
 * reflection type and installs process-exit cleanup.
 */
int moho::register_RVectorType_SAiReservedTransportBone()
{
  (void)AcquireReservedTransportBoneVectorType();
  return std::atexit(&cleanup_RVectorType_SAiReservedTransportBone);
}

/**
 * Address: 0x00BCF020 (FUN_00BCF020, register_RVectorType_SAttachPoint)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<SAttachPoint>` reflection type
 * and installs process-exit cleanup.
 */
int moho::register_RVectorType_SAttachPoint()
{
  (void)AcquireAttachPointVectorType();
  return std::atexit(&cleanup_RVectorType_SAttachPoint);
}

namespace
{
  struct IAiTransportReflectionBootstrap
  {
    IAiTransportReflectionBootstrap()
    {
      (void)moho::register_EAiTransportEventTypeInfo();
      (void)moho::register_EAiTransportEventPrimitiveSerializer();
      (void)moho::register_SAiReservedTransportBoneTypeInfo();
      (void)moho::register_SAiReservedTransportBoneSerializer();
      (void)moho::register_SAttachPointTypeInfo();
      (void)moho::register_SAttachPointSerializer();
      (void)moho::register_STransportPickUpInfoTypeInfo();
      (void)moho::register_STransportPickUpInfoSerializer();
      (void)moho::register_IAiTransportTypeInfo();
      (void)moho::register_IAiTransportSerializer();
      (void)moho::register_CAiTransportImplTypeInfo();
      (void)moho::register_CAiTransportImplConstruct();
      (void)moho::register_CAiTransportImplSerializer();
      (void)moho::register_RBroadcasterRType_EAiTransportEvent();
      (void)moho::register_RListenerRType_EAiTransportEvent();
      (void)moho::register_RVectorType_int();
      (void)moho::register_RVectorType_SAiReservedTransportBone();
      (void)moho::register_RVectorType_SAttachPoint();
    }
  };

  [[maybe_unused]] IAiTransportReflectionBootstrap gIAiTransportReflectionBootstrap;
} // namespace
