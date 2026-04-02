#include "moho/ai/IAiTransport.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
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

namespace moho
{
  class RBroadcasterRType_EAiTransportEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Broadcaster<EAiTransportEvent>";
    }

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      Finish();
    }
  };

  class RListenerRType_EAiTransportEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Listener<EAiTransportEvent>";
    }

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
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_SAiReservedTransportBone final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  class RVectorType_SAttachPoint final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
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

  template <class TVector>
  [[nodiscard]] msvc8::string MakeVectorLexical(const gpg::RType* const ownerType, const gpg::RRef& ref, const TVector* vec)
  {
    const msvc8::string base = ownerType != nullptr ? ownerType->GetLexical(ref) : msvc8::string("vector");
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
} // namespace

const char* gpg::RVectorType_int::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveIntType();
    const char* const elementName = elementType ? elementType->GetName() : "int";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "int");
  }
  return sName.c_str();
}

msvc8::string gpg::RVectorType_int::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const IntVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_int::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_int::Init()
{
  size_ = sizeof(IntVector);
  version_ = 1;
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

const char* gpg::RVectorType_SAiReservedTransportBone::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveReservedTransportBoneType();
    const char* const elementName = elementType ? elementType->GetName() : "SAiReservedTransportBone";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SAiReservedTransportBone");
  }
  return sName.c_str();
}

msvc8::string gpg::RVectorType_SAiReservedTransportBone::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const ReservedTransportBoneVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_SAiReservedTransportBone::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_SAiReservedTransportBone::Init()
{
  size_ = sizeof(ReservedTransportBoneVector);
  version_ = 1;
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

const char* gpg::RVectorType_SAttachPoint::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveAttachPointType();
    const char* const elementName = elementType ? elementType->GetName() : "SAttachPoint";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "SAttachPoint");
  }
  return sName.c_str();
}

msvc8::string gpg::RVectorType_SAttachPoint::GetLexical(const gpg::RRef& ref) const
{
  return MakeVectorLexical(this, ref, static_cast<const AttachPointVector*>(ref.mObj));
}

const gpg::RIndexed* gpg::RVectorType_SAttachPoint::IsIndexed() const
{
  return this;
}

void gpg::RVectorType_SAttachPoint::Init()
{
  size_ = sizeof(AttachPointVector);
  version_ = 1;
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
  auto* const type = AcquireBroadcasterTransportType();
  gpg::PreRegisterRType(typeid(moho::BroadcasterEventTag<moho::EAiTransportEvent>), type);
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
  auto* const type = AcquireListenerTransportType();
  gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiTransportEvent>), type);
  return std::atexit(&cleanup_RListenerRType_EAiTransportEvent);
}

/**
 * Address: 0x00BCEFE0 (FUN_00BCEFE0, register_RVectorType_int)
 *
 * What it does:
 * Registers `msvc8::vector<int>` reflection metadata and installs cleanup.
 */
int moho::register_RVectorType_int()
{
  auto* const type = AcquireIntVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<int>), type);
  return std::atexit(&cleanup_RVectorType_int);
}

/**
 * Address: 0x00BCF000 (FUN_00BCF000, register_RVectorType_SAiReservedTransportBone)
 *
 * What it does:
 * Registers `msvc8::vector<SAiReservedTransportBone>` reflection metadata and
 * installs cleanup.
 */
int moho::register_RVectorType_SAiReservedTransportBone()
{
  auto* const type = AcquireReservedTransportBoneVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SAiReservedTransportBone>), type);
  return std::atexit(&cleanup_RVectorType_SAiReservedTransportBone);
}

/**
 * Address: 0x00BCF020 (FUN_00BCF020, register_RVectorType_SAttachPoint)
 *
 * What it does:
 * Registers `msvc8::vector<SAttachPoint>` reflection metadata and installs
 * cleanup.
 */
int moho::register_RVectorType_SAttachPoint()
{
  auto* const type = AcquireAttachPointVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SAttachPoint>), type);
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
