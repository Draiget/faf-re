#include "moho/ai/IAiTransport.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiTransportImpl.h"
#include "moho/ai/CAiTransportImplTypeInfo.h"
#include "moho/ai/EAiTransportEventTypeInfo.h"
#include "moho/ai/IAiTransportSerializer.h"
#include "moho/ai/IAiTransportTypeInfo.h"
#include "moho/ai/SAiReservedTransportBone.h"
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
     * `Broadcaster<EAiTransportEvent>`.
     */
    RBroadcasterRType_EAiTransportEvent();

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005E8CA0 (FUN_005E8CA0, ?Init@RBroadcasterRType_EAiTransportEvent@Moho@@UAEXXZ)
     *
     * What it does:
     * Sizes the reflected broadcaster lane and installs its serializer pair.
     * The version stamp is part of the emission, not decoration - the archive
     * reads it back to pick a load path.
     */
    void Init() override
    {
      size_ = sizeof(Broadcaster<EAiTransportEvent>);
      version_ = 1;
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

    /**
     * Address: 0x005E8D60 (?Init@RListenerRType_EAiTransportEvent@Moho@@UAEXXZ)
     *
     * What it does:
     * Sizes the reflected listener lane. Unlike the broadcaster side this
     * type carries no serializers and no version stamp - the emission sets
     * size only.
     */
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

    /**
     * Address: 0x005ED070 (FUN_005ED070, gpg::RVectorType_int::dtr)
     */
    ~RVectorType_int() override;

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

    /**
     * Address: 0x005ED0D0 (FUN_005ED0D0, gpg::RVectorType_SAiReservedTransportBone::dtr)
     */
    ~RVectorType_SAiReservedTransportBone() override;

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

    /**
     * Address: 0x005ED130 (FUN_005ED130, gpg::RVectorType_SAttachPoint::dtr)
     */
    ~RVectorType_SAttachPoint() override;

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

  using IntVector = msvc8::vector<int>;
  using ReservedTransportBoneVector = msvc8::vector<moho::SAiReservedTransportBone>;
  using AttachPointVector = msvc8::vector<moho::SAttachPoint>;

  [[nodiscard]] BroadcasterTransportType* AcquireBroadcasterTransportType()
  {
    static BroadcasterTransportType sInstance;
    return &sInstance;
  }

  [[nodiscard]] ListenerTransportType* AcquireListenerTransportType()
  {
    static ListenerTransportType sInstance;
    return &sInstance;
  }

  [[nodiscard]] IntVectorType* AcquireIntVectorType()
  {
    static IntVectorType sInstance;
    return &sInstance;
  }

  [[nodiscard]] ReservedTransportBoneVectorType* AcquireReservedTransportBoneVectorType()
  {
    static ReservedTransportBoneVectorType sInstance;
    return &sInstance;
  }

  [[nodiscard]] AttachPointVectorType* AcquireAttachPointVectorType()
  {
    static AttachPointVectorType sInstance;
    return &sInstance;
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
} // namespace

/**
 * Address: 0x005E8C00 (FUN_005E8C00, Moho::RBroadcasterRType_EAiTransportEvent::GetName)
 * Address: 0x00BF8D60 (FUN_00BF8D60, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds the runtime type name `Broadcaster<EAiTransportEvent>` once from the
 * registered enum type name and returns it.
 */
const char* moho::RBroadcasterRType_EAiTransportEvent::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("Broadcaster<%s>", ResolveEAiTransportEventType()->GetName());
  return sName.c_str();
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
  auto* const broadcaster = PointerFromArchiveInt<moho::Broadcaster<moho::EAiTransportEvent>>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(broadcaster != nullptr);
  if (!archive || !broadcaster) {
    return;
  }

  moho::Listener<moho::EAiTransportEvent>* listener = nullptr;
  archive->ReadPointer(&listener, ownerRef);
  while (listener != nullptr) {
    broadcaster->AddListener(listener);
    archive->ReadPointer(&listener, ownerRef);
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
  auto* const broadcaster = PointerFromArchiveInt<moho::Broadcaster<moho::EAiTransportEvent>>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(broadcaster != nullptr);
  if (!archive || !broadcaster) {
    return;
  }

  const gpg::RRef nullOwner{};

  for (moho::Listener<moho::EAiTransportEvent>* const listener : broadcaster->mListeners.owners()) {
    archive->WritePointer<moho::Listener<moho::EAiTransportEvent>>(listener, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  archive->WritePointer<moho::Listener<moho::EAiTransportEvent>>(nullptr, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x005E8CC0 (FUN_005E8CC0, Moho::RListenerRType_EAiTransportEvent::GetName)
 * Address: 0x00BF8D30 (FUN_00BF8D30, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds the runtime type name `Listener<EAiTransportEvent>` once from the
 * registered enum type name and returns it.
 */
const char* moho::RListenerRType_EAiTransportEvent::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("Listener<%s>", ResolveEAiTransportEventType()->GetName());
  return sName.c_str();
}

/**
 * Address: 0x005ECC40 (FUN_005ECC40, moho::RBroadcasterRType_EAiTransportEvent::RBroadcasterRType_EAiTransportEvent)
 *
 * What it does:
 * Constructs and preregisters the broadcaster RTTI lane for
 * `Broadcaster<EAiTransportEvent>`.
 */
moho::RBroadcasterRType_EAiTransportEvent::RBroadcasterRType_EAiTransportEvent()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(moho::Broadcaster<moho::EAiTransportEvent>), this);
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
 * Address: 0x005ED070 (FUN_005ED070, gpg::RVectorType_int::dtr)
 */
gpg::RVectorType_int::~RVectorType_int() = default;

/**
 * Address: 0x005E8D70 (FUN_005E8D70, gpg::RVectorType_int::GetName)
 * Address: 0x00BF8D00 (FUN_00BF8D00, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds the runtime type name `vector<int>` once from the registered `int`
 * reflection type and returns it.
 */
const char* gpg::RVectorType_int::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("vector<%s>", ResolveIntType()->GetName());
  return sName.c_str();
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
  loaded.reserve(count);
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
 * Address: 0x005ED0D0 (FUN_005ED0D0, gpg::RVectorType_SAiReservedTransportBone::dtr)
 */
gpg::RVectorType_SAiReservedTransportBone::~RVectorType_SAiReservedTransportBone() = default;

/**
 * Address: 0x005E8FE0 (FUN_005E8FE0, gpg::RVectorType_SAiReservedTransportBone::GetName)
 * Address: 0x00BF8CD0 (FUN_00BF8CD0, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds the runtime type name for `vector<SAiReservedTransportBone>` once
 * and returns it.
 */
const char* gpg::RVectorType_SAiReservedTransportBone::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("vector<%s>", ResolveReservedTransportBoneType()->GetName());
  return sName.c_str();
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

  // Route the per-T copy-assignment through the canonical helper
  // (FUN_005EA480) so the MSVC8 vector<SAiReservedTransportBone>::operator=
  // template emission symbol shape is preserved.
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
 * Address: 0x005ED130 (FUN_005ED130, gpg::RVectorType_SAttachPoint::dtr)
 */
gpg::RVectorType_SAttachPoint::~RVectorType_SAttachPoint() = default;

/**
 * Address: 0x005E9250 (FUN_005E9250, gpg::RVectorType_SAttachPoint::GetName)
 * Address: 0x00BF8CA0 (FUN_00BF8CA0, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds the runtime type name for `vector<SAttachPoint>` once and returns it.
 */
const char* gpg::RVectorType_SAttachPoint::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("vector<%s>", ResolveAttachPointType()->GetName());
  return sName.c_str();
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
  loaded.reserve(count);

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

  storage->resize(static_cast<std::size_t>(count), moho::SAttachPoint{});
}

gpg::RType* IAiTransport::sType = nullptr;

/**
 * Address: 0x005E3C50 (FUN_005E3C50)
 * Address: 0x005E82A0 (FUN_005E82A0)
 *
 * What it does:
 * Installs the interface vtable; the `Broadcaster` base self-links the
 * listener ring. The second address is an equivalent copy.
 */
IAiTransport::IAiTransport() = default;

/**
 * Address: 0x005E3C70 (FUN_005E3C70, scalar deleting thunk target)
 *
 * What it does:
 * Nothing of its own: the `Broadcaster` base's destructor unlinks the
 * listener ring.
 */
IAiTransport::~IAiTransport() = default;

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
void moho::register_RBroadcasterRType_EAiTransportEvent()
{
  (void)AcquireBroadcasterTransportType();
}

/**
 * Address: 0x00BCEFC0 (FUN_00BCEFC0, register_RListenerRType_EAiTransportEvent)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiTransportEvent` and installs
 * process-exit cleanup.
 */
void moho::register_RListenerRType_EAiTransportEvent()
{
  (void)AcquireListenerTransportType();
}

/**
 * Address: 0x00BCEFE0 (FUN_00BCEFE0, register_RVectorType_int)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<int>` reflection type and
 * installs process-exit cleanup.
 */
void moho::register_RVectorType_int()
{
  (void)AcquireIntVectorType();
}

/**
 * Address: 0x00BCF000 (FUN_00BCF000, register_RVectorType_SAiReservedTransportBone)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<SAiReservedTransportBone>`
 * reflection type and installs process-exit cleanup.
 */
void moho::register_RVectorType_SAiReservedTransportBone()
{
  (void)AcquireReservedTransportBoneVectorType();
}

/**
 * Address: 0x00BCF020 (FUN_00BCF020, register_RVectorType_SAttachPoint)
 *
 * What it does:
 * Constructs/preregisters the `msvc8::vector<SAttachPoint>` reflection type
 * and installs process-exit cleanup.
 */
void moho::register_RVectorType_SAttachPoint()
{
  (void)AcquireAttachPointVectorType();
}

namespace
{
  struct IAiTransportReflectionBootstrap
  {
    IAiTransportReflectionBootstrap()
    {
      (void)moho::register_EAiTransportEventTypeInfo();
      (void)moho::register_SAiReservedTransportBoneTypeInfo();
      (void)moho::register_SAttachPointTypeInfo();
      (void)moho::register_SAttachPointSerializer();
      (void)moho::register_STransportPickUpInfoTypeInfo();
      (void)moho::register_STransportPickUpInfoSerializer();
      (void)moho::register_IAiTransportTypeInfo();
      (void)moho::register_IAiTransportSerializer();
      (void)moho::register_CAiTransportImplTypeInfo();
      (void)moho::register_RBroadcasterRType_EAiTransportEvent();
      (void)moho::register_RListenerRType_EAiTransportEvent();
      (void)moho::register_RVectorType_int();
      (void)moho::register_RVectorType_SAiReservedTransportBone();
      (void)moho::register_RVectorType_SAttachPoint();
    }
  };

  [[maybe_unused]] IAiTransportReflectionBootstrap gIAiTransportReflectionBootstrap;
} // namespace
