#include "moho/unit/core/UnitFastVectorReflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/sim/ReconBlip.h"

namespace
{
  using WeakPtrEntityFastVectorType = gpg::RFastVectorType<moho::WeakPtr<moho::Entity>>;
  using ReconBlipPtrFastVectorType = gpg::RFastVectorType<moho::ReconBlip*>;

  alignas(WeakPtrEntityFastVectorType) unsigned char gWeakPtrEntityFastVectorTypeStorage[sizeof(WeakPtrEntityFastVectorType)];
  bool gWeakPtrEntityFastVectorTypeConstructed = false;

  alignas(ReconBlipPtrFastVectorType) unsigned char gReconBlipPtrFastVectorTypeStorage[sizeof(ReconBlipPtrFastVectorType)];
  bool gReconBlipPtrFastVectorTypeConstructed = false;

  msvc8::string gWeakPtrEntityFastVectorTypeName;
  msvc8::string gReconBlipPtrFastVectorTypeName;
  bool gWeakPtrEntityFastVectorTypeNameCleanupRegistered = false;
  bool gReconBlipPtrFastVectorTypeNameCleanupRegistered = false;

  template <class TType>
  [[nodiscard]] TType* AcquireReflectionType(unsigned char* const storage, bool& constructedFlag)
  {
    if (!constructedFlag) {
      new (storage) TType();
      constructedFlag = true;
    }
    return reinterpret_cast<TType*>(storage);
  }

  [[nodiscard]] WeakPtrEntityFastVectorType* AcquireWeakPtrEntityFastVectorType()
  {
    return AcquireReflectionType<WeakPtrEntityFastVectorType>(
      gWeakPtrEntityFastVectorTypeStorage,
      gWeakPtrEntityFastVectorTypeConstructed
    );
  }

  [[nodiscard]] ReconBlipPtrFastVectorType* AcquireReconBlipPtrFastVectorType()
  {
    return AcquireReflectionType<ReconBlipPtrFastVectorType>(
      gReconBlipPtrFastVectorTypeStorage,
      gReconBlipPtrFastVectorTypeConstructed
    );
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedReconBlipType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = moho::ReconBlip::sType;
      if (!cached) {
        cached = gpg::LookupRType(typeid(moho::ReconBlip));
        moho::ReconBlip::sType = cached;
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedReconBlipPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ReconBlip*));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::fastvector<moho::WeakPtr<moho::Entity>>));
      if (!cached) {
        cached = moho::register_FastVectorWeakPtrEntityType_00();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedFastVectorReconBlipPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::fastvector<moho::ReconBlip*>));
      if (!cached) {
        cached = moho::register_FastVectorReconBlipPtrType_00();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeWeakPtrEntityRef(moho::WeakPtr<moho::Entity>* value)
  {
    gpg::RRef out{};
    out.mObj = value;
    out.mType = CachedWeakPtrEntityType();
    return out;
  }

  [[nodiscard]] gpg::RRef MakeReconBlipObjectRef(moho::ReconBlip* blip)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedReconBlipType();
    if (!blip) {
      return out;
    }

    gpg::RType* dynamicType = CachedReconBlipType();
    try {
      dynamicType = gpg::LookupRType(typeid(*blip));
    } catch (...) {
      dynamicType = CachedReconBlipType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && CachedReconBlipType() != nullptr &&
      dynamicType->IsDerivedFrom(CachedReconBlipType(), &baseOffset);

    out.mObj = isDerived
      ? reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(blip) - static_cast<std::uintptr_t>(baseOffset))
      : static_cast<void*>(blip);
    out.mType = dynamicType ? dynamicType : CachedReconBlipType();
    return out;
  }

  [[nodiscard]] gpg::RRef MakeReconBlipPointerSlotRef(moho::ReconBlip** slot)
  {
    if (gpg::RType* const pointerType = CachedReconBlipPointerType(); pointerType != nullptr) {
      gpg::RRef out{};
      out.mObj = slot;
      out.mType = pointerType;
      return out;
    }

    return MakeReconBlipObjectRef(slot ? *slot : nullptr);
  }

  [[nodiscard]] moho::ReconBlip* ReadPointerReconBlip(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedReconBlipType());
    if (upcast.mObj) {
      return static_cast<moho::ReconBlip*>(upcast.mObj);
    }

    const char* const expected = CachedReconBlipType() ? CachedReconBlipType()->GetName() : "ReconBlip";
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "ReconBlip",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  template <class T>
  void ResizeFastVectorWeakPtrRuntime(gpg::fastvector_runtime_view<moho::WeakPtr<T>>& view, const std::size_t newCount)
  {
    const std::size_t oldCount = view.begin ? static_cast<std::size_t>(view.end - view.begin) : 0u;
    const std::size_t oldCapacity = view.begin ? static_cast<std::size_t>(view.capacityEnd - view.begin) : 0u;

    if (newCount < oldCount) {
      for (std::size_t i = newCount; i < oldCount; ++i) {
        view.begin[i].ResetFromObject(nullptr);
      }
      view.end = view.begin + newCount;
      return;
    }

    if (newCount > oldCapacity) {
      std::size_t newCapacity = oldCapacity ? oldCapacity : 4u;
      while (newCapacity < newCount) {
        newCapacity *= 2u;
      }

      auto* const newBegin = static_cast<moho::WeakPtr<T>*>(::operator new(sizeof(moho::WeakPtr<T>) * newCapacity));
      for (std::size_t i = 0; i < newCapacity; ++i) {
        newBegin[i].ownerLinkSlot = nullptr;
        newBegin[i].nextInOwner = nullptr;
      }

      for (std::size_t i = 0; i < oldCount; ++i) {
        newBegin[i].ResetFromOwnerLinkSlot(view.begin[i].ownerLinkSlot);
        view.begin[i].ResetFromObject(nullptr);
      }

      ::operator delete(view.begin);
      view.begin = newBegin;
      view.end = newBegin + oldCount;
      view.capacityEnd = newBegin + newCapacity;
    }

    for (std::size_t i = oldCount; i < newCount; ++i) {
      view.begin[i].ownerLinkSlot = nullptr;
      view.begin[i].nextInOwner = nullptr;
    }
    view.end = view.begin + newCount;
  }

  /**
   * Address: 0x006AF3F0 (FUN_006AF3F0, sub_6AF3F0)
   *
   * What it does:
   * Deserializes `fastvector<WeakPtr<Entity>>` count/lane payloads.
   */
  void LoadFastVectorWeakPtrEntity(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::WeakPtr<moho::Entity>>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    ResizeFastVectorWeakPtrRuntime<moho::Entity>(view, static_cast<std::size_t>(count));

    gpg::RType* const weakType = CachedWeakPtrEntityType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(weakType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x006AF4C0 (FUN_006AF4C0, sub_6AF4C0)
   *
   * What it does:
   * Serializes `fastvector<WeakPtr<Entity>>` count/lane payloads.
   */
  void SaveFastVectorWeakPtrEntity(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view =
      gpg::AsFastVectorRuntimeView<moho::WeakPtr<moho::Entity>>(reinterpret_cast<const void*>(objectPtr));

    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const weakType = CachedWeakPtrEntityType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(weakType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x006AF530 (FUN_006AF530, gpg::RFastVectorType_ReconBlip_P::SerLoad)
   *
   * What it does:
   * Deserializes `fastvector<ReconBlip*>` count and tracked-pointer lanes.
   */
  void LoadFastVectorReconBlipPointer(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::ReconBlip*>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::ReconBlip* fill = nullptr;
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      view.begin[i] = ReadPointerReconBlip(archive, owner);
    }
  }

  /**
   * Address: 0x006AF590 (FUN_006AF590, gpg::RFastVectorType_ReconBlip_P::SerSave)
   *
   * What it does:
   * Serializes `fastvector<ReconBlip*>` count and tracked-pointer lanes.
   */
  void SaveFastVectorReconBlipPointer(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::ReconBlip*>(reinterpret_cast<const void*>(objectPtr));

    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::RRef objectRef = MakeReconBlipObjectRef(view.begin[i]);
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x00BFDA90 (FUN_00BFDA90, sub_BFDA90)
   */
  void cleanup_WeakPtrEntityFastVectorTypeName()
  {
    gWeakPtrEntityFastVectorTypeName = msvc8::string{};
    gWeakPtrEntityFastVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BFDA60 (FUN_00BFDA60, sub_BFDA60)
   */
  void cleanup_ReconBlipPtrFastVectorTypeName()
  {
    gReconBlipPtrFastVectorTypeName = msvc8::string{};
    gReconBlipPtrFastVectorTypeNameCleanupRegistered = false;
  }

  struct UnitFastVectorReflectionBootstrap
  {
    UnitFastVectorReflectionBootstrap()
    {
      (void)moho::register_FastVectorWeakPtrEntityType_AtExit();
      (void)moho::register_FastVectorReconBlipPtrType_AtExit();
    }
  };

  UnitFastVectorReflectionBootstrap gUnitFastVectorReflectionBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x006AE400 (FUN_006AE400, gpg::RFastVectorType_WeakPtr_Entity::GetName)
   */
  const char* RFastVectorType<moho::WeakPtr<moho::Entity>>::GetName() const
  {
    if (gWeakPtrEntityFastVectorTypeName.empty()) {
      const char* const elementName = CachedWeakPtrEntityType() ? CachedWeakPtrEntityType()->GetName() : "WeakPtr<Entity>";
      gWeakPtrEntityFastVectorTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "WeakPtr<Entity>");
      if (!gWeakPtrEntityFastVectorTypeNameCleanupRegistered) {
        gWeakPtrEntityFastVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrEntityFastVectorTypeName);
      }
    }

    return gWeakPtrEntityFastVectorTypeName.c_str();
  }

  /**
   * Address: 0x006AE4C0 (FUN_006AE4C0, gpg::RFastVectorType_WeakPtr_Entity::GetLexical)
   */
  msvc8::string RFastVectorType<moho::WeakPtr<moho::Entity>>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x006AE550 (FUN_006AE550, gpg::RFastVectorType_WeakPtr_Entity::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::WeakPtr<moho::Entity>>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x006AE4A0 (FUN_006AE4A0, gpg::RFastVectorType_WeakPtr_Entity::Init)
   */
  void RFastVectorType<moho::WeakPtr<moho::Entity>>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorWeakPtrEntity;
    serSaveFunc_ = &SaveFastVectorWeakPtrEntity;
  }

  /**
   * Address: 0x006AE5F0 (FUN_006AE5F0, gpg::RFastVectorType_WeakPtr_Entity::SubscriptIndex)
   */
  gpg::RRef RFastVectorType<moho::WeakPtr<moho::Entity>>::SubscriptIndex(void* obj, const int ind) const
  {
    if (!obj) {
      return MakeWeakPtrEntityRef(nullptr);
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::WeakPtr<moho::Entity>>(obj);
    GPG_ASSERT(ind >= 0);
    GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));
    if (ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj) || !view.begin) {
      return MakeWeakPtrEntityRef(nullptr);
    }

    return MakeWeakPtrEntityRef(view.begin + ind);
  }

  /**
   * Address: 0x006AE560 (FUN_006AE560, gpg::RFastVectorType_WeakPtr_Entity::GetCount)
   */
  size_t RFastVectorType<moho::WeakPtr<moho::Entity>>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::WeakPtr<moho::Entity>>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x006AE570 (FUN_006AE570, gpg::RFastVectorType_WeakPtr_Entity::SetCount)
   */
  void RFastVectorType<moho::WeakPtr<moho::Entity>>::SetCount(void* obj, const int count) const
  {
    GPG_ASSERT(obj != nullptr);
    GPG_ASSERT(count >= 0);
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::WeakPtr<moho::Entity>>(obj);
    ResizeFastVectorWeakPtrRuntime<moho::Entity>(view, static_cast<std::size_t>(count));
  }

  /**
   * Address: 0x006AE630 (FUN_006AE630, gpg::RFastVectorType_ReconBlip_P::GetName)
   */
  const char* RFastVectorType<moho::ReconBlip*>::GetName() const
  {
    if (gReconBlipPtrFastVectorTypeName.empty()) {
      const char* const elementName = CachedReconBlipPointerType()
        ? CachedReconBlipPointerType()->GetName()
        : "ReconBlip*";
      gReconBlipPtrFastVectorTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "ReconBlip*");
      if (!gReconBlipPtrFastVectorTypeNameCleanupRegistered) {
        gReconBlipPtrFastVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_ReconBlipPtrFastVectorTypeName);
      }
    }

    return gReconBlipPtrFastVectorTypeName.c_str();
  }

  /**
   * Address: 0x006AE6D0 (FUN_006AE6D0, gpg::RFastVectorType_ReconBlip_P::GetLexical)
   */
  msvc8::string RFastVectorType<moho::ReconBlip*>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x006AE760 (FUN_006AE760, gpg::RFastVectorType_ReconBlip_P::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::ReconBlip*>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x006AE6B0 (FUN_006AE6B0, gpg::RFastVectorType_ReconBlip_P::Init)
   */
  void RFastVectorType<moho::ReconBlip*>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorReconBlipPointer;
    serSaveFunc_ = &SaveFastVectorReconBlipPointer;
  }

  /**
   * Address: 0x006AE7A0 (FUN_006AE7A0, gpg::RFastVectorType_ReconBlip_P::SubscriptIndex)
   */
  gpg::RRef RFastVectorType<moho::ReconBlip*>::SubscriptIndex(void* obj, const int ind) const
  {
    if (!obj) {
      return MakeReconBlipPointerSlotRef(nullptr);
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::ReconBlip*>(obj);
    GPG_ASSERT(ind >= 0);
    GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));
    if (!view.begin || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return MakeReconBlipPointerSlotRef(nullptr);
    }

    return MakeReconBlipPointerSlotRef(view.begin + ind);
  }

  /**
   * Address: 0x006AE770 (FUN_006AE770, gpg::RFastVectorType_ReconBlip_P::GetCount)
   */
  size_t RFastVectorType<moho::ReconBlip*>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::ReconBlip*>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x006AE780 (FUN_006AE780, gpg::RFastVectorType_ReconBlip_P::SetCount)
   */
  void RFastVectorType<moho::ReconBlip*>::SetCount(void* obj, const int count) const
  {
    GPG_ASSERT(obj != nullptr);
    GPG_ASSERT(count >= 0);
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::ReconBlip*>(obj);
    moho::ReconBlip* fill = nullptr;
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006B1710 (FUN_006B1710, register_FastVectorWeakPtrEntityType_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `fastvector<WeakPtr<Entity>>`.
   */
  gpg::RType* register_FastVectorWeakPtrEntityType_00()
  {
    WeakPtrEntityFastVectorType* const type = AcquireWeakPtrEntityFastVectorType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<WeakPtr<Entity>>), type);
    return type;
  }

  /**
   * Address: 0x00BFDB80 (FUN_00BFDB80, cleanup_FastVectorWeakPtrEntityType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<WeakPtr<Entity>>` reflection storage.
   */
  void cleanup_FastVectorWeakPtrEntityType()
  {
    if (!gWeakPtrEntityFastVectorTypeConstructed) {
      return;
    }

    AcquireWeakPtrEntityFastVectorType()->~WeakPtrEntityFastVectorType();
    gWeakPtrEntityFastVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BD6BE0 (FUN_00BD6BE0, register_FastVectorWeakPtrEntityType_AtExit)
   *
   * What it does:
   * Registers `fastvector<WeakPtr<Entity>>` reflection and installs process-exit teardown.
   */
  int register_FastVectorWeakPtrEntityType_AtExit()
  {
    (void)register_FastVectorWeakPtrEntityType_00();
    return std::atexit(&cleanup_FastVectorWeakPtrEntityType);
  }

  /**
   * Address: 0x006B1780 (FUN_006B1780, register_FastVectorReconBlipPtrType_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `fastvector<ReconBlip*>`.
   */
  gpg::RType* register_FastVectorReconBlipPtrType_00()
  {
    ReconBlipPtrFastVectorType* const type = AcquireReconBlipPtrFastVectorType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<ReconBlip*>), type);
    return type;
  }

  /**
   * Address: 0x00BFDB20 (FUN_00BFDB20, cleanup_FastVectorReconBlipPtrType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<ReconBlip*>` reflection storage.
   */
  void cleanup_FastVectorReconBlipPtrType()
  {
    if (!gReconBlipPtrFastVectorTypeConstructed) {
      return;
    }

    AcquireReconBlipPtrFastVectorType()->~ReconBlipPtrFastVectorType();
    gReconBlipPtrFastVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BD6C00 (FUN_00BD6C00, register_FastVectorReconBlipPtrType_AtExit)
   *
   * What it does:
   * Registers `fastvector<ReconBlip*>` reflection and installs process-exit teardown.
   */
  int register_FastVectorReconBlipPtrType_AtExit()
  {
    (void)register_FastVectorReconBlipPtrType_00();
    return std::atexit(&cleanup_FastVectorReconBlipPtrType);
  }
} // namespace moho
