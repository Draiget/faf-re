#include "moho/entity/EntityFastVectorReflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

#pragma init_seg(lib)

namespace
{
  using WeakPtrEntityType = moho::RWeakPtrType<moho::Entity>;
  using WeakPtrEntity = moho::WeakPtr<moho::Entity>;
  using EntityPtrVectorType = gpg::RVectorType<moho::Entity*>;
  using EntityPtrVector = msvc8::vector<moho::Entity*>;
  using EntityPtrFastVectorType = gpg::RFastVectorType<moho::Entity*>;

  alignas(WeakPtrEntityType) unsigned char gWeakPtrEntityTypeStorage[sizeof(WeakPtrEntityType)];
  bool gWeakPtrEntityTypeConstructed = false;

  alignas(EntityPtrVectorType) unsigned char gEntityPtrVectorTypeStorage[sizeof(EntityPtrVectorType)];
  bool gEntityPtrVectorTypeConstructed = false;

  alignas(EntityPtrFastVectorType) unsigned char gEntityPtrFastVectorTypeStorage[sizeof(EntityPtrFastVectorType)];
  bool gEntityPtrFastVectorTypeConstructed = false;

  msvc8::string gWeakPtrEntityTypeName;
  bool gWeakPtrEntityTypeNameCleanupRegistered = false;

  msvc8::string gEntityPtrVectorTypeName;
  bool gEntityPtrVectorTypeNameCleanupRegistered = false;

  msvc8::string gEntityPtrFastVectorTypeName;
  bool gEntityPtrFastVectorTypeNameCleanupRegistered = false;

  [[nodiscard]] WeakPtrEntityType* AcquireWeakPtrEntityType()
  {
    if (!gWeakPtrEntityTypeConstructed) {
      new (gWeakPtrEntityTypeStorage) WeakPtrEntityType();
      gWeakPtrEntityTypeConstructed = true;
    }

    return reinterpret_cast<WeakPtrEntityType*>(gWeakPtrEntityTypeStorage);
  }

  [[nodiscard]] EntityPtrVectorType* AcquireEntityPtrVectorType()
  {
    if (!gEntityPtrVectorTypeConstructed) {
      new (gEntityPtrVectorTypeStorage) EntityPtrVectorType();
      gEntityPtrVectorTypeConstructed = true;
    }

    return reinterpret_cast<EntityPtrVectorType*>(gEntityPtrVectorTypeStorage);
  }

  [[nodiscard]] EntityPtrFastVectorType* AcquireEntityPtrFastVectorType()
  {
    if (!gEntityPtrFastVectorTypeConstructed) {
      new (gEntityPtrFastVectorTypeStorage) EntityPtrFastVectorType();
      gEntityPtrFastVectorTypeConstructed = true;
    }

    return reinterpret_cast<EntityPtrFastVectorType*>(gEntityPtrFastVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Entity));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEntityPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Entity*));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeEntityObjectRef(moho::Entity* entity)
  {
    gpg::RRef out{};
    out.mType = CachedEntityType();
    out.mObj = entity;
    if (!entity) {
      return out;
    }

    gpg::RType* dynamicType = CachedEntityType();
    try {
      dynamicType = gpg::LookupRType(typeid(*entity));
    } catch (...) {
      dynamicType = CachedEntityType();
    }

    int baseOffset = 0;
    if (dynamicType && CachedEntityType() && dynamicType->IsDerivedFrom(CachedEntityType(), &baseOffset)) {
      out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(entity) - static_cast<std::uintptr_t>(baseOffset));
      out.mType = dynamicType;
      return out;
    }

    out.mType = dynamicType ? dynamicType : CachedEntityType();
    return out;
  }

  [[nodiscard]] gpg::RRef MakeEntityPointerSlotRef(moho::Entity** slot)
  {
    if (gpg::RType* const pointerType = CachedEntityPointerType(); pointerType != nullptr) {
      gpg::RRef out{};
      out.mObj = slot;
      out.mType = pointerType;
      return out;
    }

    return MakeEntityObjectRef(slot ? *slot : nullptr);
  }

  [[nodiscard]] moho::Entity* ReadEntityPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntityType());
    if (upcast.mObj) {
      return static_cast<moho::Entity*>(upcast.mObj);
    }

    const char* const expected = CachedEntityType() ? CachedEntityType()->GetName() : "Entity";
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "Entity",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  /**
   * Address: 0x0067CD30 (FUN_0067CD30, Moho::RWeakPtrType_Entity::SerLoad)
   */
  void LoadWeakPtrEntity(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtrEntity*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    weak->ResetFromObject(ReadEntityPointer(archive, owner));
  }

  /**
   * Address: 0x0067CD60 (FUN_0067CD60, Moho::RWeakPtrType_Entity::SerSave)
   */
  void SaveWeakPtrEntity(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtrEntity*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, MakeEntityObjectRef(weak->GetObjectPtr()), gpg::TrackedPointerState::Unowned, owner);
  }

  /**
   * Address: 0x0067CDA0 (FUN_0067CDA0, gpg::RVectorType_Entity_P::SerLoad)
   */
  void LoadEntityPointerVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<EntityPtrVector*>(objectPtr);
    if (!archive || !storage) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    EntityPtrVector loaded{};
    loaded.resize(static_cast<std::size_t>(count), nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      loaded[static_cast<std::size_t>(i)] = ReadEntityPointer(archive, owner);
    }

    *storage = loaded;
  }

  /**
   * Address: 0x0067CEB0 (FUN_0067CEB0, gpg::RVectorType_Entity_P::SerSave)
   */
  void SaveEntityPointerVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<const EntityPtrVector*>(objectPtr);
    if (!archive || !storage) {
      return;
    }

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      gpg::WriteRawPointer(
        archive,
        MakeEntityObjectRef((*storage)[static_cast<std::size_t>(i)]),
        gpg::TrackedPointerState::Unowned,
        owner
      );
    }
  }

  /**
   * Address: 0x00694380 family (serializer load lane)
   *
   * What it does:
   * Deserializes tracked `Entity*` pointer lanes into `fastvector<Entity*>` storage.
   */
  void LoadFastVectorEntityPointer(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::Entity*>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::Entity* fill = nullptr;
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
      if (!tracked.object) {
        view.begin[i] = nullptr;
        continue;
      }

      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;

      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedEntityType());
      if (upcast.mObj) {
        view.begin[i] = static_cast<moho::Entity*>(upcast.mObj);
        continue;
      }

      const char* const expected = CachedEntityType() ? CachedEntityType()->GetName() : "Entity";
      const char* const actual = source.GetTypeName();
      const msvc8::string message = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
        expected ? expected : "Entity",
        actual ? actual : "null"
      );
      throw gpg::SerializationError(message.c_str());
    }
  }

  /**
   * Address: 0x00694380 family (serializer save lane)
   *
   * What it does:
   * Serializes tracked `Entity*` pointer lanes from `fastvector<Entity*>` storage.
   */
  void SaveFastVectorEntityPointer(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::Entity*>(reinterpret_cast<const void*>(objectPtr));

    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::RRef objectRef = MakeEntityObjectRef(view.begin[i]);
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x00BFC8D0 family (cleanup_WeakPtrEntityTypeName_00BFC8D0)
   */
  void cleanup_WeakPtrEntityTypeName()
  {
    gWeakPtrEntityTypeName = msvc8::string{};
    gWeakPtrEntityTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BFC8A0 family (cleanup_VectorEntityPtrTypeName_00BFC8A0)
   */
  void cleanup_EntityPtrVectorTypeName()
  {
    gEntityPtrVectorTypeName = msvc8::string{};
    gEntityPtrVectorTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BFCEA0 family (cleanup_type_name_00BFCEA0)
   */
  void cleanup_EntityPtrFastVectorTypeName()
  {
    gEntityPtrFastVectorTypeName = msvc8::string{};
    gEntityPtrFastVectorTypeNameCleanupRegistered = false;
  }

  struct EntityFastVectorReflectionBootstrap
  {
    EntityFastVectorReflectionBootstrap()
    {
      (void)moho::register_WeakPtr_Entity_Type_AtExit();
      (void)moho::register_VectorEntityPtr_Type_AtExit();
      (void)moho::register_FastVectorEntityPtrType_AtExit();
    }
  };

  [[maybe_unused]] EntityFastVectorReflectionBootstrap gEntityFastVectorReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0067CD30 (FUN_0067CD30, Moho::RWeakPtrType_Entity::SerLoad)
   */
  void WeakPtr_Entity::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    LoadWeakPtrEntity(archive, objectPtr, 0, ownerRef);
  }

  /**
   * Address: 0x0067CD60 (FUN_0067CD60, Moho::RWeakPtrType_Entity::SerSave)
   */
  void WeakPtr_Entity::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    SaveWeakPtrEntity(archive, objectPtr, 0, ownerRef);
  }

  /**
   * Address: 0x0067BDF0 (FUN_0067BDF0, Moho::RWeakPtrType_Entity::GetName)
   */
  const char* RWeakPtrType<Entity>::GetName() const
  {
    if (gWeakPtrEntityTypeName.empty()) {
      const char* const pointeeName = CachedEntityType() ? CachedEntityType()->GetName() : "Entity";
      gWeakPtrEntityTypeName = gpg::STR_Printf("WeakPtr<%s>", pointeeName ? pointeeName : "Entity");
      if (!gWeakPtrEntityTypeNameCleanupRegistered) {
        gWeakPtrEntityTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrEntityTypeName);
      }
    }

    return gWeakPtrEntityTypeName.c_str();
  }

  /**
   * Address: 0x0067BEB0 (FUN_0067BEB0, Moho::RWeakPtrType_Entity::GetLexical)
   */
  msvc8::string RWeakPtrType<Entity>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const weak = static_cast<const WeakPtrEntity*>(ref.mObj);
    if (!weak || !weak->HasValue()) {
      return msvc8::string("NULL");
    }

    const gpg::RRef pointeeRef = MakeEntityObjectRef(weak->GetObjectPtr());
    if (!pointeeRef.mObj) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x0067C040 (FUN_0067C040, Moho::RWeakPtrType_Entity::IsIndexed)
   */
  const gpg::RIndexed* RWeakPtrType<Entity>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0067C050 (FUN_0067C050, Moho::RWeakPtrType_Entity::IsPointer)
   */
  const gpg::RIndexed* RWeakPtrType<Entity>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x0067BE90 (FUN_0067BE90, Moho::RWeakPtrType_Entity::Init)
   */
  void RWeakPtrType<Entity>::Init()
  {
    size_ = sizeof(WeakPtrEntity);
    version_ = 1;
    serLoadFunc_ = &WeakPtr_Entity::Deserialize;
    serSaveFunc_ = &WeakPtr_Entity::Serialize;
  }

  /**
   * Address: 0x0067C090 (FUN_0067C090, Moho::RWeakPtrType_Entity::SubscriptIndex)
   */
  gpg::RRef RWeakPtrType<Entity>::SubscriptIndex(void* obj, const int ind) const
  {
    GPG_ASSERT(ind == 0);

    auto* const weak = static_cast<WeakPtrEntity*>(obj);
    return MakeEntityObjectRef(weak ? weak->GetObjectPtr() : nullptr);
  }

  /**
   * Address: 0x0067C060 (FUN_0067C060, Moho::RWeakPtrType_Entity::GetCount)
   */
  size_t RWeakPtrType<Entity>::GetCount(void* obj) const
  {
    auto* const weak = static_cast<WeakPtrEntity*>(obj);
    return (weak && weak->HasValue()) ? 1u : 0u;
  }

  /**
   * Address: 0x0067FF00 (FUN_0067FF00, register_WeakPtr_Entity_Type_00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `WeakPtr<Entity>`.
   */
  gpg::RType* register_WeakPtr_Entity_Type_00()
  {
    WeakPtrEntityType* const type = AcquireWeakPtrEntityType();
    gpg::PreRegisterRType(typeid(WeakPtrEntity), type);
    return type;
  }

  /**
   * Address: 0x00BFC9F0 (FUN_00BFC9F0, cleanup_WeakPtr_Entity_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<Entity>` reflection storage.
   */
  void cleanup_WeakPtr_Entity_Type()
  {
    if (!gWeakPtrEntityTypeConstructed) {
      return;
    }

    AcquireWeakPtrEntityType()->~WeakPtrEntityType();
    gWeakPtrEntityTypeConstructed = false;
  }

  /**
   * Address: 0x00BD5090 (FUN_00BD5090, register_WeakPtr_Entity_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<Entity>` reflection and installs process-exit cleanup.
   */
  int register_WeakPtr_Entity_Type_AtExit()
  {
    (void)register_WeakPtr_Entity_Type_00();
    return std::atexit(&cleanup_WeakPtr_Entity_Type);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0067C0F0 (FUN_0067C0F0, gpg::RVectorType_Entity_P::GetName)
   */
  const char* RVectorType<moho::Entity*>::GetName() const
  {
    if (gEntityPtrVectorTypeName.empty()) {
      const gpg::RType* const elementType = CachedEntityPointerType();
      const char* const elementName = elementType ? elementType->GetName() : "Entity*";
      gEntityPtrVectorTypeName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "Entity*");
      if (!gEntityPtrVectorTypeNameCleanupRegistered) {
        gEntityPtrVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_EntityPtrVectorTypeName);
      }
    }

    return gEntityPtrVectorTypeName.c_str();
  }

  /**
   * Address: 0x0067C190 (FUN_0067C190, gpg::RVectorType_Entity_P::GetLexical)
   */
  msvc8::string RVectorType<moho::Entity*>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0067C220 (FUN_0067C220, gpg::RVectorType_Entity_P::IsIndexed)
   */
  const gpg::RIndexed* RVectorType<moho::Entity*>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0067C170 (FUN_0067C170, gpg::RVectorType_Entity_P::Init)
   */
  void RVectorType<moho::Entity*>::Init()
  {
    size_ = sizeof(EntityPtrVector);
    version_ = 1;
    serLoadFunc_ = &LoadEntityPointerVector;
    serSaveFunc_ = &SaveEntityPointerVector;
  }

  /**
   * Address: 0x0067C260 (FUN_0067C260, gpg::RVectorType_Entity_P::SubscriptIndex)
   */
  gpg::RRef RVectorType<moho::Entity*>::SubscriptIndex(void* obj, const int ind) const
  {
    auto* const storage = static_cast<EntityPtrVector*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(ind >= 0);
    GPG_ASSERT(storage != nullptr && static_cast<std::size_t>(ind) < GetCount(obj));

    if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return MakeEntityPointerSlotRef(nullptr);
    }

    return MakeEntityPointerSlotRef(&(*storage)[static_cast<std::size_t>(ind)]);
  }

  /**
   * Address: 0x0067C230 (FUN_0067C230, gpg::RVectorType_Entity_P::GetCount)
   */
  size_t RVectorType<moho::Entity*>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = msvc8::AsVectorRuntimeView(*static_cast<const EntityPtrVector*>(obj));
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x0067C250 (FUN_0067C250, gpg::RVectorType_Entity_P::SetCount)
   */
  void RVectorType<moho::Entity*>::SetCount(void* obj, const int count) const
  {
    auto* const storage = static_cast<EntityPtrVector*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(count >= 0);
    if (!storage || count < 0) {
      return;
    }

    storage->resize(static_cast<std::size_t>(count), nullptr);
  }

  /**
   * Address: 0x00694380 (FUN_00694380, gpg::RFastVectorType_Entity_P::GetName)
   */
  const char* RFastVectorType<moho::Entity*>::GetName() const
  {
    if (gEntityPtrFastVectorTypeName.empty()) {
      const char* const elementName = CachedEntityPointerType() ? CachedEntityPointerType()->GetName() : "Entity*";
      gEntityPtrFastVectorTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "Entity*");
      if (!gEntityPtrFastVectorTypeNameCleanupRegistered) {
        gEntityPtrFastVectorTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_EntityPtrFastVectorTypeName);
      }
    }

    return gEntityPtrFastVectorTypeName.c_str();
  }

  /**
   * Address: 0x00694380 family (gpg::RFastVectorType_Entity_P::GetLexical)
   */
  msvc8::string RFastVectorType<moho::Entity*>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x00694380 family (gpg::RFastVectorType_Entity_P::IsIndexed)
   */
  const gpg::RIndexed* RFastVectorType<moho::Entity*>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00694380 (FUN_00694380, gpg::RFastVectorType_Entity_P::Init)
   */
  void RFastVectorType<moho::Entity*>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorEntityPointer;
    serSaveFunc_ = &SaveFastVectorEntityPointer;
  }

  /**
   * Address: 0x00694380 family (gpg::RFastVectorType_Entity_P::SubscriptIndex)
   */
  gpg::RRef RFastVectorType<moho::Entity*>::SubscriptIndex(void* obj, const int ind) const
  {
    if (!obj) {
      return MakeEntityPointerSlotRef(nullptr);
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::Entity*>(obj);
    GPG_ASSERT(ind >= 0);
    GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));
    if (!view.begin || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return MakeEntityPointerSlotRef(nullptr);
    }

    return MakeEntityPointerSlotRef(view.begin + ind);
  }

  /**
   * Address: 0x00694380 family (gpg::RFastVectorType_Entity_P::GetCount)
   */
  size_t RFastVectorType<moho::Entity*>::GetCount(void* obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::Entity*>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x00694380 family (gpg::RFastVectorType_Entity_P::SetCount)
   */
  void RFastVectorType<moho::Entity*>::SetCount(void* obj, const int count) const
  {
    GPG_ASSERT(obj != nullptr);
    GPG_ASSERT(count >= 0);
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::Entity*>(obj);
    moho::Entity* fill = nullptr;
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0067FF70 (FUN_0067FF70, register_VectorEntityPtr_Type_00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `vector<Entity*>`.
   */
  gpg::RType* register_VectorEntityPtr_Type_00()
  {
    EntityPtrVectorType* const type = AcquireEntityPtrVectorType();
    gpg::PreRegisterRType(typeid(msvc8::vector<Entity*>), type);
    return type;
  }

  /**
   * Address: 0x00BFC990 (FUN_00BFC990, cleanup_VectorEntityPtr_Type)
   *
   * What it does:
   * Tears down startup-owned `vector<Entity*>` reflection storage.
   */
  void cleanup_VectorEntityPtr_Type()
  {
    if (!gEntityPtrVectorTypeConstructed) {
      return;
    }

    AcquireEntityPtrVectorType()->~EntityPtrVectorType();
    gEntityPtrVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BD50B0 (FUN_00BD50B0, register_VectorEntityPtr_Type_AtExit)
   *
   * What it does:
   * Registers `vector<Entity*>` reflection and installs process-exit cleanup.
   */
  int register_VectorEntityPtr_Type_AtExit()
  {
    (void)register_VectorEntityPtr_Type_00();
    return std::atexit(&cleanup_VectorEntityPtr_Type);
  }

  /**
   * Address: 0x00694380 (FUN_00694380, register_FastVectorEntityPtrType_00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `fastvector<Entity*>`.
   */
  gpg::RType* register_FastVectorEntityPtrType_00()
  {
    EntityPtrFastVectorType* const type = AcquireEntityPtrFastVectorType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<Entity*>), type);
    return type;
  }

  /**
   * Address: 0x00BFCEA0 (FUN_00BFCEA0, cleanup_FastVectorEntityPtrType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<Entity*>` reflection storage.
   */
  void cleanup_FastVectorEntityPtrType()
  {
    if (!gEntityPtrFastVectorTypeConstructed) {
      return;
    }

    AcquireEntityPtrFastVectorType()->~EntityPtrFastVectorType();
    gEntityPtrFastVectorTypeConstructed = false;
  }

  /**
   * Address: 0x00BD5890 (FUN_00BD5890, register_FastVectorEntityPtrType_AtExit)
   *
   * What it does:
   * Registers `fastvector<Entity*>` reflection and installs process-exit cleanup.
   */
  int register_FastVectorEntityPtrType_AtExit()
  {
    (void)register_FastVectorEntityPtrType_00();
    return std::atexit(&cleanup_FastVectorEntityPtrType);
  }
} // namespace moho
