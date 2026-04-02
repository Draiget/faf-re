#include "moho/unit/core/IUnitWeakPtrReflection.h"

#include <cstdint>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IUnit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::IUnit>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeIUnitRefFromRawObject(void* rawObject)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIUnitType();

    if (!rawObject) {
      return out;
    }

    auto* const iunit = static_cast<moho::IUnit*>(rawObject);
    gpg::RType* dynamicType = CachedIUnitType();
    try {
      dynamicType = gpg::LookupRType(typeid(*iunit));
    } catch (...) {
      dynamicType = CachedIUnitType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(CachedIUnitType(), &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(rawObject) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeIUnitRefFromWeakPtr(const moho::WeakPtr<moho::IUnit>& weak)
  {
    return MakeIUnitRefFromRawObject(weak.GetObjectPtr());
  }

  /**
   * Address: 0x00541900 (FA), 0x1012F280 (MohoEngine)
   *
   * What it does:
   * Loads tracked pointer payload and assigns the weak pointer from the upcast IUnit object.
   */
  void LoadWeakPtrIUnit(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<moho::WeakPtr<moho::IUnit>*>(objectPtr);
    GPG_ASSERT(weak != nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      weak->ResetFromObject(nullptr);
      return;
    }

    gpg::RRef trackedRef{};
    trackedRef.mObj = tracked.object;
    trackedRef.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(trackedRef, CachedIUnitType());
    if (!upcast.mObj) {
      const char* const expected = CachedIUnitType()->GetName();
      const char* const actual = trackedRef.GetTypeName();
      const msvc8::string msg = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expected ? expected : "IUnit",
        actual ? actual : "unknown"
      );
      throw std::runtime_error(msg.c_str());
    }

    weak->ResetFromObject(static_cast<moho::IUnit*>(upcast.mObj));
  }

  /**
   * Address: 0x00541930 (FA), 0x1012F2B0 (MohoEngine)
   *
   * What it does:
   * Converts the weak pointer payload into `RRef` and writes it as an unowned raw pointer.
   */
  void SaveWeakPtrIUnit(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<moho::WeakPtr<moho::IUnit>*>(objectPtr);
    GPG_ASSERT(weak != nullptr);

    const gpg::RRef objectRef = MakeIUnitRefFromWeakPtr(*weak);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
  }

  void ResizeWeakPtrVector(moho::WeakPtrVectorStorage<moho::IUnit>& storage, const std::size_t newCount)
  {
    const std::size_t oldCount = storage.begin ? static_cast<std::size_t>(storage.end - storage.begin) : 0u;
    const std::size_t oldCapacity = storage.begin ? static_cast<std::size_t>(storage.capacityEnd - storage.begin) : 0u;

    if (newCount < oldCount) {
      for (std::size_t i = newCount; i < oldCount; ++i) {
        storage.begin[i].ResetFromObject(nullptr);
      }
      storage.end = storage.begin + newCount;
      return;
    }

    if (newCount > oldCapacity) {
      std::size_t newCapacity = oldCapacity ? oldCapacity : 4u;
      while (newCapacity < newCount) {
        newCapacity *= 2u;
      }

      auto* const newBegin =
        static_cast<moho::WeakPtr<moho::IUnit>*>(::operator new(sizeof(moho::WeakPtr<moho::IUnit>) * newCapacity));

      for (std::size_t i = 0; i < newCapacity; ++i) {
        newBegin[i].ownerLinkSlot = nullptr;
        newBegin[i].nextInOwner = nullptr;
      }

      for (std::size_t i = 0; i < oldCount; ++i) {
        newBegin[i].ResetFromOwnerLinkSlot(storage.begin[i].ownerLinkSlot);
        storage.begin[i].ResetFromObject(nullptr);
      }

      ::operator delete(storage.begin);
      storage.begin = newBegin;
      storage.end = newBegin + oldCount;
      storage.capacityEnd = newBegin + newCapacity;
    }

    for (std::size_t i = oldCount; i < newCount; ++i) {
      storage.begin[i].ownerLinkSlot = nullptr;
      storage.begin[i].nextInOwner = nullptr;
    }
    storage.end = storage.begin + newCount;
  }

  /**
   * Address: 0x0056DD80 (FA), 0x1015C0F0 (MohoEngine)
   */
  void LoadFastVectorWeakPtrIUnit(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<moho::WeakPtrVectorStorage<moho::IUnit>*>(objectPtr);
    GPG_ASSERT(storage != nullptr);

    unsigned int count = 0;
    archive->ReadUInt(&count);

    ResizeWeakPtrVector(*storage, static_cast<std::size_t>(count));

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    if (!weakPtrType->serLoadFunc_) {
      return;
    }

    for (unsigned int i = 0; i < count; ++i) {
      weakPtrType->serLoadFunc_(archive, reinterpret_cast<int>(&storage->begin[i]), 0, ownerRef);
    }
  }

  /**
   * Address: 0x0056DE50 (FA), 0x1015C1C0 (MohoEngine)
   */
  void SaveFastVectorWeakPtrIUnit(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const storage = reinterpret_cast<moho::WeakPtrVectorStorage<moho::IUnit>*>(objectPtr);
    GPG_ASSERT(storage != nullptr);

    const unsigned int count = storage->begin ? static_cast<unsigned int>(storage->end - storage->begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const weakPtrType = CachedWeakPtrIUnitType();
    if (!weakPtrType->serSaveFunc_) {
      return;
    }

    for (unsigned int i = 0; i < count; ++i) {
      weakPtrType->serSaveFunc_(archive, reinterpret_cast<int>(&storage->begin[i]), 0, ownerRef);
    }
  }
} // namespace

const char* moho::RWeakPtrType<moho::IUnit>::GetName() const
{
  static msvc8::string cachedName;
  if (cachedName.empty()) {
    const char* const pointeeName = CachedIUnitType()->GetName();
    cachedName = gpg::STR_Printf("WeakPtr<%s>", pointeeName ? pointeeName : "IUnit");
  }
  return cachedName.c_str();
}

msvc8::string moho::RWeakPtrType<moho::IUnit>::GetLexical(const gpg::RRef& ref) const
{
  auto* const weak = static_cast<const moho::WeakPtr<moho::IUnit>*>(ref.mObj);
  if (!weak || !weak->HasValue()) {
    return msvc8::string("NULL");
  }

  const gpg::RRef pointee = MakeIUnitRefFromWeakPtr(*weak);
  if (!pointee.mObj) {
    return msvc8::string("NULL");
  }

  const msvc8::string inner = pointee.GetLexical();
  return gpg::STR_Printf("[%s]", inner.c_str());
}

const gpg::RIndexed* moho::RWeakPtrType<moho::IUnit>::IsIndexed() const
{
  return this;
}

const gpg::RIndexed* moho::RWeakPtrType<moho::IUnit>::IsPointer() const
{
  return this;
}

void moho::RWeakPtrType<moho::IUnit>::Init()
{
  size_ = 0x08;
  version_ = 1;
  serLoadFunc_ = &LoadWeakPtrIUnit;
  serSaveFunc_ = &SaveWeakPtrIUnit;
}

gpg::RRef moho::RWeakPtrType<moho::IUnit>::SubscriptIndex(void* obj, const int ind) const
{
  GPG_ASSERT(ind == 0);
  auto* const weak = static_cast<moho::WeakPtr<moho::IUnit>*>(obj);
  if (!weak) {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIUnitType();
    return out;
  }
  return MakeIUnitRefFromWeakPtr(*weak);
}

size_t moho::RWeakPtrType<moho::IUnit>::GetCount(void* obj) const
{
  auto* const weak = static_cast<moho::WeakPtr<moho::IUnit>*>(obj);
  if (!weak) {
    return 0;
  }
  return weak->HasValue() ? 1u : 0u;
}

const char* gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::GetName() const
{
  static msvc8::string cachedName;
  if (cachedName.empty()) {
    const char* const elementName = CachedWeakPtrIUnitType()->GetName();
    cachedName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "WeakPtr<IUnit>");
  }
  return cachedName.c_str();
}

msvc8::string gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  const int count = static_cast<int>(GetCount(ref.mObj));
  return gpg::STR_Printf("%s, size=%d", base.c_str(), count);
}

const gpg::RIndexed* gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::IsIndexed() const
{
  return this;
}

void gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorWeakPtrIUnit;
  serSaveFunc_ = &SaveFastVectorWeakPtrIUnit;
}

gpg::RRef gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::SubscriptIndex(void* obj, const int ind) const
{
  auto* const storage = static_cast<moho::WeakPtrVectorStorage<moho::IUnit>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIUnitType();
    return out;
  }

  return MakeIUnitRefFromWeakPtr(storage->begin[ind]);
}

size_t gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::GetCount(void* obj) const
{
  auto* const storage = static_cast<moho::WeakPtrVectorStorage<moho::IUnit>*>(obj);
  if (!storage || !storage->begin) {
    return 0u;
  }
  return static_cast<std::size_t>(storage->end - storage->begin);
}

void gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::SetCount(void* obj, const int count) const
{
  auto* const storage = static_cast<moho::WeakPtrVectorStorage<moho::IUnit>*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (!storage || count < 0) {
    return;
  }

  ResizeWeakPtrVector(*storage, static_cast<std::size_t>(count));
}
