#include "moho/misc/RWeakPtrTypeclass_Moho_IUnit.h"

#include <cstdint>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace gpg
{
  /**
   * These signatures are recovered from import names used by MohoEngine:
   * - ReadArchive::ReadRawPointer
   * - WriteArchive::WriteRawPointer
   * - REF_UpcastPtr
   *
   * They are declared here so helper reconstruction can mirror original control flow.
   */
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
  gpg::RType* CachedIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IUnit));
    }
    return cached;
  }

  gpg::RRef MakeIUnitRefFromRawObject(void* rawObject)
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

  gpg::RRef MakeIUnitRefFromWeakPtr(const moho::WeakPtr<moho::IUnit>& weak)
  {
    return MakeIUnitRefFromRawObject(weak.GetObjectPtr());
  }

  /**
   * Address: 0x00541900 (FA), 0x1012F280 (MohoEngine)
   *
   * What it does:
   * Loads tracked pointer payload and assigns the weak pointer from the upcast IUnit object.
   */
  void LoadWeakPtrIUnit(gpg::ReadArchive* archive, int objectPtr, int /*unused*/, gpg::RRef* ownerRef)
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
  void SaveWeakPtrIUnit(gpg::WriteArchive* archive, int objectPtr, int /*unused*/, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<moho::WeakPtr<moho::IUnit>*>(objectPtr);
    GPG_ASSERT(weak != nullptr);

    const gpg::RRef objectRef = MakeIUnitRefFromWeakPtr(*weak);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
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
