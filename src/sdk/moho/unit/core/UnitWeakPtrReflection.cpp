#include "moho/unit/core/UnitWeakPtrReflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/unit/core/Unit.h"

namespace
{
  using WeakPtrUnitType = moho::RWeakPtrType<moho::Unit>;

  alignas(WeakPtrUnitType) unsigned char gWeakPtrUnitTypeStorage[sizeof(WeakPtrUnitType)];
  bool gWeakPtrUnitTypeConstructed = false;

  msvc8::string gWeakPtrUnitTypeName;
  bool gWeakPtrUnitTypeNameCleanupRegistered = false;

  [[nodiscard]] WeakPtrUnitType* AcquireWeakPtrUnitType()
  {
    if (!gWeakPtrUnitTypeConstructed) {
      new (gWeakPtrUnitTypeStorage) WeakPtrUnitType();
      gWeakPtrUnitTypeConstructed = true;
    }
    return reinterpret_cast<WeakPtrUnitType*>(gWeakPtrUnitTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Unit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      if (!cached) {
        cached = moho::register_WeakPtr_Unit_Type_00();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeUnitRef(moho::Unit* unit)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedUnitType();
    if (!unit) {
      return out;
    }

    gpg::RType* dynamicType = CachedUnitType();
    try {
      dynamicType = gpg::LookupRType(typeid(*unit));
    } catch (...) {
      dynamicType = CachedUnitType();
    }

    std::int32_t baseOffset = 0;
    if (dynamicType && CachedUnitType() && dynamicType->IsDerivedFrom(CachedUnitType(), &baseOffset)) {
      out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(unit) - static_cast<std::uintptr_t>(baseOffset));
      out.mType = dynamicType;
      return out;
    }

    out.mObj = unit;
    out.mType = dynamicType ? dynamicType : CachedUnitType();
    return out;
  }

  [[nodiscard]] moho::Unit* ReadPointerUnit(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitType());
    if (upcast.mObj) {
      return static_cast<moho::Unit*>(upcast.mObj);
    }

    const char* const expected = CachedUnitType() ? CachedUnitType()->GetName() : "Unit";
    const char* const actual = source.GetTypeName();
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "Unit",
      actual ? actual : "null"
    );
    throw std::runtime_error(message.c_str());
  }

  /**
   * Address: 0x00BFDAF0 (FUN_00BFDAF0, sub_BFDAF0)
   */
  void cleanup_WeakPtrUnitTypeName()
  {
    gWeakPtrUnitTypeName = msvc8::string{};
    gWeakPtrUnitTypeNameCleanupRegistered = false;
  }

  struct UnitWeakPtrReflectionBootstrap
  {
    UnitWeakPtrReflectionBootstrap()
    {
      (void)moho::register_WeakPtr_Unit_Type_AtExit();
    }
  };

  UnitWeakPtrReflectionBootstrap gUnitWeakPtrReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006AF1E0 (FUN_006AF1E0, Moho::RWeakPtrType_Unit::SerLoad)
   */
  void WeakPtr_Unit::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<Unit>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    weak->ResetFromObject(ReadPointerUnit(archive, owner));
  }

  /**
   * Address: 0x006AF210 (FUN_006AF210, Moho::RWeakPtrType_Unit::SerSave)
   */
  void WeakPtr_Unit::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<Unit>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, MakeUnitRef(weak->GetObjectPtr()), gpg::TrackedPointerState::Unowned, owner);
  }

  /**
   * Address: 0x006ADF90 (FUN_006ADF90, Moho::RWeakPtrType_Unit::GetName)
   */
  const char* RWeakPtrType<Unit>::GetName() const
  {
    if (gWeakPtrUnitTypeName.empty()) {
      const char* const pointeeName = CachedUnitType() ? CachedUnitType()->GetName() : "Unit";
      gWeakPtrUnitTypeName = gpg::STR_Printf("WeakPtr<%s>", pointeeName ? pointeeName : "Unit");
      if (!gWeakPtrUnitTypeNameCleanupRegistered) {
        gWeakPtrUnitTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrUnitTypeName);
      }
    }

    return gWeakPtrUnitTypeName.c_str();
  }

  /**
   * Address: 0x006AE050 (FUN_006AE050, Moho::RWeakPtrType_Unit::GetLexical)
   */
  msvc8::string RWeakPtrType<Unit>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const weak = static_cast<const WeakPtr<Unit>*>(ref.mObj);
    if (!weak || !weak->HasValue()) {
      return msvc8::string("NULL");
    }

    const gpg::RRef pointeeRef = MakeUnitRef(weak->GetObjectPtr());
    if (!pointeeRef.mObj) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x006AE1E0 (FUN_006AE1E0, Moho::RWeakPtrType_Unit::IsIndexed)
   */
  const gpg::RIndexed* RWeakPtrType<Unit>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x006AE1F0 (FUN_006AE1F0, Moho::RWeakPtrType_Unit::IsPointer)
   */
  const gpg::RIndexed* RWeakPtrType<Unit>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x006AE030 (FUN_006AE030, Moho::RWeakPtrType_Unit::Init)
   */
  void RWeakPtrType<Unit>::Init()
  {
    size_ = sizeof(WeakPtr<Unit>);
    version_ = 1;
    serLoadFunc_ = &WeakPtr_Unit::Deserialize;
    serSaveFunc_ = &WeakPtr_Unit::Serialize;
  }

  /**
   * Address: 0x006AE230 (FUN_006AE230, Moho::RWeakPtrType_Unit::SubscriptIndex)
   */
  gpg::RRef RWeakPtrType<Unit>::SubscriptIndex(void* const obj, const int ind) const
  {
    GPG_ASSERT(ind == 0);
    auto* const weak = static_cast<WeakPtr<Unit>*>(obj);
    return MakeUnitRef(weak ? weak->GetObjectPtr() : nullptr);
  }

  /**
   * Address: 0x006AE200 (FUN_006AE200, Moho::RWeakPtrType_Unit::GetCount)
   */
  size_t RWeakPtrType<Unit>::GetCount(void* const obj) const
  {
    auto* const weak = static_cast<WeakPtr<Unit>*>(obj);
    return (weak && weak->HasValue()) ? 1u : 0u;
  }

  /**
   * Address: 0x006B1640 (FUN_006B1640, register_WeakPtr_Unit_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `WeakPtr<Unit>`.
   */
  gpg::RType* register_WeakPtr_Unit_Type_00()
  {
    WeakPtrUnitType* const type = AcquireWeakPtrUnitType();
    gpg::PreRegisterRType(typeid(WeakPtr<Unit>), type);
    return type;
  }

  /**
   * Address: 0x00BFDC40 (FUN_00BFDC40, cleanup_WeakPtr_Unit_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<Unit>` reflection storage.
   */
  void cleanup_WeakPtr_Unit_Type()
  {
    if (!gWeakPtrUnitTypeConstructed) {
      return;
    }

    AcquireWeakPtrUnitType()->~WeakPtrUnitType();
    gWeakPtrUnitTypeConstructed = false;
  }

  /**
   * Address: 0x00BD6BA0 (FUN_00BD6BA0, register_WeakPtr_Unit_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<Unit>` reflection and installs process-exit teardown.
   */
  int register_WeakPtr_Unit_Type_AtExit()
  {
    (void)register_WeakPtr_Unit_Type_00();
    return std::atexit(&cleanup_WeakPtr_Unit_Type);
  }
} // namespace moho
