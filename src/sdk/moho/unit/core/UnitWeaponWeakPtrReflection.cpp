#include "moho/unit/core/UnitWeaponWeakPtrReflection.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/unit/core/UnitWeapon.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using WeakPtrUnitWeaponType = moho::RWeakPtrType<moho::UnitWeapon>;

  /**
   * Address: 0x00BFC490 (FUN_00BFC490, atexit destructor of the WeakPtrUnitWeaponType object)
   */
  [[nodiscard]] WeakPtrUnitWeaponType* AcquireWeakPtrUnitWeaponType()
  {
    static WeakPtrUnitWeaponType sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponType()
  {
    gpg::RType* cached = moho::UnitWeapon::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::UnitWeapon));
      moho::UnitWeapon::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeUnitWeaponRef(moho::UnitWeapon* weapon)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedUnitWeaponType();
    if (!weapon) {
      return out;
    }

    gpg::RType* dynamicType = CachedUnitWeaponType();
    try {
      dynamicType = gpg::LookupRType(typeid(*weapon));
    } catch (...) {
      dynamicType = CachedUnitWeaponType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && CachedUnitWeaponType() != nullptr &&
      dynamicType->IsDerivedFrom(CachedUnitWeaponType(), &baseOffset);

    out.mObj = isDerived
      ? reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(weapon) - static_cast<std::uintptr_t>(baseOffset))
      : static_cast<void*>(weapon);
    out.mType = dynamicType ? dynamicType : CachedUnitWeaponType();
    return out;
  }

  [[nodiscard]] moho::UnitWeapon* ReadPointerUnitWeapon(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitWeaponType());
    if (upcast.mObj) {
      return static_cast<moho::UnitWeapon*>(upcast.mObj);
    }

    const char* const expected = CachedUnitWeaponType() ? CachedUnitWeaponType()->GetName() : "UnitWeapon";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "UnitWeapon",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  struct UnitWeaponWeakPtrReflectionBootstrap
  {
    UnitWeaponWeakPtrReflectionBootstrap()
    {
      (void)moho::register_WeakPtr_UnitWeapon_Type_AtExit();
    }
  };

  UnitWeaponWeakPtrReflectionBootstrap gUnitWeaponWeakPtrReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00675220 (FUN_00675220, Moho::WeakPtr_UnitWeapon::Deserialize)
   */
  void WeakPtr_UnitWeapon::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<UnitWeapon>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    weak->ResetFromObject(ReadPointerUnitWeapon(archive, owner));
  }

  /**
   * Address: 0x00675250 (FUN_00675250, Moho::WeakPtr_UnitWeapon::Serialize)
   */
  void WeakPtr_UnitWeapon::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<UnitWeapon>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef objectRef = MakeUnitWeaponRef(weak->GetObjectPtr());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
  }

  /**
   * Address: 0x00674BB0 (FUN_00674BB0, Moho::RWeakPtrType_UnitWeapon::GetName)
   * Address: 0x00BFC3D0 (FUN_00BFC3D0, atexit destructor of GetName's cached name)
   */
  const char* RWeakPtrType<UnitWeapon>::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("WeakPtr<%s>", CachedUnitWeaponType()->GetName());
    return sName.c_str();
  }

  /**
   * Address: 0x00674C70 (FUN_00674C70, Moho::RWeakPtrType_UnitWeapon::GetLexical)
   */
  msvc8::string RWeakPtrType<UnitWeapon>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const weak = static_cast<const WeakPtr<UnitWeapon>*>(ref.mObj);
    if (!weak || !weak->HasValue()) {
      return msvc8::string("NULL");
    }

    const gpg::RRef pointeeRef = MakeUnitWeaponRef(weak->GetObjectPtr());
    if (!pointeeRef.mObj) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x00674E00 (FUN_00674E00, Moho::RWeakPtrType_UnitWeapon::IsIndexed)
   */
  const gpg::RIndexed* RWeakPtrType<UnitWeapon>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00674E10 (FUN_00674E10, Moho::RWeakPtrType_UnitWeapon::IsPointer)
   */
  const gpg::RIndexed* RWeakPtrType<UnitWeapon>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x00674C50 (FUN_00674C50, Moho::RWeakPtrType_UnitWeapon::Init)
   */
  void RWeakPtrType<UnitWeapon>::Init()
  {
    size_ = sizeof(WeakPtr<UnitWeapon>);
    version_ = 1;
    serLoadFunc_ = &WeakPtr_UnitWeapon::Deserialize;
    serSaveFunc_ = &WeakPtr_UnitWeapon::Serialize;
  }

  /**
   * Address: 0x00674E50 (FUN_00674E50, Moho::RWeakPtrType_UnitWeapon::SubscriptIndex)
   */
  gpg::RRef RWeakPtrType<UnitWeapon>::SubscriptIndex(void* const obj, const int ind) const
  {
    GPG_ASSERT(ind == 0);

    auto* const weak = static_cast<WeakPtr<UnitWeapon>*>(obj);
    return MakeUnitWeaponRef(weak ? weak->GetObjectPtr() : nullptr);
  }

  /**
   * Address: 0x00674E20 (FUN_00674E20, Moho::RWeakPtrType_UnitWeapon::GetCount)
   */
  size_t RWeakPtrType<UnitWeapon>::GetCount(void* const obj) const
  {
    auto* const weak = static_cast<WeakPtr<UnitWeapon>*>(obj);
    return (weak && weak->HasValue()) ? 1u : 0u;
  }

  /**
   * Address: 0x00675AC0 (FUN_00675AC0, register_WeakPtr_UnitWeapon_Type_00)
   */
  gpg::RType* register_WeakPtr_UnitWeapon_Type_00()
  {
    WeakPtrUnitWeaponType* const type = AcquireWeakPtrUnitWeaponType();
    gpg::PreRegisterRType(typeid(WeakPtr<UnitWeapon>), type);
    return type;
  }

  /**
   * Address: 0x00BD4DF0 (FUN_00BD4DF0, register_WeakPtr_UnitWeapon_Type_AtExit)
   */
  void register_WeakPtr_UnitWeapon_Type_AtExit()
  {
    (void)register_WeakPtr_UnitWeapon_Type_00();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_WeakPtr_UnitWeapon_Type_00_c604f3, moho::register_WeakPtr_UnitWeapon_Type_00)
