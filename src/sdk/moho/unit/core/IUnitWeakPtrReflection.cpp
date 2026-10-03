#include "moho/unit/core/IUnitWeakPtrReflection.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  class IUnitTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "IUnit";
    }

    void Init() override
    {
      size_ = sizeof(moho::IUnit);
      gpg::RType::Init();
      Finish();
    }
  };

  using WeakPtrIUnitType = moho::RWeakPtrType<moho::IUnit>;
  using FastVectorWeakPtrIUnitType = gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>;

  constexpr const char kReflectWeakPtrHeaderPath[] = "c:\\work\\rts\\main\\code\\src\\core/ReflectWeakPtr.h";

  [[nodiscard]] gpg::RType* CachedIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IUnit));
      if (!cached) {
        cached = moho::preregister_IUnitTypeInfoStartup();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::IUnit>));
      if (!cached) {
        cached = moho::preregister_WeakPtrIUnitTypeStartup();
      }
    }
    return cached;
  }

  /**
   * Address: 0x00BF5D40 (FUN_00BF5D40, atexit destructor of the FastVectorWeakPtrIUnitType object)
   */
  [[nodiscard]] FastVectorWeakPtrIUnitType* AcquireFastVectorWeakPtrIUnitType()
  {
    static FastVectorWeakPtrIUnitType sInstance;
    return &sInstance;
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

  struct BoundThiscallInvoker
  {
    using InvokeFn = int(__thiscall*)(void* boundObject);

    InvokeFn invoke;     // +0x00
    void* boundObject;   // +0x04
  };
  static_assert(sizeof(BoundThiscallInvoker) == 0x08, "BoundThiscallInvoker size must be 0x08");

  /**
   * Address: 0x00541290 (FUN_00541290)
   *
   * What it does:
   * Invokes one stored thiscall callback lane with the bound object lane at
   * offset `+0x04`.
   */
  [[maybe_unused]] int InvokeBoundThiscallCallback(
    BoundThiscallInvoker* const invoker
  )
  {
    return invoker->invoke(invoker->boundObject);
  }

  /**
   * Address: 0x00541900 (FUN_00541900, FA), 0x1012F280 (MohoEngine)
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
   * Address: 0x00541930 (FUN_00541930, FA), 0x1012F2B0 (MohoEngine)
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

  /**
   * Address: 0x0056DD80 (FUN_0056DD80, FA), 0x1015C0F0 (MohoEngine)
   *
   * What it does:
   * Reads the element count, resizes the `fastvector<WeakPtr<IUnit>>` to it
   * with empty weak pointers (`resize`, 0x0056D1D0), then reads every element
   * through the archive as a `WeakPtr<IUnit>` owned by `ownerRef`
   * (`ReadArchive::Read`, 0x00953DA0) -- not by calling the element type's
   * load callback directly.
   */
  void LoadFastVectorWeakPtrIUnit(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto& weakUnits = *reinterpret_cast<gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>*>(objectPtr);

    unsigned int count = 0;
    archive->ReadUInt(&count);
    weakUnits.resize(count, moho::WeakPtr<moho::IUnit>{});
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(CachedWeakPtrIUnitType(), &weakUnits[i], *ownerRef);
    }
  }

  /**
   * Address: 0x0056DE50 (FUN_0056DE50, FA), 0x1015C1C0 (MohoEngine)
   *
   * What it does:
   * Writes the element count, then every element through the archive
   * (`WriteArchive::Write`, 0x00953CA0) owned by `ownerRef`.
   */
  void SaveFastVectorWeakPtrIUnit(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    const auto& weakUnits = *reinterpret_cast<const gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>*>(objectPtr);

    const unsigned int count = static_cast<unsigned int>(weakUnits.Size());
    archive->WriteUInt(count);
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(CachedWeakPtrIUnitType(), &weakUnits[i], *ownerRef);
    }
  }

} // namespace

/**
 * Address: 0x00541600 (FUN_00541600, Moho::RWeakPtrType_IUnit::GetName)
 * Address: 0x00BF3E80 (FUN_00BF3E80, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds lexical type name `"WeakPtr<%s>"` once from the reflected IUnit
 * pointee type and returns it.
 */
const char* moho::RWeakPtrType<moho::IUnit>::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("WeakPtr<%s>", CachedIUnitType()->GetName());
  return sName.c_str();
}

/**
 * Address: 0x005416C0 (FUN_005416C0, Moho::RWeakPtrType_IUnit::GetLexical)
 *
 * What it does:
 * Returns `"NULL"` for empty weak pointers, otherwise wraps pointee lexical
 * text inside square brackets.
 */
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
  static_assert(sizeof(moho::WeakPtr<moho::IUnit>) == 0x08, "moho::WeakPtr<moho::IUnit> is 0x08 bytes on x86");
  size_ = sizeof(moho::WeakPtr<moho::IUnit>);
  version_ = 1;
  serLoadFunc_ = &LoadWeakPtrIUnit;
  serSaveFunc_ = &SaveWeakPtrIUnit;
}

/**
 * Address: 0x005418A0 (FUN_005418A0, Moho::RWeakPtrType_IUnit::SubscriptIndex)
 *
 * What it does:
 * Asserts `index == 0` and returns the pointed `IUnit` as a reflected `RRef`.
 */
gpg::RRef moho::RWeakPtrType<moho::IUnit>::SubscriptIndex(void* obj, const int ind) const
{
  if (ind != 0) {
    gpg::HandleAssertFailure("index == 0", 64, kReflectWeakPtrHeaderPath);
  }

  auto* const weak = static_cast<moho::WeakPtr<moho::IUnit>*>(obj);
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

gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::~RFastVectorType() = default;

/**
 * Address: 0x0056BDF0 (FUN_0056BDF0, gpg::RFastVectorType_WeakPtr_IUnit::GetName)
 * Address: 0x00BF5B60 (FUN_00BF5B60, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds lexical type name `"fastvector<%s>"` once from the reflected
 * `WeakPtr<IUnit>` element type and returns it.
 */
const char* gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("fastvector<%s>", CachedWeakPtrIUnitType()->GetName());
  return sName.c_str();
}

/**
 * Address: 0x0056BEB0 (FUN_0056BEB0, gpg::RFastVectorType_WeakPtr_IUnit::GetLexical)
 *
 * What it does:
 * Formats vector lexical text and appends the runtime weak-pointer element count.
 */
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
  static_assert(sizeof(gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>) == 0x10, "gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>> is 0x10 bytes on x86");
  size_ = sizeof(gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>);
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorWeakPtrIUnit;
  serSaveFunc_ = &SaveFastVectorWeakPtrIUnit;
}

gpg::RRef gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::SubscriptIndex(void* obj, const int ind) const
{
  auto* const weakUnits = static_cast<gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>*>(obj);
  GPG_ASSERT(weakUnits != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < GetCount(obj));

  if (!weakUnits || ind < 0 || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIUnitType();
    return out;
  }

  return MakeIUnitRefFromWeakPtr((*weakUnits)[ind]);
}

size_t gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }
  return static_cast<const gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>*>(obj)->Size();
}

/**
 * Address: 0x0056BF60 (FUN_0056BF60, gpg::RFastVectorType_WeakPtr_IUnit::SetCount)
 *
 * What it does:
 * Resizes the reflected `fastvector<WeakPtr<IUnit>>` to `count`, filling with
 * an empty `WeakPtr<IUnit>` built on the stack (0x0056BF79..0x0056BF9D) and
 * released after the `resize` (0x0056D1D0).
 */
void gpg::RFastVectorType<moho::WeakPtr<moho::IUnit>>::SetCount(void* obj, const int count) const
{
  static_cast<gpg::core::FastVectorInline<moho::WeakPtr<moho::IUnit>>*>(obj)->resize(static_cast<std::size_t>(count), moho::WeakPtr<moho::IUnit>{});
}

/**
 * Address: 0x00541400 (FUN_00541400, preregister_IUnitTypeInfoStartup)
 * Address: 0x00BF3E20 (FUN_00BF3E20, atexit destructor of the IUnitTypeInfo object)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `IUnit`.
 */
gpg::RType* moho::preregister_IUnitTypeInfoStartup()
{
  static IUnitTypeInfo sInstance;
  gpg::PreRegisterRType(typeid(moho::IUnit), &sInstance);
  return &sInstance;
}

/**
 * Address: 0x00541B40 (FUN_00541B40, preregister_WeakPtrIUnitTypeStartup)
 * Address: 0x00BF3EB0 (FUN_00BF3EB0, atexit destructor of the WeakPtrIUnitType object)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `WeakPtr<IUnit>`.
 */
gpg::RType* moho::preregister_WeakPtrIUnitTypeStartup()
{
  static WeakPtrIUnitType sInstance;
  gpg::PreRegisterRType(typeid(moho::WeakPtr<moho::IUnit>), &sInstance);
  return &sInstance;
}

/**
 * Address: 0x00571B90 (FUN_00571B90, preregister_FastVectorWeakPtrIUnitTypeStartup)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `gpg::fastvector<moho::WeakPtr<moho::IUnit>>`.
 */
gpg::RType* gpg::preregister_FastVectorWeakPtrIUnitTypeStartup()
{
  auto* const typeInfo = AcquireFastVectorWeakPtrIUnitType();
  gpg::PreRegisterRType(typeid(gpg::fastvector<moho::WeakPtr<moho::IUnit>>), typeInfo);
  return typeInfo;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_IUnitTypeInfoStartup_b5549d, moho::preregister_IUnitTypeInfoStartup)
GPG_PREREGISTER_INIT(preregister_WeakPtrIUnitTypeStartup_b5549d, moho::preregister_WeakPtrIUnitTypeStartup)
GPG_PREREGISTER_INIT(preregister_FastVectorWeakPtrIUnitTypeStartup_b5549d, gpg::preregister_FastVectorWeakPtrIUnitTypeStartup)
