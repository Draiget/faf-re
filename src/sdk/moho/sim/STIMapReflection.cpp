#include "moho/sim/STIMapReflection.h"

#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/sim/STIMap.h"

namespace
{
  class STIMapTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "STIMap";
    }

    void Init() override
    {
      size_ = sizeof(moho::STIMap);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x005098E0 (FUN_005098E0, STIMap RTTI cache resolve)
   */
  [[nodiscard]] gpg::RType* CachedSTIMapTypeVariant1()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::STIMap));
      if (!cached) {
        cached = moho::preregister_STIMapTypeInfo();
      }
    }
    return cached;
  }

  /**
   * Address: 0x00509CF0 (FUN_00509CF0, STIMap RTTI cache resolve duplicate)
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedSTIMapTypeVariant2()
  {
    return CachedSTIMapTypeVariant1();
  }

  /**
   * Address: 0x005098D0 (FUN_005098D0, nullsub_1052)
   */
  [[maybe_unused]] void noop_STIMapLaneVariant1()
  {
  }

  /**
   * Address: 0x00509900 (FUN_00509900, nullsub_1053)
   */
  [[maybe_unused]] void noop_STIMapLaneVariant2()
  {
  }

  /**
   * Address: 0x00509910 (FUN_00509910, nullsub_1054)
   */
  [[maybe_unused]] void noop_STIMapLaneVariant3()
  {
  }

  /**
   * Address: 0x00509A70 (FUN_00509A70, nullsub_1055)
   */
  [[maybe_unused]] void noop_STIMapLaneVariant4()
  {
  }

  /**
   * Address: 0x005099E0 (FUN_005099E0, STIMap RRef fill helper)
   */
  [[maybe_unused]] gpg::RRef* FillSTIMapRef(moho::STIMap* const value, gpg::RRef* const outRef)
  {
    return gpg::RRef_STIMap(outRef, value);
  }

  /**
    * Alias of FUN_005096E0 (non-canonical helper lane).
   */
  [[maybe_unused]] gpg::ReadArchive* ReadPointerSTIMapVariant1(
    moho::STIMap** const outValue, gpg::ReadArchive* const archive, const gpg::RRef& ownerRef
  )
  {
    if (outValue) {
      *outValue = gpg::ReadPointerSTIMap(archive, ownerRef);
    }
    return archive;
  }

  /**
    * Alias of FUN_005097F0 (non-canonical helper lane).
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUnownedPointerSTIMapVariant1(
    moho::STIMap* const value, gpg::WriteArchive* const archive, const gpg::RRef& ownerRef
  )
  {
    return gpg::WriteUnownedPointerSTIMap(value, archive, ownerRef);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00577750 (FUN_00577750, preregister_STIMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `STIMap`.
   */
  gpg::RType* preregister_STIMapTypeInfo()
  {
    static STIMapTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(STIMap), &typeInfo);
    return &typeInfo;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00509AC0 (FUN_00509AC0, gpg::RRef_STIMap)
   * Address: 0x007561F0 (FUN_007561F0)
   */
  gpg::RRef* RRef_STIMap(gpg::RRef* const outRef, moho::STIMap* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    outRef->mObj = value;
    outRef->mType = CachedSTIMapTypeVariant2();
    return outRef;
  }

  /**
   * Address: 0x005099A0 (FUN_005099A0, STIMap RRef upcast helper)
   */
  void* UpcastPointerToSTIMap(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTIMapTypeVariant1());
    return upcast.mObj;
  }

  /**
    * Alias of FUN_005096E0 (non-canonical helper lane).
   */
  moho::STIMap* ReadPointerSTIMap(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSTIMapTypeVariant1());
    if (upcast.mObj) {
      return static_cast<moho::STIMap*>(upcast.mObj);
    }

    const gpg::RType* const expectedType = CachedSTIMapTypeVariant1();
    const char* const expectedName = expectedType ? expectedType->GetName() : "STIMap";
    const char* const actualName = source.GetTypeName();

    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expectedName ? expectedName : "STIMap",
      actualName ? actualName : "null"
    );
    throw gpg::SerializationError(message.c_str());
  }

  /**
   * Address: 0x005097F0 (FUN_005097F0, STIMap unowned pointer write helper)
   */
  gpg::WriteArchive* WriteUnownedPointerSTIMap(
    moho::STIMap* const value, gpg::WriteArchive* const archive, const gpg::RRef& ownerRef
  )
  {
    if (!archive) {
      return nullptr;
    }

    gpg::RRef pointerRef{};
    (void)gpg::RRef_STIMap(&pointerRef, value);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);
    return archive;
  }
} // namespace gpg

