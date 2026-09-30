#include "moho/unit/core/SInfoCacheReflection.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* SInfoCache::sType = nullptr;
} // namespace moho

namespace
{
  using TypeInfo = moho::SInfoCacheTypeInfo;

  /**
   * Address: 0x00BFD8E0 (FUN_00BFD8E0, atexit destructor of the SInfoCacheTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireSInfoCacheTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RType* CachedRType(const std::type_info& typeInfo)
  {
    return gpg::LookupRType(typeInfo);
  }

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = CachedRType(typeid(TObject));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedIFormationInstanceType()
  {
    return CachedRType<moho::IFormationInstance>();
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrIUnitType()
  {
    return CachedRType<moho::WeakPtr<moho::IUnit>>();
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    return CachedRType<moho::Vector3f>();
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeTrackedRef(const TObject* const object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRType<TObject>();
    if (!object) {
      return out;
    }

    gpg::RType* runtimeType = out.mType;
    try {
      runtimeType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      runtimeType = out.mType;
    }

    if (!runtimeType || !out.mType) {
      out.mObj = const_cast<TObject*>(object);
      out.mType = runtimeType ? runtimeType : out.mType;
      return out;
    }

    std::int32_t baseOffset = 0;
    const bool derived = runtimeType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = const_cast<TObject*>(object);
      out.mType = runtimeType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(
      reinterpret_cast<std::uintptr_t>(const_cast<TObject*>(object)) - static_cast<std::uintptr_t>(baseOffset)
    );
    out.mType = runtimeType;
    return out;
  }

  template <class TObject>
  [[nodiscard]] TObject* ReadTrackedPointer(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RType* const expectedType = CachedRType<TObject>();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<TObject*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "null";
    const char* const actual = tracked.type ? tracked.type->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected,
      actual
    );
    throw gpg::SerializationError(message.c_str());
  }

  template <class TObject>
  void WriteTrackedPointer(
    gpg::WriteArchive* const archive,
    const TObject* const object,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTrackedRef(object);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  [[nodiscard]] moho::SInfoCache* AsSInfoCacheView(int objectPtr) noexcept
  {
    return reinterpret_cast<moho::SInfoCache*>(objectPtr);
  }

  [[nodiscard]] const moho::SInfoCache* AsConstSInfoCacheView(int objectPtr) noexcept
  {
    return reinterpret_cast<const moho::SInfoCache*>(objectPtr);
  }

  /**
   * Address: 0x00BD6A70 (FUN_00BD6A70, register_SInfoCacheTypeInfo)
   *
   * What it does:
   * Forces `SInfoCacheTypeInfo` construction.
   */
  void register_SInfoCacheTypeInfo_Impl()
  {
    (void)AcquireSInfoCacheTypeInfo();
  }

  struct SInfoCacheReflectionBootstrap
  {
    SInfoCacheReflectionBootstrap()
    {
      (void)register_SInfoCacheTypeInfo_Impl();
    }
  };

  SInfoCacheReflectionBootstrap gSInfoCacheReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006A4E60 (FUN_006A4E60, sub_6A4E60)
   */
  SInfoCacheTypeInfo::SInfoCacheTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(moho::SInfoCache), this);
  }

  /**
   * Address: 0x006A4EF0 (FUN_006A4EF0, sub_6A4EF0)
   */
  SInfoCacheTypeInfo::~SInfoCacheTypeInfo()
  {
    fields_ = msvc8::vector<gpg::RField>{};
    bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x006A4EE0 (FUN_006A4EE0, Moho::SInfoCacheTypeInfo::GetName)
   */
  const char* SInfoCacheTypeInfo::GetName() const
  {
    return "SInfoCache";
  }

  /**
   * Address: 0x006A4EC0 (FUN_006A4EC0, Moho::SInfoCacheTypeInfo::Init)
   */
  void SInfoCacheTypeInfo::Init()
  {
    size_ = sizeof(moho::SInfoCache);
    gpg::RType::Init();
    Finish();
  }


  /**
   * Address: 0x006B04B0 (FUN_006B04B0, Moho::SInfoCacheSerializer::Deserialize)
   *
   * What it does:
   * Loads the raw formation pointer, reflected weak unit pointer, and trailing
   * scalar/vector lanes for `SInfoCache`.
   */
  void SInfoCache::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    mFormationLayer =
      reinterpret_cast<moho::CFormationInstance*>(ReadTrackedPointer<moho::IFormationInstance>(archive, ownerRef));

    archive->Read(CachedWeakPtrIUnitType(), &mFormationLeadRef, ownerRef);
    archive->ReadInt(&mFormationPriorityOrder);
    archive->ReadBool(&mHasFormationSpeedData);
    archive->ReadFloat(&mFormationTopSpeed);
    archive->ReadFloat(&mFormationDistanceMetric);
    archive->Read(CachedVector3fType(), &mFormationHeadingHint, ownerRef);
  }

  /**
   * Address: 0x006B0580 (FUN_006B0580, Moho::SInfoCacheSerializer::Serialize)
   *
   * What it does:
   * Saves the raw formation pointer, reflected weak unit pointer, and trailing
   * scalar/vector lanes for `SInfoCache`.
   */
  void SInfoCache::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    WriteTrackedPointer(
      archive,
      reinterpret_cast<const moho::IFormationInstance*>(mFormationLayer),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );

    archive->Write(CachedWeakPtrIUnitType(), &mFormationLeadRef, ownerRef);
    archive->WriteInt(mFormationPriorityOrder);
    archive->WriteBool(mHasFormationSpeedData);
    archive->WriteFloat(mFormationTopSpeed);
    archive->WriteFloat(mFormationDistanceMetric);
    archive->Write(CachedVector3fType(), &mFormationHeadingHint, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SInfoCache>`, vtable 0x00E2A7F0.
   *
   * Address: 0x00BD6A90 (FUN_00BD6A90 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD940 (FUN_00BFD940 -- the global's destructor.)
   * Address: 0x006AE810 (FUN_006AE810 -- `Init`.)
   * Address: 0x006A4FA0 (FUN_006A4FA0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006A4FB0 (FUN_006A4FB0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SInfoCacheSerializer : gpg::SerSaveLoadHelper<SInfoCache>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B5B5C -- process-global `SInfoCacheSerializer` singleton.
  moho::SInfoCacheSerializer gSInfoCacheSerializer;
} // namespace
