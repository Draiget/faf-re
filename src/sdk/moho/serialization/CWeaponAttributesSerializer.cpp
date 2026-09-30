
#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityCategorySetVectorReflection.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/serialization/SBlackListInfoVectorReflection.h"
#include "moho/unit/core/CWeaponAttributes.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedRUnitBlueprintWeaponType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
    }

    return cached;
  }

  gpg::RType* gLegacyEntityCategorySetVectorType = nullptr;
  gpg::RType* gLegacySBlackListInfoVectorType = nullptr;

  [[nodiscard]] moho::RUnitBlueprintWeapon* ReadRUnitBlueprintWeaponPointer(
    gpg::ReadArchive* archive, const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRUnitBlueprintWeaponType());
    if (upcast.mObj) {
      return static_cast<moho::RUnitBlueprintWeapon*>(upcast.mObj);
    }

    const char* const expected = CachedRUnitBlueprintWeaponType() ? CachedRUnitBlueprintWeaponType()->GetName() : "RUnitBlueprintWeapon";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "RUnitBlueprintWeapon",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  [[nodiscard]] gpg::RRef MakeRUnitBlueprintWeaponRef(moho::RUnitBlueprintWeapon* value)
  {
    gpg::RRef ref{};
    ref.mObj = value;
    ref.mType = CachedRUnitBlueprintWeaponType();
    return ref;
  }

} // namespace

namespace moho
{
} // namespace moho

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x006DF0C0 (FUN_006DF0C0, serializer load thunk alias)
   *
   * What it does:
   * Loads the same `CWeaponAttributes` lanes as `FUN_006D3780`, but always
   * uses an empty owner-ref lane for the weapon-pointer read path.
   */
  void CWeaponAttributes::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr || this == nullptr) {
      return;
    }

    const gpg::RRef owner{};
    mBlueprint = ReadRUnitBlueprintWeaponPointer(archive, owner);
    archive->ReadFloat(&mFiringTolerance);
    archive->ReadFloat(&mRateOfFire);
    archive->ReadFloat(&mMinRadius);
    archive->ReadFloat(&mMaxRadius);
    archive->ReadFloat(&mMinRadiusSq);
    archive->ReadFloat(&mMaxRadiusSq);
    archive->ReadString(&mType);
    archive->ReadFloat(&mDamageRadius);
    archive->ReadFloat(&mDamage);
    archive->ReadFloat(&mUnknown_0044);
    archive->ReadFloat(&mUnknown_0048);
  }

  /**
   * Address: 0x006DF180 (FUN_006DF180, save body)
   *
   * What it does:
   * Saves the reflected pointer/string/float lanes for `CWeaponAttributes`.
   */
  void CWeaponAttributes::MemberSerialize(gpg::WriteArchive* const archive)
  {
    const gpg::RRef owner{};

    gpg::RRef blueprintRef = MakeRUnitBlueprintWeaponRef(mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, owner);
    archive->WriteFloat(mFiringTolerance);
    archive->WriteFloat(mRateOfFire);
    archive->WriteFloat(mMinRadius);
    archive->WriteFloat(mMaxRadius);
    archive->WriteFloat(mMinRadiusSq);
    archive->WriteFloat(mMaxRadiusSq);
    archive->WriteString(const_cast<msvc8::string*>(&mType));
    archive->WriteFloat(mDamageRadius);
    archive->WriteFloat(mDamage);
    archive->WriteFloat(mUnknown_0044);
    archive->WriteFloat(mUnknown_0048);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CWeaponAttributes>`, vtable 0x00E2E228.
   *
   * Address: 0x00BD87D0 (FUN_00BD87D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFE5F0 (FUN_00BFE5F0 -- the global's destructor.)
   * Address: 0x006D37B0 (FUN_006D37B0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x006DD290 (FUN_006DD290 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x006DD2A0 (FUN_006DD2A0 -- an unreferenced copy of `Serialize`.)
   * Address: 0x006DE5D0 (FUN_006DE5D0 -- an unreferenced copy of `Serialize`.)
   * Address: 0x006DB4C0 (FUN_006DB4C0 -- `Init`.)
   * Address: 0x006D3780 (FUN_006D3780 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006D3790 (FUN_006D3790 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CWeaponAttributesSerializer : gpg::SerSaveLoadHelper<CWeaponAttributes>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B7C70 -- process-global `CWeaponAttributesSerializer` singleton.
  moho::CWeaponAttributesSerializer gCWeaponAttributesSerializer;
} // namespace

namespace
{
  [[nodiscard]] gpg::RType* CachedCWeaponAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CWeaponAttributes));
    }

    return cached;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedArchiveType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(TObject));
    }
    return cached;
  }

  /**
   * Address: 0x006E03B0 (FUN_006E03B0)
   *
   * What it does:
   * Resolves and caches RTTI for one `vector<EntityCategorySet>` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyEntityCategorySetVectorType()
  {
    gpg::RType* type = gLegacyEntityCategorySetVectorType;
    if (!type) {
      type = gpg::LookupRType(typeid(msvc8::vector<moho::EntityCategorySet>));
      gLegacyEntityCategorySetVectorType = type;
    }
    return type;
  }

  /**
   * Address: 0x006E03D0 (FUN_006E03D0)
   *
   * What it does:
   * Resolves and caches RTTI for one `vector<SBlackListInfo>` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacySBlackListInfoVectorType()
  {
    gpg::RType* type = gLegacySBlackListInfoVectorType;
    if (!type) {
      type = gpg::LookupRType(typeid(msvc8::vector<moho::SBlackListInfo>));
      gLegacySBlackListInfoVectorType = type;
    }
    return type;
  }

  template <typename TObject>
  void ReadObjectByCachedType(gpg::ReadArchive* const archive, void* const objectPtr, gpg::RRef* const ownerRef)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    if (gpg::RType* const type = ResolveCachedArchiveType<TObject>()) {
      archive->Read(type, objectPtr, owner);
    }
  }

  template <typename TObject>
  void WriteObjectByCachedType(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    if (gpg::RType* const type = ResolveCachedArchiveType<TObject>()) {
      archive->Write(type, objectPtr, owner);
    }
  }

  /**
   * Address: 0x006DFE20 (FUN_006DFE20)
   *
   * What it does:
   * Loads one reflected `vector<SBlackListInfo>` payload using the cached RTTI
   * descriptor and returns the archive pointer for chaining.
   */
  gpg::ReadArchive* ReadCachedSBlackListInfoVectorAndReturnArchive(
    gpg::ReadArchive* const archive,
    void* const objectPtr,
    gpg::RRef* const ownerRef
  )
  {
    ReadObjectByCachedType<msvc8::vector<moho::SBlackListInfo>>(archive, objectPtr, ownerRef);
    return archive;
  }

  /**
   * Address: 0x006DFE90 (FUN_006DFE90)
   *
   * What it does:
   * Saves one reflected `CWeaponAttributes` payload using the cached RTTI
   * descriptor and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteCachedCWeaponAttributesAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    WriteObjectByCachedType<moho::CWeaponAttributes>(archive, objectPtr, ownerRef);
    return archive;
  }

  /**
   * Address: 0x006DFF00 (FUN_006DFF00)
   *
   * What it does:
   * Saves one reflected `vector<EntityCategorySet>` payload using cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteCachedEntityCategorySetVectorAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    WriteObjectByCachedType<msvc8::vector<moho::EntityCategorySet>>(archive, objectPtr, ownerRef);
    return archive;
  }

  /**
   * Address: 0x006DFF40 (FUN_006DFF40)
   *
   * What it does:
   * Saves one reflected `vector<SBlackListInfo>` payload using cached RTTI
   * lookup and returns the archive pointer for chaining.
   */
  gpg::WriteArchive* WriteCachedSBlackListInfoVectorAndReturnArchive(
    gpg::WriteArchive* const archive,
    void* const objectPtr,
    const gpg::RRef* const ownerRef
  )
  {
    WriteObjectByCachedType<msvc8::vector<moho::SBlackListInfo>>(archive, objectPtr, ownerRef);
    return archive;
  }

  /**
   * Address: 0x006E0240 (FUN_006E0240)
   *
   * What it does:
   * Read-callback bridge that loads one reflected `CWeaponAttributes` payload
   * through cached RTTI lookup.
   */
  void ReadCachedCWeaponAttributesCallback(gpg::ReadArchive* archive, void* objectPtr, gpg::RRef* ownerRef)
  {
    ReadObjectByCachedType<moho::CWeaponAttributes>(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x006E0270 (FUN_006E0270)
   *
   * What it does:
   * Write-callback bridge that saves one reflected `CWeaponAttributes` payload
   * through cached RTTI lookup.
   */
  void WriteCachedCWeaponAttributesCallback(
    gpg::WriteArchive* archive,
    void* objectPtr,
    const gpg::RRef* ownerRef
  )
  {
    WriteObjectByCachedType<moho::CWeaponAttributes>(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x006E02F0 (FUN_006E02F0)
   *
   * What it does:
   * Read-callback bridge that loads one reflected
   * `vector<EntityCategorySet>` payload through cached RTTI lookup.
   */
  void ReadCachedEntityCategorySetVectorCallback(
    gpg::ReadArchive* archive,
    void* objectPtr,
    gpg::RRef* ownerRef
  )
  {
    ReadObjectByCachedType<msvc8::vector<moho::EntityCategorySet>>(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x006E0320 (FUN_006E0320)
   *
   * What it does:
   * Write-callback bridge that saves one reflected
   * `vector<EntityCategorySet>` payload through cached RTTI lookup.
   */
  void WriteCachedEntityCategorySetVectorCallback(
    gpg::WriteArchive* archive,
    void* objectPtr,
    const gpg::RRef* ownerRef
  )
  {
    WriteObjectByCachedType<msvc8::vector<moho::EntityCategorySet>>(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x006E0350 (FUN_006E0350)
   *
   * What it does:
   * Read-callback bridge that loads one reflected `vector<SBlackListInfo>`
   * payload through cached RTTI lookup.
   */
  void ReadCachedSBlackListInfoVectorCallback(
    gpg::ReadArchive* archive,
    void* objectPtr,
    gpg::RRef* ownerRef
  )
  {
    ReadObjectByCachedType<msvc8::vector<moho::SBlackListInfo>>(archive, objectPtr, ownerRef);
  }

  /**
   * Address: 0x006E0380 (FUN_006E0380)
   *
   * What it does:
   * Write-callback bridge that saves one reflected `vector<SBlackListInfo>`
   * payload through cached RTTI lookup.
   */
  void WriteCachedSBlackListInfoVectorCallback(
    gpg::WriteArchive* archive,
    void* objectPtr,
    const gpg::RRef* ownerRef
  )
  {
    WriteObjectByCachedType<msvc8::vector<moho::SBlackListInfo>>(archive, objectPtr, ownerRef);
  }
} // namespace
