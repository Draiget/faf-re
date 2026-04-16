#include "moho/serialization/CWeaponAttributesSerializer.h"

#include <cstdlib>
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

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::CWeaponAttributesSerializer;

  [[nodiscard]] Serializer& GetCWeaponAttributesSerializer() noexcept
  {
    static Serializer serializer{};
    return serializer;
  }

  [[nodiscard]] gpg::RType* CachedCWeaponAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CWeaponAttributes));
    }

    return cached;
  }

  [[nodiscard]] gpg::RType* CachedRUnitBlueprintWeaponType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RUnitBlueprintWeapon));
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

  gpg::RType* gLegacyEntityCategorySetVectorType = nullptr;
  gpg::RType* gLegacySBlackListInfoVectorType = nullptr;

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

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(Serializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

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

  [[nodiscard]] gpg::SerHelperBase* CleanupCWeaponAttributesSerializerNode()
  {
    return UnlinkSerializerNode(GetCWeaponAttributesSerializer());
  }

  /**
   * Address: 0x006D37E0 (FUN_006D37E0)
   *
   * What it does:
   * Splices `CWeaponAttributesSerializer` out of its intrusive helper lane
   * when linked, then rewires helper links to the serializer self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCWeaponAttributesSerializerHelperNodeVariantA() noexcept
  {
    return CleanupCWeaponAttributesSerializerNode();
  }

  /**
   * Address: 0x006D3810 (FUN_006D3810)
   *
   * What it does:
   * Secondary serializer helper unlink/reset variant sharing the same behavior.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCWeaponAttributesSerializerHelperNodeVariantB() noexcept
  {
    return UnlinkCWeaponAttributesSerializerHelperNodeVariantA();
  }

  void cleanup_CWeaponAttributesSerializer_atexit()
  {
    (void)moho::cleanup_CWeaponAttributesSerializer();
  }

  /**
   * Address: 0x006D3780 (FUN_006D3780, load body)
   *
   * What it does:
   * Loads the reflected pointer/string/float lanes for `CWeaponAttributes`.
   */
  void LoadCWeaponAttributes(
    gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef
  )
  {
    auto* const attributes = reinterpret_cast<moho::CWeaponAttributes*>(objectPtr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    attributes->mBlueprint = ReadRUnitBlueprintWeaponPointer(archive, owner);
    archive->ReadFloat(&attributes->mFiringTolerance);
    archive->ReadFloat(&attributes->mRateOfFire);
    archive->ReadFloat(&attributes->mMinRadius);
    archive->ReadFloat(&attributes->mMaxRadius);
    archive->ReadFloat(&attributes->mMinRadiusSq);
    archive->ReadFloat(&attributes->mMaxRadiusSq);
    archive->ReadString(&attributes->mType);
    archive->ReadFloat(&attributes->mDamageRadius);
    archive->ReadFloat(&attributes->mDamage);
    archive->ReadFloat(&attributes->mUnknown_0044);
    archive->ReadFloat(&attributes->mUnknown_0048);
  }

  /**
   * Address: 0x006DF0C0 (FUN_006DF0C0, serializer load thunk alias)
   *
   * What it does:
   * Loads the same `CWeaponAttributes` lanes as `FUN_006D3780`, but always
   * uses an empty owner-ref lane for the weapon-pointer read path.
   */
  [[maybe_unused]] void LoadCWeaponAttributesNoOwnerRef(
    gpg::ReadArchive* const archive,
    moho::CWeaponAttributes* const attributes
  )
  {
    if (archive == nullptr || attributes == nullptr) {
      return;
    }

    const gpg::RRef owner{};
    attributes->mBlueprint = ReadRUnitBlueprintWeaponPointer(archive, owner);
    archive->ReadFloat(&attributes->mFiringTolerance);
    archive->ReadFloat(&attributes->mRateOfFire);
    archive->ReadFloat(&attributes->mMinRadius);
    archive->ReadFloat(&attributes->mMaxRadius);
    archive->ReadFloat(&attributes->mMinRadiusSq);
    archive->ReadFloat(&attributes->mMaxRadiusSq);
    archive->ReadString(&attributes->mType);
    archive->ReadFloat(&attributes->mDamageRadius);
    archive->ReadFloat(&attributes->mDamage);
    archive->ReadFloat(&attributes->mUnknown_0044);
    archive->ReadFloat(&attributes->mUnknown_0048);
  }

  /**
   * Address: 0x006DD290 (FUN_006DD290)
   *
   * What it does:
   * Jump-thunk alias that forwards to the no-owner-ref load body.
   */
  [[maybe_unused]] void LoadCWeaponAttributesNoOwnerRefThunk(
    gpg::ReadArchive* const archive,
    moho::CWeaponAttributes* const attributes
  )
  {
    LoadCWeaponAttributesNoOwnerRef(archive, attributes);
  }

  /**
   * Address: 0x006DF180 (FUN_006DF180, save body)
   *
   * What it does:
   * Saves the reflected pointer/string/float lanes for `CWeaponAttributes`.
   */
  void SaveCWeaponAttributesBody_006DF180(
    moho::CWeaponAttributes* attributes, gpg::WriteArchive* archive
  )
  {
    const gpg::RRef owner{};

    gpg::RRef blueprintRef = MakeRUnitBlueprintWeaponRef(attributes->mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, owner);
    archive->WriteFloat(attributes->mFiringTolerance);
    archive->WriteFloat(attributes->mRateOfFire);
    archive->WriteFloat(attributes->mMinRadius);
    archive->WriteFloat(attributes->mMaxRadius);
    archive->WriteFloat(attributes->mMinRadiusSq);
    archive->WriteFloat(attributes->mMaxRadiusSq);
    archive->WriteString(const_cast<msvc8::string*>(&attributes->mType));
    archive->WriteFloat(attributes->mDamageRadius);
    archive->WriteFloat(attributes->mDamage);
    archive->WriteFloat(attributes->mUnknown_0044);
    archive->WriteFloat(attributes->mUnknown_0048);
  }

  /**
   * Address: 0x006DD2A0 (FUN_006DD2A0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CWeaponAttributes serialize thunk alias into the shared
   * save body (`FUN_006DF180`).
   */
  void SaveCWeaponAttributesThunkVariantA(
    moho::CWeaponAttributes* attributes, gpg::WriteArchive* archive
  )
  {
    SaveCWeaponAttributesBody_006DF180(attributes, archive);
  }

  /**
   * Address: 0x006DE5D0 (FUN_006DE5D0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CWeaponAttributes serialize thunk alias into the
   * shared save body (`FUN_006DF180`).
   */
  void SaveCWeaponAttributesThunkVariantB(
    moho::CWeaponAttributes* attributes, gpg::WriteArchive* archive
  )
  {
    SaveCWeaponAttributesBody_006DF180(attributes, archive);
  }

  /**
   * Address: 0x006D3790 (FUN_006D3790, save callback bridge)
   *
   * What it does:
   * Adapts serializer callback ABI and forwards to `FUN_006DF180` body.
   */
  void SaveCWeaponAttributes(
    gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
  )
  {
    auto* const attributes = reinterpret_cast<moho::CWeaponAttributes*>(objectPtr);
    SaveCWeaponAttributesBody_006DF180(attributes, archive);
  }

  /**
   * Address: 0x006D37B0 (FUN_006D37B0)
   *
   * What it does:
   * Alternate serializer startup leaf that initializes global helper links,
   * binds deserialize/serialize callbacks, and returns the helper node.
   */
  [[maybe_unused]] gpg::SerHelperBase* construct_CWeaponAttributesSerializer_StartupLeaf()
  {
    Serializer& serializer = GetCWeaponAttributesSerializer();
    InitializeSerializerNode(serializer);
    serializer.mDeserialize = &LoadCWeaponAttributes;
    serializer.mSerialize = &SaveCWeaponAttributes;
    return SerializerSelfNode(serializer);
  }

  int RegisterCWeaponAttributesSerializerStartup()
  {
    Serializer& serializer = GetCWeaponAttributesSerializer();
    (void)construct_CWeaponAttributesSerializer_StartupLeaf();
    serializer.mDeserialize = &LoadCWeaponAttributes;
    serializer.mSerialize = &SaveCWeaponAttributes;
    return std::atexit(&cleanup_CWeaponAttributesSerializer_atexit);
  }
} // namespace

namespace moho
{
  /**
    * Alias of FUN_006D3780 (non-canonical helper lane).
   */
  void CWeaponAttributesSerializer::Deserialize(
    gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    LoadCWeaponAttributes(archive, objectPtr, version, ownerRef);
  }

  /**
    * Alias of FUN_006D3790 (non-canonical helper lane).
   */
  void CWeaponAttributesSerializer::Serialize(
    gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    SaveCWeaponAttributes(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006DB4C0 (FUN_006DB4C0, Moho::CWeaponAttributesSerializer::RegisterSerializeFunctions)
   */
  void CWeaponAttributesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCWeaponAttributesType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE5F0 (FUN_00BFE5F0, serializer helper unlink cleanup)
   */
  gpg::SerHelperBase* cleanup_CWeaponAttributesSerializer()
  {
    return UnlinkCWeaponAttributesSerializerHelperNodeVariantA();
  }

  /**
   * Address: 0x00BD87D0 (FUN_00BD87D0, startup registration + atexit cleanup)
   */
  int register_CWeaponAttributesSerializer()
  {
    return RegisterCWeaponAttributesSerializerStartup();
  }
} // namespace moho
