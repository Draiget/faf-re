#include "RUnitBlueprintEnumTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

namespace
{
  template <typename TEnum>
  class EnumPrimitiveSerializer
  {
  public:
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType>, mHelperNext) == 0x04,
    "EnumPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType>, mHelperPrev) == 0x08,
    "EnumPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType>, mDeserialize) == 0x0C,
    "EnumPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType>, mSerialize) == 0x10,
    "EnumPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType>) == 0x14, "EnumPrimitiveSerializer size must be 0x14");

  alignas(moho::ERuleBPUnitBuildRestrictionTypeInfo)
    unsigned char gERuleBPUnitBuildRestrictionTypeInfoStorage[sizeof(moho::ERuleBPUnitBuildRestrictionTypeInfo)];
  bool gERuleBPUnitBuildRestrictionTypeInfoConstructed = false;

  alignas(moho::ERuleBPUnitWeaponBallisticArcTypeInfo) unsigned char
    gERuleBPUnitWeaponBallisticArcTypeInfoStorage[sizeof(moho::ERuleBPUnitWeaponBallisticArcTypeInfo)];
  bool gERuleBPUnitWeaponBallisticArcTypeInfoConstructed = false;

  alignas(moho::ERuleBPUnitWeaponTargetTypeTypeInfo)
    unsigned char gERuleBPUnitWeaponTargetTypeTypeInfoStorage[sizeof(moho::ERuleBPUnitWeaponTargetTypeTypeInfo)];
  bool gERuleBPUnitWeaponTargetTypeTypeInfoConstructed = false;

  alignas(moho::ERuleBPUnitMovementTypeTypeInfo)
    unsigned char gERuleBPUnitMovementTypeTypeInfoStorage[sizeof(moho::ERuleBPUnitMovementTypeTypeInfo)];
  bool gERuleBPUnitMovementTypeTypeInfoConstructed = false;

  alignas(moho::ERuleBPUnitCommandCapsTypeInfo)
    unsigned char gERuleBPUnitCommandCapsTypeInfoStorage[sizeof(moho::ERuleBPUnitCommandCapsTypeInfo)];
  bool gERuleBPUnitCommandCapsTypeInfoConstructed = false;

  alignas(moho::ERuleBPUnitToggleCapsTypeInfo)
    unsigned char gERuleBPUnitToggleCapsTypeInfoStorage[sizeof(moho::ERuleBPUnitToggleCapsTypeInfo)];
  bool gERuleBPUnitToggleCapsTypeInfoConstructed = false;

  alignas(moho::UnitWeaponRangeCategoryTypeInfo)
    unsigned char gUnitWeaponRangeCategoryTypeInfoStorage[sizeof(moho::UnitWeaponRangeCategoryTypeInfo)];
  bool gUnitWeaponRangeCategoryTypeInfoConstructed = false;

  EnumPrimitiveSerializer<moho::ERuleBPUnitMovementType> gERuleBPUnitMovementTypePrimitiveSerializer;
  EnumPrimitiveSerializer<moho::ERuleBPUnitCommandCaps> gERuleBPUnitCommandCapsPrimitiveSerializer;
  EnumPrimitiveSerializer<moho::ERuleBPUnitToggleCaps> gERuleBPUnitToggleCapsPrimitiveSerializer;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
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

  template <typename TTypeInfo, typename TEnum>
  [[nodiscard]] gpg::REnumType* ConstructEnumTypeInfo(void* const storage)
  {
    auto* const typeInfo = new (storage) TTypeInfo();
    gpg::PreRegisterRType(typeid(TEnum), typeInfo);
    return typeInfo;
  }

  template <typename TTypeInfo>
  void DestroyEnumTypeInfo(void* const storage) noexcept
  {
    reinterpret_cast<TTypeInfo*>(storage)->~TTypeInfo();
  }

  template <typename TEnum>
  void DeserializeEnumIntLane(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<TEnum*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<TEnum>(value);
  }

  template <typename TEnum>
  void SerializeEnumIntLane(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const value = reinterpret_cast<const TEnum*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(*value));
  }

  void AddEnumEntry(gpg::REnumType* const typeInfo, const char* const token, const int value)
  {
    typeInfo->AddEnum(typeInfo->StripPrefix(token), value);
  }

  // Lazy singleton storage constructor backing
  // construct_ERuleBPUnitBuildRestrictionTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitBuildRestrictionTypeInfoImpl()
  {
    if (!gERuleBPUnitBuildRestrictionTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::ERuleBPUnitBuildRestrictionTypeInfo, moho::ERuleBPUnitBuildRestriction>(
        gERuleBPUnitBuildRestrictionTypeInfoStorage
      );
      gERuleBPUnitBuildRestrictionTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitBuildRestrictionTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing
  // construct_ERuleBPUnitWeaponBallisticArcTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitWeaponBallisticArcTypeInfoImpl()
  {
    if (!gERuleBPUnitWeaponBallisticArcTypeInfoConstructed) {
      (void)
        ConstructEnumTypeInfo<moho::ERuleBPUnitWeaponBallisticArcTypeInfo, moho::ERuleBPUnitWeaponBallisticArc>(
          gERuleBPUnitWeaponBallisticArcTypeInfoStorage
        );
      gERuleBPUnitWeaponBallisticArcTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitWeaponBallisticArcTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing
  // construct_ERuleBPUnitWeaponTargetTypeTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitWeaponTargetTypeTypeInfoImpl()
  {
    if (!gERuleBPUnitWeaponTargetTypeTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::ERuleBPUnitWeaponTargetTypeTypeInfo, moho::ERuleBPUnitWeaponTargetType>(
        gERuleBPUnitWeaponTargetTypeTypeInfoStorage
      );
      gERuleBPUnitWeaponTargetTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitWeaponTargetTypeTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing construct_ERuleBPUnitMovementTypeTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitMovementTypeTypeInfoImpl()
  {
    if (!gERuleBPUnitMovementTypeTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::ERuleBPUnitMovementTypeTypeInfo, moho::ERuleBPUnitMovementType>(
        gERuleBPUnitMovementTypeTypeInfoStorage
      );
      gERuleBPUnitMovementTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitMovementTypeTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing construct_ERuleBPUnitCommandCapsTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitCommandCapsTypeInfoImpl()
  {
    if (!gERuleBPUnitCommandCapsTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::ERuleBPUnitCommandCapsTypeInfo, moho::ERuleBPUnitCommandCaps>(
        gERuleBPUnitCommandCapsTypeInfoStorage
      );
      gERuleBPUnitCommandCapsTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitCommandCapsTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing construct_ERuleBPUnitToggleCapsTypeInfo.
  gpg::REnumType* construct_ERuleBPUnitToggleCapsTypeInfoImpl()
  {
    if (!gERuleBPUnitToggleCapsTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::ERuleBPUnitToggleCapsTypeInfo, moho::ERuleBPUnitToggleCaps>(
        gERuleBPUnitToggleCapsTypeInfoStorage
      );
      gERuleBPUnitToggleCapsTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gERuleBPUnitToggleCapsTypeInfoStorage);
  }

  // Lazy singleton storage constructor backing construct_UnitWeaponRangeCategoryTypeInfo.
  gpg::REnumType* construct_UnitWeaponRangeCategoryTypeInfoImpl()
  {
    if (!gUnitWeaponRangeCategoryTypeInfoConstructed) {
      (void)ConstructEnumTypeInfo<moho::UnitWeaponRangeCategoryTypeInfo, moho::UnitWeaponRangeCategory>(
        gUnitWeaponRangeCategoryTypeInfoStorage
      );
      gUnitWeaponRangeCategoryTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gUnitWeaponRangeCategoryTypeInfoStorage);
  }

  [[nodiscard]] moho::ERuleBPUnitBuildRestrictionTypeInfo& GetERuleBPUnitBuildRestrictionTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitBuildRestrictionTypeInfo*>(
      construct_ERuleBPUnitBuildRestrictionTypeInfoImpl()
    );
  }

  [[nodiscard]] moho::ERuleBPUnitWeaponBallisticArcTypeInfo& GetERuleBPUnitWeaponBallisticArcTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitWeaponBallisticArcTypeInfo*>(
      construct_ERuleBPUnitWeaponBallisticArcTypeInfoImpl()
    );
  }

  [[nodiscard]] moho::ERuleBPUnitWeaponTargetTypeTypeInfo& GetERuleBPUnitWeaponTargetTypeTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitWeaponTargetTypeTypeInfo*>(
      construct_ERuleBPUnitWeaponTargetTypeTypeInfoImpl()
    );
  }

  [[nodiscard]] moho::ERuleBPUnitMovementTypeTypeInfo& GetERuleBPUnitMovementTypeTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitMovementTypeTypeInfo*>(construct_ERuleBPUnitMovementTypeTypeInfoImpl());
  }

  [[nodiscard]] moho::ERuleBPUnitCommandCapsTypeInfo& GetERuleBPUnitCommandCapsTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitCommandCapsTypeInfo*>(construct_ERuleBPUnitCommandCapsTypeInfoImpl());
  }

  [[nodiscard]] moho::ERuleBPUnitToggleCapsTypeInfo& GetERuleBPUnitToggleCapsTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::ERuleBPUnitToggleCapsTypeInfo*>(construct_ERuleBPUnitToggleCapsTypeInfoImpl());
  }

  [[nodiscard]] moho::UnitWeaponRangeCategoryTypeInfo& GetUnitWeaponRangeCategoryTypeInfo() noexcept
  {
    return *reinterpret_cast<moho::UnitWeaponRangeCategoryTypeInfo*>(construct_UnitWeaponRangeCategoryTypeInfoImpl());
  }

  /**
   * Address: 0x00BF3290 (FUN_00BF3290)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitBuildRestrictionTypeInfo`
   * descriptor at process exit.
   */
  void cleanup_ERuleBPUnitBuildRestrictionTypeInfo()
  {
    if (!gERuleBPUnitBuildRestrictionTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitBuildRestrictionTypeInfo>(gERuleBPUnitBuildRestrictionTypeInfoStorage);
    gERuleBPUnitBuildRestrictionTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF32A0 (FUN_00BF32A0)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitWeaponBallisticArcTypeInfo`
   * descriptor at process exit.
   */
  void cleanup_ERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    if (!gERuleBPUnitWeaponBallisticArcTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitWeaponBallisticArcTypeInfo>(gERuleBPUnitWeaponBallisticArcTypeInfoStorage);
    gERuleBPUnitWeaponBallisticArcTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF32B0 (FUN_00BF32B0)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitWeaponTargetTypeTypeInfo`
   * descriptor at process exit.
   */
  void cleanup_ERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    if (!gERuleBPUnitWeaponTargetTypeTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitWeaponTargetTypeTypeInfo>(gERuleBPUnitWeaponTargetTypeTypeInfoStorage);
    gERuleBPUnitWeaponTargetTypeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF31D0 (FUN_00BF31D0)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitMovementTypeTypeInfo` descriptor at
   * process exit.
   */
  void cleanup_ERuleBPUnitMovementTypeTypeInfo()
  {
    if (!gERuleBPUnitMovementTypeTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitMovementTypeTypeInfo>(gERuleBPUnitMovementTypeTypeInfoStorage);
    gERuleBPUnitMovementTypeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x0051FC20 (FUN_0051FC20)
   *
   * What it does:
   * Unlinks `ERuleBPUnitMovementType` primitive serializer helper node and
   * restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitMovementTypePrimitiveSerializerNodePrimary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitMovementTypePrimitiveSerializer);
  }

  /**
   * Address: 0x0051FC50 (FUN_0051FC50)
   *
   * What it does:
   * Secondary unlink entrypoint for `ERuleBPUnitMovementType` primitive
   * serializer helper-node cleanup; behavior matches the primary lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitMovementTypePrimitiveSerializerNodeSecondary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitMovementTypePrimitiveSerializer);
  }

  /**
   * Address: 0x00BF31E0 (FUN_00BF31E0)
   *
   * What it does:
   * Unlinks the recovered `ERuleBPUnitMovementType` primitive serializer
   * helper node.
   */
  void cleanup_ERuleBPUnitMovementTypePrimitiveSerializer()
  {
    (void)CleanupERuleBPUnitMovementTypePrimitiveSerializerNodePrimary();
  }

  /**
   * Address: 0x00BF3210 (FUN_00BF3210)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitCommandCapsTypeInfo` descriptor at
   * process exit.
   */
  void cleanup_ERuleBPUnitCommandCapsTypeInfo()
  {
    if (!gERuleBPUnitCommandCapsTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitCommandCapsTypeInfo>(gERuleBPUnitCommandCapsTypeInfoStorage);
    gERuleBPUnitCommandCapsTypeInfoConstructed = false;
  }

  /**
   * Address: 0x0051FFA0 (FUN_0051FFA0)
   *
   * What it does:
   * Unlinks `ERuleBPUnitCommandCaps` primitive serializer helper node and
   * restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitCommandCapsPrimitiveSerializerNodePrimary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitCommandCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x0051FFD0 (FUN_0051FFD0)
   *
   * What it does:
   * Secondary unlink entrypoint for `ERuleBPUnitCommandCaps` primitive
   * serializer helper-node cleanup; behavior matches the primary lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitCommandCapsPrimitiveSerializerNodeSecondary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitCommandCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x00BF3220 (FUN_00BF3220)
   *
   * What it does:
   * Unlinks the recovered `ERuleBPUnitCommandCaps` primitive serializer
   * helper node.
   */
  void cleanup_ERuleBPUnitCommandCapsPrimitiveSerializer()
  {
    (void)CleanupERuleBPUnitCommandCapsPrimitiveSerializerNodePrimary();
  }

  /**
   * Address: 0x00BF3250 (FUN_00BF3250)
   *
   * What it does:
   * Tears down the recovered `ERuleBPUnitToggleCapsTypeInfo` descriptor at
   * process exit.
   */
  void cleanup_ERuleBPUnitToggleCapsTypeInfo()
  {
    if (!gERuleBPUnitToggleCapsTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::ERuleBPUnitToggleCapsTypeInfo>(gERuleBPUnitToggleCapsTypeInfoStorage);
    gERuleBPUnitToggleCapsTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00520190 (FUN_00520190)
   *
   * What it does:
   * Unlinks `ERuleBPUnitToggleCaps` primitive serializer helper node and
   * restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitToggleCapsPrimitiveSerializerNodePrimary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitToggleCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x005201C0 (FUN_005201C0)
   *
   * What it does:
   * Secondary unlink entrypoint for `ERuleBPUnitToggleCaps` primitive
   * serializer helper-node cleanup; behavior matches the primary lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase*
  CleanupERuleBPUnitToggleCapsPrimitiveSerializerNodeSecondary() noexcept
  {
    return UnlinkSerializerNode(gERuleBPUnitToggleCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x00BF3260 (FUN_00BF3260)
   *
   * What it does:
   * Unlinks the recovered `ERuleBPUnitToggleCaps` primitive serializer helper
   * node.
   */
  void cleanup_ERuleBPUnitToggleCapsPrimitiveSerializer()
  {
    (void)CleanupERuleBPUnitToggleCapsPrimitiveSerializerNodePrimary();
  }

  /**
   * Address: 0x00BF3680 (FUN_00BF3680)
   *
   * What it does:
   * Tears down the recovered `UnitWeaponRangeCategoryTypeInfo` descriptor at
   * process exit.
   */
  void cleanup_UnitWeaponRangeCategoryTypeInfo()
  {
    if (!gUnitWeaponRangeCategoryTypeInfoConstructed) {
      return;
    }

    DestroyEnumTypeInfo<moho::UnitWeaponRangeCategoryTypeInfo>(gUnitWeaponRangeCategoryTypeInfoStorage);
    gUnitWeaponRangeCategoryTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00523AB0 (FUN_00523AB0)
   *
   * What it does:
   * Reads one `int` enum lane from archive and stores it into
   * `ERuleBPUnitMovementType`.
   */
  void Deserialize_ERuleBPUnitMovementType(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::ERuleBPUnitMovementType>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00523AD0 (FUN_00523AD0)
   *
   * What it does:
   * Writes one `ERuleBPUnitMovementType` enum lane as an `int` to archive.
   */
  void Serialize_ERuleBPUnitMovementType(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::ERuleBPUnitMovementType>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00523B20 (FUN_00523B20)
   *
   * What it does:
   * Reads one `int` enum lane from archive and stores it into
   * `ERuleBPUnitCommandCaps`.
   */
  void Deserialize_ERuleBPUnitCommandCaps(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::ERuleBPUnitCommandCaps>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00523B40 (FUN_00523B40)
   *
   * What it does:
   * Writes one `ERuleBPUnitCommandCaps` enum lane as an `int` to archive.
   */
  void Serialize_ERuleBPUnitCommandCaps(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::ERuleBPUnitCommandCaps>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00523B90 (FUN_00523B90)
   *
   * What it does:
   * Reads one `int` enum lane from archive and stores it into
   * `ERuleBPUnitToggleCaps`.
   */
  void Deserialize_ERuleBPUnitToggleCaps(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::ERuleBPUnitToggleCaps>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00523BB0 (FUN_00523BB0)
   *
   * What it does:
   * Writes one `ERuleBPUnitToggleCaps` enum lane as an `int` to archive.
   */
  void Serialize_ERuleBPUnitToggleCaps(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::ERuleBPUnitToggleCaps>(archive, objectPtr, version, ownerRef);
  }

  template <typename TEnum>
  void EnumPrimitiveSerializer<TEnum>::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = gpg::LookupRType(typeid(TEnum));
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005201F0 (FUN_005201F0, construct_ERuleBPUnitBuildRestrictionTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitBuildRestriction` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitBuildRestrictionTypeInfo()
  {
    return construct_ERuleBPUnitBuildRestrictionTypeInfoImpl();
  }

  /**
   * Address: 0x00520280 (FUN_00520280, scalar deleting thunk)
   */
  ERuleBPUnitBuildRestrictionTypeInfo::~ERuleBPUnitBuildRestrictionTypeInfo() = default;

  /**
   * Address: 0x00520270 (FUN_00520270)
   */
  const char* ERuleBPUnitBuildRestrictionTypeInfo::GetName() const
  {
    return "ERuleBPUnitBuildRestriction";
  }

  /**
   * Address: 0x00520250 (FUN_00520250)
   */
  void ERuleBPUnitBuildRestrictionTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitBuildRestriction);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005202B0 (FUN_005202B0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitBuildRestriction` token/value table.
   */
  void ERuleBPUnitBuildRestrictionTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUBR_None", 0);
    AddEnumEntry(typeInfo, "RULEUBR_Bridge", 1);
    AddEnumEntry(typeInfo, "RULEUBR_OnMassDeposit", 2);
    AddEnumEntry(typeInfo, "RULEUBR_OnHydrocarbonDeposit", 3);
  }

  /**
   * Address: 0x00520310 (FUN_00520310, construct_ERuleBPUnitWeaponBallisticArcTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitWeaponBallisticArc` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    return construct_ERuleBPUnitWeaponBallisticArcTypeInfoImpl();
  }

  /**
   * Address: 0x005203A0 (FUN_005203A0, scalar deleting thunk)
   */
  ERuleBPUnitWeaponBallisticArcTypeInfo::~ERuleBPUnitWeaponBallisticArcTypeInfo() = default;

  /**
   * Address: 0x00520390 (FUN_00520390)
   */
  const char* ERuleBPUnitWeaponBallisticArcTypeInfo::GetName() const
  {
    return "ERuleBPUnitWeaponBallisticArc";
  }

  /**
   * Address: 0x00520370 (FUN_00520370)
   */
  void ERuleBPUnitWeaponBallisticArcTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitWeaponBallisticArc);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005203D0 (FUN_005203D0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitWeaponBallisticArc` token/value
   * table.
   */
  void ERuleBPUnitWeaponBallisticArcTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUBA_None", 0);
    AddEnumEntry(typeInfo, "RULEUBA_LowArc", 1);
    AddEnumEntry(typeInfo, "RULEUBA_HighArc", 2);
  }

  /**
   * Address: 0x00520420 (FUN_00520420, construct_ERuleBPUnitWeaponTargetTypeTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitWeaponTargetType` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    return construct_ERuleBPUnitWeaponTargetTypeTypeInfoImpl();
  }

  /**
   * Address: 0x005204B0 (FUN_005204B0, scalar deleting thunk)
   */
  ERuleBPUnitWeaponTargetTypeTypeInfo::~ERuleBPUnitWeaponTargetTypeTypeInfo() = default;

  /**
   * Address: 0x005204A0 (FUN_005204A0)
   */
  const char* ERuleBPUnitWeaponTargetTypeTypeInfo::GetName() const
  {
    return "ERuleBPUnitWeaponTargetType";
  }

  /**
   * Address: 0x00520480 (FUN_00520480)
   */
  void ERuleBPUnitWeaponTargetTypeTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitWeaponTargetType);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005204E0 (FUN_005204E0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitWeaponTargetType` token/value table.
   */
  void ERuleBPUnitWeaponTargetTypeTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEWTT_Unit", 0);
    AddEnumEntry(typeInfo, "RULEWTT_Projectile", 1);
    AddEnumEntry(typeInfo, "RULEWTT_Prop", 2);
  }

  /**
   * Address: 0x0051FA80 (FUN_0051FA80, construct_ERuleBPUnitMovementTypeTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitMovementType` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitMovementTypeTypeInfo()
  {
    return construct_ERuleBPUnitMovementTypeTypeInfoImpl();
  }

  /**
   * Address: 0x0051FB10 (FUN_0051FB10, scalar deleting thunk)
   */
  ERuleBPUnitMovementTypeTypeInfo::~ERuleBPUnitMovementTypeTypeInfo() = default;

  /**
   * Address: 0x0051FB00 (FUN_0051FB00)
   */
  const char* ERuleBPUnitMovementTypeTypeInfo::GetName() const
  {
    return "ERuleBPUnitMovementType";
  }

  /**
   * Address: 0x0051FAE0 (FUN_0051FAE0)
   */
  void ERuleBPUnitMovementTypeTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitMovementType);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x0051FB40 (FUN_0051FB40)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitMovementType` token/value table.
   */
  void ERuleBPUnitMovementTypeTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUMT_None", 0);
    AddEnumEntry(typeInfo, "RULEUMT_Land", 1);
    AddEnumEntry(typeInfo, "RULEUMT_Air", 2);
    AddEnumEntry(typeInfo, "RULEUMT_Water", 3);
    AddEnumEntry(typeInfo, "RULEUMT_Biped", 4);
    AddEnumEntry(typeInfo, "RULEUMT_SurfacingSub", 5);
    AddEnumEntry(typeInfo, "RULEUMT_Amphibious", 6);
    AddEnumEntry(typeInfo, "RULEUMT_Hover", 7);
    AddEnumEntry(typeInfo, "RULEUMT_AmphibiousFloating", 8);
    AddEnumEntry(typeInfo, "RULEUMT_Special", 9);
  }

  /**
   * Address: 0x0051FC80 (FUN_0051FC80, construct_ERuleBPUnitCommandCapsTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitCommandCaps` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitCommandCapsTypeInfo()
  {
    return construct_ERuleBPUnitCommandCapsTypeInfoImpl();
  }

  /**
   * Address: 0x0051FD10 (FUN_0051FD10, scalar deleting thunk)
   */
  ERuleBPUnitCommandCapsTypeInfo::~ERuleBPUnitCommandCapsTypeInfo() = default;

  /**
   * Address: 0x0051FD00 (FUN_0051FD00)
   */
  const char* ERuleBPUnitCommandCapsTypeInfo::GetName() const
  {
    return "ERuleBPUnitCommandCaps";
  }

  /**
   * Address: 0x0051FCE0 (FUN_0051FCE0)
   */
  void ERuleBPUnitCommandCapsTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitCommandCaps);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x0051FD40 (FUN_0051FD40)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitCommandCaps` token/value table.
   */
  void ERuleBPUnitCommandCapsTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUCC_Move", 1);
    AddEnumEntry(typeInfo, "RULEUCC_Stop", 2);
    AddEnumEntry(typeInfo, "RULEUCC_Attack", 4);
    AddEnumEntry(typeInfo, "RULEUCC_Guard", 8);
    AddEnumEntry(typeInfo, "RULEUCC_Patrol", 16);
    AddEnumEntry(typeInfo, "RULEUCC_RetaliateToggle", 32);
    AddEnumEntry(typeInfo, "RULEUCC_Repair", 64);
    AddEnumEntry(typeInfo, "RULEUCC_Capture", 128);
    AddEnumEntry(typeInfo, "RULEUCC_Transport", 256);
    AddEnumEntry(typeInfo, "RULEUCC_CallTransport", 512);
    AddEnumEntry(typeInfo, "RULEUCC_Nuke", 1024);
    AddEnumEntry(typeInfo, "RULEUCC_Tactical", 2048);
    AddEnumEntry(typeInfo, "RULEUCC_Teleport", 4096);
    AddEnumEntry(typeInfo, "RULEUCC_Ferry", 0x2000);
    AddEnumEntry(typeInfo, "RULEUCC_SiloBuildTactical", 0x4000);
    AddEnumEntry(typeInfo, "RULEUCC_SiloBuildNuke", 0x8000);
    AddEnumEntry(typeInfo, "RULEUCC_Sacrifice", 0x10000);
    AddEnumEntry(typeInfo, "RULEUCC_Pause", 0x20000);
    AddEnumEntry(typeInfo, "RULEUCC_Overcharge", 0x40000);
    AddEnumEntry(typeInfo, "RULEUCC_Dive", 0x80000);
    AddEnumEntry(typeInfo, "RULEUCC_Reclaim", 0x100000);
    AddEnumEntry(typeInfo, "RULEUCC_SpecialAction", 0x200000);
    AddEnumEntry(typeInfo, "RULEUCC_Dock", 0x400000);
    AddEnumEntry(typeInfo, "RULEUCC_Script", 0x800000);
    AddEnumEntry(typeInfo, "RULEUCC_Invalid", 0x1000000);
  }

  /**
   * Address: 0x00520000 (FUN_00520000, construct_ERuleBPUnitToggleCapsTypeInfo)
   *
   * What it does:
   * Constructs the `ERuleBPUnitToggleCaps` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_ERuleBPUnitToggleCapsTypeInfo()
  {
    return construct_ERuleBPUnitToggleCapsTypeInfoImpl();
  }

  /**
   * Address: 0x00520090 (FUN_00520090, scalar deleting thunk)
   */
  ERuleBPUnitToggleCapsTypeInfo::~ERuleBPUnitToggleCapsTypeInfo() = default;

  /**
   * Address: 0x00520080 (FUN_00520080)
   */
  const char* ERuleBPUnitToggleCapsTypeInfo::GetName() const
  {
    return "ERuleBPUnitToggleCaps";
  }

  /**
   * Address: 0x00520060 (FUN_00520060)
   */
  void ERuleBPUnitToggleCapsTypeInfo::Init()
  {
    size_ = sizeof(ERuleBPUnitToggleCaps);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x005200C0 (FUN_005200C0)
   *
   * What it does:
   * Registers the reflected `ERuleBPUnitToggleCaps` token/value table.
   */
  void ERuleBPUnitToggleCapsTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "RULEUTC_ShieldToggle", 1);
    AddEnumEntry(typeInfo, "RULEUTC_WeaponToggle", 2);
    AddEnumEntry(typeInfo, "RULEUTC_JammingToggle", 4);
    AddEnumEntry(typeInfo, "RULEUTC_IntelToggle", 8);
    AddEnumEntry(typeInfo, "RULEUTC_ProductionToggle", 16);
    AddEnumEntry(typeInfo, "RULEUTC_StealthToggle", 32);
    AddEnumEntry(typeInfo, "RULEUTC_GenericToggle", 64);
    AddEnumEntry(typeInfo, "RULEUTC_SpecialToggle", 128);
    AddEnumEntry(typeInfo, "RULEUTC_CloakToggle", 256);
  }

  /**
   * Address: 0x005220C0 (FUN_005220C0, construct_UnitWeaponRangeCategoryTypeInfo)
   *
   * What it does:
   * Constructs the `UnitWeaponRangeCategory` enum type descriptor and
   * preregisters RTTI.
   */
  gpg::REnumType* construct_UnitWeaponRangeCategoryTypeInfo()
  {
    return construct_UnitWeaponRangeCategoryTypeInfoImpl();
  }

  /**
   * Address: 0x00522150 (FUN_00522150, scalar deleting thunk)
   */
  UnitWeaponRangeCategoryTypeInfo::~UnitWeaponRangeCategoryTypeInfo() = default;

  /**
   * Address: 0x00522140 (FUN_00522140)
   */
  const char* UnitWeaponRangeCategoryTypeInfo::GetName() const
  {
    return "UnitWeaponRangeCategory";
  }

  /**
   * Address: 0x00522120 (FUN_00522120)
   */
  void UnitWeaponRangeCategoryTypeInfo::Init()
  {
    size_ = sizeof(UnitWeaponRangeCategory);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x00522180 (FUN_00522180)
   *
   * What it does:
   * Registers the reflected `UnitWeaponRangeCategory` token/value table.
   */
  void UnitWeaponRangeCategoryTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    AddEnumEntry(typeInfo, "UWRC_Undefined", 0);
    AddEnumEntry(typeInfo, "UWRC_DirectFire", 1);
    AddEnumEntry(typeInfo, "UWRC_IndirectFire", 2);
    AddEnumEntry(typeInfo, "UWRC_AntiAir", 3);
    AddEnumEntry(typeInfo, "UWRC_AntiNavy", 4);
    AddEnumEntry(typeInfo, "UWRC_Countermeasure", 5);
  }

  /**
   * Address: 0x00BC8A30 (FUN_00BC8A30, register_ERuleBPUnitBuildRestrictionTypeInfo)
   */
  int register_ERuleBPUnitBuildRestrictionTypeInfo()
  {
    (void)GetERuleBPUnitBuildRestrictionTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitBuildRestrictionTypeInfo);
  }

  /**
   * Address: 0x00BC8A50 (FUN_00BC8A50, register_ERuleBPUnitWeaponBallisticArcTypeInfo)
   */
  int register_ERuleBPUnitWeaponBallisticArcTypeInfo()
  {
    (void)GetERuleBPUnitWeaponBallisticArcTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitWeaponBallisticArcTypeInfo);
  }

  /**
   * Address: 0x00BC8A70 (FUN_00BC8A70, register_ERuleBPUnitWeaponTargetTypeTypeInfo)
   */
  int register_ERuleBPUnitWeaponTargetTypeTypeInfo()
  {
    (void)GetERuleBPUnitWeaponTargetTypeTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitWeaponTargetTypeTypeInfo);
  }

  /**
   * Address: 0x00BC8910 (FUN_00BC8910, register_ERuleBPUnitMovementTypeTypeInfo)
   */
  int register_ERuleBPUnitMovementTypeTypeInfo()
  {
    (void)GetERuleBPUnitMovementTypeTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitMovementTypeTypeInfo);
  }

  /**
   * Address: 0x00BC8930 (FUN_00BC8930, register_ERuleBPUnitMovementTypePrimitiveSerializer)
   */
  int register_ERuleBPUnitMovementTypePrimitiveSerializer()
  {
    (void)GetERuleBPUnitMovementTypeTypeInfo();
    InitializeSerializerNode(gERuleBPUnitMovementTypePrimitiveSerializer);
    gERuleBPUnitMovementTypePrimitiveSerializer.mDeserialize = &Deserialize_ERuleBPUnitMovementType;
    gERuleBPUnitMovementTypePrimitiveSerializer.mSerialize = &Serialize_ERuleBPUnitMovementType;
    return std::atexit(&cleanup_ERuleBPUnitMovementTypePrimitiveSerializer);
  }

  /**
   * Address: 0x00BC8970 (FUN_00BC8970, register_ERuleBPUnitCommandCapsTypeInfo)
   */
  int register_ERuleBPUnitCommandCapsTypeInfo()
  {
    (void)GetERuleBPUnitCommandCapsTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitCommandCapsTypeInfo);
  }

  /**
   * Address: 0x00BC8990 (FUN_00BC8990, register_ERuleBPUnitCommandCapsPrimitiveSerializer)
   */
  int register_ERuleBPUnitCommandCapsPrimitiveSerializer()
  {
    (void)GetERuleBPUnitCommandCapsTypeInfo();
    InitializeSerializerNode(gERuleBPUnitCommandCapsPrimitiveSerializer);
    gERuleBPUnitCommandCapsPrimitiveSerializer.mDeserialize = &Deserialize_ERuleBPUnitCommandCaps;
    gERuleBPUnitCommandCapsPrimitiveSerializer.mSerialize = &Serialize_ERuleBPUnitCommandCaps;
    return std::atexit(&cleanup_ERuleBPUnitCommandCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x00BC89D0 (FUN_00BC89D0, register_ERuleBPUnitToggleCapsTypeInfo)
   */
  int register_ERuleBPUnitToggleCapsTypeInfo()
  {
    (void)GetERuleBPUnitToggleCapsTypeInfo();
    return std::atexit(&cleanup_ERuleBPUnitToggleCapsTypeInfo);
  }

  /**
   * Address: 0x00BC89F0 (FUN_00BC89F0, register_ERuleBPUnitToggleCapsPrimitiveSerializer)
   */
  int register_ERuleBPUnitToggleCapsPrimitiveSerializer()
  {
    (void)GetERuleBPUnitToggleCapsTypeInfo();
    InitializeSerializerNode(gERuleBPUnitToggleCapsPrimitiveSerializer);
    gERuleBPUnitToggleCapsPrimitiveSerializer.mDeserialize = &Deserialize_ERuleBPUnitToggleCaps;
    gERuleBPUnitToggleCapsPrimitiveSerializer.mSerialize = &Serialize_ERuleBPUnitToggleCaps;
    return std::atexit(&cleanup_ERuleBPUnitToggleCapsPrimitiveSerializer);
  }

  /**
   * Address: 0x00BC8BD0 (FUN_00BC8BD0, register_UnitWeaponRangeCategoryTypeInfo)
   */
  int register_UnitWeaponRangeCategoryTypeInfo()
  {
    (void)GetUnitWeaponRangeCategoryTypeInfo();
    return std::atexit(&cleanup_UnitWeaponRangeCategoryTypeInfo);
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintEnumTypeInfoBootstrap
  {
    RUnitBlueprintEnumTypeInfoBootstrap()
    {
      (void)moho::register_ERuleBPUnitBuildRestrictionTypeInfo();
      (void)moho::register_ERuleBPUnitWeaponBallisticArcTypeInfo();
      (void)moho::register_ERuleBPUnitWeaponTargetTypeTypeInfo();
      (void)moho::register_ERuleBPUnitMovementTypeTypeInfo();
      (void)moho::register_ERuleBPUnitMovementTypePrimitiveSerializer();
      (void)moho::register_ERuleBPUnitCommandCapsTypeInfo();
      (void)moho::register_ERuleBPUnitCommandCapsPrimitiveSerializer();
      (void)moho::register_ERuleBPUnitToggleCapsTypeInfo();
      (void)moho::register_ERuleBPUnitToggleCapsPrimitiveSerializer();
      (void)moho::register_UnitWeaponRangeCategoryTypeInfo();
    }
  };

  RUnitBlueprintEnumTypeInfoBootstrap gRUnitBlueprintEnumTypeInfoBootstrap;
} // namespace
