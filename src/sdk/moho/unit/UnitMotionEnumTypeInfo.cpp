#include "moho/unit/UnitMotionEnumTypeInfo.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/ai/EAirCombatState.h"
#include "moho/ai/EAirCombatStateTypeInfo.h"
#include "moho/unit/CUnitMotion.h"

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
    offsetof(EnumPrimitiveSerializer<moho::EUnitMotionState>, mHelperNext) == 0x04,
    "EnumPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::EUnitMotionState>, mHelperPrev) == 0x08,
    "EnumPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::EUnitMotionState>, mDeserialize) == 0x0C,
    "EnumPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EnumPrimitiveSerializer<moho::EUnitMotionState>, mSerialize) == 0x10,
    "EnumPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(EnumPrimitiveSerializer<moho::EUnitMotionState>) == 0x14,
    "EnumPrimitiveSerializer size must be 0x14"
  );

  alignas(moho::EUnitMotionStateTypeInfo)
    unsigned char gEUnitMotionStateTypeInfoStorage[sizeof(moho::EUnitMotionStateTypeInfo)];
  alignas(moho::EUnitMotionCarrierEventTypeInfo)
    unsigned char gEUnitMotionCarrierEventTypeInfoStorage[sizeof(moho::EUnitMotionCarrierEventTypeInfo)];
  alignas(moho::EUnitMotionHorzEventTypeInfo)
    unsigned char gEUnitMotionHorzEventTypeInfoStorage[sizeof(moho::EUnitMotionHorzEventTypeInfo)];
  alignas(moho::EUnitMotionVertEventTypeInfo)
    unsigned char gEUnitMotionVertEventTypeInfoStorage[sizeof(moho::EUnitMotionVertEventTypeInfo)];
  alignas(moho::EUnitMotionTurnEventTypeInfo)
    unsigned char gEUnitMotionTurnEventTypeInfoStorage[sizeof(moho::EUnitMotionTurnEventTypeInfo)];
  alignas(moho::EAirCombatStateTypeInfo)
    unsigned char gEAirCombatStateTypeInfoStorage[sizeof(moho::EAirCombatStateTypeInfo)];

  EnumPrimitiveSerializer<moho::EUnitMotionState> gEUnitMotionStatePrimitiveSerializer;
  EnumPrimitiveSerializer<moho::EUnitMotionCarrierEvent> gEUnitMotionCarrierEventPrimitiveSerializer;
  EnumPrimitiveSerializer<moho::EUnitMotionHorzEvent> gEUnitMotionHorzEventPrimitiveSerializer;
  EnumPrimitiveSerializer<moho::EUnitMotionVertEvent> gEUnitMotionVertEventPrimitiveSerializer;
  EnumPrimitiveSerializer<moho::EUnitMotionTurnEvent> gEUnitMotionTurnEventPrimitiveSerializer;
  EnumPrimitiveSerializer<moho::EAirCombatState> gEAirCombatStatePrimitiveSerializer;

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
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  template <typename TTypeInfo>
  [[nodiscard]] TTypeInfo& AsTypeInfo(void* const storage) noexcept
  {
    return *reinterpret_cast<TTypeInfo*>(storage);
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
    AsTypeInfo<TTypeInfo>(storage).~TTypeInfo();
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

  /**
   * Address: 0x006B7130 (FUN_006B7130, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant1(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B7260 (FUN_006B7260, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant2(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B7390 (FUN_006B7390, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant3(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B74C0 (FUN_006B74C0, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant4(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B75F0 (FUN_006B75F0, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant5(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B7720 (FUN_006B7720, REnumType deleting-thunk lane)
   */
  void thunk_REnumTypeDestructorVariant6(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  /**
   * Address: 0x006B7140 (FUN_006B7140, nullsub_1838)
   */
  void no_opVariant1() {}

  /**
   * Address: 0x006B7270 (FUN_006B7270, nullsub_1839)
   */
  void no_opVariant2() {}

  /**
   * Address: 0x006B73A0 (FUN_006B73A0, nullsub_1840)
   */
  void no_opVariant3() {}

  /**
   * Address: 0x006B74D0 (FUN_006B74D0, nullsub_1841)
   */
  void no_opVariant4() {}

  /**
   * Address: 0x006B7600 (FUN_006B7600, nullsub_1842)
   */
  void no_opVariant5() {}

  /**
   * Address: 0x006B7730 (FUN_006B7730, nullsub_1843)
   */
  void no_opVariant6() {}

  /**
   * Address: 0x006BA8E0 (FUN_006BA8E0)
   */
  void Deserialize_EUnitMotionState(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef)
  {
    DeserializeEnumIntLane<moho::EUnitMotionState>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BA900 (FUN_006BA900)
   */
  void Serialize_EUnitMotionState(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef)
  {
    SerializeEnumIntLane<moho::EUnitMotionState>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BA950 (FUN_006BA950)
   */
  void Deserialize_EUnitMotionCarrierEvent(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::EUnitMotionCarrierEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BA970 (FUN_006BA970)
   */
  void Serialize_EUnitMotionCarrierEvent(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::EUnitMotionCarrierEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BA9C0 (FUN_006BA9C0)
   */
  void Deserialize_EUnitMotionHorzEvent(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::EUnitMotionHorzEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BA9E0 (FUN_006BA9E0)
   */
  void Serialize_EUnitMotionHorzEvent(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::EUnitMotionHorzEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAA30 (FUN_006BAA30)
   */
  void Deserialize_EUnitMotionVertEvent(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::EUnitMotionVertEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAA50 (FUN_006BAA50)
   */
  void Serialize_EUnitMotionVertEvent(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::EUnitMotionVertEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAAA0 (FUN_006BAAA0)
   */
  void Deserialize_EUnitMotionTurnEvent(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    DeserializeEnumIntLane<moho::EUnitMotionTurnEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAAC0 (FUN_006BAAC0)
   */
  void Serialize_EUnitMotionTurnEvent(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SerializeEnumIntLane<moho::EUnitMotionTurnEvent>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAB10 (FUN_006BAB10)
   */
  void Deserialize_EAirCombatState(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef)
  {
    DeserializeEnumIntLane<moho::EAirCombatState>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006BAB30 (FUN_006BAB30)
   */
  void Serialize_EAirCombatState(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef* const ownerRef)
  {
    SerializeEnumIntLane<moho::EAirCombatState>(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x006B7150 (FUN_006B7150)
   */
  gpg::SerHelperBase* unlink_EUnitMotionStatePrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEUnitMotionStatePrimitiveSerializer);
  }

  /**
   * Address: 0x006B7180 (FUN_006B7180)
   */
  gpg::SerHelperBase* unlink_EUnitMotionStatePrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEUnitMotionStatePrimitiveSerializer);
  }

  /**
   * Address: 0x006B7280 (FUN_006B7280)
   */
  gpg::SerHelperBase* unlink_EUnitMotionCarrierEventPrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEUnitMotionCarrierEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B72B0 (FUN_006B72B0)
   */
  gpg::SerHelperBase* unlink_EUnitMotionCarrierEventPrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEUnitMotionCarrierEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B73B0 (FUN_006B73B0)
   */
  gpg::SerHelperBase* unlink_EUnitMotionHorzEventPrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEUnitMotionHorzEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B73E0 (FUN_006B73E0)
   */
  gpg::SerHelperBase* unlink_EUnitMotionHorzEventPrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEUnitMotionHorzEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B74E0 (FUN_006B74E0)
   */
  gpg::SerHelperBase* unlink_EUnitMotionVertEventPrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEUnitMotionVertEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B7510 (FUN_006B7510)
   */
  gpg::SerHelperBase* unlink_EUnitMotionVertEventPrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEUnitMotionVertEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B7610 (FUN_006B7610)
   */
  gpg::SerHelperBase* unlink_EUnitMotionTurnEventPrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEUnitMotionTurnEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B7640 (FUN_006B7640)
   */
  gpg::SerHelperBase* unlink_EUnitMotionTurnEventPrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEUnitMotionTurnEventPrimitiveSerializer);
  }

  /**
   * Address: 0x006B7740 (FUN_006B7740)
   */
  gpg::SerHelperBase* unlink_EAirCombatStatePrimitiveSerializerVariant1()
  {
    return UnlinkSerializerNode(gEAirCombatStatePrimitiveSerializer);
  }

  /**
   * Address: 0x006B7770 (FUN_006B7770)
   */
  gpg::SerHelperBase* unlink_EAirCombatStatePrimitiveSerializerVariant2()
  {
    return UnlinkSerializerNode(gEAirCombatStatePrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDE90 (FUN_00BFDE90)
   */
  void cleanup_EUnitMotionStateTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EUnitMotionStateTypeInfo>(gEUnitMotionStateTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDEA0 (FUN_00BFDEA0)
   */
  gpg::SerHelperBase* cleanup_EUnitMotionStatePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEUnitMotionStatePrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDED0 (FUN_00BFDED0)
   */
  void cleanup_EUnitMotionCarrierEventTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EUnitMotionCarrierEventTypeInfo>(gEUnitMotionCarrierEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDEE0 (FUN_00BFDEE0)
   */
  gpg::SerHelperBase* cleanup_EUnitMotionCarrierEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEUnitMotionCarrierEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDF10 (FUN_00BFDF10)
   */
  void cleanup_EUnitMotionHorzEventTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EUnitMotionHorzEventTypeInfo>(gEUnitMotionHorzEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDF20 (FUN_00BFDF20)
   */
  gpg::SerHelperBase* cleanup_EUnitMotionHorzEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEUnitMotionHorzEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDF50 (FUN_00BFDF50)
   */
  void cleanup_EUnitMotionVertEventTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EUnitMotionVertEventTypeInfo>(gEUnitMotionVertEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDF60 (FUN_00BFDF60)
   */
  gpg::SerHelperBase* cleanup_EUnitMotionVertEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEUnitMotionVertEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDF90 (FUN_00BFDF90)
   */
  void cleanup_EUnitMotionTurnEventTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EUnitMotionTurnEventTypeInfo>(gEUnitMotionTurnEventTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDFA0 (FUN_00BFDFA0)
   */
  gpg::SerHelperBase* cleanup_EUnitMotionTurnEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEUnitMotionTurnEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BFDFD0 (FUN_00BFDFD0)
   */
  void cleanup_EAirCombatStateTypeInfo()
  {
    DestroyEnumTypeInfo<moho::EAirCombatStateTypeInfo>(gEAirCombatStateTypeInfoStorage);
  }

  /**
   * Address: 0x00BFDFE0 (FUN_00BFDFE0)
   */
  gpg::SerHelperBase* cleanup_EAirCombatStatePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEAirCombatStatePrimitiveSerializer);
  }

  template <typename TEnum>
  void EnumPrimitiveSerializer<TEnum>::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = gpg::LookupRType(typeid(TEnum));
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006B7110 (FUN_006B7110, scalar deleting thunk)
   */
  EUnitMotionStateTypeInfo::~EUnitMotionStateTypeInfo() = default;

  /**
   * Address: 0x006B7100 (FUN_006B7100)
   */
  const char* EUnitMotionStateTypeInfo::GetName() const
  {
    return "EUnitMotionState";
  }

  /**
   * Address: 0x006B70E0 (FUN_006B70E0)
   */
  void EUnitMotionStateTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionState);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7240 (FUN_006B7240, scalar deleting thunk)
   */
  EUnitMotionCarrierEventTypeInfo::~EUnitMotionCarrierEventTypeInfo() = default;

  /**
   * Address: 0x006B7230 (FUN_006B7230)
   */
  const char* EUnitMotionCarrierEventTypeInfo::GetName() const
  {
    return "EUnitMotionCarrierEvent";
  }

  /**
   * Address: 0x006B7210 (FUN_006B7210)
   */
  void EUnitMotionCarrierEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionCarrierEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7370 (FUN_006B7370, scalar deleting thunk)
   */
  EUnitMotionHorzEventTypeInfo::~EUnitMotionHorzEventTypeInfo() = default;

  /**
   * Address: 0x006B7360 (FUN_006B7360)
   */
  const char* EUnitMotionHorzEventTypeInfo::GetName() const
  {
    return "EUnitMotionHorzEvent";
  }

  /**
   * Address: 0x006B7340 (FUN_006B7340)
   */
  void EUnitMotionHorzEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionHorzEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B74A0 (FUN_006B74A0, scalar deleting thunk)
   */
  EUnitMotionVertEventTypeInfo::~EUnitMotionVertEventTypeInfo() = default;

  /**
   * Address: 0x006B7490 (FUN_006B7490)
   */
  const char* EUnitMotionVertEventTypeInfo::GetName() const
  {
    return "EUnitMotionVertEvent";
  }

  /**
   * Address: 0x006B7470 (FUN_006B7470)
   */
  void EUnitMotionVertEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionVertEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B75D0 (FUN_006B75D0, scalar deleting thunk)
   */
  EUnitMotionTurnEventTypeInfo::~EUnitMotionTurnEventTypeInfo() = default;

  /**
   * Address: 0x006B75C0 (FUN_006B75C0)
   */
  const char* EUnitMotionTurnEventTypeInfo::GetName() const
  {
    return "EUnitMotionTurnEvent";
  }

  /**
   * Address: 0x006B75A0 (FUN_006B75A0)
   */
  void EUnitMotionTurnEventTypeInfo::Init()
  {
    size_ = sizeof(EUnitMotionTurnEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B7080 (FUN_006B7080, construct_EUnitMotionStateTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionStateTypeInfo()
  {
    return ConstructEnumTypeInfo<EUnitMotionStateTypeInfo, EUnitMotionState>(gEUnitMotionStateTypeInfoStorage);
  }

  /**
   * Address: 0x006B71B0 (FUN_006B71B0, construct_EUnitMotionCarrierEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionCarrierEventTypeInfo()
  {
    return ConstructEnumTypeInfo<EUnitMotionCarrierEventTypeInfo, EUnitMotionCarrierEvent>(
      gEUnitMotionCarrierEventTypeInfoStorage
    );
  }

  /**
   * Address: 0x006B72E0 (FUN_006B72E0, construct_EUnitMotionHorzEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionHorzEventTypeInfo()
  {
    return ConstructEnumTypeInfo<EUnitMotionHorzEventTypeInfo, EUnitMotionHorzEvent>(gEUnitMotionHorzEventTypeInfoStorage);
  }

  /**
   * Address: 0x006B7410 (FUN_006B7410, construct_EUnitMotionVertEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionVertEventTypeInfo()
  {
    return ConstructEnumTypeInfo<EUnitMotionVertEventTypeInfo, EUnitMotionVertEvent>(gEUnitMotionVertEventTypeInfoStorage);
  }

  /**
   * Address: 0x006B7540 (FUN_006B7540, construct_EUnitMotionTurnEventTypeInfo)
   */
  gpg::REnumType* construct_EUnitMotionTurnEventTypeInfo()
  {
    return ConstructEnumTypeInfo<EUnitMotionTurnEventTypeInfo, EUnitMotionTurnEvent>(gEUnitMotionTurnEventTypeInfoStorage);
  }

  /**
   * Address: 0x006B7670 (FUN_006B7670, construct_EAirCombatStateTypeInfo)
   */
  gpg::REnumType* construct_EAirCombatStateTypeInfo()
  {
    return ConstructEnumTypeInfo<EAirCombatStateTypeInfo, EAirCombatState>(gEAirCombatStateTypeInfoStorage);
  }

  /**
   * Address: 0x00BD6FE0 (FUN_00BD6FE0, register_EUnitMotionStateTypeInfo)
   */
  int register_EUnitMotionStateTypeInfo()
  {
    (void)construct_EUnitMotionStateTypeInfo();
    return std::atexit(&cleanup_EUnitMotionStateTypeInfo);
  }

  /**
   * Address: 0x00BD7000 (FUN_00BD7000, register_EUnitMotionStatePrimitiveSerializer)
   */
  int register_EUnitMotionStatePrimitiveSerializer()
  {
    InitializeSerializerNode(gEUnitMotionStatePrimitiveSerializer);
    gEUnitMotionStatePrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EUnitMotionState);
    gEUnitMotionStatePrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EUnitMotionState);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EUnitMotionStatePrimitiveSerializer));
  }

  /**
   * Address: 0x00BD7040 (FUN_00BD7040, register_EUnitMotionCarrierEventTypeInfo)
   */
  int register_EUnitMotionCarrierEventTypeInfo()
  {
    (void)construct_EUnitMotionCarrierEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionCarrierEventTypeInfo);
  }

  /**
   * Address: 0x00BD7060 (FUN_00BD7060, register_EUnitMotionCarrierEventPrimitiveSerializer)
   */
  int register_EUnitMotionCarrierEventPrimitiveSerializer()
  {
    InitializeSerializerNode(gEUnitMotionCarrierEventPrimitiveSerializer);
    gEUnitMotionCarrierEventPrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EUnitMotionCarrierEvent);
    gEUnitMotionCarrierEventPrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EUnitMotionCarrierEvent);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EUnitMotionCarrierEventPrimitiveSerializer));
  }

  /**
   * Address: 0x00BD70A0 (FUN_00BD70A0, register_EUnitMotionHorzEventTypeInfo)
   */
  int register_EUnitMotionHorzEventTypeInfo()
  {
    (void)construct_EUnitMotionHorzEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionHorzEventTypeInfo);
  }

  /**
   * Address: 0x00BD70C0 (FUN_00BD70C0, register_EUnitMotionHorzEventPrimitiveSerializer)
   */
  int register_EUnitMotionHorzEventPrimitiveSerializer()
  {
    InitializeSerializerNode(gEUnitMotionHorzEventPrimitiveSerializer);
    gEUnitMotionHorzEventPrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EUnitMotionHorzEvent);
    gEUnitMotionHorzEventPrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EUnitMotionHorzEvent);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EUnitMotionHorzEventPrimitiveSerializer));
  }

  /**
   * Address: 0x00BD7100 (FUN_00BD7100, register_EUnitMotionVertEventTypeInfo)
   */
  int register_EUnitMotionVertEventTypeInfo()
  {
    (void)construct_EUnitMotionVertEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionVertEventTypeInfo);
  }

  /**
   * Address: 0x00BD7120 (FUN_00BD7120, register_EUnitMotionVertEventPrimitiveSerializer)
   */
  int register_EUnitMotionVertEventPrimitiveSerializer()
  {
    InitializeSerializerNode(gEUnitMotionVertEventPrimitiveSerializer);
    gEUnitMotionVertEventPrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EUnitMotionVertEvent);
    gEUnitMotionVertEventPrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EUnitMotionVertEvent);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EUnitMotionVertEventPrimitiveSerializer));
  }

  /**
   * Address: 0x00BD7160 (FUN_00BD7160, register_EUnitMotionTurnEventTypeInfo)
   */
  int register_EUnitMotionTurnEventTypeInfo()
  {
    (void)construct_EUnitMotionTurnEventTypeInfo();
    return std::atexit(&cleanup_EUnitMotionTurnEventTypeInfo);
  }

  /**
   * Address: 0x00BD7180 (FUN_00BD7180, register_EUnitMotionTurnEventPrimitiveSerializer)
   */
  int register_EUnitMotionTurnEventPrimitiveSerializer()
  {
    InitializeSerializerNode(gEUnitMotionTurnEventPrimitiveSerializer);
    gEUnitMotionTurnEventPrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EUnitMotionTurnEvent);
    gEUnitMotionTurnEventPrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EUnitMotionTurnEvent);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EUnitMotionTurnEventPrimitiveSerializer));
  }

  /**
   * Address: 0x00BD71C0 (FUN_00BD71C0, register_EAirCombatStateTypeInfo)
   */
  int register_EAirCombatStateTypeInfo()
  {
    (void)construct_EAirCombatStateTypeInfo();
    return std::atexit(&cleanup_EAirCombatStateTypeInfo);
  }

  /**
   * Address: 0x00BD71E0 (FUN_00BD71E0, register_EAirCombatStatePrimitiveSerializer)
   */
  int register_EAirCombatStatePrimitiveSerializer()
  {
    InitializeSerializerNode(gEAirCombatStatePrimitiveSerializer);
    gEAirCombatStatePrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_EAirCombatState);
    gEAirCombatStatePrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_EAirCombatState);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_EAirCombatStatePrimitiveSerializer));
  }
} // namespace moho

namespace
{
  struct UnitMotionEnumTypeInfoBootstrap
  {
    UnitMotionEnumTypeInfoBootstrap()
    {
      (void)moho::register_EUnitMotionStateTypeInfo();
      (void)moho::register_EUnitMotionStatePrimitiveSerializer();
      (void)moho::register_EUnitMotionCarrierEventTypeInfo();
      (void)moho::register_EUnitMotionCarrierEventPrimitiveSerializer();
      (void)moho::register_EUnitMotionHorzEventTypeInfo();
      (void)moho::register_EUnitMotionHorzEventPrimitiveSerializer();
      (void)moho::register_EUnitMotionVertEventTypeInfo();
      (void)moho::register_EUnitMotionVertEventPrimitiveSerializer();
      (void)moho::register_EUnitMotionTurnEventTypeInfo();
      (void)moho::register_EUnitMotionTurnEventPrimitiveSerializer();
      (void)moho::register_EAirCombatStateTypeInfo();
      (void)moho::register_EAirCombatStatePrimitiveSerializer();
    }
  };

  UnitMotionEnumTypeInfoBootstrap gUnitMotionEnumTypeInfoBootstrap;
} // namespace
