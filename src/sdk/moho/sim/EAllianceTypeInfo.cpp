#include "moho/sim/EAllianceTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EAllianceTypeInfo) unsigned char gEAllianceTypeInfoStorage[sizeof(moho::EAllianceTypeInfo)]{};
  bool gEAllianceTypeInfoConstructed = false;
  bool gEAllianceTypeInfoPreregistered = false;

  alignas(moho::EAlliancePrimitiveSerializer)
    unsigned char gEAlliancePrimitiveSerializerStorage[sizeof(moho::EAlliancePrimitiveSerializer)]{};
  bool gEAlliancePrimitiveSerializerConstructed = false;

  /**
   * Address: 0x00509D60 (FUN_00509D60, EAllianceTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `EAllianceTypeInfo` instance and pre-registers RTTI
   * ownership for `EAlliance`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructEAllianceTypeInfoInternal()
  {
    if (!gEAllianceTypeInfoConstructed) {
      new (gEAllianceTypeInfoStorage) moho::EAllianceTypeInfo();
      gEAllianceTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::EAllianceTypeInfo*>(gEAllianceTypeInfoStorage);
    if (!gEAllianceTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EAlliance), typeInfo);
      gEAllianceTypeInfoPreregistered = true;
    }
    return typeInfo;
  }

  [[nodiscard]] moho::EAlliancePrimitiveSerializer* AcquireEAlliancePrimitiveSerializer()
  {
    if (!gEAlliancePrimitiveSerializerConstructed) {
      new (gEAlliancePrimitiveSerializerStorage) moho::EAlliancePrimitiveSerializer();
      gEAlliancePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::EAlliancePrimitiveSerializer*>(gEAlliancePrimitiveSerializerStorage);
  }

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
  void UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  /**
   * Address: 0x00BF1F10 (FUN_00BF1F10, cleanup_EAllianceTypeInfo)
   */
  void cleanup_EAllianceTypeInfo()
  {
    if (!gEAllianceTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::EAllianceTypeInfo*>(gEAllianceTypeInfoStorage)->~EAllianceTypeInfo();
    gEAllianceTypeInfoConstructed = false;
    gEAllianceTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BF1F20 (FUN_00BF1F20, cleanup_EAlliancePrimitiveSerializer)
   */
  void cleanup_EAlliancePrimitiveSerializer()
  {
    if (!gEAlliancePrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireEAlliancePrimitiveSerializer());
  }

  /**
   * Address: 0x00509E10 (FUN_00509E10, REnumType dtor thunk for EAlliance block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant1(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00509D60 (FUN_00509D60, preregister_EAllianceTypeInfo)
   */
  gpg::REnumType* preregister_EAllianceTypeInfo()
  {
    return ConstructEAllianceTypeInfoInternal();
  }

  /**
   * Address: 0x00509DF0 (FUN_00509DF0, Moho::EAllianceTypeInfo::dtr)
   */
  EAllianceTypeInfo::~EAllianceTypeInfo() = default;

  /**
   * Address: 0x00509DE0 (FUN_00509DE0, Moho::EAllianceTypeInfo::GetName)
   */
  const char* EAllianceTypeInfo::GetName() const
  {
    return "EAlliance";
  }

  /**
   * Address: 0x00509DC0 (FUN_00509DC0, Moho::EAllianceTypeInfo::Init)
   */
  void EAllianceTypeInfo::Init()
  {
    size_ = sizeof(EAlliance);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00509E20 (FUN_00509E20, Moho::EAllianceTypeInfo::AddEnums)
   */
  void EAllianceTypeInfo::AddEnums()
  {
    mPrefix = "ALLIANCE_";
    AddEnum(StripPrefix("ALLIANCE_Neutral"), static_cast<std::int32_t>(ALLIANCE_Neutral));
    AddEnum(StripPrefix("ALLIANCE_Ally"), static_cast<std::int32_t>(ALLIANCE_Ally));
    AddEnum(StripPrefix("ALLIANCE_Enemy"), static_cast<std::int32_t>(ALLIANCE_Enemy));
  }

  /**
   * Address: 0x0050A920 (FUN_0050A920, PrimitiveSerHelper<EAlliance>::Deserialize)
   */
  void EAlliancePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EAlliance*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAlliance>(value);
  }

  /**
   * Address: 0x0050A940 (FUN_0050A940, PrimitiveSerHelper<EAlliance>::Serialize)
   */
  void EAlliancePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const EAlliance*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050A630 (FUN_0050A630, gpg::PrimitiveSerHelper<Moho::EAlliance,int>::Init)
   */
  void EAlliancePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(moho::EAlliance));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7A10 (FUN_00BC7A10, register_EAllianceTypeInfo)
   */
  int register_EAllianceTypeInfo()
  {
    (void)preregister_EAllianceTypeInfo();
    return std::atexit(&cleanup_EAllianceTypeInfo);
  }

  /**
   * Address: 0x00BC7A30 (FUN_00BC7A30, register_EAlliancePrimitiveSerializer)
   */
  int register_EAlliancePrimitiveSerializer()
  {
    auto* const serializer = AcquireEAlliancePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &EAlliancePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &EAlliancePrimitiveSerializer::Serialize;
    return std::atexit(&cleanup_EAlliancePrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct EAllianceTypeInfoBootstrap
  {
    EAllianceTypeInfoBootstrap()
    {
      (void)moho::register_EAllianceTypeInfo();
      (void)moho::register_EAlliancePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EAllianceTypeInfoBootstrap gEAllianceTypeInfoBootstrap;
} // namespace
