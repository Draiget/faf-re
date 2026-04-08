#include "moho/unit/core/EIntelTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EIntelTypeInfo) unsigned char gEIntelTypeInfoStorage[sizeof(moho::EIntelTypeInfo)]{};
  bool gEIntelTypeInfoConstructed = false;
  bool gEIntelTypeInfoPreregistered = false;

  alignas(moho::EIntelPrimitiveSerializer)
    unsigned char gEIntelPrimitiveSerializerStorage[sizeof(moho::EIntelPrimitiveSerializer)]{};
  bool gEIntelPrimitiveSerializerConstructed = false;

  /**
   * Address: 0x0050A3A0 (FUN_0050A3A0, startup preregister lane)
   *
   * What it does:
   * Constructs one static `EIntelTypeInfo` instance and preregisters RTTI
   * ownership for `EIntel`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EIntelTypeInfo()
  {
    if (!gEIntelTypeInfoConstructed) {
      new (gEIntelTypeInfoStorage) moho::EIntelTypeInfo();
      gEIntelTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::EIntelTypeInfo*>(gEIntelTypeInfoStorage);
    if (!gEIntelTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EIntel), typeInfo);
      gEIntelTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  [[nodiscard]] moho::EIntelTypeInfo* AcquireEIntelTypeInfoStorage() noexcept
  {
    return reinterpret_cast<moho::EIntelTypeInfo*>(gEIntelTypeInfoStorage);
  }

  [[nodiscard]] moho::EIntelPrimitiveSerializer* AcquireEIntelPrimitiveSerializer()
  {
    if (!gEIntelPrimitiveSerializerConstructed) {
      new (gEIntelPrimitiveSerializerStorage) moho::EIntelPrimitiveSerializer();
      gEIntelPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::EIntelPrimitiveSerializer*>(gEIntelPrimitiveSerializerStorage);
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
   * Address: 0x00BF2010 (FUN_00BF2010, cleanup_EIntelTypeInfo)
   */
  void cleanup_EIntelTypeInfo()
  {
    if (!gEIntelTypeInfoConstructed) {
      return;
    }

    AcquireEIntelTypeInfoStorage()->~EIntelTypeInfo();
    gEIntelTypeInfoConstructed = false;
    gEIntelTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BF2020 (FUN_00BF2020, cleanup_EIntelPrimitiveSerializer)
   */
  void cleanup_EIntelPrimitiveSerializer()
  {
    if (!gEIntelPrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireEIntelPrimitiveSerializer());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0050A430 (FUN_0050A430, Moho::EIntelTypeInfo::dtr)
   */
  EIntelTypeInfo::~EIntelTypeInfo() = default;

  /**
   * Address: 0x0050A420 (FUN_0050A420, Moho::EIntelTypeInfo::GetName)
   */
  const char* EIntelTypeInfo::GetName() const
  {
    return "EIntel";
  }

  /**
   * Address: 0x0050A400 (FUN_0050A400, Moho::EIntelTypeInfo::Init)
   */
  void EIntelTypeInfo::Init()
  {
    size_ = sizeof(EIntel);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050A460 (FUN_0050A460, Moho::EIntelTypeInfo::AddEnums)
   */
  void EIntelTypeInfo::AddEnums()
  {
    mPrefix = "INTEL_";
    AddEnum(StripPrefix("INTEL_None"), INTEL_None);
    AddEnum(StripPrefix("INTEL_Vision"), INTEL_Vision);
    AddEnum(StripPrefix("INTEL_WaterVision"), INTEL_WaterVision);
    AddEnum(StripPrefix("INTEL_Radar"), INTEL_Radar);
    AddEnum(StripPrefix("INTEL_Sonar"), INTEL_Sonar);
    AddEnum(StripPrefix("INTEL_Omni"), INTEL_Omni);
    AddEnum(StripPrefix("INTEL_RadarStealthField"), INTEL_RadarStealthField);
    AddEnum(StripPrefix("INTEL_SonarStealthField"), INTEL_SonarStealthField);
    AddEnum(StripPrefix("INTEL_CloakField"), INTEL_CloakField);
    AddEnum(StripPrefix("INTEL_Jammer"), INTEL_Jammer);
    AddEnum(StripPrefix("INTEL_Spoof"), INTEL_Spoof);
    AddEnum(StripPrefix("INTEL_Cloak"), INTEL_Cloak);
    AddEnum(StripPrefix("INTEL_RadarStealth"), INTEL_RadarStealth);
    AddEnum(StripPrefix("INTEL_SonarStealth"), INTEL_SonarStealth);
  }

  /**
   * Address: 0x0050AAE0 (FUN_0050AAE0, PrimitiveSerHelper<EIntel>::Deserialize)
   */
  void EIntelPrimitiveSerializer::Deserialize(
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
    *reinterpret_cast<EIntel*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EIntel>(value);
  }

  /**
   * Address: 0x0050AB00 (FUN_0050AB00, PrimitiveSerHelper<EIntel>::Serialize)
   */
  void EIntelPrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const EIntel*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050A8B0 (FUN_0050A8B0, gpg::PrimitiveSerHelper<Moho::EIntel,int>::Init)
   */
  void EIntelPrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EIntel));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7B90 (FUN_00BC7B90, register_EIntelTypeInfo)
   */
  int register_EIntelTypeInfo()
  {
    (void)preregister_EIntelTypeInfo();
    return std::atexit(&cleanup_EIntelTypeInfo);
  }

  /**
   * Address: 0x00BC7BB0 (FUN_00BC7BB0, register_EIntelPrimitiveSerializer)
   */
  int register_EIntelPrimitiveSerializer()
  {
    auto* const serializer = AcquireEIntelPrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &EIntelPrimitiveSerializer::Deserialize;
    serializer->mSerialize = &EIntelPrimitiveSerializer::Serialize;
    return std::atexit(&cleanup_EIntelPrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct EIntelTypeInfoBootstrap
  {
    EIntelTypeInfoBootstrap()
    {
      (void)moho::register_EIntelTypeInfo();
      (void)moho::register_EIntelPrimitiveSerializer();
    }
  };

  [[maybe_unused]] EIntelTypeInfoBootstrap gEIntelTypeInfoBootstrap;
} // namespace
