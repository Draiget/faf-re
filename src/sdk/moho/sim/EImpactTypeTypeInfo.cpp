#include "moho/sim/EImpactTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/sim/Sim.h"

namespace
{
  alignas(moho::EImpactTypeTypeInfo) unsigned char gEImpactTypeTypeInfoStorage[sizeof(moho::EImpactTypeTypeInfo)]{};
  bool gEImpactTypeTypeInfoConstructed = false;
  bool gEImpactTypeTypeInfoPreregistered = false;

  alignas(moho::EImpactTypePrimitiveSerializer)
    unsigned char gEImpactTypePrimitiveSerializerStorage[sizeof(moho::EImpactTypePrimitiveSerializer)]{};
  bool gEImpactTypePrimitiveSerializerConstructed = false;

  /**
   * Address: 0x00509F80 (FUN_00509F80, REnumType dtor thunk for EImpactType block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant2(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  [[nodiscard]] moho::EImpactTypePrimitiveSerializer* AcquireEImpactTypePrimitiveSerializer()
  {
    if (!gEImpactTypePrimitiveSerializerConstructed) {
      new (gEImpactTypePrimitiveSerializerStorage) moho::EImpactTypePrimitiveSerializer();
      gEImpactTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::EImpactTypePrimitiveSerializer*>(gEImpactTypePrimitiveSerializerStorage);
  }

  [[nodiscard]] moho::EImpactTypeTypeInfo* AcquireEImpactTypeTypeInfo()
  {
    if (!gEImpactTypeTypeInfoConstructed) {
      new (gEImpactTypeTypeInfoStorage) moho::EImpactTypeTypeInfo();
      gEImpactTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EImpactTypeTypeInfo*>(gEImpactTypeTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* ResolveEImpactType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EImpactType));
    }
    return cached;
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
   * Address: 0x00509ED0 (FUN_00509ED0, preregister_EImpactTypeTypeInfo)
   */
  [[nodiscard]] gpg::REnumType* ConstructEImpactTypeTypeInfoInternal()
  {
    auto* const typeInfo = AcquireEImpactTypeTypeInfo();
    if (!gEImpactTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EImpactType), typeInfo);
      gEImpactTypeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF1F60 (FUN_00BF1F60, cleanup_EImpactTypePrimitiveSerializer)
   */
  void cleanup_EImpactTypePrimitiveSerializer()
  {
    if (!gEImpactTypePrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireEImpactTypePrimitiveSerializer());
  }

  /**
   * Address: 0x00BF1F50 (FUN_00BF1F50, cleanup_EImpactTypeTypeInfo)
   */
  void cleanup_EImpactTypeTypeInfo()
  {
    if (!gEImpactTypeTypeInfoConstructed) {
      return;
    }

    AcquireEImpactTypeTypeInfo()->~EImpactTypeTypeInfo();
    gEImpactTypeTypeInfoConstructed = false;
    gEImpactTypeTypeInfoPreregistered = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00509ED0 (FUN_00509ED0, preregister_EImpactTypeTypeInfo)
   */
  gpg::REnumType* preregister_EImpactTypeTypeInfo()
  {
    return ConstructEImpactTypeTypeInfoInternal();
  }

  /**
   * Address: 0x0067B240 (FUN_0067B240, Moho::ENT_GetImpactType)
   */
  EImpactType ENT_GetImpactType(Sim* const sim, Entity* const entity, const Wm3::Vector3f& hitPosition)
  {
    static constexpr float kNoWaterElevation = -10000.0f;
    static constexpr std::uint32_t kShieldEntityMask = 0xF0000000u;
    static constexpr std::uint32_t kShieldEntityTag = 0x40000000u;

    const STIMap* const mapData = sim->mMapData;
    const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : kNoWaterElevation;

    if (waterElevation > hitPosition.y) {
      if (entity == nullptr) {
        return IMPACT_Underwater;
      }

      if (entity->IsUnit() != nullptr) {
        return IMPACT_UnitUnderwater;
      }

      if (entity->IsProjectile() != nullptr) {
        return IMPACT_ProjectileUnderwater;
      }

      if ((entity->id_ & kShieldEntityMask) == kShieldEntityTag) {
        return IMPACT_Shield;
      }

      return IMPACT_Underwater;
    }

    if (entity == nullptr) {
      return IMPACT_Air;
    }

    if (entity->IsUnit() != nullptr) {
      return (entity->mCurrentLayer == LAYER_Air) ? IMPACT_UnitAir : IMPACT_Unit;
    }

    if (entity->IsProjectile() != nullptr) {
      return IMPACT_Projectile;
    }

    if (entity->IsProp() != nullptr) {
      return IMPACT_Prop;
    }

    if ((entity->id_ & kShieldEntityMask) == kShieldEntityTag) {
      return IMPACT_Shield;
    }

    return IMPACT_Air;
  }

  /**
   * Address: 0x0067B320 (FUN_0067B320, Moho::ENT_GetImpactTypeString)
   */
  const char* ENT_GetImpactTypeString(const EImpactType impactType)
  {
    switch (impactType) {
      case IMPACT_Terrain:
        return "Terrain";
      case IMPACT_Water:
        return "Water";
      case IMPACT_Air:
        return "Air";
      case IMPACT_Underwater:
        return "Underwater";
      case IMPACT_Projectile:
        return "Projectile";
      case IMPACT_ProjectileUnderwater:
        return "ProjectileUnderwater";
      case IMPACT_Prop:
        return "Prop";
      case IMPACT_Shield:
        return "Shield";
      case IMPACT_Unit:
        return "Unit";
      case IMPACT_UnitAir:
        return "UnitAir";
      case IMPACT_UnitUnderwater:
        return "UnitUnderwater";
      default:
        return "Unknown";
    }
  }

  /**
   * Address: 0x00509F60 (FUN_00509F60, Moho::EImpactTypeTypeInfo::dtr)
   */
  EImpactTypeTypeInfo::~EImpactTypeTypeInfo() = default;

  /**
   * Address: 0x00509F50 (FUN_00509F50, Moho::EImpactTypeTypeInfo::GetName)
   */
  const char* EImpactTypeTypeInfo::GetName() const
  {
    return "EImpactType";
  }

  /**
   * Address: 0x00509F30 (FUN_00509F30, Moho::EImpactTypeTypeInfo::Init)
   */
  void EImpactTypeTypeInfo::Init()
  {
    size_ = sizeof(EImpactType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00509F90 (FUN_00509F90, Moho::EImpactTypeTypeInfo::AddEnums)
   */
  void EImpactTypeTypeInfo::AddEnums()
  {
    mPrefix = "IMPACT_";
    AddEnum(StripPrefix("IMPACT_Invalid"), static_cast<std::int32_t>(IMPACT_Invalid));
    AddEnum(StripPrefix("IMPACT_Terrain"), static_cast<std::int32_t>(IMPACT_Terrain));
    AddEnum(StripPrefix("IMPACT_Water"), static_cast<std::int32_t>(IMPACT_Water));
    AddEnum(StripPrefix("IMPACT_Air"), static_cast<std::int32_t>(IMPACT_Air));
    AddEnum(StripPrefix("IMPACT_Underwater"), static_cast<std::int32_t>(IMPACT_Underwater));
    AddEnum(StripPrefix("IMPACT_Projectile"), static_cast<std::int32_t>(IMPACT_Projectile));
    AddEnum(
      StripPrefix("IMPACT_ProjectileUnderwater"),
      static_cast<std::int32_t>(IMPACT_ProjectileUnderwater)
    );
    AddEnum(StripPrefix("IMPACT_Prop"), static_cast<std::int32_t>(IMPACT_Prop));
    AddEnum(StripPrefix("IMPACT_Shield"), static_cast<std::int32_t>(IMPACT_Shield));
    AddEnum(StripPrefix("IMPACT_Unit"), static_cast<std::int32_t>(IMPACT_Unit));
    AddEnum(StripPrefix("IMPACT_UnitAir"), static_cast<std::int32_t>(IMPACT_UnitAir));
    AddEnum(StripPrefix("IMPACT_UnitUnderwater"), static_cast<std::int32_t>(IMPACT_UnitUnderwater));
  }

  /**
   * Address: 0x00BC7A70 (FUN_00BC7A70, register_EImpactTypeTypeInfo)
   */
  int register_EImpactTypeTypeInfo()
  {
    (void)preregister_EImpactTypeTypeInfo();
    return std::atexit(&cleanup_EImpactTypeTypeInfo);
  }

  /**
   * Address: 0x0050A990 (FUN_0050A990, PrimitiveSerHelper<EImpactType>::Deserialize)
   */
  void EImpactTypePrimitiveSerializer::Deserialize(
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
    *reinterpret_cast<EImpactType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EImpactType>(value);
  }

  /**
   * Address: 0x0050A9B0 (FUN_0050A9B0, PrimitiveSerHelper<EImpactType>::Serialize)
   */
  void EImpactTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const EImpactType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050A6D0 (FUN_0050A6D0, gpg::PrimitiveSerHelper<Moho::EImpactType,int>::Init)
   */
  void EImpactTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveEImpactType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7A90 (FUN_00BC7A90, register_EImpactTypePrimitiveSerializer)
   */
  int register_EImpactTypePrimitiveSerializer()
  {
    auto* const serializer = AcquireEImpactTypePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &EImpactTypePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &EImpactTypePrimitiveSerializer::Serialize;

    return std::atexit(&cleanup_EImpactTypePrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct EImpactTypeTypeInfoBootstrap
  {
    EImpactTypeTypeInfoBootstrap()
    {
      (void)moho::register_EImpactTypeTypeInfo();
      (void)moho::register_EImpactTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EImpactTypeTypeInfoBootstrap gEImpactTypeTypeInfoBootstrap;
} // namespace
