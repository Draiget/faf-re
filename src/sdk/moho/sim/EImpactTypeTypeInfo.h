#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  class Entity;
  class Sim;

  /**
   * Owns the reflected enum descriptor for `EImpactType`.
   */
  enum EImpactType : std::int32_t
  {
    IMPACT_Invalid = 0,
    IMPACT_Terrain = 1,
    IMPACT_Water = 2,
    IMPACT_Air = 3,
    IMPACT_Underwater = 4,
    IMPACT_Projectile = 5,
    IMPACT_ProjectileUnderwater = 6,
    IMPACT_Prop = 7,
    IMPACT_Shield = 8,
    IMPACT_Unit = 9,
    IMPACT_UnitAir = 10,
    IMPACT_UnitUnderwater = 11,
  };

  static_assert(sizeof(EImpactType) == 0x04, "EImpactType size must be 0x04");

  /**
   * Address: 0x0067B240 (FUN_0067B240, Moho::ENT_GetImpactType)
   *
   * What it does:
   * Resolves impact classification from hit position vs waterline and optional
   * collided-entity runtime type/layer lanes.
   */
  [[nodiscard]] EImpactType ENT_GetImpactType(Sim* sim, Entity* entity, const Wm3::Vector3f& hitPosition);

  /**
   * Address: 0x0067B320 (FUN_0067B320, Moho::ENT_GetImpactTypeString)
   *
   * What it does:
   * Converts an impact type enum into its canonical debug/script label.
   */
  [[nodiscard]] const char* ENT_GetImpactTypeString(EImpactType impactType);

  /**
   * Owns reflected metadata for the `EImpactType` enum.
   */
  class EImpactTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00509F60 (FUN_00509F60, Moho::EImpactTypeTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the `EImpactType` enum descriptor.
     */
    ~EImpactTypeTypeInfo() override;

    /**
     * Address: 0x00509F50 (FUN_00509F50, Moho::EImpactTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EImpactType`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00509F30 (FUN_00509F30, Moho::EImpactTypeTypeInfo::Init)
     *
     * What it does:
     * Writes the enum width, installs values, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00509F90 (FUN_00509F90, Moho::EImpactTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `IMPACT_` enum names and values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EImpactTypeTypeInfo) == 0x78, "EImpactTypeTypeInfo size must be 0x78");

  class EImpactTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050A990 (FUN_0050A990, PrimitiveSerHelper<EImpactType>::Deserialize)
     *
     * What it does:
     * Deserializes one `EImpactType` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A9B0 (FUN_0050A9B0, PrimitiveSerHelper<EImpactType>::Serialize)
     *
     * What it does:
     * Serializes one `EImpactType` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A6D0 (FUN_0050A6D0, gpg::PrimitiveSerHelper<Moho::EImpactType,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EImpactType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EImpactTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EImpactTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EImpactTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EImpactTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EImpactTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "EImpactTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EImpactTypePrimitiveSerializer, mSerialize) == 0x10,
    "EImpactTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EImpactTypePrimitiveSerializer) == 0x14, "EImpactTypePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BC7A70 (FUN_00BC7A70, register_EImpactTypeTypeInfo)
   *
   * What it does:
   * Runs `EImpactType` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EImpactTypeTypeInfo();

  /**
   * Address: 0x00BC7A90 (FUN_00BC7A90, register_EImpactTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `EImpactType` and installs process-exit cleanup.
   */
  int register_EImpactTypePrimitiveSerializer();
} // namespace moho
