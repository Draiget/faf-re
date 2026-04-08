#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EIntel : std::int32_t
  {
    INTEL_None = 0,
    INTEL_Vision = 1,
    INTEL_WaterVision = 2,
    INTEL_Radar = 3,
    INTEL_Sonar = 4,
    INTEL_Omni = 5,
    INTEL_RadarStealthField = 6,
    INTEL_SonarStealthField = 7,
    INTEL_CloakField = 8,
    INTEL_Jammer = 9,
    INTEL_Spoof = 10,
    INTEL_Cloak = 11,
    INTEL_RadarStealth = 12,
    INTEL_SonarStealth = 13,
  };

  static_assert(sizeof(EIntel) == 0x04, "EIntel size must be 0x04");

  class EIntelTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0050A430 (FUN_0050A430, Moho::EIntelTypeInfo::dtr)
     */
    ~EIntelTypeInfo() override;

    /**
     * Address: 0x0050A420 (FUN_0050A420, Moho::EIntelTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A400 (FUN_0050A400, Moho::EIntelTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0050A460 (FUN_0050A460, Moho::EIntelTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EIntelTypeInfo) == 0x78, "EIntelTypeInfo size must be 0x78");

  class EIntelPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050AAE0 (FUN_0050AAE0, PrimitiveSerHelper<EIntel>::Deserialize)
     *
     * What it does:
     * Deserializes one `EIntel` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050AB00 (FUN_0050AB00, PrimitiveSerHelper<EIntel>::Serialize)
     *
     * What it does:
     * Serializes one `EIntel` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A8B0 (FUN_0050A8B0, gpg::PrimitiveSerHelper<Moho::EIntel,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EIntel`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EIntelPrimitiveSerializer, mHelperNext) == 0x04,
    "EIntelPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EIntelPrimitiveSerializer, mHelperPrev) == 0x08,
    "EIntelPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EIntelPrimitiveSerializer, mDeserialize) == 0x0C,
    "EIntelPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EIntelPrimitiveSerializer, mSerialize) == 0x10,
    "EIntelPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EIntelPrimitiveSerializer) == 0x14, "EIntelPrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BC7B90 (FUN_00BC7B90, register_EIntelTypeInfo)
   *
   * What it does:
   * Runs `EIntel` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_EIntelTypeInfo();

  /**
   * Address: 0x00BC7BB0 (FUN_00BC7BB0, register_EIntelPrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `EIntel` and installs process-exit cleanup.
   */
  int register_EIntelPrimitiveSerializer();
} // namespace moho
