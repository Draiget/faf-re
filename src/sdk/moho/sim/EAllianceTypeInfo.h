#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Owns the reflected enum descriptor for `EAlliance`.
   */
  enum EAlliance : std::int32_t
  {
    ALLIANCE_Neutral = 0,
    ALLIANCE_Ally = 1,
    ALLIANCE_Enemy = 2,
  };

  static_assert(sizeof(EAlliance) == 0x04, "EAlliance size must be 0x04");

  /**
   * Owns reflected metadata for the `EAlliance` enum.
   */
  class EAllianceTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00509DF0 (FUN_00509DF0, Moho::EAllianceTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for the `EAlliance` enum descriptor.
     */
    ~EAllianceTypeInfo() override;

    /**
     * Address: 0x00509DE0 (FUN_00509DE0, Moho::EAllianceTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `EAlliance`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00509DC0 (FUN_00509DC0, Moho::EAllianceTypeInfo::Init)
     *
     * What it does:
     * Writes the enum width, installs values, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00509E20 (FUN_00509E20, Moho::EAllianceTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `ALLIANCE_` enum names and values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAllianceTypeInfo) == 0x78, "EAllianceTypeInfo size must be 0x78");

  class EAlliancePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050A920 (FUN_0050A920, PrimitiveSerHelper<EAlliance>::Deserialize)
     *
     * What it does:
     * Deserializes one `EAlliance` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A940 (FUN_0050A940, PrimitiveSerHelper<EAlliance>::Serialize)
     *
     * What it does:
     * Serializes one `EAlliance` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A630 (FUN_0050A630, gpg::PrimitiveSerHelper<Moho::EAlliance,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EAlliance`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EAlliancePrimitiveSerializer, mHelperNext) == 0x04,
    "EAlliancePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAlliancePrimitiveSerializer, mHelperPrev) == 0x08,
    "EAlliancePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAlliancePrimitiveSerializer, mDeserialize) == 0x0C,
    "EAlliancePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EAlliancePrimitiveSerializer, mSerialize) == 0x10,
    "EAlliancePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EAlliancePrimitiveSerializer) == 0x14, "EAlliancePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BC7A10 (FUN_00BC7A10, register_EAllianceTypeInfo)
   *
   * What it does:
   * Runs `EAlliance` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EAllianceTypeInfo();

  /**
   * Address: 0x00BC7A30 (FUN_00BC7A30, register_EAlliancePrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `EAlliance` and installs process-exit cleanup.
   */
  int register_EAlliancePrimitiveSerializer();
} // namespace moho
