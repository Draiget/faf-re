#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EVisibilityMode : std::int32_t
  {
    VIZMODE_Never = 1,
    VIZMODE_Always = 2,
    VIZMODE_Intel = 4,
  };

  static_assert(sizeof(EVisibilityMode) == 0x04, "EVisibilityMode size must be 0x04");

  class EVisibilityModeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF1F90 (FUN_00BF1F90, Moho::EVisibilityModeTypeInfo::dtr)
     */
    ~EVisibilityModeTypeInfo() override;

    /**
     * Address: 0x0050A0D0 (FUN_0050A0D0, Moho::EVisibilityModeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A160 (FUN_0050A160, Moho::EVisibilityModeTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050A1C0 (FUN_0050A1C0, Moho::EVisibilityModeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EVisibilityModeTypeInfo) == 0x78, "EVisibilityModeTypeInfo size must be 0x78");

  class EVisibilityModePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050AA00 (FUN_0050AA00, PrimitiveSerHelper<EVisibilityMode>::Deserialize)
     *
     * What it does:
     * Deserializes one `EVisibilityMode` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050AA20 (FUN_0050AA20, PrimitiveSerHelper<EVisibilityMode>::Serialize)
     *
     * What it does:
     * Serializes one `EVisibilityMode` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A770 (FUN_0050A770, gpg::PrimitiveSerHelper<Moho::EVisibilityMode,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected
     * `EVisibilityMode`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EVisibilityModePrimitiveSerializer, mHelperNext) == 0x04,
    "EVisibilityModePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EVisibilityModePrimitiveSerializer, mHelperPrev) == 0x08,
    "EVisibilityModePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EVisibilityModePrimitiveSerializer, mDeserialize) == 0x0C,
    "EVisibilityModePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EVisibilityModePrimitiveSerializer, mSerialize) == 0x10,
    "EVisibilityModePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(EVisibilityModePrimitiveSerializer) == 0x14,
    "EVisibilityModePrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x0050A100 (FUN_0050A100, preregister_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `EVisibilityMode`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EVisibilityModeTypeInfo();

  /**
   * Address: 0x00BC7AD0 (FUN_00BC7AD0, register_EVisibilityModeTypeInfo)
   *
   * What it does:
   * Runs `EVisibilityMode` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EVisibilityModeTypeInfo();

  /**
   * Address: 0x00BC7AF0 (FUN_00BC7AF0, register_EVisibilityModePrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `EVisibilityMode` and installs process-exit cleanup.
   */
  int register_EVisibilityModePrimitiveSerializer();
} // namespace moho

