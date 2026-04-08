#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Entity.h"

namespace moho
{
  class ELayerTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF2070 (FUN_00BF2070, Moho::ELayerTypeInfo::dtr)
     */
    ~ELayerTypeInfo() override;

    /**
     * Address: 0x0050BA70 (FUN_0050BA70, Moho::ELayerTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BA50 (FUN_0050BA50, Moho::ELayerTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0050BAB0 (FUN_0050BAB0, Moho::ELayerTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ELayerTypeInfo) == 0x78, "ELayerTypeInfo size must be 0x78");

  class ELayerPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050CA20 (FUN_0050CA20, PrimitiveSerHelper<ELayer>::Deserialize)
     *
     * What it does:
     * Deserializes one `ELayer` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050CA40 (FUN_0050CA40, PrimitiveSerHelper<ELayer>::Serialize)
     *
     * What it does:
     * Serializes one `ELayer` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050C690 (FUN_0050C690, gpg::PrimitiveSerHelper<Moho::ELayer,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `ELayer`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(ELayerPrimitiveSerializer, mHelperNext) == 0x04,
    "ELayerPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ELayerPrimitiveSerializer, mHelperPrev) == 0x08,
    "ELayerPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ELayerPrimitiveSerializer, mDeserialize) == 0x0C,
    "ELayerPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ELayerPrimitiveSerializer, mSerialize) == 0x10,
    "ELayerPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(ELayerPrimitiveSerializer) == 0x14, "ELayerPrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x0050B9F0 (FUN_0050B9F0, preregister_ELayerTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for `ELayer`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ELayerTypeInfo();

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   *
   * What it does:
   * Runs `ELayer` typeinfo preregistration and installs process-exit cleanup.
   */
  int register_ELayerTypeInfo();

  /**
   * Address: 0x00BC7C80 (FUN_00BC7C80, register_ELayerPrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `ELayer` and installs process-exit cleanup.
   */
  int register_ELayerPrimitiveSerializer();
} // namespace moho
