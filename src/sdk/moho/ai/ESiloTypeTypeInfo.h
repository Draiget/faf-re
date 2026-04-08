#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiSiloBuild.h"

namespace moho
{
  class ESiloTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00BF1FD0 (FUN_00BF1FD0, Moho::ESiloTypeTypeInfo::dtr)
     */
    ~ESiloTypeTypeInfo() override;

    /**
     * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(ESiloTypeTypeInfo) == 0x78, "ESiloTypeTypeInfo size must be 0x78");

  class ESiloTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0050AA70 (FUN_0050AA70, PrimitiveSerHelper<ESiloType>::Deserialize)
     *
     * What it does:
     * Deserializes one `ESiloType` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050AA90 (FUN_0050AA90, PrimitiveSerHelper<ESiloType>::Serialize)
     *
     * What it does:
     * Serializes one `ESiloType` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0050A810 (FUN_0050A810, gpg::PrimitiveSerHelper<Moho::ESiloType,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `ESiloType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(ESiloTypePrimitiveSerializer, mHelperNext) == 0x04,
    "ESiloTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ESiloTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "ESiloTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ESiloTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "ESiloTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ESiloTypePrimitiveSerializer, mSerialize) == 0x10,
    "ESiloTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(ESiloTypePrimitiveSerializer) == 0x14, "ESiloTypePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `ESiloType`.
   */
  [[nodiscard]] gpg::REnumType* preregister_ESiloTypeTypeInfo();

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   *
   * What it does:
   * Runs `ESiloType` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_ESiloTypeTypeInfo();

  /**
   * Address: 0x00BC7B50 (FUN_00BC7B50, register_ESiloTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `ESiloType` and installs process-exit cleanup.
   */
  int register_ESiloTypePrimitiveSerializer();
} // namespace moho
