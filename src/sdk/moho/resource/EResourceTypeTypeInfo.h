#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EResourceType : std::int32_t
  {
    RESTYPE_None = 0,
    RESTYPE_Mass = 1,
    RESTYPE_Hydrocarbon = 2,
    RESTYPE_Max = 3,
  };

  static_assert(sizeof(EResourceType) == 0x4, "EResourceType size must be 0x4");

  class EResourceTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00545AE0 (FUN_00545AE0, Moho::EResourceTypeTypeInfo::dtr)
     */
    ~EResourceTypeTypeInfo() override;

    /**
     * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  class EResourceTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005478E0 (FUN_005478E0, PrimitiveSerHelper<EResourceType>::Deserialize)
     *
     * What it does:
     * Deserializes one `EResourceType` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00547900 (FUN_00547900, PrimitiveSerHelper<EResourceType>::Serialize)
     *
     * What it does:
     * Serializes one `EResourceType` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EResourceType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EResourceTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EResourceTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EResourceTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EResourceTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EResourceTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "EResourceTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EResourceTypePrimitiveSerializer, mSerialize) == 0x10,
    "EResourceTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EResourceTypePrimitiveSerializer) == 0x14, "EResourceTypePrimitiveSerializer size must be 0x14");

  static_assert(sizeof(EResourceTypeTypeInfo) == 0x78, "EResourceTypeTypeInfo size must be 0x78");
} // namespace moho
