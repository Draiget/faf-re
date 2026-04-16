#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EJobType : std::int32_t
  {
    JOB_None = 0,
    JOB_Build = 1,
    JOB_Repair = 2,
    JOB_Reclaim = 3,
  };

  static_assert(sizeof(EJobType) == 0x4, "EJobType size must be 0x4");

  class EJobTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055B810 (FUN_0055B810, Moho::EJobTypeTypeInfo::EJobTypeTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EJobType` with the reflection registry.
     */
    EJobTypeTypeInfo();

    /**
     * Address: 0x0055B8A0 (FUN_0055B8A0, Moho::EJobTypeTypeInfo::dtr)
     */
    ~EJobTypeTypeInfo() override;

    /**
     * Address: 0x0055B890 (FUN_0055B890, Moho::EJobTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055B870 (FUN_0055B870, Moho::EJobTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055B8D0 (FUN_0055B8D0, Moho::EJobTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  class EJobTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0055D370 (FUN_0055D370, PrimitiveSerHelper<EJobType>::Deserialize)
     *
     * What it does:
     * Deserializes one `EJobType` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055D390 (FUN_0055D390, PrimitiveSerHelper<EJobType>::Serialize)
     *
     * What it does:
     * Serializes one `EJobType` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EJobType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EJobTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EJobTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EJobTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EJobTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EJobTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "EJobTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EJobTypePrimitiveSerializer, mSerialize) == 0x10,
    "EJobTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EJobTypePrimitiveSerializer) == 0x14, "EJobTypePrimitiveSerializer size must be 0x14");

  static_assert(sizeof(EJobTypeTypeInfo) == 0x78, "EJobTypeTypeInfo size must be 0x78");
} // namespace moho
