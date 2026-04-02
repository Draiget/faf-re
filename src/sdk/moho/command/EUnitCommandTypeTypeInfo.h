#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/command/SSTICommandIssueData.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E17A04
   * COL:  0x00E6BB78
   */
  class EUnitCommandTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00552140 (FUN_00552140, Moho::EUnitCommandTypeTypeInfo::dtr)
     */
    ~EUnitCommandTypeTypeInfo() override;

    /**
     * Address: 0x00552130 (FUN_00552130, Moho::EUnitCommandTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00552110 (FUN_00552110, Moho::EUnitCommandTypeTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x00552170 (FUN_00552170, Moho::EUnitCommandTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EUnitCommandTypeTypeInfo) == 0x78, "EUnitCommandTypeTypeInfo size must be 0x78");

  class EUnitCommandTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x00553540 (FUN_00553540, Deserialize_EUnitCommandType_Primitive)
     *
     * What it does:
     * Reads one `int` enum lane and writes it to `EUnitCommandType`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00553560 (FUN_00553560, Serialize_EUnitCommandType_Primitive)
     *
     * What it does:
     * Writes one `EUnitCommandType` enum lane as `int`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00552D60 (FUN_00552D60, gpg::SerSaveLoadHelper_EUnitCommandType::Init)
     *
     * What it does:
     * Binds load/save callback lanes to reflected `EUnitCommandType` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(
    offsetof(EUnitCommandTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EUnitCommandTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EUnitCommandTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EUnitCommandTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EUnitCommandTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "EUnitCommandTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EUnitCommandTypePrimitiveSerializer, mSerialize) == 0x10,
    "EUnitCommandTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(EUnitCommandTypePrimitiveSerializer) == 0x14,
    "EUnitCommandTypePrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x005520B0 (FUN_005520B0, preregister_EUnitCommandTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup-owned RTTI descriptor storage for
   * `EUnitCommandType`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EUnitCommandTypeTypeInfo();

  /**
   * Address: 0x00BC9C20 (FUN_00BC9C20, register_EUnitCommandTypeTypeInfo)
   *
   * What it does:
   * Runs `EUnitCommandType` typeinfo preregistration and installs process-exit
   * cleanup.
   */
  int register_EUnitCommandTypeTypeInfo();

  /**
   * Address: 0x00BC9C40 (FUN_00BC9C40, register_EUnitCommandTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes startup primitive serializer helper links/callbacks for
   * `EUnitCommandType` and installs process-exit cleanup.
   */
  int register_EUnitCommandTypePrimitiveSerializer();
} // namespace moho

