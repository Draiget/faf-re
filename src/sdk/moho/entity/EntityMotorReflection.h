#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityMotor.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class MotorTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00694800 (FUN_00694800, Moho::MotorTypeInfo::MotorTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI metadata for `moho::Motor`.
     */
    MotorTypeInfo();

    /**
     * Address: 0x00BFCF00 (FUN_00BFCF00, Moho::MotorTypeInfo::~MotorTypeInfo)
     *
     * What it does:
     * Releases reflected base/field vectors for `moho::Motor` type info.
     */
    ~MotorTypeInfo() override;

    /**
     * Address: 0x00694880 (FUN_00694880, Moho::MotorTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection name literal for `moho::Motor`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00694860 (FUN_00694860, Moho::MotorTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size metadata and finalizes the `moho::Motor` type.
     */
    void Init() override;
  };

  static_assert(sizeof(MotorTypeInfo) == 0x64, "MotorTypeInfo size must be 0x64");

  class MotorSerializer
  {
  public:
    /**
     * Address: 0x00694940 (FUN_00694940, Moho::MotorSerializer::Deserialize)
     *
     * What it does:
     * No-op load callback for `moho::Motor` (base motor has no serialized fields).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00694950 (FUN_00694950, Moho::MotorSerializer::Serialize)
     *
     * What it does:
     * No-op save callback for `moho::Motor` (base motor has no serialized fields).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00694A20 (FUN_00694A20, gpg::SerSaveLoadHelper<Moho::Motor>::Init)
     *
     * What it does:
     * Binds load/save callbacks into the reflected `moho::Motor` type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(MotorSerializer, mHelperLinks) == 0x04, "MotorSerializer::mHelperLinks offset must be 0x04");
  static_assert(offsetof(MotorSerializer, mDeserialize) == 0x0C, "MotorSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(MotorSerializer, mSerialize) == 0x10, "MotorSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(MotorSerializer) == 0x14, "MotorSerializer size must be 0x14");

  /**
   * Address: 0x00BFCF60 (FUN_00BFCF60)
   *
   * What it does:
   * Unlinks `MotorSerializer` helper links and restores a self-linked node.
   */
  gpg::SerHelperBase* cleanup_MotorSerializer();

  /**
   * Address: 0x00BD5910 (FUN_00BD5910, register_MotorTypeInfo)
   *
   * What it does:
   * Initializes global `MotorTypeInfo` storage and schedules exit cleanup.
   */
  void register_MotorTypeInfo();

  /**
   * Address: 0x00BD5930 (FUN_00BD5930, register_MotorSerializer)
   *
   * What it does:
   * Initializes `MotorSerializer` callback lanes and schedules exit cleanup.
   */
  void register_MotorSerializer();
} // namespace moho


