#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  struct SerHelperBase;
}

namespace moho
{
  struct RProjectileBlueprint;

  /**
   * Address-backed projectile attribute payload used by projectile serialization.
   *
   * Layout recovered from:
   * - 0x0069A8B0 (CProjectileAttributesTypeInfo::Init size lane)
   * - 0x0069F470 / 0x0069F4D0 (member serialize/deserialize body)
   */
  struct CProjectileAttributes
  {
    /**
     * Address: 0x0069A4A0 (FUN_0069A4A0, Moho::CProjectileAttributes::CProjectileAttributes)
     *
     * What it does:
     * Initializes projectile zig-zag/detonation override lanes to unset
     * sentinel values and clears blueprint pointer ownership.
     */
    CProjectileAttributes() noexcept;

    /**
     * Address: 0x0069A4D0 (FUN_0069A4D0, Moho::CProjectileAttributes::CProjectileAttributes)
     *
     * What it does:
     * Initializes one projectile-attributes payload from a blueprint pointer
     * while keeping zig-zag/detonation override lanes unset.
     */
    explicit CProjectileAttributes(RProjectileBlueprint* blueprint) noexcept;

    RProjectileBlueprint* mBlueprint; // +0x00
    float mMaxZigZag;                 // +0x04
    float mZigZagFrequency;           // +0x08
    float mDetonateAboveHeight;       // +0x0C
    float mDetonateBelowHeight;       // +0x10

    static gpg::RType* sType;
  };

  static_assert(offsetof(CProjectileAttributes, mBlueprint) == 0x00, "CProjectileAttributes::mBlueprint offset must be 0x00");
  static_assert(offsetof(CProjectileAttributes, mMaxZigZag) == 0x04, "CProjectileAttributes::mMaxZigZag offset must be 0x04");
  static_assert(
    offsetof(CProjectileAttributes, mZigZagFrequency) == 0x08,
    "CProjectileAttributes::mZigZagFrequency offset must be 0x08"
  );
  static_assert(
    offsetof(CProjectileAttributes, mDetonateAboveHeight) == 0x0C,
    "CProjectileAttributes::mDetonateAboveHeight offset must be 0x0C"
  );
  static_assert(
    offsetof(CProjectileAttributes, mDetonateBelowHeight) == 0x10,
    "CProjectileAttributes::mDetonateBelowHeight offset must be 0x10"
  );
  static_assert(sizeof(CProjectileAttributes) == 0x14, "CProjectileAttributes size must be 0x14");

  class CProjectileAttributesTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0069A850 (FUN_0069A850, Moho::CProjectileAttributesTypeInfo::CProjectileAttributesTypeInfo)
     *
     * What it does:
     * Preregisters `CProjectileAttributes` reflection metadata at startup.
     */
    CProjectileAttributesTypeInfo();

    /**
     * Address: 0x0069A8E0 (FUN_0069A8E0, Moho::CProjectileAttributesTypeInfo::dtr)
     */
    ~CProjectileAttributesTypeInfo() override;

    /**
     * Address: 0x0069A8D0 (FUN_0069A8D0, Moho::CProjectileAttributesTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0069A8B0 (FUN_0069A8B0, Moho::CProjectileAttributesTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CProjectileAttributesTypeInfo) == 0x64, "CProjectileAttributesTypeInfo size must be 0x64");

  class CProjectileAttributesSerializer
  {
  public:
    /**
     * Address: 0x0069A990 (FUN_0069A990, Moho::CProjectileAttributesSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0069A9A0 (FUN_0069A9A0, Moho::CProjectileAttributesSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0069E900 (FUN_0069E900, serializer registration lane)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CProjectileAttributesSerializer, mHelperNext) == 0x04,
    "CProjectileAttributesSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CProjectileAttributesSerializer, mHelperPrev) == 0x08,
    "CProjectileAttributesSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CProjectileAttributesSerializer, mDeserialize) == 0x0C,
    "CProjectileAttributesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CProjectileAttributesSerializer, mSerialize) == 0x10,
    "CProjectileAttributesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CProjectileAttributesSerializer) == 0x14, "CProjectileAttributesSerializer size must be 0x14");

  /**
   * Address: 0x00BFD580 (FUN_00BFD580, cleanup_CProjectileAttributesTypeInfo)
   *
   * What it does:
   * Tears down startup `CProjectileAttributesTypeInfo` storage.
   */
  void cleanup_CProjectileAttributesTypeInfo();

  /**
   * Address: 0x00BD6390 (FUN_00BD6390, register_CProjectileAttributesTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `CProjectileAttributesTypeInfo` and installs
   * process-exit cleanup.
   */
  int register_CProjectileAttributesTypeInfo();

  /**
   * Address: 0x00BFD5E0 (FUN_00BFD5E0, cleanup_CProjectileAttributesSerializer)
   *
   * What it does:
   * Unlinks `CProjectileAttributesSerializer` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_CProjectileAttributesSerializer();

  /**
   * Address: 0x00BD63B0 (FUN_00BD63B0, register_CProjectileAttributesSerializer)
   *
   * What it does:
   * Initializes startup `CProjectileAttributesSerializer` callback lanes and
   * installs process-exit cleanup.
   */
  int register_CProjectileAttributesSerializer();
} // namespace moho
