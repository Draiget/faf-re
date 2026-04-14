#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CGeomSolid3;
  class CHeightField;

  enum EDepositType : std::int32_t
  {
    kNone = 0x0,
    kMass = 0x1,
    kHydrocarbon = 0x2,
  };

  struct ResourceDeposit
  {
    gpg::Rect2i footprintRect; // +0x00

    EDepositType depositType; // +0x10

    /**
     * Address: 0x005486E0 (FUN_005486E0, Moho::ResourceDeposit::MemberDeserialize)
     *
     * What it does:
     * Loads the footprint rectangle and deposit resource type from a reflected
     * archive stream into one `ResourceDeposit` payload.
     */
    static void MemberDeserialize(ResourceDeposit* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x00546170 (Moho::ResourceDeposit::Intersects)
     *
     * Moho::CGeomSolid3 const&, Moho::CHeightField const&
     *
     * What it does:
     * Builds a terrain-aligned AABB for the deposit corners and tests it against
     * the provided clipping solid.
     */
    [[nodiscard]] bool Intersects(const CGeomSolid3& solid, const CHeightField& field) const;
  };

  /**
   * Patch-parity payload for `GetDepositsAroundPoint` style queries.
   *
   * Carries the original deposit record plus center-distance from the query
   * point in world/grid XZ space.
   */
  struct ResourceDepositDistance
  {
    ResourceDeposit deposit; // +0x00
    float centerDistance;    // +0x14
  };

  /**
   * VFTABLE: 0x00E170FC
   * COL: 0x00E6B5B4
   */
  class ResourceDepositTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00545BD0 (FUN_00545BD0, Moho::ResourceDepositTypeInfo::ResourceDepositTypeInfo)
     *
     * What it does:
     * Initializes base reflection lanes and preregisters RTTI ownership for
     * `ResourceDeposit`.
     */
    ResourceDepositTypeInfo();

    /**
     * Address: 0x00545C60 (FUN_00545C60, Moho::ResourceDepositTypeInfo::dtr)
     * Slot: 2
     */
    ~ResourceDepositTypeInfo() override;

    /**
     * Address: 0x00545C50 (FUN_00545C50, Moho::ResourceDepositTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00545C30 (FUN_00545C30, Moho::ResourceDepositTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected object size for `ResourceDeposit` and finalizes type
     * registration metadata.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC9650 (FUN_00BC9650, register_ResourceDepositTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `ResourceDepositTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_ResourceDepositTypeInfo();

  static_assert(sizeof(ResourceDeposit) == 0x14, "ResourceDeposit size must be 0x14");
  static_assert(offsetof(ResourceDeposit, depositType) == 0x10, "ResourceDeposit::depositType offset must be 0x10");
  static_assert(sizeof(ResourceDepositDistance) == 0x18, "ResourceDepositDistance size must be 0x18");
  static_assert(
    offsetof(ResourceDepositDistance, centerDistance) == 0x14,
    "ResourceDepositDistance::centerDistance offset must be 0x14"
  );
  static_assert(sizeof(ResourceDepositTypeInfo) == 0x64, "ResourceDepositTypeInfo size must be 0x64");
} // namespace moho
