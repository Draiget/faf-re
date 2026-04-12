#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "wm3/Vector3.h"

namespace moho
{
  class COGrid;
  struct SCoordsVec2;
  struct SOCellPos;

  enum class EFootprintFlags : int8_t
  {
    FPFLAG_None = 0x0,
    FPFLAG_IgnoreStructures = 0x1,
  };

  // OC_ANY = 0xFF is a bitmask sentinel; the underlying type must be unsigned
  // 8-bit so 0xFF (255) is representable. The struct field that holds this
  // enum is declared as `EOccupancyCaps mOccupancyCaps; // +0x02` which is a
  // single byte in the binary, so std::uint8_t preserves the layout.
  enum class EOccupancyCaps : std::uint8_t
  {
    OC_LAND = 0x1,
    OC_SEABED = 0x2,
    OC_SUB = 0x4,
    OC_WATER = 0x8,
    OC_AIR = 0x10,
    OC_ORBIT = 0x20,
    OC_ANY = 0xFF,
  };

  struct SFootprint
  {
    std::uint8_t mSizeX;           // +0x00
    std::uint8_t mSizeZ;           // +0x01
    EOccupancyCaps mOccupancyCaps; // +0x02
    EFootprintFlags mFlags;        // +0x03
    float mMaxSlope;               // +0x04
    float mMinWaterDepth;          // +0x08
    float mMaxWaterDepth;          // +0x0C

    /**
     * Address: 0x00720AA0 (FUN_00720AA0, Moho::SFootprint::FitsAt)
     *
     * Moho::SCoordsVec2 const &, Moho::COGrid const &
     *
     * What it does:
     * Converts world-space center coordinates to a footprint-origin cell and
     * returns occupancy-fit caps via `OCCUPY_FootprintFits(..., OC_ANY)`.
     */
    [[nodiscard]] EOccupancyCaps FitsAt(const SCoordsVec2& worldPos, const COGrid& grid) const;

    /**
     * Address: 0x00579300 (FUN_00579300, Moho::SFootprint::ToCellPos)
     *
     * What it does:
     * Converts world-space center coordinates to footprint-origin grid cell.
     */
    [[nodiscard]] SOCellPos ToCellPos(const Wm3::Vec3f& worldPos) const;

    /**
     * Address: 0x0050D090 (FUN_0050D090, Moho::SFootprint::MemberDeserialize)
     *
     * What it does:
     * Loads the serialized footprint lanes in the exact binary field order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0050D0E0 (FUN_0050D0E0, Moho::SFootprint::MemberSerialize)
     *
     * What it does:
     * Stores the serialized footprint lanes in the exact binary field order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  class SFootprintSerializer
  {
  public:
    /**
     * Address: 0x0050C5A0 (FUN_0050C5A0, Moho::SFootprintSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading to `SFootprint::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, SFootprint* footprint);

    /**
     * Address: 0x0050C5B0 (FUN_0050C5B0, Moho::SFootprintSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving to `SFootprint::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, SFootprint* footprint);

    virtual ~SFootprintSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(SFootprintSerializer, mHelperNext) == 0x04, "SFootprintSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SFootprintSerializer, mHelperPrev) == 0x08, "SFootprintSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SFootprintSerializer, mDeserialize) == 0x0C, "SFootprintSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SFootprintSerializer, mSerialize) == 0x10, "SFootprintSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SFootprintSerializer) == 0x14, "SFootprintSerializer size must be 0x14");

  static_assert(offsetof(SFootprint, mSizeX) == 0x00, "SFootprint::mSizeX offset must be 0x00");
  static_assert(offsetof(SFootprint, mSizeZ) == 0x01, "SFootprint::mSizeZ offset must be 0x01");
  static_assert(offsetof(SFootprint, mOccupancyCaps) == 0x02, "SFootprint::mOccupancyCaps offset must be 0x02");
  static_assert(offsetof(SFootprint, mFlags) == 0x03, "SFootprint::mFlags offset must be 0x03");
  static_assert(offsetof(SFootprint, mMaxSlope) == 0x04, "SFootprint::mMaxSlope offset must be 0x04");
  static_assert(offsetof(SFootprint, mMinWaterDepth) == 0x08, "SFootprint::mMinWaterDepth offset must be 0x08");
  static_assert(offsetof(SFootprint, mMaxWaterDepth) == 0x0C, "SFootprint::mMaxWaterDepth offset must be 0x0C");
  static_assert(sizeof(SFootprint) == 0x10, "SFootprint size must be 0x10");
} // namespace moho
