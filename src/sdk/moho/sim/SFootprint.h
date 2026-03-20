#pragma once
#include <cstddef>
#include <cstdint>

namespace moho
{
  enum class EFootprintFlags : int8_t
  {
    FPFLAG_None = 0x0,
    FPFLAG_IgnoreStructures = 0x1,
  };

  enum class EOccupancyCaps : int8_t
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
  };

  static_assert(offsetof(SFootprint, mSizeX) == 0x00, "SFootprint::mSizeX offset must be 0x00");
  static_assert(offsetof(SFootprint, mSizeZ) == 0x01, "SFootprint::mSizeZ offset must be 0x01");
  static_assert(offsetof(SFootprint, mOccupancyCaps) == 0x02, "SFootprint::mOccupancyCaps offset must be 0x02");
  static_assert(offsetof(SFootprint, mFlags) == 0x03, "SFootprint::mFlags offset must be 0x03");
  static_assert(offsetof(SFootprint, mMaxSlope) == 0x04, "SFootprint::mMaxSlope offset must be 0x04");
  static_assert(offsetof(SFootprint, mMinWaterDepth) == 0x08, "SFootprint::mMinWaterDepth offset must be 0x08");
  static_assert(offsetof(SFootprint, mMaxWaterDepth) == 0x0C, "SFootprint::mMaxWaterDepth offset must be 0x0C");
  static_assert(sizeof(SFootprint) == 0x10, "SFootprint size must be 0x10");
} // namespace moho
