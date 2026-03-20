// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace moho
{
  /**
   * VFTABLE: 0x1075E608
   * COL:  0x107A8638
   */
  class AirPlatformExtractor
  {
  public:
    /**
     * Address: 0x103B6970
     * Slot: 0
     * Demangled: (likely scalar deleting destructor thunk)
     */
    virtual ~AirPlatformExtractor() = default;

    /**
     * Address: 0x103B6340
     * Slot: 1
     *
     * What it does:
     * Reads interpolated entity position and writes a 4-float payload
     * `{x, y, z, range}` when the platform has a valid positive range.
     */
    virtual bool Extract(float* outPosRange, void* userEntity, float alpha) = 0;
  };
} // namespace moho
