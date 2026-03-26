#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  struct SScmBoneBoundsSample
  {
    float mLocalPositionX;           // +0x00
    float mLocalPositionY;           // +0x04
    float mLocalPositionZ;           // +0x08
    std::uint8_t mUnknown0C[0x40 - 0x0C];
    std::uint8_t mBoneIndex;         // +0x40
    std::uint8_t mUnknown41[0x03];
  };

  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionX) == 0x00,
    "SScmBoneBoundsSample::mLocalPositionX offset must be 0x00"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionY) == 0x04,
    "SScmBoneBoundsSample::mLocalPositionY offset must be 0x04"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mLocalPositionZ) == 0x08,
    "SScmBoneBoundsSample::mLocalPositionZ offset must be 0x08"
  );
  static_assert(
    offsetof(SScmBoneBoundsSample, mBoneIndex) == 0x40,
    "SScmBoneBoundsSample::mBoneIndex offset must be 0x40"
  );
  static_assert(sizeof(SScmBoneBoundsSample) == 0x44, "SScmBoneBoundsSample size must be 0x44");

  struct SScmFile
  {
    std::uint8_t mUnknown00[0x08];
    std::uint32_t mBoneTableOffset;        // +0x08
    std::uint8_t mUnknown0C[0x04];
    std::uint32_t mBoneBoundsSampleOffset; // +0x10
    std::uint8_t mUnknown14[0x04];
    std::uint32_t mBoneBoundsSampleCount;  // +0x18
    std::uint8_t mUnknown1C[0x10];
    std::uint32_t mBoneCount;              // +0x2C
  };

  static_assert(offsetof(SScmFile, mBoneTableOffset) == 0x08, "SScmFile::mBoneTableOffset offset must be 0x08");
  static_assert(
    offsetof(SScmFile, mBoneBoundsSampleOffset) == 0x10,
    "SScmFile::mBoneBoundsSampleOffset offset must be 0x10"
  );
  static_assert(
    offsetof(SScmFile, mBoneBoundsSampleCount) == 0x18,
    "SScmFile::mBoneBoundsSampleCount offset must be 0x18"
  );
  static_assert(offsetof(SScmFile, mBoneCount) == 0x2C, "SScmFile::mBoneCount offset must be 0x2C");

  namespace scm_file
  {
    [[nodiscard]] const SScmBoneBoundsSample* GetBoneBoundsSamples(const SScmFile& file);
  } // namespace scm_file
} // namespace moho
