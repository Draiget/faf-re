#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/math/Vector4f.h"
#include "moho/render/camera/VTransform.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class RType;
}

namespace moho
{
  struct SWorldBeam
  {
    enum class BlendMode : std::int32_t
    {
      Mode0 = 0,
      Mode1 = 1,
      Mode2 = 2,
      Mode3 = 3,
    };

    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sBlendModeType = nullptr;

    /**
     * Address: 0x00655CC0 (FUN_00655CC0, Moho::SWorldBeam::SWorldBeam)
     *
     * What it does:
     * Initializes the four endpoint transforms to identity rotation and zero
     * translation, and constructs both counted texture-pointer lanes.
     */
    SWorldBeam();

    VTransform mCurStart;                    // +0x00
    VTransform mLastStart;                   // +0x1C
    bool mFromStart = false;                 // +0x38
    std::uint8_t mPadding39[3]{};            // +0x39
    VTransform mCurEnd;                      // +0x3C
    VTransform mLastEnd;                     // +0x58
    float mLastInterpolation = 0.0f;         // +0x74
    Wm3::Vector3<float> mStart;              // +0x78
    Wm3::Vector3<float> mEnd;                // +0x84
    float mWidth = 0.0f;                     // +0x90
    Vector4f mStartColor;                    // +0x94
    Vector4f mEndColor;                      // +0xA4
    CountedPtr_CParticleTexture mTexture1;   // +0xB4
    CountedPtr_CParticleTexture mTexture2;   // +0xB8
    float mUShift = 0.0f;                     // +0xBC
    float mVShift = 0.0f;                     // +0xC0
    float mRepeatRate = 0.0f;                 // +0xC4
    BlendMode mBlendMode = BlendMode::Mode0;  // +0xC8

    /**
     * Address: 0x00490000 (FUN_00490000, Moho::SWorldBeam::MemberDeserialize)
     *
     * What it does:
     * Loads one world-beam payload from archive in the original field order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004902B0 (FUN_004902B0, Moho::SWorldBeam::MemberSerialize)
     *
     * What it does:
     * Saves one world-beam payload to archive in the original field order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(SWorldBeam, mCurStart) == 0x00, "SWorldBeam::mCurStart offset must be 0x00");
  static_assert(offsetof(SWorldBeam, mLastStart) == 0x1C, "SWorldBeam::mLastStart offset must be 0x1C");
  static_assert(offsetof(SWorldBeam, mFromStart) == 0x38, "SWorldBeam::mFromStart offset must be 0x38");
  static_assert(offsetof(SWorldBeam, mCurEnd) == 0x3C, "SWorldBeam::mCurEnd offset must be 0x3C");
  static_assert(offsetof(SWorldBeam, mLastEnd) == 0x58, "SWorldBeam::mLastEnd offset must be 0x58");
  static_assert(
    offsetof(SWorldBeam, mLastInterpolation) == 0x74, "SWorldBeam::mLastInterpolation offset must be 0x74"
  );
  static_assert(offsetof(SWorldBeam, mStart) == 0x78, "SWorldBeam::mStart offset must be 0x78");
  static_assert(offsetof(SWorldBeam, mEnd) == 0x84, "SWorldBeam::mEnd offset must be 0x84");
  static_assert(offsetof(SWorldBeam, mWidth) == 0x90, "SWorldBeam::mWidth offset must be 0x90");
  static_assert(offsetof(SWorldBeam, mStartColor) == 0x94, "SWorldBeam::mStartColor offset must be 0x94");
  static_assert(offsetof(SWorldBeam, mEndColor) == 0xA4, "SWorldBeam::mEndColor offset must be 0xA4");
  static_assert(offsetof(SWorldBeam, mTexture1) == 0xB4, "SWorldBeam::mTexture1 offset must be 0xB4");
  static_assert(offsetof(SWorldBeam, mTexture2) == 0xB8, "SWorldBeam::mTexture2 offset must be 0xB8");
  static_assert(offsetof(SWorldBeam, mUShift) == 0xBC, "SWorldBeam::mUShift offset must be 0xBC");
  static_assert(offsetof(SWorldBeam, mVShift) == 0xC0, "SWorldBeam::mVShift offset must be 0xC0");
  static_assert(offsetof(SWorldBeam, mRepeatRate) == 0xC4, "SWorldBeam::mRepeatRate offset must be 0xC4");
  static_assert(offsetof(SWorldBeam, mBlendMode) == 0xC8, "SWorldBeam::mBlendMode offset must be 0xC8");
  static_assert(sizeof(SWorldBeam) == 0xCC, "SWorldBeam size must be 0xCC");
} // namespace moho
