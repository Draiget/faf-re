#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
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
  struct SWorldParticle
  {
    enum class BlendMode : std::int32_t
    {
      Mode0 = 0,
      Mode1 = 1,
      Mode2 = 2,
      Mode3 = 3,
    };

    enum class ZMode : std::int32_t
    {
      Mode0 = 0,
      Mode1 = 1,
      Mode2 = 2,
      Mode3 = 3,
    };

    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sBlendModeType = nullptr;
    inline static gpg::RType* sZModeType = nullptr;

    /**
     * Address: 0x0065B7F0 (FUN_0065B7F0, ??0SParticle@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one world-particle payload with default resistance, size,
     * blend/z modes, texture lanes, and army-index sentinel.
     */
    SWorldParticle();

    bool mEnabled = false;                            // +0x00
    std::uint8_t mPadding01[3]{};                     // +0x01
    float mResistance = 0.0f;                         // +0x04
    Wm3::Vector3<float> mPos;                         // +0x08
    Wm3::Vector3<float> mDir;                         // +0x14
    Wm3::Vector3<float> mAccel;                       // +0x20
    float mInterop = 0.0f;                            // +0x2C
    float mLifetime = 0.0f;                           // +0x30
    float mFramerate = 0.0f;                          // +0x34
    float mValue1 = 0.0f;                             // +0x38
    float mTextureSelection = 0.0f;                   // +0x3C
    float mValue3 = 0.0f;                             // +0x40
    float mRampSelection = 0.0f;                      // +0x44
    float mBeginSize = 0.0f;                          // +0x48
    float mEndSize = 0.0f;                            // +0x4C
    float mAngle = 0.0f;                              // +0x50
    float mRotationCurve = 0.0f;                      // +0x54
    float mReserved54 = 0.0f;                         // +0x58
    CountedPtr_CParticleTexture mTexture;             // +0x5C
    CountedPtr_CParticleTexture mRampTexture;         // +0x60
    msvc8::string mTypeTag;                           // +0x64
    std::int32_t mArmyIndex = 0;                      // +0x80
    BlendMode mBlendMode = BlendMode::Mode0;          // +0x84
    ZMode mZMode = ZMode::Mode0;                      // +0x88

    /**
     * Address: 0x00490570 (FUN_00490570, Moho::SWorldParticle::MemberDeserialize)
     *
     * What it does:
     * Loads one world-particle payload from archive in the original field order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004907D0 (FUN_004907D0, Moho::SWorldParticle::MemberSerialize)
     *
     * What it does:
     * Saves one world-particle payload to archive in the original field order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(SWorldParticle, mEnabled) == 0x00, "SWorldParticle::mEnabled offset must be 0x00");
  static_assert(offsetof(SWorldParticle, mResistance) == 0x04, "SWorldParticle::mResistance offset must be 0x04");
  static_assert(offsetof(SWorldParticle, mPos) == 0x08, "SWorldParticle::mPos offset must be 0x08");
  static_assert(offsetof(SWorldParticle, mDir) == 0x14, "SWorldParticle::mDir offset must be 0x14");
  static_assert(offsetof(SWorldParticle, mAccel) == 0x20, "SWorldParticle::mAccel offset must be 0x20");
  static_assert(offsetof(SWorldParticle, mInterop) == 0x2C, "SWorldParticle::mInterop offset must be 0x2C");
  static_assert(offsetof(SWorldParticle, mLifetime) == 0x30, "SWorldParticle::mLifetime offset must be 0x30");
  static_assert(offsetof(SWorldParticle, mFramerate) == 0x34, "SWorldParticle::mFramerate offset must be 0x34");
  static_assert(offsetof(SWorldParticle, mValue1) == 0x38, "SWorldParticle::mValue1 offset must be 0x38");
  static_assert(
    offsetof(SWorldParticle, mTextureSelection) == 0x3C,
    "SWorldParticle::mTextureSelection offset must be 0x3C"
  );
  static_assert(offsetof(SWorldParticle, mValue3) == 0x40, "SWorldParticle::mValue3 offset must be 0x40");
  static_assert(
    offsetof(SWorldParticle, mRampSelection) == 0x44,
    "SWorldParticle::mRampSelection offset must be 0x44"
  );
  static_assert(offsetof(SWorldParticle, mBeginSize) == 0x48, "SWorldParticle::mBeginSize offset must be 0x48");
  static_assert(offsetof(SWorldParticle, mEndSize) == 0x4C, "SWorldParticle::mEndSize offset must be 0x4C");
  static_assert(offsetof(SWorldParticle, mAngle) == 0x50, "SWorldParticle::mAngle offset must be 0x50");
  static_assert(
    offsetof(SWorldParticle, mRotationCurve) == 0x54,
    "SWorldParticle::mRotationCurve offset must be 0x54"
  );
  static_assert(
    offsetof(SWorldParticle, mReserved54) == 0x58,
    "SWorldParticle::mReserved54 offset must be 0x58"
  );
  static_assert(offsetof(SWorldParticle, mTexture) == 0x5C, "SWorldParticle::mTexture offset must be 0x5C");
  static_assert(
    offsetof(SWorldParticle, mRampTexture) == 0x60,
    "SWorldParticle::mRampTexture offset must be 0x60"
  );
  static_assert(offsetof(SWorldParticle, mTypeTag) == 0x64, "SWorldParticle::mTypeTag offset must be 0x64");
  static_assert(offsetof(SWorldParticle, mArmyIndex) == 0x80, "SWorldParticle::mArmyIndex offset must be 0x80");
  static_assert(offsetof(SWorldParticle, mBlendMode) == 0x84, "SWorldParticle::mBlendMode offset must be 0x84");
  static_assert(offsetof(SWorldParticle, mZMode) == 0x88, "SWorldParticle::mZMode offset must be 0x88");
  static_assert(sizeof(SWorldParticle) == 0x8C, "SWorldParticle size must be 0x8C");
} // namespace moho
