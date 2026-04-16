#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/containers/TDatList.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class CDecalHandle;

  using CDecalHandleListNode = TDatListItem<CDecalHandle, void>;
  using CDecalHandleList = TDatList<CDecalHandle, void>;

  struct SDecalInfo
  {
    static gpg::RType* sType;

    /**
     * Address: 0x00778B60 (FUN_00778B60, SDecalInfo::SDecalInfo)
     *
     * What it does:
     * Initializes one default decal payload with empty textures/type and
     * default fidelity.
     */
    SDecalInfo();

    /**
     * Address: 0x0066D210 (FUN_0066D210, Moho::SDecalInfo::SDecalInfo)
     *
     * What it does:
     * Copies position/size/rotation + texture/type strings and seeds runtime
     * decal metadata fields.
     */
    SDecalInfo(
      const Wm3::Vec3f& size,
      const Wm3::Vec3f& position,
      const Wm3::Vec3f& rotation,
      const msvc8::string& textureNamePrimary,
      const msvc8::string& textureNameSecondary,
      bool isSplat,
      float lodParam,
      std::uint32_t startTick,
      const msvc8::string& typeName,
      std::uint32_t armyIndex,
      std::uint32_t fidelity
    );

    /**
     * Address: 0x0077D470 (FUN_0077D470, Moho::SDecalInfo::MemberDeserialize)
     *
     * What it does:
     * Loads decal position/size/rotation vectors plus texture/type lanes and
     * runtime metadata fields from archive payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0077D5A0 (FUN_0077D5A0)
     *
     * What it does:
     * Saves decal position/size/rotation vectors, texture/type lanes, and
     * runtime metadata fields to archive payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    Wm3::Vec3f mPos;         // +0x00
    Wm3::Vec3f mSize;        // +0x0C
    Wm3::Vec3f mRot;         // +0x18
    msvc8::string mTexName1; // +0x24
    msvc8::string mTexName2; // +0x40
    std::uint8_t mIsSplat;   // +0x5C
    std::uint8_t mPad5D[0x03];
    float mLODParam;          // +0x60
    std::uint32_t mStartTick; // +0x64
    msvc8::string mType;      // +0x68
    std::uint32_t mObj;       // +0x84
    std::uint32_t mArmy;      // +0x88
    std::uint32_t mFidelity;  // +0x8C
  };

  static_assert(offsetof(SDecalInfo, mPos) == 0x00, "SDecalInfo::mPos offset must be 0x00");
  static_assert(offsetof(SDecalInfo, mSize) == 0x0C, "SDecalInfo::mSize offset must be 0x0C");
  static_assert(offsetof(SDecalInfo, mRot) == 0x18, "SDecalInfo::mRot offset must be 0x18");
  static_assert(offsetof(SDecalInfo, mTexName1) == 0x24, "SDecalInfo::mTexName1 offset must be 0x24");
  static_assert(offsetof(SDecalInfo, mTexName2) == 0x40, "SDecalInfo::mTexName2 offset must be 0x40");
  static_assert(offsetof(SDecalInfo, mIsSplat) == 0x5C, "SDecalInfo::mIsSplat offset must be 0x5C");
  static_assert(offsetof(SDecalInfo, mLODParam) == 0x60, "SDecalInfo::mLODParam offset must be 0x60");
  static_assert(offsetof(SDecalInfo, mStartTick) == 0x64, "SDecalInfo::mStartTick offset must be 0x64");
  static_assert(offsetof(SDecalInfo, mType) == 0x68, "SDecalInfo::mType offset must be 0x68");
  static_assert(offsetof(SDecalInfo, mObj) == 0x84, "SDecalInfo::mObj offset must be 0x84");
  static_assert(offsetof(SDecalInfo, mArmy) == 0x88, "SDecalInfo::mArmy offset must be 0x88");
  static_assert(offsetof(SDecalInfo, mFidelity) == 0x8C, "SDecalInfo::mFidelity offset must be 0x8C");
  static_assert(sizeof(SDecalInfo) == 0x90, "SDecalInfo size must be 0x90");

  static_assert(sizeof(CDecalHandleListNode) == 0x08, "CDecalHandleListNode size must be 0x08");
  static_assert(sizeof(CDecalHandleList) == 0x08, "CDecalHandleList size must be 0x08");
} // namespace moho
