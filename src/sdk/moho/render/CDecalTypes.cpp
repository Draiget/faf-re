#include "moho/render/CDecalTypes.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RListType_SDecalInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0077A760 (FUN_0077A760, gpg::RListType_SDecalInfo::GetName)
     *
     * What it does:
     * Lazily builds and caches reflected lexical type label `list<SDecalInfo>`.
     */
    [[nodiscard]] const char* GetName() const override;
  };
} // namespace gpg

namespace
{
  msvc8::string gSDecalInfoListTypeName{};
  std::uint32_t gSDecalInfoListTypeNameInitGuard = 0u;

  [[nodiscard]] gpg::RType* CachedSDecalInfoType()
  {
    gpg::RType* type = moho::SDecalInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SDecalInfo));
      moho::SDecalInfo::sType = type;
    }
    return type;
  }

  void cleanup_SDecalInfoListTypeName()
  {
    gSDecalInfoListTypeName.clear();
    gSDecalInfoListTypeNameInitGuard = 0u;
  }
} // namespace

/**
 * Address: 0x0077A760 (FUN_0077A760, gpg::RListType_SDecalInfo::GetName)
 *
 * What it does:
 * Lazily builds and caches reflected lexical type label `list<SDecalInfo>`
 * from runtime RTTI metadata.
 */
const char* gpg::RListType_SDecalInfo::GetName() const
{
  if ((gSDecalInfoListTypeNameInitGuard & 1u) == 0u) {
    gSDecalInfoListTypeNameInitGuard |= 1u;

    gpg::RType* const valueType = CachedSDecalInfoType();
    const char* const valueTypeName = valueType ? valueType->GetName() : "SDecalInfo";
    gSDecalInfoListTypeName = gpg::STR_Printf("list<%s>", valueTypeName ? valueTypeName : "SDecalInfo");
    (void)std::atexit(&cleanup_SDecalInfoListTypeName);
  }

  return gSDecalInfoListTypeName.c_str();
}

namespace moho
{
  gpg::RType* SDecalInfo::sType = nullptr;

  /**
   * Address: 0x00778B60 (FUN_00778B60, SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Initializes one default decal payload with empty textures/type and
   * default fidelity.
   */
  SDecalInfo::SDecalInfo()
    : mPos{}
    , mSize{}
    , mRot{}
    , mTexName1()
    , mTexName2()
    , mIsSplat(0)
    , mPad5D{0, 0, 0}
    , mLODParam(0.0f)
    , mStartTick(0)
    , mType()
    , mObj(0)
    , mArmy(0)
    , mFidelity(1)
  {}

  /**
   * Address: 0x0066D210 (FUN_0066D210, Moho::SDecalInfo::SDecalInfo)
   *
   * What it does:
   * Copies position/size/rotation + texture/type strings and seeds runtime
   * decal metadata fields.
   */
  SDecalInfo::SDecalInfo(
    const Wm3::Vec3f& size,
    const Wm3::Vec3f& position,
    const Wm3::Vec3f& rotation,
    const msvc8::string& textureNamePrimary,
    const msvc8::string& textureNameSecondary,
    const bool isSplat,
    const float lodParam,
    const std::uint32_t startTick,
    const msvc8::string& typeName,
    const std::uint32_t armyIndex,
    const std::uint32_t fidelity
  )
    : mPos(position)
    , mSize(size)
    , mRot(rotation)
    , mTexName1(textureNamePrimary)
    , mTexName2(textureNameSecondary)
    , mIsSplat(isSplat ? 1u : 0u)
    , mPad5D{0, 0, 0}
    , mLODParam(lodParam)
    , mStartTick(startTick)
    , mType(typeName)
    , mObj(0)
    , mArmy(armyIndex)
    , mFidelity(fidelity)
  {}
} // namespace moho
