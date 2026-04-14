#include "moho/render/CDecalTypes.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"

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

    /**
     * Address: 0x0077A820 (FUN_0077A820, gpg::RListType_SDecalInfo::GetLexical)
     *
     * What it does:
     * Formats inherited list lexical text with current `SDecalInfo` list size.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0077A800 (FUN_0077A800, gpg::RListType_SDecalInfo::Init)
     *
     * What it does:
     * Configures reflected `list<SDecalInfo>` layout/version lanes and installs
     * list serializer callbacks.
     */
    void Init() override;

    /**
     * Address: 0x0077B260 (FUN_0077B260, gpg::RListType_SDecalInfo::SerLoad)
     *
     * What it does:
     * Clears one reflected `list<SDecalInfo>`, reads element count, then
     * deserializes each decal entry in archive order.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);

    /**
     * Address: 0x0077B420 (FUN_0077B420, gpg::RListType_SDecalInfo::SerSave)
     *
     * What it does:
     * Writes reflected `list<SDecalInfo>` element count, then serializes each
     * entry in list traversal order.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
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

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return type;
  }

  void cleanup_SDecalInfoListTypeName()
  {
    gSDecalInfoListTypeName.clear();
    gSDecalInfoListTypeNameInitGuard = 0u;
  }

  struct SDecalInfoListRuntimeView
  {
    void* mNodeProxy;      // +0x00
    void* mSentinelNode;   // +0x04
    std::uint32_t mCount;  // +0x08
  };
  static_assert(
    offsetof(SDecalInfoListRuntimeView, mCount) == 0x08, "SDecalInfoListRuntimeView::mCount offset must be 0x08"
  );
  static_assert(sizeof(SDecalInfoListRuntimeView) == 0x0C, "SDecalInfoListRuntimeView size must be 0x0C");

  [[nodiscard]] int CountSDecalInfoListElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0;
    }

    const auto* const listView = static_cast<const SDecalInfoListRuntimeView*>(object);
    return static_cast<int>(listView->mCount);
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

/**
 * Address: 0x0077A820 (FUN_0077A820, gpg::RListType_SDecalInfo::GetLexical)
 *
 * What it does:
 * Formats inherited list lexical text with current `SDecalInfo` list size.
 */
msvc8::string gpg::RListType_SDecalInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), CountSDecalInfoListElements(ref.mObj));
}

/**
 * Address: 0x0077A800 (FUN_0077A800, gpg::RListType_SDecalInfo::Init)
 *
 * What it does:
 * Configures reflected `list<SDecalInfo>` layout/version lanes and installs
 * list serializer callbacks.
 */
void gpg::RListType_SDecalInfo::Init()
{
  size_ = sizeof(msvc8::list<moho::SDecalInfo>);
  version_ = 1;
  serLoadFunc_ = &gpg::RListType_SDecalInfo::SerLoad;
  serSaveFunc_ = &gpg::RListType_SDecalInfo::SerSave;
}

/**
 * Address: 0x0077B260 (FUN_0077B260, gpg::RListType_SDecalInfo::SerLoad)
 *
 * What it does:
 * Clears one reflected `list<SDecalInfo>`, reads element count, then
 * deserializes each decal entry in archive order.
 */
void gpg::RListType_SDecalInfo::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const list = reinterpret_cast<msvc8::list<moho::SDecalInfo>*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  if (archive == nullptr || list == nullptr) {
    return;
  }

  unsigned int count = 0u;
  archive->ReadUInt(&count);
  list->clear();

  gpg::RType* const elementType = CachedSDecalInfoType();
  if (elementType == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (unsigned int i = 0u; i < count; ++i) {
    moho::SDecalInfo value{};
    archive->Read(elementType, &value, owner);
    list->push_back(value);
  }
}

/**
 * Address: 0x0077B420 (FUN_0077B420, gpg::RListType_SDecalInfo::SerSave)
 *
 * What it does:
 * Writes reflected `list<SDecalInfo>` element count, then serializes each
 * entry in list traversal order.
 */
void gpg::RListType_SDecalInfo::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto* const list = reinterpret_cast<const msvc8::list<moho::SDecalInfo>*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  if (archive == nullptr) {
    return;
  }

  const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
  archive->WriteUInt(count);
  if (list == nullptr) {
    return;
  }

  gpg::RType* const elementType = CachedSDecalInfoType();
  if (elementType == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  for (const moho::SDecalInfo& value : *list) {
    archive->Write(elementType, &value, owner);
  }
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

  /**
   * Address: 0x0077D470 (FUN_0077D470, Moho::SDecalInfo::MemberDeserialize)
   *
   * What it does:
   * Loads decal position/size/rotation vectors plus texture/type lanes and
   * runtime metadata fields from archive payload.
   */
  void SDecalInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const vector3fType = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3fType, &mPos, ownerRef);
    archive->Read(vector3fType, &mSize, ownerRef);
    archive->Read(vector3fType, &mRot, ownerRef);

    archive->ReadString(&mTexName1);
    archive->ReadString(&mTexName2);

    bool isSplat = false;
    archive->ReadBool(&isSplat);
    mIsSplat = isSplat ? 1u : 0u;

    archive->ReadFloat(&mLODParam);
    archive->ReadUInt(&mStartTick);
    archive->ReadString(&mType);

    std::int32_t objectId = 0;
    std::int32_t armyIndex = 0;
    std::int32_t fidelity = 0;
    archive->ReadInt(&objectId);
    archive->ReadInt(&armyIndex);
    archive->ReadInt(&fidelity);
    mObj = static_cast<std::uint32_t>(objectId);
    mArmy = static_cast<std::uint32_t>(armyIndex);
    mFidelity = static_cast<std::uint32_t>(fidelity);
  }
} // namespace moho
