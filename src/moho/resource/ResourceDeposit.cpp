#include "ResourceDeposit.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/resource/EResourceTypeTypeInfo.h"
#include "moho/sim/STIMap.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  constexpr float kTerrainHeightWordScale = 1.0f / 128.0f;

  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr int kSerializationLoadLine = 84;
  constexpr int kSerializationSaveLine = 87;

  [[nodiscard]] int ClampTerrainSampleIndex(const int value, const int maxInclusive) noexcept
  {
    // Preserve binary clamp order: upper clamp first, then clamp to zero.
    int clamped = value;
    if (clamped >= maxInclusive) {
      clamped = maxInclusive;
    }
    if (clamped < 0) {
      clamped = 0;
    }
    return clamped;
  }

  void ExtendBoundsWithTerrainCorner(
    Wm3::AxisAlignedBox3f& bounds, const moho::CHeightField& field, const int worldX, const int worldZ
  ) noexcept
  {
    const int sampleX = ClampTerrainSampleIndex(worldX, field.width - 1);
    const int sampleZ = ClampTerrainSampleIndex(worldZ, field.height - 1);
    const float terrainY = static_cast<float>(field.data[sampleX + sampleZ * field.width]) * kTerrainHeightWordScale;

    const float pointX = static_cast<float>(worldX);
    const float pointZ = static_cast<float>(worldZ);
    bounds.Min.x = std::min(bounds.Min.x, pointX);
    bounds.Min.y = std::min(bounds.Min.y, terrainY);
    bounds.Min.z = std::min(bounds.Min.z, pointZ);
    bounds.Max.x = std::max(bounds.Max.x, pointX);
    bounds.Max.y = std::max(bounds.Max.y, terrainY);
    bounds.Max.z = std::max(bounds.Max.z, pointZ);
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* cached = gpg::Rect2i::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEResourceTypeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EResourceType));
    }
    return cached;
  }

  /**
   * Address: 0x00545CC0 (FUN_00545CC0)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `ResourceDepositTypeInfo`.
   */
  [[maybe_unused]] void cleanup_ResourceDepositTypeInfoRTypeBase(moho::ResourceDepositTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  [[nodiscard]] moho::ResourceDepositTypeInfo& AcquireResourceDepositTypeInfo()
  {
    static moho::ResourceDepositTypeInfo sInstance;
    return sInstance;
  }

  struct ResourceDepositTypeInfoStartup
  {
    ResourceDepositTypeInfoStartup()
    {
      moho::register_ResourceDepositTypeInfo();
    }
  };

  [[maybe_unused]] ResourceDepositTypeInfoStartup gResourceDepositTypeInfoStartup;
} // namespace

gpg::RType* moho::ResourceDeposit::sType = nullptr;

namespace moho
{
  /**
   * Address: 0x005486E0 (FUN_005486E0, Moho::ResourceDeposit::MemberDeserialize)
   *
   * What it does:
   * Loads one reflected `ResourceDeposit` payload from an archive by reading
   * the footprint rectangle first, then the resource-type lane at +0x10.
   */
  void ResourceDeposit::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedRect2iType(), this, ownerRef);
    archive->Read(CachedEResourceTypeType(), &depositType, ownerRef);
  }

  /**
   * Address: 0x00548760 (FUN_00548760, Moho::ResourceDeposit::MemberSerialize)
   *
   * What it does:
   * Writes one reflected `ResourceDeposit` payload into an archive by writing
   * the footprint rectangle lane first and the resource-type lane at +0x10
   * second.
   */
  void ResourceDeposit::MemberSerialize(gpg::WriteArchive* const archive)
  {
    const gpg::RRef footprintOwnerRef{};
    archive->Write(CachedRect2iType(), this, footprintOwnerRef);

    const gpg::RRef depositTypeOwnerRef{};
    archive->Write(CachedEResourceTypeType(), &depositType, depositTypeOwnerRef);
  }

  /**
   * Address: 0x00546170 (FUN_00546170, Moho::ResourceDeposit::Intersects)
   *
   * Moho::CGeomSolid3 const&, Moho::CHeightField const&
   *
   * What it does:
   * Samples terrain heights at the deposit rectangle corners, builds a world-space
   * AABB, and tests it against the clipping solid.
   */
  bool ResourceDeposit::Intersects(const CGeomSolid3& solid, const CHeightField& field) const
  {
    Wm3::AxisAlignedBox3f bounds{
      {std::numeric_limits<float>::max(), std::numeric_limits<float>::max(), std::numeric_limits<float>::max()},
      {-std::numeric_limits<float>::max(), -std::numeric_limits<float>::max(), -std::numeric_limits<float>::max()}
    };

    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x0, footprintRect.z0);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x0, footprintRect.z1);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x1, footprintRect.z0);
    ExtendBoundsWithTerrainCorner(bounds, field, footprintRect.x1, footprintRect.z1);
    return solid.Intersects(bounds);
  }

  /**
   * Address: 0x00545BD0 (FUN_00545BD0, Moho::ResourceDepositTypeInfo::ResourceDepositTypeInfo)
   */
  ResourceDepositTypeInfo::ResourceDepositTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(ResourceDeposit), this);
  }

  /**
   * Address: 0x00545C60 (FUN_00545C60, Moho::ResourceDepositTypeInfo::dtr)
   */
  ResourceDepositTypeInfo::~ResourceDepositTypeInfo() = default;

  /**
   * Address: 0x00545C50 (FUN_00545C50, Moho::ResourceDepositTypeInfo::GetName)
   */
  const char* ResourceDepositTypeInfo::GetName() const
  {
    return "ResourceDeposit";
  }

  /**
   * Address: 0x00545C30 (FUN_00545C30, Moho::ResourceDepositTypeInfo::Init)
   */
  void ResourceDepositTypeInfo::Init()
  {
    size_ = sizeof(ResourceDeposit);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC9650 (FUN_00BC9650, register_ResourceDepositTypeInfo)
   */
  void register_ResourceDepositTypeInfo()
  {
    (void)AcquireResourceDepositTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ResourceDepositTypeInfo_91baf4, moho::register_ResourceDepositTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<ResourceDeposit>`, vtable 0x00E1712C.
   *
   * Address: 0x00BC9670 (FUN_00BC9670 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4230 (FUN_00BF4230 -- the global's destructor.)
   * Address: 0x00545D30 (FUN_00545D30 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00547450 (FUN_00547450 -- `Init`.)
   * Address: 0x00545D10 (FUN_00545D10 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00545D20 (FUN_00545D20 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct ResourceDepositSerializer : gpg::SerSaveLoadHelper<ResourceDeposit>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ABEEC -- process-global `ResourceDepositSerializer` singleton.
  moho::ResourceDepositSerializer gResourceDepositSerializer;
} // namespace
