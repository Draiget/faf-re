#include "ResourceDeposit.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/resource/EResourceTypeTypeInfo.h"
#include "moho/sim/STIMap.h"

namespace
{
  constexpr float kTerrainHeightWordScale = 1.0f / 128.0f;

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

  alignas(moho::ResourceDepositTypeInfo) unsigned char
    gResourceDepositTypeInfoStorage[sizeof(moho::ResourceDepositTypeInfo)]{};
  bool gResourceDepositTypeInfoConstructed = false;

  [[nodiscard]] moho::ResourceDepositTypeInfo& AcquireResourceDepositTypeInfo()
  {
    if (!gResourceDepositTypeInfoConstructed) {
      new (gResourceDepositTypeInfoStorage) moho::ResourceDepositTypeInfo();
      gResourceDepositTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::ResourceDepositTypeInfo*>(gResourceDepositTypeInfoStorage);
  }

  void cleanup_ResourceDepositTypeInfo()
  {
    if (!gResourceDepositTypeInfoConstructed) {
      return;
    }

    AcquireResourceDepositTypeInfo().~ResourceDepositTypeInfo();
    gResourceDepositTypeInfoConstructed = false;
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

namespace moho
{
  /**
   * Address: 0x005486E0 (FUN_005486E0, Moho::ResourceDeposit::MemberDeserialize)
   *
   * What it does:
   * Loads one reflected `ResourceDeposit` payload from an archive by reading
   * the footprint rectangle first, then the resource-type lane at +0x10.
   */
  void ResourceDeposit::MemberDeserialize(ResourceDeposit* const object, gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedRect2iType(), object, ownerRef);
    archive->Read(CachedEResourceTypeType(), &object->depositType, ownerRef);
  }

  /**
   * Address: 0x00546170 (Moho::ResourceDeposit::Intersects)
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
    (void)std::atexit(&cleanup_ResourceDepositTypeInfo);
  }
} // namespace moho
