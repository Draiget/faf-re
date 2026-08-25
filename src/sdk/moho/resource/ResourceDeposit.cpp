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

  alignas(moho::ResourceDepositTypeInfo) unsigned char
    gResourceDepositTypeInfoStorage[sizeof(moho::ResourceDepositTypeInfo)]{};
  bool gResourceDepositTypeInfoConstructed = false;

  /**
   * Demangled: Moho::ResourceDepositSerializer
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='ResourceDepositSerializer@Moho'`): `FUN_00BC9670` (real,
   * `__xc_a`-reachable) vs. a dead zero-xref duplicate at `FUN_00545D30`
   * (same field writes, no `atexit` call, confirmed via raw asm never
   * live). Confirmed via raw asm: the real ctor default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_00545D10`/`FUN_00545D20` (thin forwarders into
   * `ResourceDeposit::MemberDeserialize`/`MemberSerialize`), installs the
   * `ResourceDepositSerializer` vtable, and pushes the real mangled
   * destructor `??1ResourceDepositSerializer@Moho@@QAE@@Z` (`FUN_00BF4230`,
   * confirmed unlink-then-self-link shape matching `SerHelperBase::
   * ResetLinks()`) as its `atexit` target -- no eager `RegisterSerializeFunctions`/
   * `Init()` call exists in the real ctor. Two zero-xref duplicate
   * emissions of that unlink logic (`FUN_00545D60`, `FUN_00545D90`,
   * formerly `CleanupResourceDepositSerializerHelperNodePrimary/Secondary`)
   * are dead ICF twins, sha256-identical to the real destructor.
   *
   * Not a `gpg::SerSaveLoadHelper<ResourceDeposit>` instantiation: this
   * class's own leaf Deserialize/Serialize bodies forward to
   * `ResourceDeposit::MemberDeserialize`/`MemberSerialize`, which are
   * themselves `static` free-style methods taking an explicit object
   * pointer (not the `void MemberDeserialize(archive)` instance-method
   * shape the generic template expects) -- kept as its own concrete class,
   * same precedent as `Box3fSerializer`/`CSimResourcesSerializer`.
   */
  class ResourceDepositSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9670 (FUN_00BC9670, dynamic initializer for the global
     * `ResourceDepositSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    ResourceDepositSerializer();

    /**
     * Address: 0x00BF4230 (FUN_00BF4230, Moho::ResourceDepositSerializer::~ResourceDepositSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~ResourceDepositSerializer();

    /**
     * Address: 0x00545D10 (FUN_00545D10, Moho::ResourceDepositSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load requests into `ResourceDeposit::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00545D20 (FUN_00545D20, Moho::ResourceDepositSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save requests into `ResourceDeposit::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00547450 (FUN_00547450, gpg::SerSaveLoadHelper_ResourceDeposit::Init)
     *
     * What it does:
     * Lazily resolves and caches `ResourceDeposit` RTTI on
     * `ResourceDeposit::sType`, then binds load/save serializer callbacks
     * into it. Confirmed via raw asm: this address reads/writes
     * `Moho__ResourceDeposit__sType` directly (a genuine static member,
     * previously missing from the recovered `ResourceDeposit` struct) --
     * matches the `SerSaveLoadHelper<T>::Init()` generic caching shape
     * exactly, including the same `"!type->mSerLoadFunc"`/
     * `"!type->mSerSaveFunc"` assert strings at
     * `gpgcore/reflection/serialization.h` lines 84/87 used by every other
     * confirmed instantiation. `ArchiveSerialization.cpp` currently cites
     * this SAME address for a different, incompatible generic dispatcher
     * (`InstallMohoResourceDepositSerializerCallbacks`); removed there.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };
  static_assert(
    offsetof(ResourceDepositSerializer, mLoadCallback) == 0x0C,
    "ResourceDepositSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ResourceDepositSerializer, mSaveCallback) == 0x10,
    "ResourceDepositSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ResourceDepositSerializer) == 0x14, "ResourceDepositSerializer size must be 0x14");

  // Address: 0x010ABEEC -- process-global `ResourceDepositSerializer`
  // singleton (constructed by FUN_00BC9670, self-registering via `__xc_a`).
  ResourceDepositSerializer gResourceDepositSerializer;

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

  /**
   * Address: 0x00545D10 (FUN_00545D10, Moho::ResourceDepositSerializer::Deserialize)
   */
  void ResourceDepositSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const object = reinterpret_cast<moho::ResourceDeposit*>(static_cast<std::uintptr_t>(objectPtr));
    moho::ResourceDeposit::MemberDeserialize(object, archive);
  }

  /**
   * Address: 0x00545D20 (FUN_00545D20, Moho::ResourceDepositSerializer::Serialize)
   */
  void ResourceDepositSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const object = reinterpret_cast<moho::ResourceDeposit*>(static_cast<std::uintptr_t>(objectPtr));
    moho::ResourceDeposit::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00547450 (FUN_00547450, gpg::SerSaveLoadHelper_ResourceDeposit::Init)
   */
  void ResourceDepositSerializer::Init()
  {
    if (moho::ResourceDeposit::sType == nullptr) {
      moho::ResourceDeposit::sType = gpg::LookupRType(typeid(moho::ResourceDeposit));
    }

    gpg::RType* const type = moho::ResourceDeposit::sType;
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", kSerializationLoadLine, kSerializationSourcePath);
    }
    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serLoadFunc_ = mLoadCallback;
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BC9670 (FUN_00BC9670, dynamic initializer for the global
   * `ResourceDepositSerializer` singleton)
   */
  ResourceDepositSerializer::ResourceDepositSerializer()
    : mLoadCallback(&ResourceDepositSerializer::Deserialize)
    , mSaveCallback(&ResourceDepositSerializer::Serialize)
  {}

  ResourceDepositSerializer::~ResourceDepositSerializer()
  {
    ResetLinks();
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
  void ResourceDeposit::MemberDeserialize(ResourceDeposit* const object, gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedRect2iType(), object, ownerRef);
    archive->Read(CachedEResourceTypeType(), &object->depositType, ownerRef);
  }

  /**
   * Address: 0x00548760 (FUN_00548760, Moho::ResourceDeposit::MemberSerialize)
   *
   * What it does:
   * Writes one reflected `ResourceDeposit` payload into an archive by writing
   * the footprint rectangle lane first and the resource-type lane at +0x10
   * second.
   */
  void ResourceDeposit::MemberSerialize(ResourceDeposit* const object, gpg::WriteArchive* const archive)
  {
    const gpg::RRef footprintOwnerRef{};
    archive->Write(CachedRect2iType(), object, footprintOwnerRef);

    const gpg::RRef depositTypeOwnerRef{};
    archive->Write(CachedEResourceTypeType(), &object->depositType, depositTypeOwnerRef);
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
    (void)std::atexit(&cleanup_ResourceDepositTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ResourceDepositTypeInfo_91baf4, moho::register_ResourceDepositTypeInfo)
