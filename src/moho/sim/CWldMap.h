#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "boost/shared_ptr.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/List.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/Map.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/VisibilityRect.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace gpg
{
  using StrArg = const char*;
  class BinaryReader;
  class BinaryWriter;
  class BitArray2D;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  struct CBackgroundTaskControl;
  class CHeightField;
  class Cartographic;
  class CWaterShaderProperties;
  class CD3DDynamicTextureSheet;
  class CDecalManager;
  struct CStratumMaterial;
  class CWldMap;
  class CWldTerrainRes;
  struct GeomCamera3;
  class IDecalManager;
  class ID3DTextureSheet;
  class IWldTerrainRes;
  class RD3DTextureResource;
  class SkyDome;
  class STIMap;
  class StratumMaterial;
  struct Vector4f;
  class WaveSystem;

  struct CWldPropEntry
  {
    msvc8::string mBlueprintPath; // +0x00
    VTransform mTransform;        // +0x1C
  };
  static_assert(offsetof(CWldPropEntry, mBlueprintPath) == 0x00, "CWldPropEntry::mBlueprintPath offset must be 0x00");
  static_assert(offsetof(CWldPropEntry, mTransform) == 0x1C, "CWldPropEntry::mTransform offset must be 0x1C");
  static_assert(sizeof(CWldPropEntry) == 0x38, "CWldPropEntry size must be 0x38");

  struct CWldProps
  {
    /**
     * Address: 0x008918E0 (FUN_008918E0,
     * ?Load@CWldProps@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Loads map prop descriptors into the pre-sized props-entry storage.
     */
    [[nodiscard]] bool Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl);

    /**
     * Address: 0x00891D50 (FUN_00891D50, ?Save@CWldProps@Moho@@QAE_NAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Saves all prop entries as blueprint path + position + rotation matrix
     * lanes in the world-map binary format.
     */
    [[nodiscard]] bool Save(gpg::BinaryWriter& writer) const;

    /**
     * Address: 0x008916A0 (FUN_008916A0, Moho::CWldProps::~CWldProps,
     * scalar-deleting variant)
     *
     * The whole object is one vector head: the proxy at `+0x00` and
     * `{_Myfirst, _Mylast, _Myend}` at `+0x04`, `+0x08`, `+0x0C`. The growth
     * cap the resize at 0x008922F0 checks is 0x04924924, which is
     * `0xFFFFFFFF / 0x38` for this element. 0x008916A0 tidies it and frees
     * the object: `delete props`.
     */
    msvc8::vector<CWldPropEntry> mEntries; // +0x00
  };
  static_assert(sizeof(CWldProps) == 0x10, "CWldProps size must be 0x10");

  /**
   * Address: 0x00892210 (FUN_00892210, ?WLD_CreateProps@Moho@@YAPAVCWldProps@1@XZ)
   *
   * What it does:
   * Allocates one `CWldProps` object and clears entry-storage pointer lanes.
   */
  [[nodiscard]] CWldProps* WLD_CreateProps();

  /**
   * Address: 0x00891330 (FUN_00891330,
   * ?WLD_LoadMapPreview@Moho@@YA?AV?$auto_ptr@VCWldMap@Moho@@@std@@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Heap-allocates one `CWldMap`, loads it in preview-only mode via `MapLoad`,
   * and returns the auto_ptr; if the load did not produce a preview chunk
   * (`mMapPreviewChunk == nullptr`), tears the map down and returns an empty
   * auto_ptr.
   */
  [[nodiscard]] msvc8::auto_ptr<CWldMap> WLD_LoadMapPreview(gpg::StrArg mapPath);

  /**
   * Address: 0x008A7B90 (FUN_008A7B90, ?WLD_CreateTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
   *
   * What it does:
   * Allocates one terrain-resource instance used by world map load/new flows.
   */
  [[nodiscard]] IWldTerrainRes* WLD_CreateTerrainRes();

  /**
   * Engine addition (dedicated-server plan WPL.4): the client's terrain resource
   * for WLD_CreateTerrainRes (`new CWldTerrainRes()`). moho/terrain/CWldTerrainRes.cpp
   * sets it during static initialisation.
   */
  using TerrainResFactoryHook = IWldTerrainRes* (*)();
  extern TerrainResFactoryHook sTerrainResFactory;

  /**
   * Engine addition (dedicated-server plan WPL.4): RWldMapPreviewChunk::Load's
   * preview texture, from the device resources: the texture sheet
   * `_mappreview.dds` made from `payload` (`payloadSize` bytes), or the fallback
   * texture when `payloadSize` is 0. moho/terrain/CWldTerrainRes.cpp sets it during
   * static initialisation; without a client a preview loads with no texture.
   */
  using PreviewTextureLoadHook = boost::shared_ptr<ID3DTextureSheet> (*)(char* payload, std::size_t payloadSize);
  extern PreviewTextureLoadHook sPreviewTextureLoad;

  /**
   * Engine addition (dedicated-server plan WPL.4): the terrain resource a map loads
   * into without a client (moho/sim/WldTerrainResHeadless.cpp). Its Load reads the
   * same terrain payload as CWldTerrainRes::Load and keeps only the map data the
   * simulation uses (STIMap: heightfield, terrain types, water); the sky, lighting,
   * strata, water shading, waves, decals and cartographic data are read and dropped.
   */
  [[nodiscard]] IWldTerrainRes* WLD_CreateHeadlessTerrainRes();

  struct RWldMapPreviewChunk
  {
    /**
     * Address: 0x008902E0 (FUN_008902E0, ??0RWldMapPreviewChunk@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes preview texture ownership, preview size metadata, and preview name to
     * an empty state.
     */
    RWldMapPreviewChunk();

    /**
     * Address: 0x00890350 (FUN_00890350)
     * Mangled: ??0RWldMapPreviewChunk@Moho@@QAE@V?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z
     *
     * What it does:
     * Captures the provided texture-sheet handle, preview size, and preview
     * display name into this chunk.
     */
    RWldMapPreviewChunk(
      boost::shared_ptr<ID3DTextureSheet> textureSheet, const Wm3::Vector2f& previewSize, const char* previewName
    );

    /**
     * Address: 0x00890420 (FUN_00890420, ??1RWldMapPreviewChunk@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases owned preview-name storage and drops preview texture ownership.
     */
    ~RWldMapPreviewChunk();

    /**
     * Address: 0x00890480 (FUN_00890480, ?GetTextureSheet@RWldMapPreviewChunk@Moho@@QAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture-sheet handle for this preview chunk.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetTextureSheet();

    /**
     * Address: 0x008904A0 (FUN_008904A0, ?GetTerrainDim@RWldMapPreviewChunk@Moho@@QBE?AV?$Vector2@M@Wm3@@XZ)
     *
     * What it does:
     * Returns stored preview terrain dimensions.
     */
    [[nodiscard]] Wm3::Vector2f GetTerrainDim() const;

    /**
     * Address: 0x008904B0 (FUN_008904B0, ?GetDescription@RWldMapPreviewChunk@Moho@@QBEPBDXZ)
     *
     * What it does:
     * Returns preview description text buffer pointer.
     */
    [[nodiscard]] const char* GetDescription() const;

    /**
     * Address: 0x008904C0 (FUN_008904C0,
     * ?Load@RWldMapPreviewChunk@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Loads preview metadata/blob data from stream and resolves a runtime texture
     * sheet handle for this chunk.
     */
    [[nodiscard]] bool Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl);

    /**
     * Address: 0x008908F0 (FUN_008908F0,
     * ?Save@RWldMapPreviewChunk@Moho@@QAE_NAAVBinaryWriter@gpg@@@Z)
     *
     * IDA signature:
     * bool __thiscall Moho::RWldMapPreviewChunk::Save(
     *     Moho::RWldMapPreviewChunk *this, gpg::BinaryWriter &writer);
     *
     * What it does:
     * Writes the preview-chunk header (`0xBEEFFEED` magic, version 2, preview
     * width/height, UTF-16 preview name including its terminator, and a
     * zero metadata-entry count), then re-encodes the retained preview texture
     * through the GAL backend into a memory buffer and appends it as a
     * size-prefixed blob. Returns false without writing the payload when no
     * runtime texture is bound.
     */
    [[nodiscard]] bool Save(gpg::BinaryWriter& writer);

    boost::shared_ptr<ID3DTextureSheet> mPreviewTexture; // +0x00
    Wm3::Vector2f mPreviewSize;                          // +0x08
    msvc8::string mPreviewName;                          // +0x10
  };
  static_assert(
    sizeof(boost::shared_ptr<ID3DTextureSheet>) == 0x08, "boost::shared_ptr<ID3DTextureSheet> size must be 0x08"
  );
  static_assert(
    offsetof(RWldMapPreviewChunk, mPreviewTexture) == 0x00, "RWldMapPreviewChunk::mPreviewTexture offset must be 0x00"
  );
  static_assert(
    offsetof(RWldMapPreviewChunk, mPreviewSize) == 0x08, "RWldMapPreviewChunk::mPreviewSize offset must be 0x08"
  );
  static_assert(
    offsetof(RWldMapPreviewChunk, mPreviewName) == 0x10, "RWldMapPreviewChunk::mPreviewName offset must be 0x10"
  );
  static_assert(sizeof(RWldMapPreviewChunk) == 0x2C, "RWldMapPreviewChunk size must be 0x2C");

  struct TerrainEnvironmentLookupEntry
  {
    /**
     * Address: 0x008A7C80 (FUN_008A7C80, `msvc8::map<msvc8::string,
     * TerrainEnvironmentLookupEntry>::operator[]` -- inlined default-value
     * construction on the lower-bound-miss path, before the fresh slot is
     * handed to `insert_hint`)
     *
     * What it does:
     * Default-constructs an empty environment-lookup slot: an empty SSO
     * environment name and a null texture handle. This is the value
     * `operator[]` inserts the first time a given environment key is seen;
     * `IWldTerrainRes::AddEnvLookup` immediately overwrites both fields.
     */
    TerrainEnvironmentLookupEntry() = default;

    /**
     * Address: 0x008A0A20 (FUN_008A0A20, ??0struct_Env@@QAE@@Z)
     *
     * What it does:
     * Stores one environment lookup name and one resolved terrain texture
     * resource handle.
     */
    TerrainEnvironmentLookupEntry(
      const msvc8::string& environmentName,
      boost::shared_ptr<RD3DTextureResource> texture
    );

    msvc8::string mEnvironmentName;                  // +0x00
    boost::shared_ptr<RD3DTextureResource> mTexture; // +0x1C
  };
  static_assert(
    offsetof(TerrainEnvironmentLookupEntry, mEnvironmentName) == 0x00,
    "TerrainEnvironmentLookupEntry::mEnvironmentName offset must be 0x00"
  );
  static_assert(
    offsetof(TerrainEnvironmentLookupEntry, mTexture) == 0x1C,
    "TerrainEnvironmentLookupEntry::mTexture offset must be 0x1C"
  );
  static_assert(sizeof(TerrainEnvironmentLookupEntry) == 0x24, "TerrainEnvironmentLookupEntry size must be 0x24");

  /**
   * Address: 0x004CD320 (FUN_004CD320, compiler-generated
   * `std::pair<msvc8::string,msvc8::string>::~pair()`)
   *
   * What it does:
   * Implicit pair destructor, member-destroyed in reverse declaration order:
   * tears down `second` (the `msvc8::string` at offset +0x1C, fields at
   * +0x34/+0x20/+0x30 relative to the pair) then `first` (offset +0x00,
   * fields at +0x18/+0x04/+0x14) -- releasing each string's heap buffer when
   * its capacity is >= 0x10 (the SSO threshold) and resetting it to the
   * empty-SSO state (`_Myres=0xF, _Mysize=0, buffer[0]=0`), matching the
   * inline-expanded form of `msvc8::string::tidy()` (FUN_00402740) applied
   * twice. No 2007 source line wrote this body -- it is the compiler's
   * implicit destructor for the pair, triggered wherever a
   * `TerrainEnvironmentLookupPair` is destroyed, e.g.
   * `EraseTerrainEnvironmentLookupPairRange`'s `pairs.erase(first, last)`
   * call in CWldMap.cpp (reached from `IWldTerrainRes::EnumerateEnvLookup`,
   * FUN_008A1500).
   */
  /**
   * The per-tile normal-map sheets at +0x948 of the terrain resource: an
   * `msvc8::vector` of texture handles whose emissions (`_Tidy`, `size`,
   * `capacity`, `reserve`, `_Copy_opt`, `erase`, `resize`) are cited on the
   * Vector.h members. The release build strips the debug proxy for this lane,
   * so the triple is 0x0C and the second template argument is `false`.
   */
  using TerrainNormalMapHandleArray = msvc8::vector<boost::shared_ptr<CD3DDynamicTextureSheet>, false>;
  static_assert(sizeof(TerrainNormalMapHandleArray) == 0x0C, "TerrainNormalMapHandleArray size must be 0x0C");

  /**
   * The environment-lookup cache at +0x9A4: a `std::map<std::string, entry>`
   * in the shipped binary, modeled with this project's ABI-matching
   * `msvc8::map` so the 12-byte header and 0x50-byte node stay where the
   * terrain resource needs them. Every tree mechanic (lower-bound search,
   * hinted insert, erase, in-order increment) is `msvc8::map`'s own
   * address-cited template member rather than a per-field reimplementation.
   */
  using TerrainEnvironmentLookupMap = msvc8::map<msvc8::string, TerrainEnvironmentLookupEntry>;
  static_assert(sizeof(TerrainEnvironmentLookupMap) == 0x0C, "TerrainEnvironmentLookupMap size must be 0x0C");

  /**
   * The edit-mode word buffer at +0x9B0: the `{proxy, begin, end, capacity}`
   * storage of a VC8 `std::vector<bool>`, which this tree models as
   * `msvc8::detail::vector_bool_storage`.
   */
  using TerrainEditWordBuffer = msvc8::detail::vector_bool_storage;
  static_assert(sizeof(TerrainEditWordBuffer) == 0x10, "TerrainEditWordBuffer size must be 0x10");

  /**
   * The debug dirty-rect list at +0x9D8. `{proxy, head, size}` with
   * `{next, prev, value}` nodes is a VC8 `std::list`, i.e. `msvc8::list`:
   * a 0x0C header and 0x18 nodes for a 0x10-byte `gpg::Rect2i`.
   */
  using TerrainDirtyRectList = msvc8::list<gpg::Rect2i>;
  static_assert(sizeof(TerrainDirtyRectList) == 0x0C, "TerrainDirtyRectList size must be 0x0C");

  using TerrainEnvironmentLookupPair = std::pair<msvc8::string, msvc8::string>;
  using TerrainEnvironmentLookupPairs = msvc8::vector<TerrainEnvironmentLookupPair>;
  static_assert(sizeof(TerrainEnvironmentLookupPair) == 0x38, "TerrainEnvironmentLookupPair size must be 0x38");

  struct SNormalMapInfo
  {
    float mXResolution;                                    // +0x00
    float mYResolution;                                    // +0x04
    float mScaleBiasX;                                     // +0x08
    float mScaleBiasY;                                     // +0x0C
    float mOffsetScaleX;                                   // +0x10
    float mOffsetScaleY;                                   // +0x14
    float mOffsetScaleZ;                                   // +0x18
    float mOffsetScaleW;                                   // +0x1C
    boost::shared_ptr<CD3DDynamicTextureSheet> mTexture; // +0x20
    float mTileOriginX;                                    // +0x28
    float mTileOriginY;                                    // +0x2C
    float mWidth;                                          // +0x30
    float mHeight;                                         // +0x34
  };
  static_assert(offsetof(SNormalMapInfo, mXResolution) == 0x00, "SNormalMapInfo::mXResolution offset must be 0x00");
  static_assert(offsetof(SNormalMapInfo, mYResolution) == 0x04, "SNormalMapInfo::mYResolution offset must be 0x04");
  static_assert(offsetof(SNormalMapInfo, mScaleBiasX) == 0x08, "SNormalMapInfo::mScaleBiasX offset must be 0x08");
  static_assert(offsetof(SNormalMapInfo, mScaleBiasY) == 0x0C, "SNormalMapInfo::mScaleBiasY offset must be 0x0C");
  static_assert(offsetof(SNormalMapInfo, mOffsetScaleX) == 0x10, "SNormalMapInfo::mOffsetScaleX offset must be 0x10");
  static_assert(offsetof(SNormalMapInfo, mOffsetScaleY) == 0x14, "SNormalMapInfo::mOffsetScaleY offset must be 0x14");
  static_assert(offsetof(SNormalMapInfo, mOffsetScaleZ) == 0x18, "SNormalMapInfo::mOffsetScaleZ offset must be 0x18");
  static_assert(offsetof(SNormalMapInfo, mOffsetScaleW) == 0x1C, "SNormalMapInfo::mOffsetScaleW offset must be 0x1C");
  static_assert(offsetof(SNormalMapInfo, mTexture) == 0x20, "SNormalMapInfo::mTexture offset must be 0x20");
  static_assert(offsetof(SNormalMapInfo, mTileOriginX) == 0x28, "SNormalMapInfo::mTileOriginX offset must be 0x28");
  static_assert(offsetof(SNormalMapInfo, mTileOriginY) == 0x2C, "SNormalMapInfo::mTileOriginY offset must be 0x2C");
  static_assert(offsetof(SNormalMapInfo, mWidth) == 0x30, "SNormalMapInfo::mWidth offset must be 0x30");
  static_assert(offsetof(SNormalMapInfo, mHeight) == 0x34, "SNormalMapInfo::mHeight offset must be 0x34");
  static_assert(sizeof(SNormalMapInfo) == 0x38, "SNormalMapInfo size must be 0x38");

  struct SFogInfo
  {
    float mStartDistance;                  // +0x00
    float mCutoffDistance;                 // +0x04
    float mMinClamp;                       // +0x08
    float mMaxClamp;                       // +0x0C
    float mCurveExponent;                  // +0x10
    std::uint8_t mUnknown14_2F[0x1C]{};    // +0x14
  };
  static_assert(sizeof(SFogInfo) == 0x30, "SFogInfo size must be 0x30");
  static_assert(offsetof(SFogInfo, mStartDistance) == 0x00, "SFogInfo::mStartDistance offset must be 0x00");
  static_assert(offsetof(SFogInfo, mCurveExponent) == 0x10, "SFogInfo::mCurveExponent offset must be 0x10");

  /**
   * Chart dimensions handed by value into `CWldTerrainRes::Reset`
   * (`?Reset@CWldTerrainRes@Moho@@EAE_NUSChartSize@2@PAVLuaState@LuaPlus@@@Z`).
   *
   * Layout evidence (0x008A6220):
   *  - `0x008A627A: mov ecx, [ebp+arg_0]` / `0x008A627D: mov esi, [ebp+arg_4]`
   *    feed `Moho::STIMap::STIMap(width, height)` at 0x008A6282 in that order,
   *    so `+0x00` is the width lane and `+0x04` is the height lane.
   *  - `0x008A6253: retn 0Ch` with one trailing `LuaPlus::LuaState*` argument
   *    pins the by-value struct at exactly two dwords.
   */
  struct SChartSize
  {
    std::int32_t mWidth;  // +0x00
    std::int32_t mHeight; // +0x04
  };
  static_assert(offsetof(SChartSize, mWidth) == 0x00, "SChartSize::mWidth offset must be 0x00");
  static_assert(offsetof(SChartSize, mHeight) == 0x04, "SChartSize::mHeight offset must be 0x04");
  static_assert(sizeof(SChartSize) == 0x08, "SChartSize size must be 0x08");

  /**
   * The terrain interface every consumer holds. Its vtable
   * (`??_7IWldTerrainRes@Moho@@6B@`, 0x00E4BC14) has its own destructor in
   * slot 0 and `_purecall` in the other 76; `CWldTerrainRes` is the only
   * implementation. The one field is the map it owns, at +0x04: a vfptr-only
   * base keeps it there, which is how the derived object can be 8-aligned
   * (through `WaveSystem`'s `fastvector_n`) and still read `[this+4]` as the
   * map.
   */
  class IWldTerrainRes
  {
  public:
    /**
     * Address: 0x0089E870 (FUN_0089E870, IWldTerrainRes scalar-deleting destructor)
     *
     * What it does:
     * Deletes the owned `mMap`.
     */
    virtual ~IWldTerrainRes();

    [[nodiscard]] virtual bool GetBool() const = 0;
    [[nodiscard]] virtual const Cartographic& GetCartographic() const = 0;
    [[nodiscard]] virtual Cartographic& GetCartographic() = 0;
    [[nodiscard]] virtual const SkyDome& GetSkyDome() const = 0;
    [[nodiscard]] virtual SkyDome& GetSkyDome() = 0;
    virtual void SetSkycube(const msvc8::string& texturePath) = 0;
    [[nodiscard]] virtual const msvc8::string& GetSkycubeFile() const = 0;
    [[nodiscard]] virtual boost::shared_ptr<ID3DTextureSheet> GetSkycube() const = 0;
    virtual void SetBackground(const msvc8::string& texturePath) = 0;
    [[nodiscard]] virtual const msvc8::string& GetBackgroundFile() const = 0;
    [[nodiscard]] virtual boost::shared_ptr<ID3DTextureSheet> GetBackground() const = 0;
    virtual void AddEnvLookup(const msvc8::string& environmentKey, const msvc8::string& texturePath) = 0;
    virtual void RemoveEnvLookup(const msvc8::string& environmentKey) = 0;
    [[nodiscard]] virtual boost::shared_ptr<ID3DTextureSheet> GetEnvLookup(const msvc8::string& environmentKey) const = 0;
    virtual void EnumerateEnvLookup(TerrainEnvironmentLookupPairs& outPairs) const = 0;
    virtual void ClearEnvLookup() = 0;
    virtual void SetTopographicSamples(std::int32_t sampleCount) = 0;
    [[nodiscard]] virtual std::int32_t GetTopographicSamples() const = 0;
    virtual void SetHypsometricColor(std::int32_t colorIndex, std::uint32_t colorValue) = 0;
    [[nodiscard]] virtual std::uint32_t GetHypsometricColor(std::int32_t colorIndex) const = 0;
    virtual void SetImagerElevationOffset(float elevationOffset) = 0;
    [[nodiscard]] virtual float GetImagerElevationOffset() const = 0;
    virtual bool Reset(SChartSize chartSize, LuaPlus::LuaState* state) = 0;
    [[nodiscard]] virtual Wm3::AxisAlignedBox3f GetWorldBounds() const = 0;
    [[nodiscard]] virtual StratumMaterial& GetStratumMaterial() = 0;
    [[nodiscard]] virtual WaveSystem* GetWaveSystem() = 0;
    virtual void UpdateWaveSystem(const GeomCamera3& camera, float elapsedSeconds, std::int32_t tick) = 0;
    [[nodiscard]] virtual boost::shared_ptr<ID3DTextureSheet> GetWaterMap() const = 0;
    virtual void UpdateWaterMap(const gpg::Rect2i& rect) = 0;
    virtual void UpdateWaterMap() = 0;
    [[nodiscard]] virtual Wm3::Vector2f GetWaterMapSize() const = 0;
    virtual void UpdateNormalMap(const gpg::Rect2i& rect) = 0;
    virtual void NotifyMapChange(const gpg::Rect2i& rect) = 0;
    [[nodiscard]] virtual gpg::BitArray2D* GetDebugDirtyTerrain() = 0;
    [[nodiscard]] virtual const msvc8::list<gpg::Rect2i>& GetDebugDirtyRects() const = 0;
    [[nodiscard]] virtual std::int32_t GetNormalMapCount() = 0;
    [[nodiscard]] virtual SNormalMapInfo GetNormalMapInfo(std::int32_t index) const = 0;
    virtual void UpdateStratumMask(
      std::int32_t stratumIndex,
      const std::uint8_t* sourceMask,
      std::int32_t columnStart,
      std::int32_t rowStart,
      std::int32_t columnEnd,
      std::int32_t rowEnd
    ) = 0;
    virtual void UpdateStratumMask(std::int32_t stratumIndex, const std::uint8_t* sourceMask) = 0;
    virtual void GetStratumMask(std::int32_t stratumIndex, std::uint8_t* outMask) = 0;
    [[nodiscard]] virtual float GetLightingMultiplier() const = 0;
    virtual void SetLightingMultiplier(const float& multiplier) = 0;
    [[nodiscard]] virtual Wm3::Vector3f GetSunDirection() const = 0;
    virtual void SetSunDirection(const Wm3::Vector3f& direction) = 0;
    [[nodiscard]] virtual Wm3::Vector3f GetSunAmbience() const = 0;
    virtual void SetSunAmbience(const Wm3::Vector3f& ambience) = 0;
    [[nodiscard]] virtual Wm3::Vector3f GetSunColor() const = 0;
    virtual void SetSunColor(const Wm3::Vector3f& color) = 0;
    [[nodiscard]] virtual Wm3::Vector3f GetShadowFillColor() const = 0;
    virtual void SetShadowFillColor(const Wm3::Vector3f& color) = 0;
    [[nodiscard]] virtual Vector4f GetSpecularColor() const = 0;
    virtual void SetSpecularColor(const Vector4f& color) = 0;
    [[nodiscard]] virtual float GetBloom() const = 0;
    virtual void SetBloom(float bloom) = 0;
    [[nodiscard]] virtual const SFogInfo& GetFogInfo() const = 0;
    virtual void SetFogInfo(const SFogInfo& fogInfo) = 0;
    virtual void WaterEnabled(bool enabled) = 0;
    virtual void SetWaterElevation(float elevation) = 0;
    virtual void SetWaterElevationDeep(float elevation) = 0;
    virtual void SetWaterElevationAbyss(float elevation) = 0;
    [[nodiscard]] virtual bool SetPlayableMapRect(const VisibilityRect& rect) = 0;
    [[nodiscard]] virtual const VisibilityRect* GetPlayableMapRect(VisibilityRect& outRect) const = 0;
    [[nodiscard]] virtual bool IsInPlayableRect(const Wm3::Vec3f& worldPos) = 0;
    virtual void SetWaterShaderProperties(const CWaterShaderProperties& properties) = 0;
    [[nodiscard]] virtual CWaterShaderProperties* GetWaterShaderProperties() = 0;
    [[nodiscard]] virtual std::uint8_t* GetWaterFoam() = 0;
    [[nodiscard]] virtual std::uint8_t* GetWaterFlatness() = 0;
    [[nodiscard]] virtual std::uint8_t* GetWaterDepthBias() = 0;
    [[nodiscard]] virtual bool IsInEditMode() const = 0;
    virtual void EnterEditMode(CBackgroundTaskControl& loadControl) = 0;
    virtual void ExitEditMode() = 0;
    virtual void SyncTerrain(const CHeightField* source) = 0;
    [[nodiscard]]
    virtual bool Load(gpg::BinaryReader& reader, LuaPlus::LuaState* state, CBackgroundTaskControl& loadControl) = 0;
    virtual bool Save(gpg::BinaryWriter& writer) = 0;
    [[nodiscard]] virtual bool Finalize() = 0;
    [[nodiscard]] virtual IDecalManager* GetDecalManager() = 0;

  protected:
    /**
     * Address: 0x008A74D0 (FUN_008A74D0, IWldTerrainRes ctor lane)
     *
     * What it does:
     * Initializes one terrain-resource interface base and clears playable-rect
     * source ownership to null.
     */
    IWldTerrainRes();

  public:
    /**
     * Not a distinct binary function - every caller inlines the same
     * `mMap->mHeightField.get()` chase (`IWldTerrainRes+0x04` ->
     * `STIMap+0x00`), `CUIWorldView`'s build-drag adjacency pass
     * (`sub_854B70`) among them.
     */
    [[nodiscard]] CHeightField* GetHeightField() const;

    /**
     * Not a distinct binary function - every caller inlines the same
     * `mMap->mWaterEnabled` field read.
     * Promoted to a public accessor for the same reason as `GetHeightField()`.
     */
    [[nodiscard]] bool IsWaterEnabled() const;

    /**
     * Not a distinct binary function - every caller inlines the same
     * `mMap->mWaterElevation` field read.
     * Promoted to a public accessor for the same reason as `GetHeightField()`.
     */
    [[nodiscard]] float GetWaterElevation() const;

    /**
     * Address: 0x00811210 (FUN_00811210, Moho::CWldTerrainRes::GetHeightAt)
     *
     * What it does:
     * Returns one clamped terrain height sample at `(x,z)` converted from
     * 16-bit height words into world height units (`* 1/128`).
     */
    [[nodiscard]] float GetHeightAt(std::int32_t x, std::int32_t z) const;

    /**
     * The terrain's map data, owned by this interface: `~IWldTerrainRes`
     * deletes it, `GetPlayableMapRect` reads `mPlayableRect` out of it at
     * +0x08, and every consumer that reaches `[terrainRes+0x04]` in the binary
     * - the cartographic view, the splat and clutter passes, the map imager,
     * the console's map queries - follows it straight into `STIMap`.
     */
    STIMap* mMap;                                          // +0x004
  };

  /**
   * Recovered owning layout for CWldMap.
   * Preview chunk, terrain resource, and world props ownership are tracked as
   * three adjacent pointers.
   */
  class CWldMap
  {
  public:
    /**
     * Address: 0x00890C70 (FUN_00890C70, ??1CWldMap@Moho@@QAE@XZ)
     *
     * What it does:
     * Resets owned map resources, then performs guarded teardown of any
     * remaining preview/terrain/props pointers.
     */
    ~CWldMap();

    /**
     * Address: 0x00890D40 (FUN_00890D40, ?MapNew@CWldMap@Moho@@QAE_NHHPAVLuaState@LuaPlus@@@Z)
     *
     * What it does:
     * Creates fresh terrain/props resources for a new map and resets prior
     * owned state.
     */
    [[nodiscard]] bool MapNew(std::int32_t width, std::int32_t height, LuaPlus::LuaState* state);

    /**
     * Address: 0x00890DA0 (FUN_00890DA0)
     * (?MapLoad@CWldMap@Moho@@QAE_NVStrArg@gpg@@PAVLuaState@LuaPlus@@_NAAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Loads map preview + terrain + props from disk stream with staged load
     * progress updates.
     */
    [[nodiscard]]
    bool MapLoad(gpg::StrArg mapName, LuaPlus::LuaState* state, bool previewOnly, CBackgroundTaskControl& loadControl);

    /**
     * Address: 0x00891030 (FUN_00891030, ?MapSave@CWldMap@Moho@@QAE_NVStrArg@gpg@@@Z)
     *
     * IDA signature:
     * bool __thiscall Moho::CWldMap::MapSave(Moho::CWldMap *this, gpg::StrArg mapName);
     *
     * What it does:
     * Resolves `mapName` to a writable on-disk path through the virtual file
     * system (mounted directory prefix + `\` + base name), opens it for
     * writing, emits the `Map\x1A` / version-2 file header, then saves the
     * preview chunk, the terrain resource and the prop set through the same
     * `gpg::BinaryWriter`. Returns false when any owned map resource is missing
     * or the destination stream cannot be opened.
     */
    [[nodiscard]] bool MapSave(gpg::StrArg mapName);

    /**
     * Address: 0x00891250 (FUN_00891250, ?MapSetPreview@CWldMap@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z)
     *
     * What it does:
     * Replaces the owned preview chunk with one built from the provided
     * texture/size/name lane and destroys any previous chunk.
     */
    void
    MapSetPreview(boost::shared_ptr<ID3DTextureSheet> textureSheet, const Wm3::Vector2f& previewSize, const char* previewName);

  private:
    /**
     * Address: 0x00890CF0 (FUN_00890CF0, ?Reset@CWldMap@Moho@@AAEXXZ)
     *
     * What it does:
     * Releases and clears all owned preview/terrain/props resources.
     */
    void Reset();

  public:
    RWldMapPreviewChunk* mMapPreviewChunk; // +0x00
    IWldTerrainRes* mTerrainRes;           // +0x04
    CWldProps* mProps;                     // +0x08
  };
  static_assert(offsetof(CWldMap, mMapPreviewChunk) == 0x00, "CWldMap::mMapPreviewChunk offset must be 0x00");
  static_assert(offsetof(CWldMap, mTerrainRes) == 0x04, "CWldMap::mTerrainRes offset must be 0x04");
  static_assert(offsetof(CWldMap, mProps) == 0x08, "CWldMap::mProps offset must be 0x08");
  static_assert(sizeof(CWldMap) == 0x0C, "CWldMap size must be 0x0C");
} // namespace moho
