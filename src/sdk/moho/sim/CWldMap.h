#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

#include "boost/shared_ptr.h"
#include "legacy/containers/List.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
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
  class CWldTerrainRes;
  struct GeomCamera3;
  class IDecalManager;
  class ID3DTextureSheet;
  class IWldTerrainRes;
  class RD3DTextureResource;
  class SkyDome;
  class StratumMaterial;
  struct Vector4f;
  class WaveSystem;

  struct CWldPropEntry
  {
    msvc8::string mBlueprintPath; // +0x00
    float mTransformData[7];      // +0x1C
  };
  static_assert(offsetof(CWldPropEntry, mBlueprintPath) == 0x00, "CWldPropEntry::mBlueprintPath offset must be 0x00");
  static_assert(offsetof(CWldPropEntry, mTransformData) == 0x1C, "CWldPropEntry::mTransformData offset must be 0x1C");
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

    std::uint32_t mUnknown00;           // +0x00
    CWldPropEntry* mEntriesBegin;       // +0x04
    CWldPropEntry* mEntriesEnd;         // +0x08
    CWldPropEntry* mEntriesCapacityEnd; // +0x0C
  };
  static_assert(offsetof(CWldProps, mEntriesBegin) == 0x04, "CWldProps::mEntriesBegin offset must be 0x04");
  static_assert(offsetof(CWldProps, mEntriesEnd) == 0x08, "CWldProps::mEntriesEnd offset must be 0x08");
  static_assert(offsetof(CWldProps, mEntriesCapacityEnd) == 0x0C, "CWldProps::mEntriesCapacityEnd offset must be 0x0C");
  static_assert(sizeof(CWldProps) == 0x10, "CWldProps size must be 0x10");

  /**
   * Address: 0x00892210 (FUN_00892210, ?WLD_CreateProps@Moho@@YAPAVCWldProps@1@XZ)
   *
   * What it does:
   * Allocates one `CWldProps` object and clears entry-storage pointer lanes.
   */
  [[nodiscard]] CWldProps* WLD_CreateProps();

  /**
   * Address: 0x008A7B90 (FUN_008A7B90, ?WLD_CreateTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
   *
   * What it does:
   * Allocates one terrain-resource instance used by world map load/new flows.
   */
  [[nodiscard]] IWldTerrainRes* WLD_CreateTerrainRes();

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

  using TerrainEnvironmentLookupPair = std::pair<msvc8::string, msvc8::string>;
  using TerrainEnvironmentLookupPairs = msvc8::vector<TerrainEnvironmentLookupPair>;
  static_assert(sizeof(TerrainEnvironmentLookupPair) == 0x38, "TerrainEnvironmentLookupPair size must be 0x38");

  struct TerrainPlayableRectSource
  {
    std::uint8_t pad_0000_0008[0x08];
    VisibilityRect mPlayableRect; // 0x08
  };
  static_assert(
    offsetof(TerrainPlayableRectSource, mPlayableRect) == 0x08,
    "TerrainPlayableRectSource::mPlayableRect offset must be 0x08"
  );

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
   * Recovered leading layout for IWldTerrainRes.
   * Only fields used by 0x0089E710 are mapped here.
   */
  class IWldTerrainRes
  {
  public:
    /**
     * Address: 0x008A74D0 (FUN_008A74D0, IWldTerrainRes ctor lane)
     *
     * What it does:
     * Initializes one terrain-resource interface base and clears playable-rect
     * source ownership to null.
     */
    IWldTerrainRes();

    virtual ~IWldTerrainRes() = default;

    /**
     * Address: 0x008A1700 (CWldTerrainRes::Load implementation path)
     *
     * What it does:
     * Loads terrain map data from stream payload and initializes runtime
     * terrain state for the active world map.
     */
    [[nodiscard]]
    virtual bool Load(gpg::BinaryReader& reader, LuaPlus::LuaState* state, CBackgroundTaskControl& loadControl) = 0;

    /**
     * Address: 0x0089E710 (FUN_0089E710, ?GetPlayableMapRect@IWldTerrainRes@Moho@@UBE?AV?$Rect2@H@gpg@@XZ)
     *
     * What it does:
     * Copies playable map bounds from terrain-res internal storage into `outRect`
     * and returns `&outRect`.
     */
    [[nodiscard]] const VisibilityRect* GetPlayableMapRect(VisibilityRect& outRect) const;

    /**
     * Address: 0x008A6DA0 (FUN_008A6DA0, ?SetPlayableMapRect@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Writes one playable-map rectangle through the owned terrain map and emits
     * warning text when bounds are invalid.
     */
    [[nodiscard]] bool SetPlayableMapRect(const VisibilityRect& rect);

    /**
     * Address: 0x008A6DD0 (FUN_008A6DD0, ?IsInPlayableRect@CWldTerrainRes@Moho@@EAE_NABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Checks whether one world-space position lies inside the playable map
     * rectangle bounds.
     */
    [[nodiscard]] bool IsInPlayableRect(const Wm3::Vec3f& worldPos);

    /**
     * Address: 0x008A1080 (FUN_008A1080, ?SetBackground@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Stores terrain background texture path and resolves the corresponding D3D
     * texture resource handle.
     */
    void SetBackground(const msvc8::string& texturePath);

    /**
     * Address: 0x008A11C0 (FUN_008A11C0, ?SetSkycube@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Stores terrain skycube texture path and resolves the corresponding D3D
     * texture resource handle.
     */
    void SetSkycube(const msvc8::string& texturePath);

    /**
     * Address: 0x008A1190 (FUN_008A1190, ?GetBackground@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for terrain background.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetBackground() const;

    /**
     * Address: 0x008A12D0 (FUN_008A12D0, ?GetSkycube@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for terrain skycube.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetSkycube() const;

    /**
     * Address: 0x008A1300
     * (FUN_008A1300, ?AddEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z)
     *
     * What it does:
     * Resolves one environment texture path and upserts it into the
     * terrain environment-lookup map keyed by environment id.
     */
    virtual void AddEnvLookup(const msvc8::string& environmentKey, const msvc8::string& texturePath);

    /**
     * Address: 0x008A13F0
     * (FUN_008A13F0, ?RemoveEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Removes one environment-lookup map entry by key when present.
     */
    virtual void RemoveEnvLookup(const msvc8::string& environmentKey);

    /**
     * Address: 0x008A1430
     * (FUN_008A1430, ?GetEnvLookup@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Returns one environment texture handle by key, with `<default>` fallback.
     */
    [[nodiscard]] virtual boost::shared_ptr<ID3DTextureSheet> GetEnvLookup(const msvc8::string& environmentKey) const;

    /**
     * Address: 0x008A1500
     * (FUN_008A1500, ?EnumerateEnvLookup@CWldTerrainRes@Moho@@UBEXAAV?$vector@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@@2@@std@@@Z)
     *
     * What it does:
     * Rebuilds caller-provided list with all environment-key/name pairs in map order.
     */
    virtual void EnumerateEnvLookup(TerrainEnvironmentLookupPairs& outPairs) const;

    /**
     * Address: 0x008A1640
     * (FUN_008A1640, ?ClearEnvLookup@CWldTerrainRes@Moho@@UAEXXZ)
     *
     * What it does:
     * Clears all environment-lookup entries and resets map head links to empty.
     */
    virtual void ClearEnvLookup();

    /**
     * Address: 0x008A1030 (FUN_008A1030, Moho::CWldTerrainRes::GetBool)
     *
     * What it does:
     * Returns the terrain runtime boolean lane at `+0x08`.
     */
    [[nodiscard]] bool GetBool() const;

    /**
     * Address: 0x008A1040 (FUN_008A1040, ?GetCartographic@CWldTerrainRes@Moho@@UAEAAVCartographic@2@XZ)
     *
     * What it does:
     * Returns mutable access to terrain cartographic runtime state.
     */
    [[nodiscard]] Cartographic& GetCartographic();

    /**
     * Address: 0x008A1050 (FUN_008A1050, ?GetCartographic@CWldTerrainRes@Moho@@UBEABVCartographic@2@XZ)
     *
     * What it does:
     * Returns read-only access to terrain cartographic runtime state.
     */
    [[nodiscard]] const Cartographic& GetCartographic() const;

    /**
     * Address: 0x008A1060 (FUN_008A1060, ?GetSkyDome@CWldTerrainRes@Moho@@UAEAAVSkyDome@2@XZ)
     *
     * What it does:
     * Returns mutable access to terrain skydome runtime state.
     */
    [[nodiscard]] SkyDome& GetSkyDome();

    /**
     * Address: 0x008A1070 (FUN_008A1070, ?GetSkyDome@CWldTerrainRes@Moho@@UBEABVSkyDome@2@XZ)
     *
     * What it does:
     * Returns read-only access to terrain skydome runtime state.
     */
    [[nodiscard]] const SkyDome& GetSkyDome() const;

    /**
     * Address: 0x008A1680 (FUN_008A1680, ?SetTopographicSamples@CWldTerrainRes@Moho@@UAEXH@Z)
     *
     * What it does:
     * Sets the active topographic sample-count lane.
     */
    void SetTopographicSamples(std::int32_t sampleCount);

    /**
     * Address: 0x008A1690 (FUN_008A1690, ?GetTopographicSamples@CWldTerrainRes@Moho@@UBEHXZ)
     *
     * What it does:
     * Returns the active topographic sample-count lane.
     */
    [[nodiscard]] std::int32_t GetTopographicSamples() const;

    /**
     * Address: 0x008A16A0
     * (FUN_008A16A0, ?SetHypsometricColor@CWldTerrainRes@Moho@@UAEXW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@I@Z)
     *
     * What it does:
     * Writes one indexed hypsometric color lane.
     */
    void SetHypsometricColor(std::int32_t colorIndex, std::uint32_t colorValue);

    /**
     * Address: 0x008A16C0
     * (FUN_008A16C0, ?GetHypsometricColor@CWldTerrainRes@Moho@@UBEIW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@@Z)
     *
     * What it does:
     * Returns one indexed hypsometric color lane.
     */
    [[nodiscard]] std::uint32_t GetHypsometricColor(std::int32_t colorIndex) const;

    /**
     * Address: 0x008A16D0 (FUN_008A16D0, ?SetImagerElevationOffset@CWldTerrainRes@Moho@@UAEXM@Z)
     *
     * What it does:
     * Sets the terrain imager elevation offset lane.
     */
    void SetImagerElevationOffset(float elevationOffset);

    /**
     * Address: 0x008A16F0 (FUN_008A16F0, ?GetImagerElevationOffset@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns the terrain imager elevation offset lane.
     */
    [[nodiscard]] float GetImagerElevationOffset() const;

    /**
     * Address: 0x008A5010 (FUN_008A5010, ?GetWaveSystem@CWldTerrainRes@Moho@@EAEPAVWaveSystem@2@XZ)
     *
     * What it does:
     * Returns the owned terrain wave-system object.
     */
    [[nodiscard]] WaveSystem* GetWaveSystem();

    /**
     * Address: 0x008A5040 (FUN_008A5040, ?GetWaterMap@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for the terrain water map.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetWaterMap() const;

    /**
     * Address: 0x008A5070 (FUN_008A5070, ?GetWaterMapSize@CWldTerrainRes@Moho@@UBE?AV?$Vector2@M@Wm3@@XZ)
     *
     * What it does:
     * Returns half-resolution terrain water-map dimensions derived from the
     * backing heightfield (`(width - 1) / 2`, `(height - 1) / 2`).
     */
    [[nodiscard]] Wm3::Vector2f GetWaterMapSize() const;

    /**
     * Address: 0x008A5020 (FUN_008A5020, ?UpdateWaveSystem@CWldTerrainRes@Moho@@UAEXABVGeomCamera3@2@MH@Z)
     *
     * What it does:
     * Forwards one camera/timestep update into terrain wave simulation.
     */
    void UpdateWaveSystem(const GeomCamera3& camera, float elapsedSeconds, std::int32_t tick);

    /**
     * Address: 0x008A54B0 (FUN_008A54B0, ?GetDebugDirtyTerrain@CWldTerrainRes@Moho@@EAEPAVBitArray2D@gpg@@XZ)
     *
     * What it does:
     * Returns debug dirty-region bitmask storage.
     */
    [[nodiscard]] gpg::BitArray2D* GetDebugDirtyTerrain();

    /**
     * Address: 0x008A54C0 (FUN_008A54C0, ?GetDebugDirtyRects@CWldTerrainRes@Moho@@UBEABV?$list@V?$Rect2@H@gpg@@V?$allocator@V?$Rect2@H@gpg@@@std@@@std@@XZ)
     *
     * What it does:
     * Returns the debug dirty-rectangle list lane.
     */
    [[nodiscard]] const msvc8::list<gpg::Rect2i>& GetDebugDirtyRects() const;

    /**
     * Address: 0x008A5FB0 (FUN_008A5FB0, ?GetNormalMapCount@CWldTerrainRes@Moho@@EAEHXZ)
     *
     * What it does:
     * Returns number of active normal-map tile handles.
     */
    [[nodiscard]] std::int32_t GetNormalMapCount();

    /**
     * Address: 0x00811210 (FUN_00811210, Moho::CWldTerrainRes::GetHeightAt)
     *
     * What it does:
     * Returns one clamped terrain height sample at `(x,z)` converted from
     * 16-bit height words into world height units (`* 1/128`).
     */
    [[nodiscard]] float GetHeightAt(std::int32_t x, std::int32_t z) const;

    /**
     * Address: 0x008A6A60 (FUN_008A6A60, ?GetWorldBounds@CWldTerrainRes@Moho@@EBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns terrain world-space bounds derived from the map heightfield.
     */
    [[nodiscard]] Wm3::AxisAlignedBox3f GetWorldBounds() const;

    /**
     * Address: 0x008A6AB0 (FUN_008A6AB0, ?GetLightingMultiplier@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns terrain lighting multiplier.
     */
    [[nodiscard]] float GetLightingMultiplier() const;

    /**
     * Address: 0x008A6AC0 (FUN_008A6AC0, ?SetLightingMultiplier@CWldTerrainRes@Moho@@EAEXABM@Z)
     *
     * What it does:
     * Sets terrain lighting multiplier.
     */
    void SetLightingMultiplier(const float& multiplier);

    /**
     * Address: 0x008A6AD0 (FUN_008A6AD0, ?GetSunDirection@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun direction vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunDirection() const;

    /**
     * Address: 0x008A6B00 (FUN_008A6B00, ?SetSunDirection@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun direction vector.
     */
    void SetSunDirection(const Wm3::Vector3f& direction);

    /**
     * Address: 0x008A6B30 (FUN_008A6B30, ?GetSunAmbience@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun ambience vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunAmbience() const;

    /**
     * Address: 0x008A6B60 (FUN_008A6B60, ?SetSunAmbience@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun ambience vector.
     */
    void SetSunAmbience(const Wm3::Vector3f& ambience);

    /**
     * Address: 0x008A6B90 (FUN_008A6B90, ?GetSpecularColor@CWldTerrainRes@Moho@@EBE?AVVector4f@2@XZ)
     *
     * What it does:
     * Returns terrain specular color vector.
     */
    [[nodiscard]] Vector4f GetSpecularColor() const;

    /**
     * Address: 0x008A6BC0 (FUN_008A6BC0, ?SetSpecularColor@CWldTerrainRes@Moho@@EAEXABVVector4f@2@@Z)
     *
     * What it does:
     * Sets terrain specular color vector.
     */
    void SetSpecularColor(const Vector4f& color);

    /**
     * Address: 0x008A6BF0 (FUN_008A6BF0, ?GetBloom@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns terrain bloom strength lane.
     */
    [[nodiscard]] float GetBloom() const;

    /**
     * Address: 0x008A6C00 (FUN_008A6C00, ?SetBloom@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets terrain bloom strength lane.
     */
    void SetBloom(float bloom);

    /**
     * Address: 0x008A6C20 (FUN_008A6C20, ?GetFogInfo@CWldTerrainRes@Moho@@EBEABUSFogInfo@2@XZ)
     *
     * What it does:
     * Returns read-only terrain fog parameter block.
     */
    [[nodiscard]] const SFogInfo& GetFogInfo() const;

    /**
     * Address: 0x008A6C30 (FUN_008A6C30, ?SetFogInfo@CWldTerrainRes@Moho@@EAEXABUSFogInfo@2@@Z)
     *
     * What it does:
     * Updates primary terrain fog parameter lanes.
     */
    void SetFogInfo(const SFogInfo& fogInfo);

    /**
     * Address: 0x008A6C70 (FUN_008A6C70, ?GetSunColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun color vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunColor() const;

    /**
     * Address: 0x008A6CA0 (FUN_008A6CA0, ?SetSunColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun color vector.
     */
    void SetSunColor(const Wm3::Vector3f& color);

    /**
     * Address: 0x008A6CD0 (FUN_008A6CD0, ?GetShadowFillColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns shadow-fill color vector.
     */
    [[nodiscard]] Wm3::Vector3f GetShadowFillColor() const;

    /**
     * Address: 0x008A6D00 (FUN_008A6D00, ?SetShadowFillColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets shadow-fill color vector.
     */
    void SetShadowFillColor(const Wm3::Vector3f& color);

    /**
     * Address: 0x008A6D30 (FUN_008A6D30, ?WaterEnabled@CWldTerrainRes@Moho@@EAEX_N@Z)
     *
     * What it does:
     * Toggles world-map water rendering/logic enabled flag.
     */
    void WaterEnabled(bool enabled);

    /**
     * Address: 0x008A6D40 (FUN_008A6D40, ?SetWaterElevation@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map surface water elevation.
     */
    void SetWaterElevation(float elevation);

    /**
     * Address: 0x008A6D60 (FUN_008A6D60, ?SetWaterElevationDeep@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map deep-water threshold elevation.
     */
    void SetWaterElevationDeep(float elevation);

    /**
     * Address: 0x008A6D80 (FUN_008A6D80, ?SetWaterElevationAbyss@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map abyss-water threshold elevation.
     */
    void SetWaterElevationAbyss(float elevation);

    /**
     * Address: 0x008A6E20 (FUN_008A6E20, ?SetWaterShaderProperties@CWldTerrainRes@Moho@@EAEXABVCWaterShaderProperties@2@@Z)
     *
     * What it does:
     * Copies one water-shader property block into terrain state.
     */
    void SetWaterShaderProperties(const CWaterShaderProperties& properties);

    /**
     * Address: 0x008A6E40 (FUN_008A6E40, ?GetWaterShaderProperties@CWldTerrainRes@Moho@@EAEPAVCWaterShaderProperties@2@XZ)
     *
     * What it does:
     * Returns mutable pointer to the owned water-shader property block.
     */
    [[nodiscard]] CWaterShaderProperties* GetWaterShaderProperties();

    /**
     * Address: 0x008A6E50 (FUN_008A6E50, ?GetWaterFoam@CWldTerrainRes@Moho@@EAEPAEZX)
     *
     * What it does:
     * Returns terrain water-foam mask buffer.
     */
    [[nodiscard]] std::uint8_t* GetWaterFoam();

    /**
     * Address: 0x008A6E60 (FUN_008A6E60, ?GetWaterFlatness@CWldTerrainRes@Moho@@EAEPAEZX)
     *
     * What it does:
     * Returns terrain water-flatness mask buffer.
     */
    [[nodiscard]] std::uint8_t* GetWaterFlatness();

    /**
     * Address: 0x008A6E80 (FUN_008A6E80, ?IsInEditMode@CWldTerrainRes@Moho@@EBE_NXZ)
     *
     * What it does:
     * Returns true when terrain-resource edit mode is enabled.
     */
    [[nodiscard]] virtual bool IsInEditMode() const;

    /**
     * Address: 0x008A6E90 (FUN_008A6E90, ?EnterEditMode@CWldTerrainRes@Moho@@EAEXAAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Enables terrain edit mode, prepares packed edit-word lanes, and clones
     * dynamic map/stratum textures into edit-safe instances.
     */
    virtual void EnterEditMode(CBackgroundTaskControl& loadControl);

    /**
     * Address: 0x008A7130 (FUN_008A7130, ?ExitEditMode@CWldTerrainRes@Moho@@EAEXXZ)
     *
     * What it does:
     * Flushes packed edit-word lanes into water-map texture and restores
     * runtime texture instances after edit mode.
     */
    virtual void ExitEditMode();

    /**
     * Address: 0x008A7400 (FUN_008A7400, ?GetDecalManager@CWldTerrainRes@Moho@@EAEPAVIDecalManager@2@XZ)
     *
     * What it does:
     * Returns terrain decal-manager lane.
     */
    [[nodiscard]] IDecalManager* GetDecalManager();

    /**
     * Address: 0x008A2DD0 (FUN_008A2DD0, ?Finalize@CWldTerrainRes@Moho@@UAE_NXZ)
     *
     * What it does:
     * Finalizes terrain runtime resources and returns whether the pass
     * completed without requiring deferred map-change handling.
     */
    [[nodiscard]] virtual bool Finalize() = 0;

    /**
     * Address: 0x008A5890 (FUN_008A5890, ?SyncTerrain@CWldTerrainRes@Moho@@EAEXPBVCHeightField@2@@Z)
     *
     * What it does:
     * Applies queued dirty terrain rectangles from one source heightfield into
     * the live map heightfield for camera-visible regions, then clears synced
     * dirty lanes and refreshes terrain error bounds.
     */
    virtual void SyncTerrain(const CHeightField* source);

    /**
     * Address: 0x008A5BC0 (FUN_008A5BC0, ?UpdateNormalMap@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one caller-provided rectangle of terrain normal-map data.
     */
    virtual void UpdateNormalMap(const gpg::Rect2i& rect);

    /**
     * Address: 0x008A5730 (FUN_008A5730, ?NotifyMapChange@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Routes one map-change rectangle through normal-map updates, then records
     * the affected half-resolution region in debug dirty masks.
     */
    virtual void NotifyMapChange(const gpg::Rect2i& rect);

    /**
     * Address: 0x008A7410 (FUN_008A7410, ?CreateWaterMasks@CWldTerrainRes@Moho@@AAEXHH@Z)
     *
     * What it does:
     * Reallocates terrain water mask lanes for foam/flatness/depth-bias and
     * initializes each lane with its runtime default fill.
     */
    void CreateWaterMasks(std::int32_t width, std::int32_t height);

    /**
     * Address: 0x008A50C0 (FUN_008A50C0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXXZ)
     *
     * What it does:
     * Rebuilds the full half-resolution RGBA water-map texture from terrain
     * height samples and water mask lanes.
     */
    void UpdateWaterMap();

    /**
     * Address: 0x008A50F0 (FUN_008A50F0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one clipped rectangle of the half-resolution RGBA water-map
     * texture from terrain height samples and water mask lanes.
     */
    void UpdateWaterMap(const gpg::Rect2i& rect);

    /**
     * Address: 0x008A5130 (FUN_008A5130, ?UpdateWaterMap@CWldTerrainRes@Moho@@QAEXAAVCBackgroundTaskControl@2@ABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one clipped rectangle of water-map texels and uploads the
     * result into the dynamic terrain water-map texture.
     */
    void UpdateWaterMap(CBackgroundTaskControl& loadControl, const gpg::Rect2i& rect);

    /**
     * Address: 0x008A4CB0 (FUN_008A4CB0, ?UpdateTexture@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@PAI@Z)
     *
     * What it does:
     * Copies a packed RGBA texel buffer row-by-row into one dynamic texture
     * sheet lock.
     */
    void UpdateTexture(boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet, const std::uint32_t* sourcePixels);

    /**
     * Address: 0x008A4DA0 (FUN_008A4DA0, ?ClearTexture@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
     *
     * What it does:
     * Clears one lockable terrain texture sheet to zero over all rows.
     */
    void ClearTexture(boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet);

    /**
     * Address: 0x008A4B90 (FUN_008A4B90, ?UpdateTextureChannel@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@HHHHIIPBE@Z)
     *
     * What it does:
     * Updates one channel lane in a dynamic RGBA terrain texture from source
     * byte-mask rows over the caller-provided rectangle.
     */
    void UpdateTextureChannel(
      std::int32_t rowStart,
      std::int32_t columnEnd,
      boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet,
      std::int32_t columnStart,
      std::int32_t rowEnd,
      std::uint32_t channelMask,
      std::uint32_t channelShift,
      const std::uint8_t* sourceMask
    );

    /**
     * Address: 0x008A4A60 (FUN_008A4A60, ?GetTextureChannel@CWldTerrainRes@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@IIPAE@Z)
     *
     * What it does:
     * Reads one packed channel lane from a locked RGBA terrain texture and
     * writes unpacked bytes to caller-provided destination rows.
     */
    void GetTextureChannel(
      boost::shared_ptr<CD3DDynamicTextureSheet> textureSheet,
      std::uint32_t channelMask,
      std::uint32_t channelShift,
      std::uint8_t* outChannelData
    );

    /**
     * Address: 0x008A4ED0 (FUN_008A4ED0, ?UpdateStratumMask@CWldTerrainRes@Moho@@UAEXHPBEHHHH@Z)
     *
     * What it does:
     * Routes one stratum-byte mask update into the matching packed RGBA
     * channel lane of stratum-mask texture 0/1.
     */
    void UpdateStratumMask(
      std::int32_t stratumIndex,
      const std::uint8_t* sourceMask,
      std::int32_t columnStart,
      std::int32_t rowStart,
      std::int32_t columnEnd,
      std::int32_t rowEnd
    );

    /**
     * Address: 0x008A4F90 (FUN_008A4F90, ?GetStratumMask@CWldTerrainRes@Moho@@UAEXHPAE@Z)
     *
     * What it does:
     * Selects one stratum-mask texture/channel lane and exports unpacked mask
     * bytes through `GetTextureChannel`.
     */
    void GetStratumMask(std::int32_t stratumIndex, std::uint8_t* outMask);

    /**
     * Address: 0x008A6020 (FUN_008A6020, ?GetNormalMapInfo@CWldTerrainRes@Moho@@EAE?AUSNormalMapInfo@2@H@Z)
     *
     * What it does:
     * Builds shader-ready UV scale/offset lanes and texture ownership for one
     * normal-map tile index.
     */
    [[nodiscard]] SNormalMapInfo GetNormalMapInfo(std::int32_t index) const;

    /**
     * Address: 0x008A4600 (FUN_008A4600, ?SaveTexturing@CWldTerrainRes@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Saves stratum-layer texture path/size lanes in terrain save order, then
     * delegates decal-manager persistence.
     */
    void SaveTexturing(gpg::BinaryWriter& writer);

    /**
     * Address: 0x008A49D0 (FUN_008A49D0, ?GetStratumMaterial@CWldTerrainRes@Moho@@UAEAAVStratumMaterial@2@XZ)
     *
     * What it does:
     * Returns mutable access to the owned terrain stratum material set.
     */
    [[nodiscard]] StratumMaterial& GetStratumMaterial();

    /**
     * Address: 0x008A49E0 (FUN_008A49E0, ?SetStratumDefaults@CWldTerrainRes@Moho@@QAEXXZ)
     *
     * What it does:
     * Rebuilds terrain strata with default layer descriptors and reapplies map
     * size scaling to each configured layer.
     */
    void SetStratumDefaults();

  private:
    /**
     * Address: 0x008A61B0 (FUN_008A61B0, ?SetWaterDefaults@CWldTerrainRes@Moho@@AAEXXZ)
     *
     * What it does:
     * Replaces the active water-shader property payload with a freshly
     * default-constructed property block.
     */
    void SetWaterDefaults();

    /**
     * Address: 0x008A54D0 (FUN_008A54D0, ?InitNormalMap@CWldTerrainRes@Moho@@AAEXAAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Recomputes normal-map tile layout and allocates one dynamic normal-map
     * texture per tile before rebuilding full terrain coverage.
     */
    void InitNormalMap(CBackgroundTaskControl& loadControl);

    /**
     * Address: 0x008A5BE0 (FUN_008A5BE0, ?UpdateNormalMap@CWldTerrainRes@Moho@@AAEXAAVCBackgroundTaskControl@2@ABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one clipped normal-map rectangle across all normal-map tiles and
     * encodes per-texel normal lanes into DXT payload blocks.
     */
    void UpdateNormalMap(CBackgroundTaskControl& loadControl, const gpg::Rect2i& rect);

  public:
    TerrainPlayableRectSource* mPlayableRectSource; // 0x04
  };
  static_assert(sizeof(IWldTerrainRes) == 0x08, "IWldTerrainRes head size must be 0x08");

  /**
   * Recovered owning layout for CWldMap.
   * Preview chunk, terrain resource, and world props ownership are tracked as
   * three adjacent pointers.
   */
  class CWldMap
  {
  public:
    /**
     * Address: 0x00890C70 (??1CWldMap@Moho@@QAE@XZ)
     *
     * What it does:
     * Resets owned map resources, then performs guarded teardown of any
     * remaining preview/terrain/props pointers.
     */
    ~CWldMap();

    /**
     * Address: 0x00890D40 (?MapNew@CWldMap@Moho@@QAE_NHHPAVLuaState@LuaPlus@@@Z)
     *
     * What it does:
     * Creates fresh terrain/props resources for a new map and resets prior
     * owned state.
     */
    [[nodiscard]] bool MapNew(std::int32_t width, std::int32_t height, LuaPlus::LuaState* state);

    /**
     * Address: 0x00890DA0
     * (?MapLoad@CWldMap@Moho@@QAE_NVStrArg@gpg@@PAVLuaState@LuaPlus@@_NAAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Loads map preview + terrain + props from disk stream with staged load
     * progress updates.
     */
    [[nodiscard]]
    bool MapLoad(gpg::StrArg mapName, LuaPlus::LuaState* state, bool previewOnly, CBackgroundTaskControl& loadControl);

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
     * Address: 0x00890CF0 (?Reset@CWldMap@Moho@@AAEXXZ)
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
