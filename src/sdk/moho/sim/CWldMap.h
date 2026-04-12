#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/sim/VisibilityRect.h"
#include "Wm3Vector2.h"

namespace gpg
{
  using StrArg = const char*;
  class BinaryReader;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  struct CBackgroundTaskControl;
  class ID3DTextureSheet;
  class IWldTerrainRes;

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

  struct TerrainPlayableRectSource
  {
    std::uint8_t pad_0000_0008[0x08];
    VisibilityRect mPlayableRect; // 0x08
  };
  static_assert(
    offsetof(TerrainPlayableRectSource, mPlayableRect) == 0x08,
    "TerrainPlayableRectSource::mPlayableRect offset must be 0x08"
  );

  /**
   * Recovered leading layout for IWldTerrainRes.
   * Only fields used by 0x0089E710 are mapped here.
   */
  class IWldTerrainRes
  {
  public:
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
