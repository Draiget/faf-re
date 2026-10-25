// Engine addition (dedicated-server plan WPL.4, WPR.11): the terrain resource a map
// loads into when there is no client (no renderer): the game server, faf-replay and
// the Linux build. CWldTerrainRes (moho/terrain/CWldTerrainRes.cpp) is the client's.
//
// Load reads the terrain payload of a `.scmap` exactly as CWldTerrainRes::Load
// (0x008A1700) does, in the same order and with the same reads, so the stream ends
// where the props start (CWldMap::MapLoad reads them next). It builds the map data
// the simulation copies (STIMap: heightfield, terrain types, water) with the same
// calls, and reads past everything that only the renderer uses: the stratum shader,
// background, skycube and environment lookups, lighting and fog, water shading, wave
// generators, topographic colours, strata texturing and terrain decals, the utility
// and water-map sheets, the water masks, the sky dome and the cartographic decals.
// Each skip below names the loader whose reads it mirrors.
//
// The rest of IWldTerrainRes is the renderer's and the editor's; nothing reaches it
// without a client. The getters return the defaults CWldTerrainRes starts with, and
// the calls that need render objects end the process with a message.

#include "moho/sim/CWldMap.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/math/Vector4f.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WldSessionInfo.h"

namespace
{
  using moho::CBackgroundTaskControl;

  void TickLoadingProgress(CBackgroundTaskControl& loadControl)
  {
    if (loadControl.mHandle != nullptr) {
      loadControl.mHandle->UpdateLoadingProgress();
    }
  }

  void SkipString(gpg::BinaryReader& reader)
  {
    msvc8::string scratch;
    reader.ReadString(&scratch);
  }

  void SkipBytes(gpg::BinaryReader& reader, const std::size_t byteCount)
  {
    std::vector<char> scratch(byteCount);
    if (byteCount != 0u) {
      reader.Read(scratch.data(), scratch.size());
    }
  }

  template <class T>
  void SkipValue(gpg::BinaryReader& reader)
  {
    T scratch{};
    reader.ReadExact(scratch);
  }

  /// One `payloadSize` + payload sheet, as the utility-mask and water-map loops read it.
  void SkipSizedPayload(gpg::BinaryReader& reader)
  {
    std::uint32_t payloadSize = 0;
    reader.ReadExact(payloadSize);
    SkipBytes(reader, payloadSize);
  }

  /// CWaterShaderProperties::Load (0x008A03C0): 20 floats, the cubemap and ramp
  /// paths, 4 floats, then 4 x { 2 floats, wave texture path }.
  void SkipWaterShaderProperties(gpg::BinaryReader& reader)
  {
    SkipBytes(reader, 20u * sizeof(float));
    SkipString(reader);
    SkipString(reader);
    SkipBytes(reader, 4u * sizeof(float));
    for (int wave = 0; wave < 4; ++wave) {
      SkipBytes(reader, 2u * sizeof(float));
      SkipString(reader);
    }
  }

  /// WaveSystem::Load (0x008899E0): a generator count, then per generator
  /// WaveGenerator::LoadSerializedState: two texture paths, 13 floats (position,
  /// angle, direction, lifetime, update interval and size ranges) and, after
  /// format 51, 4 more (ramp scale, framerate range, texture selection).
  void SkipWaveSystem(gpg::BinaryReader& reader, const std::uint32_t version)
  {
    std::int32_t generatorCount = 0;
    reader.ReadExact(generatorCount);
    for (std::int32_t index = 0; index < generatorCount; ++index) {
      SkipString(reader);
      SkipString(reader);
      SkipBytes(reader, 13u * sizeof(float));
      if (static_cast<std::int32_t>(version) > 51) {
        SkipBytes(reader, 4u * sizeof(float));
      }
    }
  }

  /// CWldTerrainRes::LoadLayer (0x008A3FC0): a texture path and its size.
  void SkipStratumLayer(gpg::BinaryReader& reader)
  {
    SkipString(reader);
    SkipValue<float>(reader);
  }

  /// CDecalManager::Load (0x00877CD0): two counters, the decals
  /// (CWldTerrainDecal::DecalLoad), then the decal groups
  /// (CDecalGroup::ReadFromStream).
  void SkipTerrainDecals(gpg::BinaryReader& reader)
  {
    SkipValue<std::uint32_t>(reader); // mDecalCount
    SkipValue<std::uint32_t>(reader); // mNumDecals

    std::uint32_t decalCount = 0;
    reader.Read(reinterpret_cast<char*>(&decalCount), sizeof(decalCount));
    for (; decalCount != 0u; --decalCount) {
      SkipValue<std::int32_t>(reader); // index
      SkipValue<std::int32_t>(reader); // type
      std::int32_t nameCount = 0;
      reader.Read(reinterpret_cast<char*>(&nameCount), sizeof(nameCount));
      for (std::int32_t slot = 0; slot < nameCount; ++slot) {
        std::int32_t nameLength = 0;
        reader.Read(reinterpret_cast<char*>(&nameLength), sizeof(nameLength));
        std::vector<char> nameBytes(static_cast<std::size_t>(nameLength));
        if (nameLength > 0) {
          reader.Read(nameBytes.data(), static_cast<std::size_t>(nameLength));
        }
      }
      // Scale, position and orientation (3 x Vec3f), LOD cutoff, near cutoff, army.
      SkipBytes(reader, 9u * sizeof(float) + 2u * sizeof(float) + sizeof(std::int32_t));
    }

    std::uint32_t groupCount = 0;
    reader.Read(reinterpret_cast<char*>(&groupCount), sizeof(groupCount));
    for (; groupCount != 0u; --groupCount) {
      SkipValue<std::int32_t>(reader); // mIndex
      SkipString(reader);              // mName
      std::int32_t memberCount = 0;
      reader.Read(reinterpret_cast<char*>(&memberCount), sizeof(memberCount));
      for (std::int32_t member = 0; member < memberCount; ++member) {
        SkipValue<std::int32_t>(reader);
      }
    }
  }

  /// CWldTerrainRes::LoadTexturing (0x008A4040): the strata layers (a flat layout
  /// before version 54, 19 LoadLayer records since), then the terrain decals.
  void SkipTexturing(gpg::BinaryReader& reader, const std::uint32_t version)
  {
    if (version < 54) {
      SkipString(reader);                // shader name
      SkipValue<std::uint32_t>(reader);  // discarded lane
      for (int pair = 0; pair < 5; ++pair) { // lower, then strata 0..3
        SkipString(reader);
        SkipString(reader);
        SkipValue<float>(reader);
        SkipValue<float>(reader);
      }
      SkipString(reader);                // upper albedo
      SkipString(reader);                // discarded upper normal
      SkipValue<float>(reader);          // upper size
      SkipValue<std::uint32_t>(reader);  // discarded lane
    } else {
      for (int layer = 0; layer < 19; ++layer) {
        SkipStratumLayer(reader);
      }
    }

    SkipTerrainDecals(reader);
  }

  /// SkyDome::Load (0x00815FA0, read from version 0x3A): dome origin and shape, size,
  /// horizon and sky colours and blend (64 bytes), the two atmosphere paths, the
  /// decal-upload records (0x28 bytes each), three cloud paths, the cirrus
  /// multiplier and colour, the cirrus path, a discarded layer count and the four
  /// 20-byte cirrus layer records.
  void SkipSkyDome(gpg::BinaryReader& reader)
  {
    SkipBytes(reader, 64u);
    SkipString(reader);
    SkipString(reader);
    std::int32_t cloudRecordCount = 0;
    reader.ReadExact(cloudRecordCount);
    for (std::int32_t record = 0; record < cloudRecordCount; ++record) {
      SkipBytes(reader, 0x28u);
    }
    SkipString(reader);
    SkipString(reader);
    SkipString(reader);
    SkipBytes(reader, 4u * sizeof(float));
    SkipString(reader);
    SkipValue<std::int32_t>(reader);
    SkipBytes(reader, 4u * 20u);
  }

  /// Cartographic::ReadDecals (0x007D1D30): a batch count, then per batch
  /// (CartographicDecalBatch::Read, 0x007D5400) the technique name (from 0x3C),
  /// the texture path, a decal count and 36 bytes per decal.
  void SkipCartographicDecals(gpg::BinaryReader& reader, const std::uint32_t version)
  {
    std::int32_t batchCount = 0;
    reader.Read(reinterpret_cast<char*>(&batchCount), sizeof(batchCount));
    while (batchCount > 0) {
      if (version >= 0x3Cu) {
        SkipString(reader);
      }
      SkipString(reader);
      std::int32_t decalCount = 0;
      reader.Read(reinterpret_cast<char*>(&decalCount), sizeof(decalCount));
      for (std::int32_t remaining = decalCount; remaining > 0; --remaining) {
        SkipBytes(reader, 36u);
      }
      --batchCount;
    }
  }

  [[noreturn]] void DieNoRenderer(const char* const call)
  {
    gpg::Die("IWldTerrainRes::%s: this terrain resource has no renderer (no client in this process)", call);
  }

  class CWldTerrainResHeadless final : public moho::IWldTerrainRes
  {
  public:
    CWldTerrainResHeadless() = default;
    ~CWldTerrainResHeadless() override = default;

    bool GetBool() const override { return false; }
    const moho::Cartographic& GetCartographic() const override { DieNoRenderer("GetCartographic"); }
    moho::Cartographic& GetCartographic() override { DieNoRenderer("GetCartographic"); }
    const moho::SkyDome& GetSkyDome() const override { DieNoRenderer("GetSkyDome"); }
    moho::SkyDome& GetSkyDome() override { DieNoRenderer("GetSkyDome"); }
    void SetSkycube(const msvc8::string& texturePath) override { mSkycubeFile = texturePath; }
    const msvc8::string& GetSkycubeFile() const override { return mSkycubeFile; }
    boost::shared_ptr<moho::ID3DTextureSheet> GetSkycube() const override { return {}; }
    void SetBackground(const msvc8::string& texturePath) override { mBackgroundFile = texturePath; }
    const msvc8::string& GetBackgroundFile() const override { return mBackgroundFile; }
    boost::shared_ptr<moho::ID3DTextureSheet> GetBackground() const override { return {}; }
    void AddEnvLookup(const msvc8::string&, const msvc8::string&) override {}
    void RemoveEnvLookup(const msvc8::string&) override {}
    boost::shared_ptr<moho::ID3DTextureSheet> GetEnvLookup(const msvc8::string&) const override { return {}; }
    void EnumerateEnvLookup(moho::TerrainEnvironmentLookupPairs&) const override {}
    void ClearEnvLookup() override {}
    void SetTopographicSamples(std::int32_t) override {}
    std::int32_t GetTopographicSamples() const override { return 20; }
    void SetHypsometricColor(std::int32_t, std::uint32_t) override {}
    std::uint32_t GetHypsometricColor(std::int32_t) const override { return 0xFFFFFFFFu; }
    void SetImagerElevationOffset(float) override {}
    float GetImagerElevationOffset() const override { return 0.0f; }
    bool Reset(moho::SChartSize, LuaPlus::LuaState*) override { DieNoRenderer("Reset"); }
    Wm3::AxisAlignedBox3f GetWorldBounds() const override { DieNoRenderer("GetWorldBounds"); }
    moho::StratumMaterial& GetStratumMaterial() override { DieNoRenderer("GetStratumMaterial"); }
    moho::WaveSystem* GetWaveSystem() override { return nullptr; }
    void UpdateWaveSystem(const moho::GeomCamera3&, float, std::int32_t) override {}
    boost::shared_ptr<moho::ID3DTextureSheet> GetWaterMap() const override { return {}; }
    void UpdateWaterMap(const gpg::Rect2i&) override {}
    void UpdateWaterMap() override {}
    Wm3::Vector2f GetWaterMapSize() const override { return Wm3::Vector2f{0.0f, 0.0f}; }
    void UpdateNormalMap(const gpg::Rect2i&) override {}
    void NotifyMapChange(const gpg::Rect2i&) override {}
    gpg::BitArray2D* GetDebugDirtyTerrain() override { return nullptr; }
    const msvc8::list<gpg::Rect2i>& GetDebugDirtyRects() const override { return mDebugDirtyRects; }
    std::int32_t GetNormalMapCount() override { return 0; }
    moho::SNormalMapInfo GetNormalMapInfo(std::int32_t) const override { DieNoRenderer("GetNormalMapInfo"); }
    void UpdateStratumMask(std::int32_t, const std::uint8_t*, std::int32_t, std::int32_t, std::int32_t, std::int32_t) override {}
    void UpdateStratumMask(std::int32_t, const std::uint8_t*) override {}
    void GetStratumMask(std::int32_t, std::uint8_t*) override { DieNoRenderer("GetStratumMask"); }
    float GetLightingMultiplier() const override { return 1.5f; }
    void SetLightingMultiplier(const float&) override {}
    Wm3::Vector3f GetSunDirection() const override { return Wm3::Vector3f{0.70700002f, 0.70700002f, 0.0f}; }
    void SetSunDirection(const Wm3::Vector3f&) override {}
    Wm3::Vector3f GetSunAmbience() const override { return Wm3::Vector3f{0.2f, 0.2f, 0.2f}; }
    void SetSunAmbience(const Wm3::Vector3f&) override {}
    Wm3::Vector3f GetSunColor() const override { return Wm3::Vector3f{1.0f, 1.0f, 1.0f}; }
    void SetSunColor(const Wm3::Vector3f&) override {}
    Wm3::Vector3f GetShadowFillColor() const override { return Wm3::Vector3f{0.69999999f, 0.69999999f, 0.75f}; }
    void SetShadowFillColor(const Wm3::Vector3f&) override {}
    moho::Vector4f GetSpecularColor() const override { return moho::Vector4f{}; }
    void SetSpecularColor(const moho::Vector4f&) override {}
    float GetBloom() const override { return 0.079999998f; }
    void SetBloom(float) override {}
    const moho::SFogInfo& GetFogInfo() const override { DieNoRenderer("GetFogInfo"); }
    void SetFogInfo(const moho::SFogInfo&) override {}

    void WaterEnabled(const bool enabled) override { mMap->mWaterEnabled = enabled; }
    void SetWaterElevation(const float elevation) override { mMap->mWaterElevation = elevation; }
    void SetWaterElevationDeep(const float elevation) override { mMap->mWaterElevationDeep = elevation; }
    void SetWaterElevationAbyss(const float elevation) override { mMap->mWaterElevationAbyss = elevation; }

    /// CWldTerrainRes::SetPlayableMapRect (0x008A6DA0).
    bool SetPlayableMapRect(const moho::VisibilityRect& rect) override
    {
      moho::STIMap* const map = mMap;
      if (map == nullptr) {
        return false;
      }
      if (!map->SetPlayableMapRect(rect.AsRect2i())) {
        gpg::Warnf("Attempting to set an invalid playable rect");
        return false;
      }
      return true;
    }

    /// CWldTerrainRes::GetPlayableMapRect.
    const moho::VisibilityRect* GetPlayableMapRect(moho::VisibilityRect& outRect) const override
    {
      outRect = moho::VisibilityRect::FromRect2i(mMap->mPlayableRect);
      return &outRect;
    }

    /// CWldTerrainRes::IsInPlayableRect (0x008A6DD0).
    bool IsInPlayableRect(const Wm3::Vec3f& worldPos) override
    {
      const gpg::Rect2i& playableRect = mMap->mPlayableRect;
      return static_cast<float>(playableRect.x0) <= worldPos.x && static_cast<float>(playableRect.z0) <= worldPos.z &&
             worldPos.x <= static_cast<float>(playableRect.x1) && worldPos.z <= static_cast<float>(playableRect.z1);
    }

    void SetWaterShaderProperties(const moho::CWaterShaderProperties&) override {}
    moho::CWaterShaderProperties* GetWaterShaderProperties() override { return nullptr; }
    std::uint8_t* GetWaterFoam() override { return nullptr; }
    std::uint8_t* GetWaterFlatness() override { return nullptr; }
    std::uint8_t* GetWaterDepthBias() override { return nullptr; }
    bool IsInEditMode() const override { return false; }
    void EnterEditMode(CBackgroundTaskControl&) override { DieNoRenderer("EnterEditMode"); }
    void ExitEditMode() override {}
    void SyncTerrain(const moho::CHeightField*) override {}
    bool Load(gpg::BinaryReader& reader, LuaPlus::LuaState* state, CBackgroundTaskControl& loadControl) override;
    bool Save(gpg::BinaryWriter&) override { DieNoRenderer("Save"); }
    bool Finalize() override { return false; }
    moho::IDecalManager* GetDecalManager() override { return nullptr; }

  private:
    msvc8::string mSkycubeFile;
    msvc8::string mBackgroundFile;
    msvc8::list<gpg::Rect2i> mDebugDirtyRects;
  };

  /**
   * The reads of CWldTerrainRes::Load (0x008A1700), in its order; see the file
   * comment. The map data is built with the same calls.
   */
  bool CWldTerrainResHeadless::Load(
    gpg::BinaryReader& reader, LuaPlus::LuaState* const state, CBackgroundTaskControl& loadControl
  )
  {
    std::uint32_t version = 0;
    reader.ReadExact(version);
    if (version < 0x33u) {
      return false;
    }

    std::uint32_t mapWidth = 0;
    std::uint32_t mapHeight = 0;
    float heightScale = 0.0f;
    reader.ReadExact(mapWidth);
    reader.ReadExact(mapHeight);
    reader.ReadExact(heightScale);
    TickLoadingProgress(loadControl);

    {
      moho::STIMap* const oldMap = mMap;
      mMap = new moho::STIMap(mapWidth, mapHeight);
      if (oldMap != nullptr) {
        oldMap->~STIMap();
        ::operator delete(oldMap);
      }
    }

    moho::CHeightField* const field = mMap->mHeightField.get();
    reader.Read(reinterpret_cast<char*>(field->data), static_cast<std::size_t>(2 * field->width * field->height));

    // (CWldTerrainRes makes its decal manager here.)

    if (heightScale != 0.0078125f) {
      field->Rescale(heightScale * 128.0f);
    }

    mMap->LoadTerrainTypes(state);
    TickLoadingProgress(loadControl);

    gpg::Rect2i fullRect{};
    fullRect.x0 = 0;
    fullRect.z0 = 0;
    fullRect.x1 = 0x7FFFFFFF;
    fullRect.z1 = 0x7FFFFFFF;
    mMap->mHeightField.get()->UpdateBounds(fullRect);
    TickLoadingProgress(loadControl);
    mMap->mHeightField.get()->UpdateError(loadControl, fullRect);
    TickLoadingProgress(loadControl);

    // Stratum shader byte (from 0x36) and name, background, skycube.
    if (version >= 0x36u) {
      (void)reader.ReadChar();
    }
    SkipString(reader);
    {
      msvc8::string backgroundPath;
      reader.ReadString(&backgroundPath);
      mBackgroundFile = backgroundPath;
    }
    {
      msvc8::string skycubePath;
      reader.ReadString(&skycubePath);
      mSkycubeFile = skycubePath;
    }

    // Environment lookups.
    if (version < 0x37u) {
      SkipString(reader);
    } else {
      std::int32_t envCount = 0;
      reader.ReadExact(envCount);
      for (; envCount > 0; --envCount) {
        SkipString(reader);
        SkipString(reader);
      }
    }

    // Lighting, sun, ambience, colours, specular, bloom and fog: 23 floats.
    SkipBytes(reader, 23u * sizeof(float));

    // Water: enabled + three elevations, kept on the map.
    mMap->mWaterEnabled = reader.ReadChar() != 0;
    reader.ReadExact(mMap->mWaterElevation);
    reader.ReadExact(mMap->mWaterElevationDeep);
    reader.ReadExact(mMap->mWaterElevationAbyss);

    SkipWaterShaderProperties(reader);
    SkipWaveSystem(reader, version);
    TickLoadingProgress(loadControl);

    // Topographic samples and hypsometric palette (from 0x38), imager offset (from 0x39).
    if (version >= 0x38u) {
      SkipBytes(reader, sizeof(std::int32_t) + 5u * sizeof(std::uint32_t));
    }
    if (version >= 0x39u) {
      SkipValue<float>(reader);
    }

    SkipTexturing(reader, version);
    TickLoadingProgress(loadControl);

    // Legacy skip-list: two discarded dwords and a count of size-prefixed records.
    {
      SkipValue<std::uint32_t>(reader);
      SkipValue<std::uint32_t>(reader);
      std::int32_t skipCount = 0;
      reader.ReadExact(skipCount);
      for (; skipCount > 0; --skipCount) {
        std::int32_t recordSize = 0;
        reader.ReadExact(recordSize);
        reader.stream()->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginCurr, recordSize);
      }
    }
    TickLoadingProgress(loadControl);

    // Stratum mask sheets.
    if (version >= 0x36u) {
      SkipSizedPayload(reader);
      TickLoadingProgress(loadControl);
      SkipSizedPayload(reader);
      TickLoadingProgress(loadControl);
    } else {
      std::int32_t maskCount = 0;
      reader.ReadExact(maskCount);
      for (std::int32_t maskIndex = 0; maskIndex < maskCount; ++maskIndex) {
        SkipSizedPayload(reader);
        TickLoadingProgress(loadControl);
      }
    }

    // Water-map sheets.
    {
      std::int32_t waterMapCount = 0;
      reader.ReadExact(waterMapCount);
      for (std::int32_t waterMapIndex = 0; waterMapIndex < waterMapCount; ++waterMapIndex) {
        SkipSizedPayload(reader);
        TickLoadingProgress(loadControl);
      }
    }

    // Water masks (foam, flatness, depth bias), half resolution.
    {
      const std::int32_t maskTileX = (mMap->mHeightField.get()->width - 1) >> 1;
      const std::int32_t maskTileY = (mMap->mHeightField.get()->height - 1) >> 1;
      const std::size_t maskBytes = static_cast<std::size_t>(maskTileX * maskTileY);
      SkipBytes(reader, maskBytes);
      SkipBytes(reader, maskBytes);
      SkipBytes(reader, maskBytes);
    }
    TickLoadingProgress(loadControl);

    // Terrain-type grid, kept on the map.
    {
      moho::STIMap* const map = mMap;
      const std::size_t terrainTypeBytes = static_cast<std::size_t>(map->mTerrainType.width * map->mTerrainType.height);
      reader.Read(reinterpret_cast<char*>(map->mTerrainType.data), terrainTypeBytes);
    }

    if (version < 0x35u) {
      SkipString(reader);
      SkipString(reader);
    }

    // Sky dome (stored from 0x3A; CWldTerrainRes derives it otherwise, reading nothing).
    if (version >= 0x3Au) {
      SkipSkyDome(reader);
    }

    if (version >= 0x3Bu) {
      SkipCartographicDecals(reader, version);
    }

    return true;
  }
} // namespace

moho::IWldTerrainRes* moho::WLD_CreateHeadlessTerrainRes()
{
  return new (std::nothrow) CWldTerrainResHeadless();
}
