#pragma once

// Engine addition (dedicated-server plan WPL.4): the terrain resource class, moved
// unchanged out of moho/sim/CWldMap.h. It holds the sky, lighting, strata, water,
// normal maps and decals the renderer draws; the simulation reaches the map data
// through IWldTerrainRes (CWldMap.h).

#include "moho/sim/CWldMap.h"
#include "moho/render/Cartographic.h"
#include "moho/render/SkyDome.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaveSystem.h"

namespace moho
{
  /**
   * The terrain resource (`??_7CWldTerrainRes@Moho@@6B@`, 0x00E4BD54): every
   * slot of `IWldTerrainRes` implemented, and the sky, lighting, strata,
   * water, normal maps and decals behind them.
   */
  class CWldTerrainRes final : public IWldTerrainRes
  {
  public:
    /**
     * Address: 0x008A0AD0 (FUN_008A0AD0, ??0CWldTerrainRes@Moho@@QAE@XZ)
     *
     * What it does:
     * Sets the lighting, sun, hypsometric and imager defaults and nulls the
     * owned buffers; every member with a constructor builds itself.
     */
    CWldTerrainRes();

    /**
     * Address: 0x008A0D60 (FUN_008A0D60, ??1CWldTerrainRes@Moho@@UAE@XZ)
     * Address: 0x008A74B0 (FUN_008A74B0, ??_ECWldTerrainRes@Moho@@UAEPAXI@Z -- the scalar deleting destructor, slot 0)
     *
     * What it does:
     * Frees the raw owned buffers (decal manager, debug dirty bitmap, water
     * masks, edit words); the members then destroy themselves and
     * `~IWldTerrainRes` deletes the map.
     */
    ~CWldTerrainRes() override;

    /**
     * Address: 0x008A1030 (FUN_008A1030, Moho::CWldTerrainRes::GetBool)
     *
     * What it does:
     * Returns the terrain runtime boolean lane at `+0x08`.
     */
    [[nodiscard]] bool GetBool() const override;

    /**
     * Address: 0x008A1050 (FUN_008A1050, ?GetCartographic@CWldTerrainRes@Moho@@UBEABVCartographic@2@XZ)
     *
     * What it does:
     * Returns read-only access to terrain cartographic runtime state.
     */
    [[nodiscard]] const Cartographic& GetCartographic() const override;

    /**
     * Address: 0x008A1040 (FUN_008A1040, ?GetCartographic@CWldTerrainRes@Moho@@UAEAAVCartographic@2@XZ)
     *
     * What it does:
     * Returns mutable access to terrain cartographic runtime state.
     */
    [[nodiscard]] Cartographic& GetCartographic() override;

    /**
     * Address: 0x008A1070 (FUN_008A1070, ?GetSkyDome@CWldTerrainRes@Moho@@UBEABVSkyDome@2@XZ)
     *
     * What it does:
     * Returns read-only access to terrain skydome runtime state.
     */
    [[nodiscard]] const SkyDome& GetSkyDome() const override;

    /**
     * Address: 0x008A1060 (FUN_008A1060, ?GetSkyDome@CWldTerrainRes@Moho@@UAEAAVSkyDome@2@XZ)
     *
     * What it does:
     * Returns mutable access to terrain skydome runtime state.
     */
    [[nodiscard]] SkyDome& GetSkyDome() override;

    /**
     * Address: 0x008A11C0 (FUN_008A11C0, ?SetSkycube@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Stores terrain skycube texture path and resolves the corresponding D3D
     * texture resource handle.
     */
    void SetSkycube(const msvc8::string& texturePath) override;

    /**
     * Address: 0x008A12C0 (FUN_008A12C0,
     *   ?GetSkycubeFile@CWldTerrainRes@Moho@@UBEABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ)
     * Slot: 7 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54)
     *
     * What it does:
     * The skycube counterpart of `GetBackgroundFile`: `lea eax, [ecx+980h];
     * retn`, returning the stored path by reference.
     */
    [[nodiscard]] const msvc8::string& GetSkycubeFile() const override;

    /**
     * Address: 0x008A12D0 (FUN_008A12D0, ?GetSkycube@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for terrain skycube.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetSkycube() const override;

    /**
     * Address: 0x008A1080 (FUN_008A1080, ?SetBackground@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Stores terrain background texture path and resolves the corresponding D3D
     * texture resource handle.
     */
    void SetBackground(const msvc8::string& texturePath) override;

    /**
     * Address: 0x008A1180 (FUN_008A1180,
     *   ?GetBackgroundFile@CWldTerrainRes@Moho@@UBEABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ)
     * Slot: 10 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54)
     *
     * What it does:
     * Returns the path `SetBackground` stored, by reference. The whole body is
     * `lea eax, [ecx+95Ch]; retn` -- the string itself, not a copy.
     */
    [[nodiscard]] const msvc8::string& GetBackgroundFile() const override;

    /**
     * Address: 0x008A1190 (FUN_008A1190, ?GetBackground@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for terrain background.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetBackground() const override;

    /**
     * Address: 0x008A1300 (FUN_008A1300)
     * (FUN_008A1300, ?AddEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0@Z)
     *
     * What it does:
     * Resolves one environment texture path and upserts it into the
     * terrain environment-lookup map keyed by environment id.
     */
    void AddEnvLookup(const msvc8::string& environmentKey, const msvc8::string& texturePath) override;

    /**
     * Address: 0x008A13F0 (FUN_008A13F0)
     * (FUN_008A13F0, ?RemoveEnvLookup@CWldTerrainRes@Moho@@UAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Removes one environment-lookup map entry by key when present.
     */
    void RemoveEnvLookup(const msvc8::string& environmentKey) override;

    /**
     * Address: 0x008A1430 (FUN_008A1430)
     * (FUN_008A1430, ?GetEnvLookup@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
     *
     * What it does:
     * Returns one environment texture handle by key, with `<default>` fallback.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetEnvLookup(const msvc8::string& environmentKey) const override;

    /**
     * Address: 0x008A1500 (FUN_008A1500)
     * (FUN_008A1500, ?EnumerateEnvLookup@CWldTerrainRes@Moho@@UBEXAAV?$vector@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@V?$allocator@U?$pair@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@@2@@std@@@Z)
     *
     * What it does:
     * Rebuilds caller-provided list with all environment-key/name pairs in map order.
     */
    void EnumerateEnvLookup(TerrainEnvironmentLookupPairs& outPairs) const override;

    /**
     * Address: 0x008A1640 (FUN_008A1640)
     * (FUN_008A1640, ?ClearEnvLookup@CWldTerrainRes@Moho@@UAEXXZ)
     *
     * What it does:
     * Clears all environment-lookup entries and resets map head links to empty.
     */
    void ClearEnvLookup() override;

    /**
     * Address: 0x008A1680 (FUN_008A1680, ?SetTopographicSamples@CWldTerrainRes@Moho@@UAEXH@Z)
     *
     * What it does:
     * Sets the active topographic sample-count lane.
     */
    void SetTopographicSamples(std::int32_t sampleCount) override;

    /**
     * Address: 0x008A1690 (FUN_008A1690, ?GetTopographicSamples@CWldTerrainRes@Moho@@UBEHXZ)
     *
     * What it does:
     * Returns the active topographic sample-count lane.
     */
    [[nodiscard]] std::int32_t GetTopographicSamples() const override;

    /**
     * Address: 0x008A16A0 (FUN_008A16A0)
     * (FUN_008A16A0, ?SetHypsometricColor@CWldTerrainRes@Moho@@UAEXW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@I@Z)
     *
     * What it does:
     * Writes one indexed hypsometric color lane.
     */
    void SetHypsometricColor(std::int32_t colorIndex, std::uint32_t colorValue) override;

    /**
     * Address: 0x008A16C0 (FUN_008A16C0)
     * (FUN_008A16C0, ?GetHypsometricColor@CWldTerrainRes@Moho@@UBEIW4HYPSOMETRIC_COLOR@IWldTerrainRes@2@@Z)
     *
     * What it does:
     * Returns one indexed hypsometric color lane.
     */
    [[nodiscard]] std::uint32_t GetHypsometricColor(std::int32_t colorIndex) const override;

    /**
     * Address: 0x008A16D0 (FUN_008A16D0, ?SetImagerElevationOffset@CWldTerrainRes@Moho@@UAEXM@Z)
     *
     * What it does:
     * Sets the terrain imager elevation offset lane.
     */
    void SetImagerElevationOffset(float elevationOffset) override;

    /**
     * Address: 0x008A16F0 (FUN_008A16F0, ?GetImagerElevationOffset@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns the terrain imager elevation offset lane.
     */
    [[nodiscard]] float GetImagerElevationOffset() const override;

    /**
     * Address: 0x008A6220 (FUN_008A6220)
     * Mangled: ?Reset@CWldTerrainRes@Moho@@EAE_NUSChartSize@2@PAVLuaState@LuaPlus@@@Z
     * Slot: 23 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54, entry 0x00E4BDB0)
     *
     * IDA signature:
     * char __thiscall Moho::CWldTerrainRes::Reset(Moho::CWldTerrainRes *this,
     *     int chartWidth, int chartHeight, LuaPlus::LuaState *state);
     *
     * What it does:
     * Rebuilds every terrain-resource lane for a brand-new chart of the given
     * size: replaces the owned `STIMap`, reloads terrain types from Lua,
     * refreshes the whole heightfield bound/error hierarchy, reallocates the
     * half-resolution debug dirty mask, restores the default background /
     * skycube / `<default>` env-cube lookup, rebuilds the normal map and the
     * stratum defaults, allocates and clears both stratum-mask textures plus the
     * water map, restores the fixed lighting/sun/fog constants, recreates the
     * water masks at water-map resolution, cycles edit mode once, replaces the
     * decal manager, and reconfigures the sky dome from the fresh world bounds.
     * Always returns `true`.
     *
     * Callsite evidence: VTABLE_CONFIRMED - zero direct code callers, one data
     * xref from `??_7CWldTerrainRes@Moho@@6B@` (0x00E4BD54) whose slot-23 entry
     * at 0x00E4BDB0 holds 0x008A6220; `CWldMap::MapNew` (0x00890D40) dispatches
     * exactly that slot at 0x00890D69.
     *
     * (Private virtual in the binary; declared public here because the merged
     * `IWldTerrainRes` model has no `CWldMap` friendship and `CWldMap::MapNew`
     * dispatches this slot directly at 0x00890D69.)
     */
    bool Reset(SChartSize chartSize, LuaPlus::LuaState* state) override;

    /**
     * Address: 0x008A6A60 (FUN_008A6A60, ?GetWorldBounds@CWldTerrainRes@Moho@@EBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns terrain world-space bounds derived from the map heightfield.
     */
    [[nodiscard]] Wm3::AxisAlignedBox3f GetWorldBounds() const override;

    /**
     * Address: 0x008A49D0 (FUN_008A49D0, ?GetStratumMaterial@CWldTerrainRes@Moho@@UAEAAVStratumMaterial@2@XZ)
     *
     * What it does:
     * Returns mutable access to the owned terrain stratum material set.
     */
    [[nodiscard]] StratumMaterial& GetStratumMaterial() override;

    /**
     * Address: 0x008A5010 (FUN_008A5010, ?GetWaveSystem@CWldTerrainRes@Moho@@EAEPAVWaveSystem@2@XZ)
     *
     * What it does:
     * Returns the owned terrain wave-system object.
     */
    [[nodiscard]] WaveSystem* GetWaveSystem() override;

    /**
     * Address: 0x008A5020 (FUN_008A5020, ?UpdateWaveSystem@CWldTerrainRes@Moho@@UAEXABVGeomCamera3@2@MH@Z)
     *
     * What it does:
     * Forwards one camera/timestep update into terrain wave simulation.
     */
    void UpdateWaveSystem(const GeomCamera3& camera, float elapsedSeconds, std::int32_t tick) override;

    /**
     * Address: 0x008A5040 (FUN_008A5040, ?GetWaterMap@CWldTerrainRes@Moho@@UBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns one retained shared texture handle for the terrain water map.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetWaterMap() const override;

    /**
     * Address: 0x008A50F0 (FUN_008A50F0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one clipped rectangle of the half-resolution RGBA water-map
     * texture from terrain height samples and water mask lanes.
     */
    void UpdateWaterMap(const gpg::Rect2i& rect) override;

    /**
     * Address: 0x008A50C0 (FUN_008A50C0, ?UpdateWaterMap@CWldTerrainRes@Moho@@UAEXXZ)
     *
     * What it does:
     * Rebuilds the full half-resolution RGBA water-map texture from terrain
     * height samples and water mask lanes.
     */
    void UpdateWaterMap() override;

    /**
     * Address: 0x008A5070 (FUN_008A5070, ?GetWaterMapSize@CWldTerrainRes@Moho@@UBE?AV?$Vector2@M@Wm3@@XZ)
     *
     * What it does:
     * Returns half-resolution terrain water-map dimensions derived from the
     * backing heightfield (`(width - 1) / 2`, `(height - 1) / 2`).
     */
    [[nodiscard]] Wm3::Vector2f GetWaterMapSize() const override;

    /**
     * Address: 0x008A5BC0 (FUN_008A5BC0, ?UpdateNormalMap@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Rebuilds one caller-provided rectangle of terrain normal-map data.
     */
    void UpdateNormalMap(const gpg::Rect2i& rect) override;

    /**
     * Address: 0x008A5730 (FUN_008A5730, ?NotifyMapChange@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Routes one map-change rectangle through normal-map updates, then records
     * the affected half-resolution region in debug dirty masks.
     */
    void NotifyMapChange(const gpg::Rect2i& rect) override;

    /**
     * Address: 0x008A54B0 (FUN_008A54B0, ?GetDebugDirtyTerrain@CWldTerrainRes@Moho@@EAEPAVBitArray2D@gpg@@XZ)
     *
     * What it does:
     * Returns debug dirty-region bitmask storage.
     */
    [[nodiscard]] gpg::BitArray2D* GetDebugDirtyTerrain() override;

    /**
     * Address: 0x008A54C0 (FUN_008A54C0, ?GetDebugDirtyRects@CWldTerrainRes@Moho@@UBEABV?$list@V?$Rect2@H@gpg@@V?$allocator@V?$Rect2@H@gpg@@@std@@@std@@XZ)
     *
     * What it does:
     * Returns the debug dirty-rectangle list lane.
     */
    [[nodiscard]] const msvc8::list<gpg::Rect2i>& GetDebugDirtyRects() const override;

    /**
     * Address: 0x008A5FB0 (FUN_008A5FB0, ?GetNormalMapCount@CWldTerrainRes@Moho@@EAEHXZ)
     *
     * What it does:
     * Returns number of active normal-map tile handles.
     */
    [[nodiscard]] std::int32_t GetNormalMapCount() override;

    /**
     * Address: 0x008A6020 (FUN_008A6020, ?GetNormalMapInfo@CWldTerrainRes@Moho@@EAE?AUSNormalMapInfo@2@H@Z)
     *
     * What it does:
     * Builds shader-ready UV scale/offset lanes and texture ownership for one
     * normal-map tile index.
     */
    [[nodiscard]] SNormalMapInfo GetNormalMapInfo(std::int32_t index) const override;

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
    ) override;

    /**
     * Address: 0x008A4EA0 (FUN_008A4EA0, ?UpdateStratumMask@CWldTerrainRes@Moho@@UAEXHPBE@Z)
     * Slot: 39 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54; the six-argument
     * overload above is slot 38)
     *
     * What it does:
     * Updates the whole stratum mask rather than a sub-rectangle: forwards to
     * the six-argument overload with the rectangle spanning (0, 0) to the mask
     * texture's own size. The binary reaches the overload through the vtable
     * (`call [eax+98h]` at 0x008A4EC4, which is slot 38) and takes the two
     * extents from `mStratumMaskWidth`/`mStratumMaskHeight` at +0x4CC/+0x4D0 --
     * the half-chart dimensions `Reset` seeded at 0x008A65B3/0x008A65B9 when it
     * created the mask textures.
     */
    void UpdateStratumMask(std::int32_t stratumIndex, const std::uint8_t* sourceMask) override;

    /**
     * Address: 0x008A4F90 (FUN_008A4F90, ?GetStratumMask@CWldTerrainRes@Moho@@UAEXHPAE@Z)
     *
     * What it does:
     * Selects one stratum-mask texture/channel lane and exports unpacked mask
     * bytes through `GetTextureChannel`.
     */
    void GetStratumMask(std::int32_t stratumIndex, std::uint8_t* outMask) override;

    /**
     * Address: 0x008A6AB0 (FUN_008A6AB0, ?GetLightingMultiplier@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns terrain lighting multiplier.
     */
    [[nodiscard]] float GetLightingMultiplier() const override;

    /**
     * Address: 0x008A6AC0 (FUN_008A6AC0, ?SetLightingMultiplier@CWldTerrainRes@Moho@@EAEXABM@Z)
     *
     * What it does:
     * Sets terrain lighting multiplier.
     */
    void SetLightingMultiplier(const float& multiplier) override;

    /**
     * Address: 0x008A6AD0 (FUN_008A6AD0, ?GetSunDirection@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun direction vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunDirection() const override;

    /**
     * Address: 0x008A6B00 (FUN_008A6B00, ?SetSunDirection@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun direction vector.
     */
    void SetSunDirection(const Wm3::Vector3f& direction) override;

    /**
     * Address: 0x008A6B30 (FUN_008A6B30, ?GetSunAmbience@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun ambience vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunAmbience() const override;

    /**
     * Address: 0x008A6B60 (FUN_008A6B60, ?SetSunAmbience@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun ambience vector.
     */
    void SetSunAmbience(const Wm3::Vector3f& ambience) override;

    /**
     * Address: 0x008A6C70 (FUN_008A6C70, ?GetSunColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns sun color vector.
     */
    [[nodiscard]] Wm3::Vector3f GetSunColor() const override;

    /**
     * Address: 0x008A6CA0 (FUN_008A6CA0, ?SetSunColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets sun color vector.
     */
    void SetSunColor(const Wm3::Vector3f& color) override;

    /**
     * Address: 0x008A6CD0 (FUN_008A6CD0, ?GetShadowFillColor@CWldTerrainRes@Moho@@EBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Returns shadow-fill color vector.
     */
    [[nodiscard]] Wm3::Vector3f GetShadowFillColor() const override;

    /**
     * Address: 0x008A6D00 (FUN_008A6D00, ?SetShadowFillColor@CWldTerrainRes@Moho@@EAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets shadow-fill color vector.
     */
    void SetShadowFillColor(const Wm3::Vector3f& color) override;

    /**
     * Address: 0x008A6B90 (FUN_008A6B90, ?GetSpecularColor@CWldTerrainRes@Moho@@EBE?AVVector4f@2@XZ)
     *
     * What it does:
     * Returns terrain specular color vector.
     */
    [[nodiscard]] Vector4f GetSpecularColor() const override;

    /**
     * Address: 0x008A6BC0 (FUN_008A6BC0, ?SetSpecularColor@CWldTerrainRes@Moho@@EAEXABVVector4f@2@@Z)
     *
     * What it does:
     * Sets terrain specular color vector.
     */
    void SetSpecularColor(const Vector4f& color) override;

    /**
     * Address: 0x008A6BF0 (FUN_008A6BF0, ?GetBloom@CWldTerrainRes@Moho@@UBEMXZ)
     *
     * What it does:
     * Returns terrain bloom strength lane.
     */
    [[nodiscard]] float GetBloom() const override;

    /**
     * Address: 0x008A6C00 (FUN_008A6C00, ?SetBloom@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets terrain bloom strength lane.
     */
    void SetBloom(float bloom) override;

    /**
     * Address: 0x008A6C20 (FUN_008A6C20, ?GetFogInfo@CWldTerrainRes@Moho@@EBEABUSFogInfo@2@XZ)
     *
     * What it does:
     * Returns read-only terrain fog parameter block.
     */
    [[nodiscard]] const SFogInfo& GetFogInfo() const override;

    /**
     * Address: 0x008A6C30 (FUN_008A6C30, ?SetFogInfo@CWldTerrainRes@Moho@@EAEXABUSFogInfo@2@@Z)
     *
     * What it does:
     * Updates primary terrain fog parameter lanes.
     */
    void SetFogInfo(const SFogInfo& fogInfo) override;

    /**
     * Address: 0x008A6D30 (FUN_008A6D30, ?WaterEnabled@CWldTerrainRes@Moho@@EAEX_N@Z)
     *
     * What it does:
     * Toggles world-map water rendering/logic enabled flag.
     */
    void WaterEnabled(bool enabled) override;

    /**
     * Address: 0x008A6D40 (FUN_008A6D40, ?SetWaterElevation@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map surface water elevation.
     */
    void SetWaterElevation(float elevation) override;

    /**
     * Address: 0x008A6D60 (FUN_008A6D60, ?SetWaterElevationDeep@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map deep-water threshold elevation.
     */
    void SetWaterElevationDeep(float elevation) override;

    /**
     * Address: 0x008A6D80 (FUN_008A6D80, ?SetWaterElevationAbyss@CWldTerrainRes@Moho@@EAEXM@Z)
     *
     * What it does:
     * Sets world-map abyss-water threshold elevation.
     */
    void SetWaterElevationAbyss(float elevation) override;

    /**
     * Address: 0x008A6DA0 (FUN_008A6DA0, ?SetPlayableMapRect@CWldTerrainRes@Moho@@EAEXABV?$Rect2@H@gpg@@@Z)
     *
     * What it does:
     * Writes one playable-map rectangle through the owned terrain map and emits
     * warning text when bounds are invalid.
     */
    [[nodiscard]] bool SetPlayableMapRect(const VisibilityRect& rect) override;

    /**
     * Address: 0x0089E710 (FUN_0089E710, ?GetPlayableMapRect@IWldTerrainRes@Moho@@UBE?AV?$Rect2@H@gpg@@XZ)
     *
     * What it does:
     * Copies playable map bounds from terrain-res internal storage into `outRect`
     * and returns `&outRect`.
     */
    [[nodiscard]] const VisibilityRect* GetPlayableMapRect(VisibilityRect& outRect) const override;

    /**
     * Address: 0x008A6DD0 (FUN_008A6DD0, ?IsInPlayableRect@CWldTerrainRes@Moho@@EAE_NABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Checks whether one world-space position lies inside the playable map
     * rectangle bounds.
     */
    [[nodiscard]] bool IsInPlayableRect(const Wm3::Vec3f& worldPos) override;

    /**
     * Address: 0x008A6E20 (FUN_008A6E20, ?SetWaterShaderProperties@CWldTerrainRes@Moho@@EAEXABVCWaterShaderProperties@2@@Z)
     *
     * What it does:
     * Copies one water-shader property block into terrain state.
     */
    void SetWaterShaderProperties(const CWaterShaderProperties& properties) override;

    /**
     * Address: 0x008A6E40 (FUN_008A6E40, ?GetWaterShaderProperties@CWldTerrainRes@Moho@@EAEPAVCWaterShaderProperties@2@XZ)
     *
     * What it does:
     * Returns mutable pointer to the owned water-shader property block.
     */
    [[nodiscard]] CWaterShaderProperties* GetWaterShaderProperties() override;

    /**
     * Address: 0x008A6E50 (FUN_008A6E50, ?GetWaterFoam@CWldTerrainRes@Moho@@EAEPAEZX)
     *
     * What it does:
     * Returns terrain water-foam mask buffer.
     */
    [[nodiscard]] std::uint8_t* GetWaterFoam() override;

    /**
     * Address: 0x008A6E60 (FUN_008A6E60, ?GetWaterFlatness@CWldTerrainRes@Moho@@EAEPAEZX)
     *
     * What it does:
     * Returns terrain water-flatness mask buffer.
     */
    [[nodiscard]] std::uint8_t* GetWaterFlatness() override;

    /**
     * Address: 0x008A6E70 (FUN_008A6E70, ?GetWaterDepthBias@CWldTerrainRes@Moho@@EAEPAEXZ)
     * Slot: 68 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54), immediately
     * after `GetWaterFlatness` at slot 67
     *
     * What it does:
     * The third of the three water masks, and the only one that had no
     * declaration here: `mov eax, [ecx+9D0h]; retn`, the same shape as its two
     * neighbours at +0x9C8 and +0x9CC.
     */
    [[nodiscard]] std::uint8_t* GetWaterDepthBias() override;

    /**
     * Address: 0x008A6E80 (FUN_008A6E80, ?IsInEditMode@CWldTerrainRes@Moho@@EBE_NXZ)
     *
     * What it does:
     * Returns true when terrain-resource edit mode is enabled.
     */
    [[nodiscard]] bool IsInEditMode() const override;

    /**
     * Address: 0x008A6E90 (FUN_008A6E90, ?EnterEditMode@CWldTerrainRes@Moho@@EAEXAAVCBackgroundTaskControl@2@@Z)
     *
     * What it does:
     * Enables terrain edit mode, prepares packed edit-word lanes, and clones
     * dynamic map/stratum textures into edit-safe instances.
     */
    void EnterEditMode(CBackgroundTaskControl& loadControl) override;

    /**
     * Address: 0x008A7130 (FUN_008A7130, ?ExitEditMode@CWldTerrainRes@Moho@@EAEXXZ)
     *
     * What it does:
     * Flushes packed edit-word lanes into water-map texture and restores
     * runtime texture instances after edit mode.
     */
    void ExitEditMode() override;

    /**
     * Address: 0x008A5890 (FUN_008A5890, ?SyncTerrain@CWldTerrainRes@Moho@@EAEXPBVCHeightField@2@@Z)
     *
     * What it does:
     * Applies queued dirty terrain rectangles from one source heightfield into
     * the live map heightfield for camera-visible regions, then clears synced
     * dirty lanes and refreshes terrain error bounds.
     */
    void SyncTerrain(const CHeightField* source) override;

    /**
     * Address: 0x008A1700 (FUN_008A1700, CWldTerrainRes::Load implementation path)
     *
     * What it does:
     * Loads terrain map data from stream payload and initializes runtime
     * terrain state for the active world map.
     */
    [[nodiscard]]
    bool Load(gpg::BinaryReader& reader, LuaPlus::LuaState* state, CBackgroundTaskControl& loadControl) override;

    /**
     * Address: 0x008A30B0 (FUN_008A30B0, ?Save@CWldTerrainRes@Moho@@UAE_NAAVBinaryWriter@gpg@@@Z)
     * Slot: 74 (`??_7CWldTerrainRes@Moho@@6B@` at 0x00E4BD54, entry 0x00E4BE7C),
     * i.e. the slot immediately after `Load` (slot 73, 0x008A1700).
     *
     * IDA signature:
     * bool __thiscall Moho::CWldTerrainRes::Save(
     *     Moho::CWldTerrainRes *this, gpg::BinaryWriter &writer);
     *
     * What it does:
     * Writes the complete terrain payload of a `.scmap` in save order: format
     * version 60, heightfield extents/scale/samples, resolved composite-shader
     * flag and shader/background/skycube names, environment-lookup pairs,
     * lighting/fog/water scalars, water shader + wave system, hypsometric and
     * imager lanes, stratum texturing, the normal-map sheet array, both stratum
     * masks, the water map, the water foam/flatness/depth-bias planes, the
     * terrain-type grid, the sky dome, and the decal set.
     */
    bool Save(gpg::BinaryWriter& writer) override;

    /**
     * Address: 0x008A2DD0 (FUN_008A2DD0, ?Finalize@CWldTerrainRes@Moho@@UAE_NXZ)
     *
     * What it does:
     * Finalizes terrain runtime resources and returns whether the pass
     * completed without requiring deferred map-change handling.
     */
    [[nodiscard]] bool Finalize() override;

    /**
     * Address: 0x008A7400 (FUN_008A7400, ?GetDecalManager@CWldTerrainRes@Moho@@EAEPAVIDecalManager@2@XZ)
     *
     * What it does:
     * Returns terrain decal-manager lane.
     */
    [[nodiscard]] IDecalManager* GetDecalManager() override;

    /**
     * Address: 0x008A4040 (FUN_008A4040, ?LoadTexturing@CWldTerrainRes@Moho@@QAEXAAVBinaryReader@gpg@@I@Z)
     *
     * What it does:
     * Loads the terrain strata/texturing state from the map stream. For map
     * versions >= 54 it delegates to LoadLayer for each stratum layer; for legacy
     * versions it reads the historical flat layout, then forwards to the decal
     * manager's Load.
     */
    void LoadTexturing(gpg::BinaryReader& reader, std::uint32_t version);

    /**
     * Address: 0x008A3FC0 (FUN_008A3FC0, ?LoadLayer@CWldTerrainRes@Moho@@QAEXAAULayer@StratumMaterial@2@AAVBinaryReader@gpg@@@Z)
     *
     * What it does:
     * Deserializes one terrain stratum layer descriptor (path + size) into the
     * provided layer from the map stream.
     */
    void LoadLayer(CStratumMaterial& outLayer, gpg::BinaryReader& reader);





    /**
     * Address: 0x008A7410 (FUN_008A7410, ?CreateWaterMasks@CWldTerrainRes@Moho@@AAEXHH@Z)
     *
     * What it does:
     * Reallocates terrain water mask lanes for foam/flatness/depth-bias and
     * initializes each lane with its runtime default fill.
     */
    void CreateWaterMasks(std::int32_t width, std::int32_t height);

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
     * Address: 0x008A4600 (FUN_008A4600, ?SaveTexturing@CWldTerrainRes@Moho@@QAEXAAVBinaryWriter@gpg@@@Z)
     *
     * What it does:
     * Saves stratum-layer texture path/size lanes in terrain save order, then
     * delegates decal-manager persistence.
     */
    void SaveTexturing(gpg::BinaryWriter& writer);

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
    std::uint8_t mBool;                                    // +0x008
    std::uint8_t mEditMode;                                // +0x009
    std::uint8_t mUnknown00A_00B[0x02];                    // +0x00A
    Cartographic mCartographic;                            // +0x00C
    SkyDome mSkyDome;                                      // +0x0B0 (0x228, 8-aligned)
    float mLightingMultiplier;                             // +0x2D8
    Wm3::Vector3f mSunDirection;                           // +0x2DC
    Wm3::Vector3f mSunAmbience;                            // +0x2E8
    Wm3::Vector3f mSunColor;                               // +0x2F4
    Wm3::Vector3f mShadowFillColor;                        // +0x300
    Vector4f mSpecularColor;                               // +0x30C
    float mBloom;                                          // +0x31C

    /**
     * The fog block the reflected `SFogInfo` type serializes as one unit, and
     * the lanes behind it that `SetTopographicSamples`, `SetHypsometricColor`
     * and `SetImagerElevationOffset` write one at a time. Same bytes either
     * way, which is why those accessors reach +0x334..+0x34C directly.
     */
    union
    {
      SFogInfo mFogInfo;                                   // +0x320
      struct
      {
        float mFogStartDistance;                           // +0x320
        float mFogCutoffDistance;                          // +0x324
        float mFogMinClamp;                                // +0x328
        float mFogMaxClamp;                                // +0x32C
        float mFogCurveExponent;                           // +0x330
        std::int32_t mTopographicSamples;                  // +0x334
        std::uint32_t mHypsometricColor[5];                // +0x338
        float mImagerElevationOffset;                      // +0x34C
      };
    };

    CWaterShaderProperties mWaterShaderProperties;         // +0x350
    StratumMaterial mStrata;                               // +0x4AC
    std::uint8_t mUnknown944_947[0x04];                    // +0x944
    TerrainNormalMapHandleArray mNormalMap;                // +0x948
    std::int32_t mNormalMapWidth;                          // +0x954
    std::int32_t mNormalMapHeight;                         // +0x958
    msvc8::string mBackgroundFile;                         // +0x95C
    ID3DDeviceResources::TextureResourceHandle mBackgroundTexture; // +0x978
    msvc8::string mSkycubeFile;                            // +0x980
    ID3DDeviceResources::TextureResourceHandle mSkycubeTexture;     // +0x99C
    TerrainEnvironmentLookupMap mEnvLookup;                // +0x9A4
    TerrainEditWordBuffer mEditWordBuffer;                 // +0x9B0
    ID3DDeviceResources::DynamicTextureSheetHandle mWaterMapTexture; // +0x9C0
    std::uint8_t* mWaterFoam;                              // +0x9C8
    std::uint8_t* mWaterFlatness;                          // +0x9CC
    std::uint8_t* mWaterDepthBias;                         // +0x9D0
    gpg::BitArray2D* mDebugDirtyTerrain;                   // +0x9D4
    TerrainDirtyRectList mDebugDirtyRects;                 // +0x9D8
    std::uint8_t mUnknown9E4_9E7[0x04];                    // +0x9E4
    WaveSystem mWaveSystem;                                // +0x9E8
    CDecalManager* mDecalManager;                          // +0xC30
    std::uint8_t mUnknownC34_C37[0x04];                    // +0xC34

  };

  static_assert(sizeof(IWldTerrainRes) == 0x08, "IWldTerrainRes size must be 0x08");
  static_assert(alignof(CWldTerrainRes) == 8, "CWldTerrainRes must be 8-aligned");
  static_assert(
    sizeof(CWldTerrainRes) == 0xC38,
    "CWldTerrainRes size must be 0xC38"
  );
  static_assert(
    offsetof(IWldTerrainRes, mMap) == 0x004,
    "IWldTerrainRes::mMap offset must be 0x004"
  );
  static_assert(
    offsetof(CWldTerrainRes, mBool) == 0x008,
    "CWldTerrainRes::mBool offset must be 0x008"
  );
  static_assert(
    offsetof(CWldTerrainRes, mEditMode) == 0x009,
    "CWldTerrainRes::mEditMode offset must be 0x009"
  );
  static_assert(
    offsetof(CWldTerrainRes, mCartographic) == 0x00C,
    "CWldTerrainRes::mCartographic offset must be 0x00C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mSkyDome) == 0x0B0,
    "CWldTerrainRes::mSkyDome offset must be 0x0B0"
  );
  static_assert(
    offsetof(CWldTerrainRes, mLightingMultiplier) == 0x2D8,
    "CWldTerrainRes::mLightingMultiplier offset must be 0x2D8"
  );
  static_assert(
    offsetof(CWldTerrainRes, mSpecularColor) == 0x30C,
    "CWldTerrainRes::mSpecularColor offset must be 0x30C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mBloom) == 0x31C,
    "CWldTerrainRes::mBloom offset must be 0x31C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mFogInfo) == 0x320,
    "CWldTerrainRes::mFogInfo offset must be 0x320"
  );
  static_assert(
    offsetof(CWldTerrainRes, mTopographicSamples) == 0x334,
    "CWldTerrainRes::mTopographicSamples offset must be 0x334"
  );
  static_assert(
    offsetof(CWldTerrainRes, mHypsometricColor) == 0x338,
    "CWldTerrainRes::mHypsometricColor offset must be 0x338"
  );
  static_assert(
    offsetof(CWldTerrainRes, mImagerElevationOffset) == 0x34C,
    "CWldTerrainRes::mImagerElevationOffset offset must be 0x34C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaterShaderProperties) == 0x350,
    "CWldTerrainRes::mWaterShaderProperties offset must be 0x350"
  );
  static_assert(
    offsetof(CWldTerrainRes, mStrata) == 0x4AC,
    "CWldTerrainRes::mStrata offset must be 0x4AC"
  );
  static_assert(
    offsetof(CWldTerrainRes, mNormalMap) == 0x948,
    "CWldTerrainRes::mNormalMap offset must be 0x948"
  );
  static_assert(
    offsetof(CWldTerrainRes, mNormalMapWidth) == 0x954,
    "CWldTerrainRes::mNormalMapWidth offset must be 0x954"
  );
  static_assert(
    offsetof(CWldTerrainRes, mNormalMapHeight) == 0x958,
    "CWldTerrainRes::mNormalMapHeight offset must be 0x958"
  );
  static_assert(
    offsetof(CWldTerrainRes, mBackgroundFile) == 0x95C,
    "CWldTerrainRes::mBackgroundFile offset must be 0x95C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mBackgroundTexture) == 0x978,
    "CWldTerrainRes::mBackgroundTexture offset must be 0x978"
  );
  static_assert(
    offsetof(CWldTerrainRes, mSkycubeFile) == 0x980,
    "CWldTerrainRes::mSkycubeFile offset must be 0x980"
  );
  static_assert(
    offsetof(CWldTerrainRes, mSkycubeTexture) == 0x99C,
    "CWldTerrainRes::mSkycubeTexture offset must be 0x99C"
  );
  static_assert(
    offsetof(CWldTerrainRes, mEnvLookup) == 0x9A4,
    "CWldTerrainRes::mEnvLookup offset must be 0x9A4"
  );
  static_assert(
    offsetof(CWldTerrainRes, mEditWordBuffer) == 0x9B0,
    "CWldTerrainRes::mEditWordBuffer offset must be 0x9B0"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaterMapTexture) == 0x9C0,
    "CWldTerrainRes::mWaterMapTexture offset must be 0x9C0"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaterFoam) == 0x9C8,
    "CWldTerrainRes::mWaterFoam offset must be 0x9C8"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaterFlatness) == 0x9CC,
    "CWldTerrainRes::mWaterFlatness offset must be 0x9CC"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaterDepthBias) == 0x9D0,
    "CWldTerrainRes::mWaterDepthBias offset must be 0x9D0"
  );
  static_assert(
    offsetof(CWldTerrainRes, mDebugDirtyTerrain) == 0x9D4,
    "CWldTerrainRes::mDebugDirtyTerrain offset must be 0x9D4"
  );
  static_assert(
    offsetof(CWldTerrainRes, mDebugDirtyRects) == 0x9D8,
    "CWldTerrainRes::mDebugDirtyRects offset must be 0x9D8"
  );
  static_assert(
    offsetof(CWldTerrainRes, mWaveSystem) == 0x9E8,
    "CWldTerrainRes::mWaveSystem offset must be 0x9E8"
  );
  static_assert(
    offsetof(CWldTerrainRes, mDecalManager) == 0xC30,
    "CWldTerrainRes::mDecalManager offset must be 0xC30"
  );
} // namespace moho
