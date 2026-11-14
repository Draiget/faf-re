#pragma once

#include "editor/ui/EdUnitCatalog.h"
#include "editor/ui/EdProperties.h"
#include "editor/tools/EdArrange.h"
#include "editor/tools/EdTerrainPath.h"
#include "editor/tools/EdWaterMasks.h"
#include "editor/tools/EdErosionSuite.h"
#include "editor/tools/EdInterop.h"
#include "editor/tools/EdScTools.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdBrushLibrary.h"
#include "editor/tools/EdSymmetrize.h"
#include "editor/tools/EdShaderProfiles.h"
#include "editor/tools/EdLayerConvert.h"
#include "editor/tools/EdSymmetryCheck.h"
#include "editor/tools/EdMaskBrush.h"
#include "editor/tools/EdMaskGen.h"
#include "editor/tools/EdRecipes.h"
#include "editor/tools/EdTextureSets.h"
#include "editor/doc/EdPropPaint.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdWaves.h"
#include "editor/tools/EdTerrainTypes.h"
#include "editor/doc/EdWater.h"
#include "editor/doc/EdWaterBodies.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdPickFilter.h"
#include "editor/doc/EdViewState.h"
#include "editor/tools/EdTextureLibrary.h"

#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <cmath>
#include <array>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * The tool box, as the mockup lays it out: a strip of tool icons at the window's left edge (DrawStrip, drawn by
   * the shell) and the chosen tool's settings in the Tools panel (brush modes, size, strength, falloff, the symmetry
   * modes with their diagrams, limits). The settings are kept here; the tools act on a map from stages 3 to 6 of the
   * plan.
   */
  class EdTools
  {
  public:
    /** Draws the panel's contents into the current ImGui window. */
    void Draw();

    /** Whether the Terrain tool is the chosen one (the viewport's left button paints heights). */
    [[nodiscard]] bool TerrainToolActive() const noexcept
    {
      return mTool == 1;
    }
    /** The Select tool (the viewport's left button picks and moves objects) and the Props tool. */
    [[nodiscard]] bool SelectToolActive() const noexcept
    {
      return mTool == 0;
    }
    [[nodiscard]] bool PropsToolActive() const noexcept
    {
      return mTool == 4;
    }
    /** The Props tool's settings: the blueprint placed, Single / Scatter / Erase, props a second, random turn. */
    enum class PropMode
    {
      Single,
      Scatter,
      Erase,
    };
    [[nodiscard]] const std::string& PropBlueprint() const noexcept
    {
      return mPropBlueprint;
    }
    [[nodiscard]] PropMode CurrentPropMode() const noexcept
    {
      return static_cast<PropMode>(mPropMode);
    }
    [[nodiscard]] float PropDensity() const noexcept
    {
      return mPropDensity;
    }
    [[nodiscard]] bool RandomPropTurn() const noexcept
    {
      return mPropRandomTurn;
    }
    /** Scatter's paint list (FAFME's): when it has props, Scatter picks one of them by chance for each prop. */
    [[nodiscard]] const std::vector<PropPaintEntry>& PaintList() const noexcept
    {
      return mPaintList;
    }
    /** The palette's spelling of this prop blueprint (case aside), or empty when it hasn't it. */
    [[nodiscard]] std::string PropBlueprintNamed(
      const std::string& path
    ) const
    {
      const auto lower = [](std::string text) {
        for (char& c : text) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return text;
      };
      const std::string wanted = lower(path);
      const auto at = std::find_if(mPropBlueprints.begin(), mPropBlueprints.end(), [&](const std::string& known) {
        return lower(known) == wanted;
      });
      return at != mPropBlueprints.end() ? *at : std::string();
    }
    void SetPaintList(
      std::vector<PropPaintEntry> list
    )
    {
      mPaintList = std::move(list);
    }
    /** The paint list's Import / Export of a `.proppaintset`, taken by the app. */
    [[nodiscard]] bool TakePaintSetImport() noexcept
    {
      return std::exchange(mPaintSetImport, false);
    }
    [[nodiscard]] bool TakePaintSetExport() noexcept
    {
      return std::exchange(mPaintSetExport, false);
    }
    /** The chosen prop's reclaim, scale and LODs, for the panel. */
    void SetPropDetails(
      std::string details
    )
    {
      mPropDetails = std::move(details);
    }
    /** The prop blueprints the rules have (their ids), for the palette. */
    void SetPropBlueprints(
      std::vector<std::string> blueprints
    )
    {
      mPropBlueprints = std::move(blueprints);
    }
    /** Where the panels get a prop blueprint's picture (an ImTextureID, 0 until made): the app's thumbnail cache. */
    void SetPropPictures(
      std::function<std::uint64_t(const std::string&)> source
    )
    {
      mPropPictures = std::move(source);
    }
    [[nodiscard]] std::uint64_t PropPicture(
      const std::string& blueprint
    ) const
    {
      return mPropPictures ? mPropPictures(blueprint) : 0U;
    }
    [[nodiscard]] bool HasPropBlueprints() const noexcept
    {
      return !mPropBlueprints.empty();
    }
    /** The prop blueprints the game has (the Props tool's palette; the Properties panel's prop browser). */
    [[nodiscard]] const std::vector<std::string>& PropBlueprints() const noexcept
    {
      return mPropBlueprints;
    }
    /** The map's prop reclaim for the panel (the app counts it now and then while the Props tool shows). */
    void SetPropReclaim(
      std::string summary,
      std::vector<std::string> rows
    )
    {
      mReclaimSummary = std::move(summary);
      mReclaimRows = std::move(rows);
    }
    /** The Markers tool. */
    [[nodiscard]] bool MarkersToolActive() const noexcept
    {
      return mTool == 6;
    }
    /** The Check's results on the map, for the view's pins: where, and how bad (0 error, 1 warning, 2 note). */
    struct CheckPin
    {
      float x;
      float z;
      int level;
    };
    void SetCheckPins(
      std::vector<CheckPin> pins
    )
    {
      mCheckPins = std::move(pins);
    }
    /** The Check's pathing on the ground: blocks of cells in a colour (ARGB), drawn while the switch is on. */
    struct PathQuad
    {
      float x0;
      float z0;
      float x1;
      float z1;
      std::uint32_t color;
    };
    void SetPathing(
      std::vector<PathQuad> land,
      std::vector<PathQuad> ships
    )
    {
      mPathQuads = std::move(land);
      mShipQuads = std::move(ships);
    }
    /** The layer shown: the land unit's (0) or the ship's (1). */
    [[nodiscard]] const std::vector<PathQuad>& PathingQuads() const noexcept
    {
      return mPathingLayer == 1 ? mShipQuads : mPathQuads;
    }
    [[nodiscard]] bool& ShowPathing() noexcept
    {
      return mShowPathing;
    }
    [[nodiscard]] int& PathingLayer() noexcept
    {
      return mPathingLayer;
    }
    [[nodiscard]] bool ShowingPathing() const noexcept
    {
      return mShowPathing && !PathingQuads().empty();
    }
    [[nodiscard]] const std::vector<CheckPin>& CheckPins() const noexcept
    {
      return mCheckPins;
    }
    /** The Water tool's panel: the map's water as it is, and a change it made (`final` when a drag or a click ended).
     */
    [[nodiscard]] bool WaterToolActive() const noexcept
    {
      return mTool == 3;
    }
    void SetWater(
      const WaterState& water
    )
    {
      if (!mWaterEditing) {
        mWater = water;
      }
    }
    /** The Water panel's Import / Export of FAForeverMapEditor's `.scmwtr`, taken by the app (it asks for the file). */
    [[nodiscard]] bool TakeWaterImport() noexcept
    {
      return std::exchange(mWaterImport, false);
    }
    [[nodiscard]] bool TakeWaterExport() noexcept
    {
      return std::exchange(mWaterExport, false);
    }
    /** The Water panel's waves: what was asked, and the settings for adding them along the shore. */
    enum class WaveAsk
    {
      None,
      AddAlongShore,
      Clear,
      LoadPatterns,
      Import,
      Export,
    };
    struct WaveSettings
    {
      WavePattern pattern;
      float depth = 2.0f;
      float density = 0.25f;
      float spacing = 4.0f;
      float centre = 0.0f;
      float range = 180.0f;
      /** Each picked place copied through the map's symmetry (the brushes' setting). */
      bool symmetric = false;
    };
    /** Pick waves: a click picks a wave generator (Ctrl adds, Shift removes it), a drag moves the picked. */
    [[nodiscard]] bool WavePicking() const noexcept
    {
      return mTool == 3 && mWavePick;
    }
    void SetWaveSelectionCount(
      const int count
    ) noexcept
    {
      mWaveSelectionCount = count;
    }
    [[nodiscard]] bool TakeWaveDelete() noexcept
    {
      return std::exchange(mWaveDelete, false);
    }
    void SetWaveCount(
      const int count
    ) noexcept
    {
      mWaveCount = count;
    }
    [[nodiscard]] WaveAsk TakeWaveAsk(
      WaveSettings& settings
    )
    {
      if (mWavePatterns.empty()) {
        mWavePatterns = BuiltInWavePatterns();
      }
      mWavePattern = std::clamp(mWavePattern, 0, static_cast<int>(mWavePatterns.size()) - 1);
      settings = {
        mWavePatterns[static_cast<std::size_t>(mWavePattern)],
        mWaveDepth,
        mWaveDensity,
        mWaveSpacing,
        mWaveCentre,
        mWaveRange,
        mWaveSymmetric
      };
      return std::exchange(mWaveAsk, WaveAsk::None);
    }
    /** Patterns read from a file, after the built-in ones. */
    void AddWavePatterns(
      const std::vector<WavePattern>& patterns
    )
    {
      if (mWavePatterns.empty()) {
        mWavePatterns = BuiltInWavePatterns();
      }
      mWavePatterns.insert(mWavePatterns.end(), patterns.begin(), patterns.end());
    }
    /** Test runs (`/waves`): a pattern, depth, density and spacing, then add them along the shore. */
    void AskWaves(
      const int pattern,
      const float depth,
      const float density,
      const float spacing
    ) noexcept
    {
      mWavePattern = pattern;
      mWaveDepth = depth;
      mWaveDensity = density;
      mWaveSpacing = spacing;
      mWaveAsk = WaveAsk::AddAlongShore;
    }
    /** The Water tool's mask brush: on (a drag in the view paints), which mask, and the brush. */
    [[nodiscard]] bool WaterMaskPainting() const noexcept
    {
      return mTool == 3 && mWaterMaskPaint;
    }
    [[nodiscard]] WaterMask WaterMaskKind() const noexcept
    {
      return static_cast<WaterMask>(mWaterMaskKind);
    }
    [[nodiscard]] WaterMaskBrush WaterMaskBrushNow() const noexcept
    {
      WaterMaskBrush brush = mWaterMaskBrush;
      brush.value = static_cast<std::uint8_t>(std::clamp(mWaterMaskValue, 0, 255));
      return brush;
    }
    /** Test runs (`/watermasktest`): the Water tool painting this mask towards this value. */
    void SetWaterMaskPaint(
      const WaterMask mask,
      const int value,
      const float radius
    ) noexcept
    {
      mTool = 3;
      mWaterMaskPaint = true;
      mWaterMaskKind = static_cast<int>(mask);
      mWaterMaskValue = value;
      mWaterMaskBrush.radius = radius;
      mWaterMaskBrush.strength = 1.0f;
    }
    /** The water's sun turns with the Lighting panel's sun (on by default). */
    [[nodiscard]] bool WaterSunFollows() const noexcept
    {
      return mWaterSunFollows;
    }
    /** "Take it now": the water's sun set from the lighting sun once, as its own undo step. */
    [[nodiscard]] bool TakeWaterTakeLightingSun() noexcept
    {
      return std::exchange(mWaterTakeLightingSun, false);
    }
    [[nodiscard]] bool TakeWaterChange(
      WaterState& water,
      bool& final
    )
    {
      if (!mWaterChanged) {
        return false;
      }
      water = mWater;
      final = mWaterFinal;
      mWaterChanged = false;
      mWaterFinal = false;
      return true;
    }
    /**
     * The Water panel's water bodies (`ScenarioInfo.WaterBodies`): the scenario's, given each frame and kept while the
     * panel or the view is changing them; a change either made (`final` when a drag or a click ended).
     */
    void SetWaterBodies(
      const std::vector<WaterBody>& bodies,
      std::string error
    )
    {
      if (!mBodiesEditing && !mBodiesChanged) {
        mBodies = bodies;
      }
      mBodiesError = std::move(error);
      mBody = std::clamp(mBody, -1, static_cast<int>(mBodies.size()) - 1);
    }
    [[nodiscard]] bool TakeWaterBodiesChange(
      std::vector<WaterBody>& bodies,
      bool& final
    )
    {
      if (!mBodiesChanged) {
        return false;
      }
      bodies = mBodies;
      final = mBodiesFinal;
      mBodiesChanged = false;
      mBodiesFinal = false;
      return true;
    }
    /** For the view: the bodies as the panel has them, the one chosen (-1 none), and a change it made to them. */
    [[nodiscard]] std::vector<WaterBody>& EditedWaterBodies() noexcept
    {
      return mBodies;
    }
    [[nodiscard]] int SelectedWaterBody() const noexcept
    {
      return mBody;
    }
    void SelectWaterBody(
      const int body
    ) noexcept
    {
      mBody = body;
    }
    void WaterBodiesChanged(
      const bool final
    ) noexcept
    {
      mBodiesChanged = true;
      mBodiesFinal = mBodiesFinal || final;
    }
    /** What a click in the view does to the chosen body: nothing, put its seed there, or add an outline point. */
    enum class WaterPick
    {
      None,
      Seed,
      Outline,
    };
    [[nodiscard]] WaterPick& WaterBodyPick() noexcept
    {
      return mWaterPick;
    }
    /** The panel's Add: a new body, chosen, waiting for its seed to be clicked on the map. */
    void AddWaterBody()
    {
      WaterBody body;
      body.elevation = mWater.enabled ? mWater.elevation : 0.0f;
      mBodies.push_back(body);
      mBody = static_cast<int>(mBodies.size()) - 1;
      mWaterPick = WaterPick::Seed;
      mBodyIsNew = true;
      mBodiesChanged = true;
      mBodiesFinal = true;
    }
    /** A new body waits for its seed: the click also sets its level a little above the ground there. */
    [[nodiscard]] bool& WaterBodyIsNew() noexcept
    {
      return mBodyIsNew;
    }
    /** The view is dragging a seed or an outline point (the panel keeps its copy). */
    void SetWaterBodyDragging(
      const bool dragging
    ) noexcept
    {
      mBodyDragging = dragging;
    }
    /** What the fill made of the bodies: a line for each (cells, or why the game skips it), and the game's other lines.
     */
    void SetWaterBodyReport(
      std::vector<std::string> perBody,
      std::vector<std::string> log
    )
    {
      mBodyReport = std::move(perBody);
      mBodyLog = std::move(log);
    }
    /** The Units tool: Place (the chosen unit type in the chosen army, with symmetric copies) or Select. */
    [[nodiscard]] bool UnitsToolActive() const noexcept
    {
      return mTool == 7;
    }
    [[nodiscard]] bool UnitPlaceMode() const noexcept
    {
      return mUnitMode == 0;
    }
    /** The Units tool's group tree of its army (the app gives it now and then), and what the panel asked of it. */
    enum class GroupAsk
    {
      None,
      Select,
      Add,
      Rename,
      Remove,
      MoveSelected,
    };
    void SetUnitTree(
      std::string army,
      UnitGroup tree
    )
    {
      mUnitTreeArmy = std::move(army);
      mUnitTree = std::move(tree);
    }
    [[nodiscard]] GroupAsk TakeGroupAsk(
      std::vector<std::string>& path,
      std::string& name
    )
    {
      path = mGroupPath;
      name = mGroupName;
      return std::exchange(mGroupAsk, GroupAsk::None);
    }
    /** Test runs (`/unitgroup <ask>,<path a/b>[,<name>]`). */
    void AskGroup(
      const GroupAsk ask,
      std::vector<std::string> path,
      const std::string& name
    )
    {
      mGroupPath = std::move(path);
      (void)std::snprintf(mGroupName, sizeof(mGroupName), "%s", name.c_str());
      mGroupAsk = ask;
    }
    [[nodiscard]] const std::string& UnitType() const noexcept
    {
      return mUnitType;
    }
    [[nodiscard]] const std::string& UnitArmy() const noexcept
    {
      return mUnitArmy;
    }
    [[nodiscard]] bool RandomUnitTurn() const noexcept
    {
      return mUnitRandomTurn;
    }
    /** The unit blueprints the rules have: id and name. */
    void SetUnitTypes(
      std::vector<std::pair<std::string, std::string>> types
    )
    {
      mUnitTypes = std::move(types);
    }
    [[nodiscard]] bool HasUnitTypes() const noexcept
    {
      return !mUnitTypes.empty();
    }
    /** Each unit's faction, kind and tech (its blueprint's categories), for the unit browser. */
    void SetUnitInfos(
      std::vector<EdUnitInfo> infos
    )
    {
      mUnitInfos = std::move(infos);
    }
    [[nodiscard]] const std::vector<EdUnitInfo>& UnitInfos() const noexcept
    {
      return mUnitInfos;
    }
    /** A unit blueprint's name ("Mass Extractor"), or "" when the rules don't have it. */
    [[nodiscard]] std::string UnitTypeName(
      const std::string& id
    ) const
    {
      for (const auto& [type, name] : mUnitTypes) {
        if (
          type.size() == id.size() && std::equal(type.begin(), type.end(), id.begin(), [](const char a, const char b) {
          return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        })
        ) {
          return name;
        }
      }
      return {};
    }
    /** The selected units' rings: weapons' reach (and their least), vision and radar, from the blueprints. */
    [[nodiscard]] bool ShowRangeRings() const noexcept
    {
      return mShowRangeRings;
    }
    /** The Units panel's Give: the selected units to its army (taken once). */
    [[nodiscard]] bool TakeGiveUnits() noexcept
    {
      return std::exchange(mGiveUnits, false);
    }
    void SetUnitSelectionCount(
      const int count
    ) noexcept
    {
      mUnitSelectionCount = count;
    }
    /** The view's unit selection (army, name), each frame, for the panels. */
    void SetUnitSelection(
      std::vector<std::pair<std::string, std::string>> units
    )
    {
      mUnitSelectionNow = std::move(units);
    }
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& UnitSelection() const noexcept
    {
      return mUnitSelectionNow;
    }
    /** A panel's ask: select these units, or move these units of an army into a group (made when missing). */
    struct UnitGroupAsk
    {
      bool select = false;
      /** Remove the group at `path` of `army` (and those at `morePaths`) with their units instead of moving into it. */
      bool removeGroup = false;
      std::vector<std::vector<std::string>> morePaths;
      std::vector<std::pair<std::string, std::string>> units;
      std::string army;
      std::vector<std::string> names;
      std::vector<std::string> path;
    };
    void AskUnitGroup(
      UnitGroupAsk ask
    )
    {
      mUnitGroupAsk = std::move(ask);
      mUnitGroupAsked = true;
    }
    [[nodiscard]] bool TakeUnitGroup(
      UnitGroupAsk& ask
    )
    {
      if (!std::exchange(mUnitGroupAsked, false)) {
        return false;
      }
      ask = std::move(mUnitGroupAsk);
      return true;
    }
    /** Test runs (`/unittool <type>,<army>[,select]`). */
    void SetUnitTool(
      std::string type,
      std::string army,
      const bool select
    )
    {
      mTool = 7;
      mUnitType = std::move(type);
      mUnitArmy = std::move(army);
      mUnitMode = select ? 1 : 0;
    }
    /** The Decals tool: Place (a click places the chosen texture with its symmetric copies) or Select (pick, drag,
     * delete). */
    [[nodiscard]] bool DecalsToolActive() const noexcept
    {
      return mTool == 5;
    }
    [[nodiscard]] bool DecalPlaceMode() const noexcept
    {
      return mDecalMode == 0;
    }
    /** Path mode: clicks lay a curve's points; decals follow it end to end when placed. */
    [[nodiscard]] bool DecalPathMode() const noexcept
    {
      return mDecalMode == 2;
    }
    /** Select mode: pick, drag, delete. */
    [[nodiscard]] bool DecalSelectMode() const noexcept
    {
      return mDecalMode == 1;
    }
    /** Scatter: a drag strews the texture over the brush's circle, apart from each other (FAF Studio's). */
    [[nodiscard]] bool DecalScatterMode() const noexcept
    {
      return mDecalMode == 3;
    }
    /** Erase: a drag removes the decals in the brush's circle (only the chosen texture's, when asked). */
    [[nodiscard]] bool DecalEraseMode() const noexcept
    {
      return mDecalMode == 4;
    }
    struct DecalBrush
    {
      float radius = 24.0f;
      int count = 3;      // decals a dab
      float apart = 8.0f; // the least distance between two
      bool onlyThisTexture = false;
    };
    [[nodiscard]] const DecalBrush& DecalBrushSettings() const noexcept
    {
      return mDecalBrush;
    }
    /** Each click or scattered decal: its size times 1 +- this at random (one draw shared by the symmetric copies). */
    [[nodiscard]] float DecalSizeVariation() const noexcept
    {
      return mDecalSizeVariation;
    }
    /** How much each decal along a path overlaps the next (0 to 0.9 of its length). */
    [[nodiscard]] float DecalOverlap() const noexcept
    {
      return mDecalOverlap;
    }
    /** What the panel's path buttons asked for, taken once. */
    enum class DecalPathAction
    {
      None,
      Place,
      RemoveLast,
      Clear,
    };
    [[nodiscard]] DecalPathAction TakeDecalPathAction() noexcept
    {
      return std::exchange(mDecalPathAction, DecalPathAction::None);
    }
    /** The path's points and the decals it would place, for the panel. */
    void SetDecalPathInfo(
      const int points,
      const int decals
    ) noexcept
    {
      mDecalPathPoints = points;
      mDecalPathDecals = decals;
    }
    [[nodiscard]] const std::string& DecalTexturePath() const noexcept
    {
      return mDecalTexture;
    }
    /** The albedo's spec map, the decal's second texture, or "" when it has none or the option is off. */
    [[nodiscard]] std::string DecalPairPath() const
    {
      if (!mDecalWithPair) {
        return {};
      }
      for (const DecalTexture& texture : mDecalTextures) {
        if (texture.path == mDecalTexture) {
          return texture.pair;
        }
      }
      return {};
    }
    [[nodiscard]] float DecalSizeX() const noexcept
    {
      return mDecalSize[0];
    }
    [[nodiscard]] float DecalSizeZ() const noexcept
    {
      return mDecalSize[1];
    }
    /** The heading in radians; a random one when Random turn is on. */
    [[nodiscard]] float DecalTurnDegrees() const noexcept
    {
      return mDecalTurn;
    }
    [[nodiscard]] bool RandomDecalTurn() const noexcept
    {
      return mDecalRandomTurn;
    }
    /** The far cutoff distance (0: the decal works one out from its size). */
    [[nodiscard]] float DecalCutoff() const noexcept
    {
      return mDecalCutoff;
    }
    /** How many decals the view has selected, for the panel. */
    void SetDecalSelectionCount(
      const int count
    ) noexcept
    {
      mDecalSelectionCount = count;
    }
    /** Test runs (`/decaltool <texture>[,select]`): the Decals tool with this texture and mode. */
    void SetDecalTool(
      std::string texture,
      const int mode
    )
    {
      mTool = 5;
      mDecalTexture = std::move(texture);
      mDecalMode = mode;
    }
    /** The map's playable area (x0, z0, x1, z1) as it is, and the map's size, for the panel. */
    void SetPlayableArea(
      const std::optional<std::array<int, 4>>& area,
      const int width,
      const int height
    )
    {
      mArea = area;
      mMapWidth = width;
      mMapHeight = height;
    }
    /** The map's size in units (its height field's samples less one), as the app last gave it. */
    [[nodiscard]] int MapWidth() const noexcept
    {
      return mMapWidth;
    }
    [[nodiscard]] int MapHeight() const noexcept
    {
      return mMapHeight;
    }
    /** A change the panel asked for: the new area, or none to remove it. */
    [[nodiscard]] bool TakePlayableAreaChange(
      std::optional<std::array<int, 4>>& area
    )
    {
      if (!mAreaChanged) {
        return false;
      }
      mAreaChanged = false;
      area = mAreaChange;
      return true;
    }

    /** The Markers tool's air node grid: its size and whether it replaces the map's air nodes, asked once. */
    void AskAirGrid(
      const int count,
      const bool replace
    ) noexcept
    {
      mAirGridCount = count;
      mAirGridReplace = replace;
      mAirGridAsked = true;
    }
    [[nodiscard]] bool TakeAirGrid(
      int& count,
      bool& replace
    ) noexcept
    {
      count = mAirGridCount;
      replace = mAirGridReplace;
      return std::exchange(mAirGridAsked, false);
    }
    /** The Markers tool's type to place (an entry of MarkerTypes()). */
    [[nodiscard]] const MarkerType& PlaceMarkerType() const noexcept
    {
      return MarkerTypes()[static_cast<std::size_t>(mMarkerType)];
    }
    /** The markers the view has selected (copies of their entries), for the properties panel. */
    void SetMarkerSelection(
      std::vector<SaveEntry> selection
    )
    {
      mMarkerSelection = std::move(selection);
    }
    /** A property of the selected marker the panel changed (`key` "name" renames it). */
    [[nodiscard]] bool TakeMarkerEdit(
      std::string& marker,
      std::string& key,
      std::string& value
    )
    {
      if (mMarkerEditKey.empty()) {
        return false;
      }
      marker = std::exchange(mMarkerEditName, {});
      key = std::exchange(mMarkerEditKey, {});
      value = std::exchange(mMarkerEditValue, {});
      return true;
    }
    /** The scenario's armies and extra armies, for the panel; an extra-armies change it asks for. */
    void SetArmies(
      std::vector<std::string> armies,
      std::vector<std::string> extra
    )
    {
      mArmies = std::move(armies);
      mExtraArmies = std::move(extra);
    }
    /** The scenario's teams, for the panel's slot order and its FFA check; a change it asks for, taken once. */
    void SetTeams(
      std::vector<ScenarioTeam> teams
    )
    {
      mTeams = std::move(teams);
    }
    [[nodiscard]] bool TakeTeamsChange(
      std::vector<ScenarioTeam>& teams
    )
    {
      if (!mTeamsChanged) {
        return false;
      }
      mTeamsChanged = false;
      teams = mTeamsChange;
      return true;
    }
    /** The Armies panel's slot order and extra armies (one space-separated list), taken like the tool's own. */
    void AskTeamsChange(
      std::vector<ScenarioTeam> teams
    )
    {
      mTeamsChange = std::move(teams);
      mTeamsChanged = true;
    }
    void AskExtraArmiesChange(
      const std::string& extra
    )
    {
      (void)std::snprintf(mExtraBuffer, sizeof(mExtraBuffer), "%s", extra.c_str());
      mExtraChanged = true;
    }
    /** The Markers tool's "Open the Armies panel", taken by the shell. */
    [[nodiscard]] bool TakeOpenArmies() noexcept
    {
      return std::exchange(mOpenArmies, false);
    }
    [[nodiscard]] bool TakeExtraArmiesChange(
      std::string& extra
    )
    {
      if (!mExtraChanged) {
        return false;
      }
      mExtraChanged = false;
      extra = mExtraBuffer;
      return true;
    }

    /**
     * The map border (the playable area) edited from any tool: the toolbar's border button. While on, the view draws
     * the border's handles and a drag on an edge moves it; the Properties panel shows the settings (DrawPlayableArea).
     */
    [[nodiscard]] bool& EditingBorder() noexcept
    {
      return mEditBorder;
    }
    /** Moving one edge moves the opposite one the same way, so the border stays centred on the map. */
    [[nodiscard]] bool BorderCentred() const noexcept
    {
      return mBorderCentred;
    }
    /** The border's settings: on or off, the four edges, centred (the Markers tool and the Properties panel show them).
     */
    void DrawPlayableArea();
    /** The toolbar's Show menu: prop and unit models drawn or hidden (hidden ones are not picked either). */
    [[nodiscard]] bool& ShowProps() noexcept
    {
      return mShowProps;
    }
    [[nodiscard]] bool& ShowUnits() noexcept
    {
      return mShowUnits;
    }
    /** Rings a panel asks the view to draw this frame (a choice's markers or units under the mouse); the panels refill
     * them each frame. */
    struct ViewRing
    {
      float x = 0.0f;
      float z = 0.0f;
      float radius = 3.0f;
      std::uint32_t colour = 0xF0FFA040u;
    };
    /** The view switches and tool, as kept per map across restarts (doc/EdViewState). */
    [[nodiscard]] ViewState GetViewState() const
    {
      ViewState s;
      s.tool = mTool;
      s.grid = mShowGrid;
      s.snap = mSnap;
      s.gridStep = mGridStep;
      s.keepOnGround = mKeepOnGround;
      s.slope = mShowSlope;
      s.kmGrid = mShowKmGrid;
      s.terrainTypes = mShowTerrainTypes;
      s.pathing = mShowPathing;
      s.pathingLayer = mPathingLayer;
      s.layerWeight = mShowWeight;
      s.differences = mShowDifferences;
      s.props = mShowProps;
      s.units = mShowUnits;
      s.gameUnits = mShowGameUnits;
      s.hiddenMarkerTypes = mHiddenMarkerTypes;
      return s;
    }
    void SetViewState(
      const ViewState& s
    )
    {
      mTool = s.tool;
      mShowGrid = s.grid;
      mSnap = s.snap;
      mGridStep = s.gridStep;
      mKeepOnGround = s.keepOnGround;
      mShowSlope = s.slope;
      mShowKmGrid = s.kmGrid;
      mShowTerrainTypes = s.terrainTypes;
      mShowPathing = s.pathing;
      mPathingLayer = s.pathingLayer;
      mShowWeight = s.layerWeight;
      mShowDifferences = s.differences;
      mShowProps = s.props;
      mShowUnits = s.units;
      mShowGameUnits = s.gameUnits;
      mHiddenMarkerTypes = s.hiddenMarkerTypes;
    }
    /** In front of a play: the game's units selected in the editor's view (entity ids), for the Properties panel. */
    void SetLiveSelection(
      std::vector<std::uint32_t> ids
    )
    {
      mLiveSelection = std::move(ids);
    }
    [[nodiscard]] const std::vector<std::uint32_t>& LiveSelection() const noexcept
    {
      return mLiveSelection;
    }
    /** The game's units drawn in the editor's view in front of a play (hidden: not drawn, not picked). */
    [[nodiscard]] bool& ShowGameUnits() noexcept
    {
      return mShowGameUnits;
    }
    /** The map's props and units still loading (the view says so, else an empty map looks finished; user report). */
    void SetModelsLoading(
      const bool loading
    ) noexcept
    {
      mModelsLoading = loading;
    }
    [[nodiscard]] bool ModelsLoading() const noexcept
    {
      return mModelsLoading;
    }
    void ClearViewRings() noexcept
    {
      mViewRings.clear();
    }
    void AddViewRing(
      const ViewRing& ring
    )
    {
      mViewRings.push_back(ring);
    }
    [[nodiscard]] const std::vector<ViewRing>& ViewRings() const noexcept
    {
      return mViewRings;
    }
    /**
     * The Adaptive Map window's preview of a game: the units (army, name) and markers a lobby setting doesn't create,
     * hidden in the view (not drawn, not picked) while it is on; empty when off.
     */
    void SetPreviewHidden(
      std::set<std::pair<std::string, std::string>> units,
      std::set<std::string> markers
    )
    {
      mPreviewHiddenUnits = std::move(units);
      mPreviewHiddenMarkers = std::move(markers);
    }
    [[nodiscard]] const std::set<std::pair<std::string, std::string>>& PreviewHiddenUnits() const noexcept
    {
      return mPreviewHiddenUnits;
    }
    [[nodiscard]] const std::set<std::string>& PreviewHiddenMarkers() const noexcept
    {
      return mPreviewHiddenMarkers;
    }
    /** The Markers panel: the types it hides (not drawn, not picked), and what it asks the view for. */
    [[nodiscard]] const std::set<std::string>& HiddenMarkerTypes() const noexcept
    {
      return mHiddenMarkerTypes;
    }
    [[nodiscard]] std::set<std::string>& HiddenMarkerTypes() noexcept
    {
      return mHiddenMarkerTypes;
    }
    /** Select these markers (`add`: Ctrl, toggles them in the selection); the Markers tool comes up to edit them. */
    void AskMarkerSelect(
      std::vector<std::string> names,
      const bool add
    )
    {
      mAskSelect = std::move(names);
      mAskSelectAdd = add;
      mAskSelectSet = true;
      mTool = 6;
    }
    void AskMarkerFrame(
      std::string name
    )
    {
      mAskFrame = std::move(name);
    }
    /** The view to a point of the map (the Check's prop issues). */
    void AskPointFrame(
      const float x,
      const float z
    )
    {
      mAskPoint = {x, z};
      mAskPointSet = true;
    }
    [[nodiscard]] bool TakePointFrame(
      float& x,
      float& z
    )
    {
      if (!std::exchange(mAskPointSet, false)) {
        return false;
      }
      x = mAskPoint[0];
      z = mAskPoint[1];
      return true;
    }
    [[nodiscard]] bool TakeMarkerSelect(
      std::vector<std::string>& names,
      bool& add
    )
    {
      if (!mAskSelectSet) {
        return false;
      }
      mAskSelectSet = false;
      names = std::move(mAskSelect);
      add = mAskSelectAdd;
      return true;
    }
    [[nodiscard]] bool TakeMarkerFrame(
      std::string& name
    )
    {
      if (mAskFrame.empty()) {
        return false;
      }
      name = std::exchange(mAskFrame, {});
      return true;
    }
    [[nodiscard]] const std::vector<SaveEntry>& MarkerSelection() const noexcept
    {
      return mMarkerSelection;
    }
    /** The layer textures and their thumbnails (the Info panel shows the map's layers with them too). */
    [[nodiscard]] EdTextureLibrary& Library() noexcept
    {
      return mLibrary;
    }

    /** The build grid around the cursor, snapping to its cells, and its step in game units (toolbar). */
    [[nodiscard]] bool ShowGrid() const noexcept
    {
      return mShowGrid;
    }
    void SetShowGrid(
      const bool show
    ) noexcept
    {
      mShowGrid = show;
    }
    [[nodiscard]] bool SnapToGrid() const noexcept
    {
      return mSnap;
    }
    void SetSnapToGrid(
      const bool snap
    ) noexcept
    {
      mSnap = snap;
    }
    [[nodiscard]] float GridStep() const noexcept
    {
      return mGridStep;
    }
    /** The move gizmo keeps objects on the ground (X, Z and free moves); off, they keep their height. Never below it.
     */
    [[nodiscard]] bool KeepOnGround() const noexcept
    {
      return mKeepOnGround;
    }
    void SetKeepOnGround(
      const bool keep
    ) noexcept
    {
      mKeepOnGround = keep;
    }
    void SetGridStep(
      const float step
    ) noexcept
    {
      mGridStep = step;
    }

    /** The Markers tool's connect mode: a click on a path node links it to the selection. */
    /** Draw chain (FAF Studio's chains.lua): each marker placed joins the chain named in the panel. */
    [[nodiscard]] bool DrawingChain() const noexcept
    {
      return MarkersToolActive() && mDrawChain;
    }
    [[nodiscard]] std::string ChainName() const
    {
      return mChainName;
    }
    void SetChainName(
      const std::string& name
    )
    {
      (void)std::snprintf(mChainName, sizeof(mChainName), "%s", name.c_str());
    }
    [[nodiscard]] bool ConnectPathNodes() const noexcept
    {
      return mConnectNodes;
    }
    void SetConnectPathNodes(
      const bool connect
    ) noexcept
    {
      mConnectNodes = connect;
    }
    /** Test runs (`/markertool`): the Markers tool placing this type. */
    void SetMarkerTool(
      std::string type
    ) noexcept
    {
      mTool = 6;
      // `_` for a space, as a command line option is one word (`Blank_Marker`).
      std::replace(type.begin(), type.end(), '_', ' ');
      for (std::size_t i = 0; i < MarkerTypes().size(); ++i) {
        if (type == MarkerTypes()[i].type) {
          mMarkerType = static_cast<int>(i);
        }
      }
    }

    /** How many objects the view has selected, for the Select tool's panel. */
    /** The Properties panel: the selection's active item (the view gives it each frame), and an edit it asks for. */
    void SetSelectionProperties(
      SelectionProperties properties
    )
    {
      mSelectionProperties = std::move(properties);
    }
    [[nodiscard]] const SelectionProperties& SelectionPropertiesNow() const noexcept
    {
      return mSelectionProperties;
    }
    void AskPropertyEdit(
      PropertyEdit edit
    )
    {
      mPropertyEdit = std::move(edit);
    }
    [[nodiscard]] bool TakePropertyEdit(
      PropertyEdit& edit
    )
    {
      if (mPropertyEdit.what == PropertyEdit::What::None) {
        return false;
      }
      edit = std::exchange(mPropertyEdit, PropertyEdit{});
      return true;
    }
    /** The Select tool's panel: what is selected and what a click would pick, in words (the view gives them). */
    void SetSelectInfo(
      std::string selected,
      std::string hover,
      const bool any
    )
    {
      mSelectSelected = std::move(selected);
      mSelectHover = std::move(hover);
      mSelectAny = any;
    }
    /** Test runs (`/proptool`): the Props tool with this blueprint and mode, the list filtered to its name. */
    void SetPropTool(
      std::string blueprint,
      const int mode
    ) noexcept
    {
      mTool = 4;
      mPropBlueprint = std::move(blueprint);
      mPropMode = mode;
      const std::size_t slash = mPropBlueprint.find_last_of('/');
      std::string name = slash == std::string::npos ? mPropBlueprint : mPropBlueprint.substr(slash + 1);
      if (const std::size_t suffix = name.find("_prop.bp"); suffix != std::string::npos) {
        name.resize(suffix);
      }
      (void)std::snprintf(mPropFilter, sizeof(mPropFilter), "%s", name.c_str());
    }
    void SetTool(
      const int tool
    ) noexcept
    {
      mTool = tool;
    }
    /** Properties: these units of `army` become wrecks from the start (its WRECKAGE group) or units again (INITIAL). */
    struct UnitWreckAsk
    {
      std::string army;
      std::vector<std::string> names;
      bool wreck = false;
    };
    void AskUnitWreck(
      UnitWreckAsk ask
    )
    {
      mUnitWreckAsk = std::move(ask);
      mUnitWreckAsked = true;
    }
    [[nodiscard]] bool TakeUnitWreck(
      UnitWreckAsk& ask
    )
    {
      if (!std::exchange(mUnitWreckAsked, false)) {
        return false;
      }
      ask = std::move(mUnitWreckAsk);
      return true;
    }
    /** The tool shown (0 Select ... 7 Units). */
    [[nodiscard]] int Tool() const noexcept
    {
      return mTool;
    }
    /** How many tools the strip has, and each one's name ("Select", "Terrain", ...). */
    [[nodiscard]] static int ToolCount() noexcept;
    [[nodiscard]] static const char* ToolName(int tool) noexcept;
    /** A tool's icon (ui/EdIconFont.h). */
    [[nodiscard]] static const char* ToolIcon(int tool) noexcept;
    /**
     * The tool strip (the shell's, at the window's left edge, `width` wide): a button per tool and the measuring
     * button. True when a tool was picked.
     */
    bool DrawStrip(float width);
    /** The Layers panel (the right dock): the shader, the ten layers, the paint layer, moving one. */
    void DrawLayersPanel();
    /** The symmetry the brushes and the check use (the Terrain panel's tiles: 0 None ... 9 N-way). */
    [[nodiscard]] int SymmetryIndex() const noexcept
    {
      return mSymmetry;
    }
    void PickSymmetry(
      const int mode
    ) noexcept
    {
      mSymmetry = mode;
    }
    /** The symmetry mode the toolbar's pointer is over (-1: none): the map previews it. Set every frame. */
    void SetSymmetryHover(
      const int mode
    ) noexcept
    {
      mSymmetryHover = mode;
    }
    [[nodiscard]] int SymmetryHover() const noexcept
    {
      return mSymmetryHover;
    }
    [[nodiscard]] static const char* SymmetryName(int mode) noexcept;
    /**
     * The view's camera for its overlays, the scene's each frame: the directions on the ground of the view's up and
     * right (unit vectors in x, z), the ground under the view's corners (top-left, top-right, bottom-right,
     * bottom-left; fewer when a corner shows sky), and the map's rectangle.
     */
    struct ViewFrame
    {
      bool valid = false;
      float upX = 0.0f;
      float upZ = -1.0f;
      float rightX = 1.0f;
      float rightZ = 0.0f;
      int corners = 0;
      float cornerX[4]{};
      float cornerZ[4]{};
      float minX = 0.0f;
      float minZ = 0.0f;
      float maxX = 0.0f;
      float maxZ = 0.0f;
    };
    [[nodiscard]] ViewFrame& View() noexcept
    {
      return mViewFrame;
    }
    [[nodiscard]] const ViewFrame& View() const noexcept
    {
      return mViewFrame;
    }
    /**
     * Where the minimap sits in the view, in the view's pixels (x, y, width, height; zero size when it isn't shown):
     * the scene draws the map from above into it.
     */
    /** The minimap's last copy as an image (0: none; the scene's view then draws under the frame every frame). */
    void SetMinimapImage(
      const std::uint64_t image
    ) noexcept
    {
      mMinimapImage = image;
    }
    [[nodiscard]] std::uint64_t MinimapImage() const noexcept
    {
      return mMinimapImage;
    }
    void SetMinimapRect(
      const float x,
      const float y,
      const float width,
      const float height
    ) noexcept
    {
      mMinimapRect[0] = x;
      mMinimapRect[1] = y;
      mMinimapRect[2] = width;
      mMinimapRect[3] = height;
    }
    [[nodiscard]] const float* MinimapRect() const noexcept
    {
      return mMinimapRect;
    }
    /** Move stratum `from` to place `to` (0..7) with its mask, next frame (the scene takes it; one undo step). */
    void AskLayerMove(
      const int from,
      const int to
    ) noexcept
    {
      mLayerMoveFrom = from;
      mLayerMoveTo = to;
    }
    [[nodiscard]] bool TakeLayerMove(
      int& from,
      int& to
    ) noexcept
    {
      from = std::exchange(mLayerMoveFrom, -1);
      to = mLayerMoveTo;
      return from >= 0;
    }
    /** What the Select tool may pick (its panel's Pick pills). */
    [[nodiscard]] PickFilter& Pickable() noexcept
    {
      return mPickable;
    }
    [[nodiscard]] const PickFilter& Pickable() const noexcept
    {
      return mPickable;
    }
    /** The Layers panel's map-wide textures: what a row asks (kind 0 the normal map, 1 the lighting, 2 the specular, 3
     * the macrotexture), and its state. */
    enum class MapTextureOp : std::uint8_t
    {
      None,
      Make,
      Clear,
      Export,
      Import,
    };
    struct MapTextureRow
    {
      bool available = false; // the shader reads this kind
      bool shared = false;    // one texture holds both kinds (TerrainPBR, Terrain301)
      bool present = false;   // the slot holds a texture
      bool made = false;      // made here
      bool stale = false;     // made here, and what it was made from changed since
      std::string state;      // one line for the panel
    };
    /** `file`: a test run's path instead of the dialog (Export, Import); `raiseAfter`: a test run's height edit after
     * Make. */
    void AskMapTexture(
      const int kind,
      const MapTextureOp op,
      std::string file = {},
      const bool raiseAfter = false
    )
    {
      mMapTextureKind = kind;
      mMapTextureOp = op;
      mMapTextureFile = std::move(file);
      mMapTextureRaise = raiseAfter;
    }
    [[nodiscard]] const std::string& MapTextureFile() const noexcept
    {
      return mMapTextureFile;
    }
    [[nodiscard]] bool MapTextureRaiseAfter() const noexcept
    {
      return mMapTextureRaise;
    }
    [[nodiscard]] bool TakeMapTextureAsk(
      int& kind,
      MapTextureOp& op
    ) noexcept
    {
      kind = mMapTextureKind;
      op = std::exchange(mMapTextureOp, MapTextureOp::None);
      return op != MapTextureOp::None;
    }
    [[nodiscard]] MapTextureRow& MapTextureState(
      const int kind
    ) noexcept
    {
      return mMapTextureRows[std::clamp(kind, 0, 3)];
    }
    /** The minimap's click: the camera looks at (x, z) next frame (the scene takes it). */
    void AskCameraAt(
      const float x,
      const float z
    ) noexcept
    {
      mCameraAsk = true;
      mCameraAskX = x;
      mCameraAskZ = z;
    }
    [[nodiscard]] bool TakeCameraAsk(
      float& x,
      float& z
    ) noexcept
    {
      x = mCameraAskX;
      z = mCameraAskZ;
      return std::exchange(mCameraAsk, false);
    }
    /** The view's HUD: the terrain brush's mode by name ("Raise"), or null for the other tools. */
    [[nodiscard]] const char* HudMode() const noexcept;
    /** The view's HUD: how many copies an edit makes (the symmetry's), 1 for tools that don't mirror. */
    [[nodiscard]] int HudCopies() const noexcept;
    /** A symmetry's picture (its tile's) in the square at `p`, `s` wide. */
    void DrawSymmetryPicture(ImDrawList* draw, int mode, ImVec2 p, float s) const;
    /**
     * A symmetry mode's tooltip body (call between BeginTooltip and EndTooltip): its name, what it does in a sentence,
     * and a small map in motion with its mirror lines or turn centre and a dab painting with its copies. `fromToolbar`
     * adds where the other modes are.
     */
    void DrawSymmetryTooltip(int mode, bool fromToolbar) const;
    /** The toolbar's symmetry menu body: the ten modes as pictures, the N-way count, what the map's heights fit. */
    void DrawSymmetryMenu();
    /** The key each tool's command has (Settings > Keys), shown in the strip's corner and its tooltip. */
    void SetToolKeys(
      std::vector<std::string> keys
    )
    {
      mToolKeys = std::move(keys);
    }
    /** The Review workspace: only the Select tool (the strip's others say why); the tool becomes Select. */
    void SetReadOnly(
      const bool readOnly
    ) noexcept
    {
      mReadOnly = readOnly;
      if (readOnly) {
        mTool = 0;
      }
    }

    /** Whether the Texture tool is the chosen one (the viewport's left button paints a layer's mask). */
    [[nodiscard]] bool TextureToolActive() const noexcept
    {
      return mTool == 2;
    }
    /** The Texture tool paints the terrain type grid instead of the layer masks. */
    [[nodiscard]] bool PaintingTerrainTypes() const noexcept
    {
      return mTool == 2 && mTexturePaint == 1;
    }
    [[nodiscard]] std::uint8_t TerrainTypeCode() const noexcept
    {
      return static_cast<std::uint8_t>(mTerrainTypeCode);
    }
    [[nodiscard]] bool ShowTerrainTypes() const noexcept
    {
      return mTool == 2 && mTexturePaint == 1 && mShowTerrainTypes;
    }
    /** The game's types (TerrainTypes.lua), given once the app has read them. */
    void SetTerrainTypes(
      std::vector<TerrainTypeInfo> types
    )
    {
      mTerrainTypes = std::move(types);
    }
    /** The game's terrain types (codes and names). */
    [[nodiscard]] const std::vector<TerrainTypeInfo>& TerrainTypeList() const noexcept
    {
      return mTerrainTypes;
    }
    [[nodiscard]] bool HasTerrainTypes() const noexcept
    {
      return !mTerrainTypes.empty();
    }
    [[nodiscard]] std::uint32_t TerrainTypeColor(
      const std::uint8_t code
    ) const noexcept
    {
      for (const TerrainTypeInfo& type : mTerrainTypes) {
        if (type.code == code) {
          return type.color;
        }
      }
      return 0xFFFF00FFu;
    }
    /** The view aids: the slope bands, the km grid with the centre lines, and the status bar's cursor and ruler. */
    /** The slope view's rule: mobile units by footprint, or structures by skirt and building rule, against a limit. */
    struct SlopeView
    {
      bool buildings = false;
      int footprint = 1; // cells
      int skirt = 2;     // cells
      bool ring = true;  // a flattened skirt (most buildings); else the whole area
      float unitLimit = 0.75f;
      float ringLimit = 1.0f;
      float areaLimit = 1.0f;
      /** The rule as the ratings name it: 0 path, 1 area, 2 ring; its window in cells; its limit in world units. */
      [[nodiscard]] int Kind() const noexcept
      {
        return !buildings ? 0 : ring ? 2 : 1;
      }
      [[nodiscard]] int Window() const noexcept
      {
        return buildings ? skirt : footprint;
      }
      [[nodiscard]] float Limit() const noexcept
      {
        return !buildings ? unitLimit : ring ? ringLimit : areaLimit;
      }
    };
    [[nodiscard]] SlopeView& SlopeSettings() noexcept
    {
      return mSlopeView;
    }
    /** Terrain types from the layers: Generate asked, with each layer's type (0 the base) and whether only Default
     * cells change. */
    [[nodiscard]] bool TakeTypesFromLayers(
      std::array<int, 9>& types,
      bool& onlyDefault
    )
    {
      if (!mTypesFromLayersAsk) {
        return false;
      }
      mTypesFromLayersAsk = false;
      for (std::size_t layer = 0; layer < types.size(); ++layer) {
        types[layer] = mLayerTypeOverride[layer] >= 0 || layer >= mSlots.size()
          ? std::max(1, mLayerTypeOverride[layer])
          : DefaultTerrainTypeFor(mSlots[layer].albedo, mTerrainTypes);
      }
      onlyDefault = mTypesOnlyDefault;
      return true;
    }
    void AskTypesFromLayers(
      const bool onlyDefault
    ) noexcept
    {
      mTypesFromLayersAsk = true;
      mTypesOnlyDefault = onlyDefault;
    }
    /** Follow symmetry: moving, turning or deleting an object does the same to its mirrored copies. */
    [[nodiscard]] bool FollowSymmetry() const noexcept
    {
      return mFollowSymmetry;
    }
    /** The Erosion window: open it, what it asks the view (with the solver and its settings), and what it hears back.
     */
    enum class ErosionAsk
    {
      None,
      Preview,
      Revert,
      Apply,
    };
    void OpenErosion() noexcept
    {
      mErosionOpen = true;
    }
    [[nodiscard]] bool TakeErosionAsk(
      ErosionAsk& ask,
      std::string& solver,
      ErosionValues& values
    )
    {
      ask = std::exchange(mErosionAsk, ErosionAsk::None);
      if (ask == ErosionAsk::None) {
        return false;
      }
      solver = mErosionSolver;
      values = mErosionValues[mErosionSolver];
      if (values.empty()) {
        if (const ErosionSolver* const s = FindErosionSolver(solver); s != nullptr) {
          values = ErosionDefaults(*s);
        }
      }
      return true;
    }
    /** Which of a full run's masks go to which texture layer (1 to 8): wear, deposit, flow, drainage. */
    struct ErosionMaskChoice
    {
      bool on[4] = {false, false, false, false};
      int layer[4] = {1, 2, 3, 4};
    };
    [[nodiscard]] const ErosionMaskChoice& ErosionMasksChosen() const noexcept
    {
      return mErosionMasks;
    }
    /** Test runs: masks to layers as the window's ticks set them. */
    void SetErosionMasks(
      const ErosionMaskChoice& choice
    ) noexcept
    {
      mErosionMasks = choice;
    }
    /** Test runs (`/erosiontest`): a preset chosen and an ask made, as the window's buttons do. */
    void AskErosion(
      const std::string& preset,
      const ErosionAsk ask
    )
    {
      for (const ErosionPreset& p : ErosionPresets()) {
        if (preset == p.id) {
          mErosionPreset = p.id;
          mErosionSolver = p.solver;
          mErosionValues[p.solver] = ErosionPresetValues(p);
        }
      }
      mErosionOpen = true;
      mErosionAsk = ask;
    }
    void SetErosionStatus(
      std::string status,
      const bool previewShown
    )
    {
      mErosionStatus = std::move(status);
      mErosionPreviewShown = previewShown;
    }
    void DrawErosionWindow();
    /** The SC tools window: open it, what it asks the view, and what the view says back. */
    enum class ScAsk
    {
      None,
      PadsApply,
      PadsRemove,
      SlopeReport,
      SlopeApply,
      Ramp,
    };
    void OpenScTools() noexcept
    {
      mScToolsOpen = true;
    }
    [[nodiscard]] ScAsk TakeScAsk() noexcept
    {
      return std::exchange(mScAsk, ScAsk::None);
    }
    /** Test runs (`/sctest`): an ask as the window's buttons make it. */
    void AskSc(
      const ScAsk ask
    ) noexcept
    {
      mScToolsOpen = true;
      mScAsk = ask;
    }
    [[nodiscard]] PadSettings& PadSettingsNow() noexcept
    {
      return mPadSettings;
    }
    [[nodiscard]] const SlopeLimitSettings& SlopeSettingsNow() const noexcept
    {
      return mSlope;
    }
    void SetPadsState(
      const bool applied,
      const bool stale
    ) noexcept
    {
      mPadsApplied = applied;
      mPadsStale = stale;
    }
    void SetScStatus(
      std::string status
    )
    {
      if (!status.empty()) {
        mScStatus = std::move(status);
      }
    }
    void SetSlopeReport(
      std::string report
    )
    {
      mSlopeReport = std::move(report);
    }
    void SetRampReport(
      std::string report
    )
    {
      mRampReport = std::move(report);
    }
    void DrawScToolsWindow();
    /**
     * The Import / Export window (Terrain > Import / Export...): a heightmap from another tool mapped, turned and
     * blended onto the map's heights, a live link that imports it again whenever that tool saves it, and an export with
     * a sidecar telling that tool what the image is.
     */
    enum class InteropAsk
    {
      None,
      Probe,        // read the import file and say what it holds
      Import,       // one undo step
      Revert,       // the last import undone, while it is the newest step
      Export,       // the export file (and its sidecar)
      SendAndWatch, // export, then link the same file back in (a round trip through another tool)
    };
    void OpenInterop() noexcept
    {
      mInteropOpen = true;
    }
    [[nodiscard]] InteropAsk TakeInteropAsk() noexcept
    {
      return std::exchange(mInteropAsk, InteropAsk::None);
    }
    /** Test runs (`/interoptest`): an ask as the window's buttons make it. */
    void AskInterop(
      const InteropAsk ask
    ) noexcept
    {
      mInteropOpen = true;
      mInteropAsk = ask;
    }
    /** The Browse buttons, taken by the app (it asks for the file): 1 the import file, 2 the export file. */
    [[nodiscard]] int TakeInteropBrowse() noexcept
    {
      return std::exchange(mInteropBrowse, 0);
    }
    void SetInteropFile(bool exportFile, const std::string& file);
    [[nodiscard]] std::string InteropFile(
      const bool exportFile
    ) const
    {
      return exportFile ? mInteropExportPath : mInteropImportPath;
    }
    [[nodiscard]] ImportSettings& InteropSettings() noexcept
    {
      return mImport;
    }
    [[nodiscard]] bool InteropLive() const noexcept
    {
      return mInteropLive;
    }
    void SetInteropLive(
      const bool on
    ) noexcept
    {
      mInteropLive = on;
    }
    [[nodiscard]] bool InteropSidecar() const noexcept
    {
      return mInteropSidecar;
    }
    /** The export's width in samples (0 for the map's own) and its words per height. */
    [[nodiscard]] int InteropExportWidth() const noexcept
    {
      return kExportWidths[mInteropExportSize];
    }
    [[nodiscard]] float InteropExportScale() const noexcept
    {
      return mInteropExportScale;
    }
    void SetInteropStatus(
      std::string status
    )
    {
      if (!status.empty()) {
        mInteropStatus = std::move(status);
      }
    }
    void SetInteropProbe(
      std::string probe
    )
    {
      mInteropProbe = std::move(probe);
    }
    /** The view says whether the last import can still be reverted and when the link last imported. */
    void SetInteropState(
      const bool canRevert,
      std::string linkNote
    )
    {
      mInteropCanRevert = canRevert;
      mInteropLinkNote = std::move(linkNote);
    }
    void DrawInteropWindow();
    /** How many of each kind the map has now (the view gives them each frame), for Properties with nothing chosen. */
    /** The map's counts as the view gave them last: 0 markers, 1 props, 2 units, 3 decals. */
    [[nodiscard]] int MapCount(
      const int kind
    ) const noexcept
    {
      return kind >= 0 && kind < 4 ? mMapCounts[kind] : 0;
    }
    void SetMapCounts(
      const int markers,
      const int props,
      const int units,
      const int decals
    ) noexcept
    {
      mMapCounts[0] = markers;
      mMapCounts[1] = props;
      mMapCounts[2] = units;
      mMapCounts[3] = decals;
    }
    [[nodiscard]] const int* MapCounts() const noexcept
    {
      return mMapCounts;
    }
    /** The view's HUD while G or R runs: what it is doing (empty: the tool's own mode). */
    void SetHudOverride(
      std::string text
    )
    {
      mHudOverride = std::move(text);
    }
    /** The Props tool's Fill the map: its options, the button (taken by the view), and what the last fill did. */
    struct FillOptions
    {
      float density = 10.0f; // per 100 x 100 units
      float spacing = 6.0f;
      float maxSlope = 30.0f; // degrees
      bool dry = true;
    };
    [[nodiscard]] bool TakeFillRequest(
      FillOptions& options
    ) noexcept
    {
      options = mFill;
      return std::exchange(mFillRequest, false);
    }
    void RequestFill(
      const FillOptions& options
    ) noexcept
    {
      mFill = options;
      mFillRequest = true;
    }
    void SetFillMessage(
      std::string message
    )
    {
      mFillMessage = std::move(message);
    }
    /** Arrange's buttons (and the Edit menu's): the op asked, taken by the view each frame, and its grid step. */
    void RequestArrange(
      const ArrangeOp op
    ) noexcept
    {
      mArrangeRequest = op;
    }
    [[nodiscard]] bool TakeArrangeRequest(
      ArrangeOp& op,
      float& step
    ) noexcept
    {
      op = std::exchange(mArrangeRequest, ArrangeOp::Count);
      step = static_cast<float>(1 << mArrangeSnap);
      return op != ArrangeOp::Count;
    }
    /** Why the last arrange did nothing ("" when it was done), shown under the buttons. */
    void SetArrangeMessage(
      std::string message
    )
    {
      mArrangeMessage = std::move(message);
    }
    [[nodiscard]] bool ShowSlope() const noexcept
    {
      return mShowSlope;
    }
    void SetShowSlope(
      const bool on
    ) noexcept
    {
      mShowSlope = on;
    }
    /** The heights view: the ground coloured by height in bands, the sea's ground blue (the view's shading: Heights).
     */
    [[nodiscard]] bool ShowHeights() const noexcept
    {
      return mShowHeights;
    }
    void SetShowHeights(
      const bool on
    ) noexcept
    {
      mShowHeights = on;
    }
    /** The view's shading as its corner button cycles it: 0 lit, 1 heights, 2 slope. */
    [[nodiscard]] int Shading() const noexcept
    {
      return mShowSlope ? 2 : mShowHeights ? 1 : 0;
    }
    void SetShading(
      const int shading
    ) noexcept
    {
      mShowHeights = shading == 1;
      mShowSlope = shading == 2;
    }
    [[nodiscard]] bool ShowKmGrid() const noexcept
    {
      return mShowKmGrid;
    }
    void SetShowKmGrid(
      const bool on
    ) noexcept
    {
      mShowKmGrid = on;
    }
    void SetCursorText(
      std::string text
    )
    {
      mCursorText = std::move(text);
    }
    [[nodiscard]] const std::string& CursorText() const noexcept
    {
      return mCursorText;
    }
    void SetRulerText(
      std::string text
    )
    {
      mRulerText = std::move(text);
    }
    [[nodiscard]] const std::string& RulerText() const noexcept
    {
      return mRulerText;
    }
    /** The type under the cursor (-1: none), for the panel. */
    void SetTerrainTypeUnderCursor(
      const int code
    ) noexcept
    {
      mTypeUnderCursor = code;
    }
    /** Test runs (`/terraintype <code>`): the Texture tool painting that type. */
    void SetTerrainTypeTool(
      const int code
    ) noexcept
    {
      mTool = 2;
      mTexturePaint = 1;
      mTerrainTypeCode = code;
    }

    /** The texture brush as the panel sets it: the brush's shape, the layer, the mode. */
    [[nodiscard]] MaskBrush CurrentMaskBrush() const noexcept
    {
      MaskBrush brush;
      brush.shape = CurrentHeightBrush();
      brush.mode = static_cast<MaskBrushMode>(mMaskMode);
      brush.layer = mMaskLayer;
      brush.lowerAbove = mLowerAbove;
      brush.target = mMaskTarget;
      brush.scatter = mMaskScatter;
      brush.limitMinSlope = std::tan(mMaskMinSlopeDegrees * 0.0174532925f);
      brush.buildUp = mMaskBuildUp;
      return brush;
    }
    /** The open map's layer texture paths (lower, strata 1-8, upper), for the layer list. */
    void SetLayerNames(
      std::vector<std::string> names
    )
    {
      mLayerNames = std::move(names);
    }

    /** One of the map's ten texture slots (lower, strata 1-8, upper): albedo and normal map, each with its size in game
     * units. */
    struct LayerSlot
    {
      std::string albedo;
      std::string normals;
      float albedoSize = 4.0f;
      float normalsSize = 4.0f;
      bool operator==(
        const LayerSlot& other
      ) const
      {
        return albedo == other.albedo && normals == other.normals && albedoSize == other.albedoSize &&
          normalsSize == other.normalsSize;
      }
    };
    /** The open map's size in game units (the larger side), for the slots' map-wide switch. */
    void SetMapSizeUnits(
      const float size
    ) noexcept
    {
      mMapSizeUnits = size;
    }
    /** A layer slot the user wants a texture made for with nodes (the Material Editor opens on it); taken once. */
    [[nodiscard]] bool TakeMaterialAsk(
      int& slot
    ) noexcept
    {
      if (mMaterialAsk < 0) {
        return false;
      }
      slot = std::exchange(mMaterialAsk, -1);
      return true;
    }
    /** The open map's slots as the terrain has them, each frame. */
    void SetLayerSlots(
      std::vector<LayerSlot> slots
    )
    {
      mSlots = std::move(slots);
    }
    /** A slot the panel changed (its texture or size): the app applies it. */
    [[nodiscard]] bool TakeLayerChange(
      int& slot,
      LayerSlot& value
    )
    {
      if (mChangedSlot < 0) {
        return false;
      }
      slot = std::exchange(mChangedSlot, -1);
      value = mChangedValue;
      return true;
    }
    /** Each stratum's share of the map (0..1), for the paint list. */
    void SetCoverage(
      const float (&coverage)[8]
    ) noexcept
    {
      for (int i = 0; i < 8; ++i) {
        mCoverage[i] = coverage[i];
      }
      mHasCoverage = true;
    }
    /** The paint layer's mask buttons: Clear, Import, Export. */
    enum class MaskOp
    {
      None,
      Clear,
      Fill,
      Import,
      Export,
    };
    [[nodiscard]] MaskOp TakeMaskOp() noexcept
    {
      return std::exchange(mMaskOp, MaskOp::None);
    }
    [[nodiscard]] int MaskLayer() const noexcept
    {
      return mMaskLayer;
    }
    /** Whether the view colours the paint layer's weight on the terrain. */
    [[nodiscard]] bool ShowLayerWeight() const noexcept
    {
      return mShowWeight;
    }
    void SetShowLayerWeight(
      const bool show
    ) noexcept
    {
      mShowWeight = show;
    }
    /** The terrain shaders the game data has, and the map's. */
    void SetShaders(
      std::vector<std::string> shaders,
      std::string current
    )
    {
      mShaders = std::move(shaders);
      mShader = std::move(current);
    }
    /** Test runs (`/shaderbrowser <name>`): the shader browser open on that shader. */
    void OpenShaderBrowser(
      std::string shader
    )
    {
      mShaderBrowserOpen = true;
      mBrowsedShader = std::move(shader);
    }
    void DrawShaderBrowser();
    /** The browser's Convert section: the shader and options it shows a plan for (changed since the last plan). */
    [[nodiscard]] bool TakeConversionPlanRequest(
      std::string& shader,
      LayerConvertOptions& options
    )
    {
      const std::string key = mBrowsedShader + "|" + std::to_string(static_cast<int>(mConvertOptions.lost)) + "|" +
        std::to_string(mConvertOptions.mergeInto) + "|" + (mConvertOptions.arrange ? "1" : "0");
      if (!mShaderBrowserOpen || mBrowsedShader.empty() || key == mConvertPlanKey) {
        return false;
      }
      mConvertPlanKey = key;
      shader = mBrowsedShader;
      options = mConvertOptions;
      return true;
    }
    void SetConversionPlan(
      LayerConvertPlan plan
    )
    {
      mConvertPlan = std::move(plan);
    }
    /** Convert was pressed: the shader and options. */
    [[nodiscard]] bool TakeConversionRequest(
      std::string& shader,
      LayerConvertOptions& options
    )
    {
      if (!mConvertRequested) {
        return false;
      }
      mConvertRequested = false;
      shader = mBrowsedShader;
      options = mConvertOptions;
      return true;
    }
    void SetConversionReport(
      std::vector<std::string> report
    )
    {
      mConvertReport = std::move(report);
      mConvertPlanKey.clear(); // the map changed: plan again
    }
    [[nodiscard]] bool TakeShaderChange(
      std::string& shader
    )
    {
      if (mShaderChange.empty()) {
        return false;
      }
      shader = std::exchange(mShaderChange, {});
      return true;
    }

    /** Apply rules to whole map was pressed; the rules. */
    [[nodiscard]] bool TakeRulesRequest() noexcept
    {
      return std::exchange(mRulesRequested, false);
    }
    [[nodiscard]] const std::vector<MaskRule>& Rules() const noexcept
    {
      return mRules;
    }
    /** Test runs (`/maskrule`): one more rule, then Apply. */
    void AddRule(
      const MaskRule& rule
    )
    {
      mTool = 2;
      mRules.push_back(rule);
    }
    void RequestRules() noexcept
    {
      mRulesRequested = true;
    }
    /** The Mask generator: its rules, where it writes, and what the panel asks of the app. */
    struct MaskGenTarget
    {
      int layer = 1;
      MaskWriteMode mode = MaskWriteMode::Replace;
      float strength = 1.0f;
      bool takeAway = false; // only where the layers above leave the ground free
    };
    [[nodiscard]] const std::vector<MaskGenRule>& GenRules() const noexcept
    {
      return mGenRules;
    }
    void SetGenRules(
      std::vector<MaskGenRule> rules
    )
    {
      mGenRules = std::move(rules);
      ++mGenRevision;
    }
    [[nodiscard]] MaskGenTarget& GenTarget() noexcept
    {
      return mGenTarget;
    }
    /** Changes to the rules: the app re-evaluates the preview when it moves. */
    [[nodiscard]] int GenRevision() const noexcept
    {
      return mGenRevision;
    }
    /** A starting point picked ("cliffs" ...): the app fills its rules (it knows the map's heights). */
    [[nodiscard]] bool TakeGenPresetAsk(
      std::string& id
    )
    {
      if (mGenPresetAsk.empty()) {
        return false;
      }
      id = std::exchange(mGenPresetAsk, {});
      return true;
    }
    void AskGenPreset(
      std::string id
    )
    {
      mGenPresetAsk = std::move(id);
    }
    [[nodiscard]] bool TakeGenApply() noexcept
    {
      return std::exchange(mGenApply, false);
    }
    void AskGenApply() noexcept
    {
      mGenApply = true;
    }
    /** The preview the app made: an image (0: none), its share of the map, or why there is none. */
    void SetGenPreview(
      const std::uint64_t image,
      const float coverage,
      std::string note
    )
    {
      mGenPreviewImage = image;
      mGenCoverage = coverage;
      mGenNote = std::move(note);
    }
    [[nodiscard]] std::uint64_t GenPreviewImage() const noexcept
    {
      return mGenPreviewImage;
    }
    [[nodiscard]] bool GenSectionOpen() const noexcept
    {
      return mGenOpen;
    }

    /** The Stratum recipes section: the style, its settings, each layer's kind (detected by the app, or chosen). */
    [[nodiscard]] int RecipeStyle() const noexcept
    {
      return mRecipeStyle;
    }
    [[nodiscard]] const RecipeKnobs& RecipeSettings() const noexcept
    {
      return mRecipeKnobs;
    }
    void SetRecipeStyle(
      const int style
    )
    {
      mRecipeStyle = style;
      mRecipeKnobs = RecipeKnobsOf(style);
    }
    /** -1: as detected; 0: not used; 1..8: the GroundKind chosen for the layer. */
    [[nodiscard]] const std::array<int, 9>& RecipeOverrides() const noexcept
    {
      return mRecipeOverride;
    }
    void SetRecipeDetected(
      const std::array<GroundKind, 9>& kinds,
      const std::array<std::string, 9>& names,
      const int cap
    )
    {
      mRecipeDetected = kinds;
      mRecipeNames = names;
      mRecipeCap = cap;
    }
    [[nodiscard]] bool TakeRecipeApply() noexcept
    {
      return std::exchange(mRecipeApply, false);
    }
    void AskRecipeApply() noexcept
    {
      mRecipeApply = true;
    }
    void SetRecipeResult(
      std::string text
    )
    {
      mRecipeResult = std::move(text);
    }
    [[nodiscard]] bool RecipesOpen() const noexcept
    {
      return mRecipesOpen;
    }

    /** Each slot's optimal tile size (EdTexScale, from its texture's width; 0: unknown), for the row menus. */
    void SetOptimalTiles(
      const std::array<float, 10>& tiles
    ) noexcept
    {
      mOptimalTiles = tiles;
    }
    /** The Texture sets section: the theme picked, what it would give, and what the panel asks. */
    enum class ThemeOp : std::uint8_t
    {
      None,
      Try,   // applied, the layers before kept to go back to
      Keep,  // the tried theme stays
      Back,  // the layers as they were before Try
      Apply, // applied and kept at once
    };
    [[nodiscard]] int ThemeIndex() const noexcept
    {
      return mThemeIndex;
    }
    void SetThemeIndex(
      const int index
    ) noexcept
    {
      mThemeIndex = index;
    }
    void AskTheme(
      const ThemeOp op
    ) noexcept
    {
      mThemeOp = op;
    }
    [[nodiscard]] ThemeOp TakeThemeOp() noexcept
    {
      return std::exchange(mThemeOp, ThemeOp::None);
    }
    /** The app: whether a theme is being tried, and what the picked one would give each layer ("2  Rock  EvRock006c").
     */
    void SetThemeState(
      const bool trying,
      std::vector<std::string> preview
    )
    {
      mThemeTrying = trying;
      mThemePreview = std::move(preview);
    }
    /** Test runs (`/layerop`): a row menu item of the Layers panel on `slot` (fill, remove, optimal). False when it
     * can't. */
    bool RunLayerMenuItem(int slot, const std::string& item);
    [[nodiscard]] bool LayersPanelShown() const noexcept
    {
      return mLayersShown;
    }

    /** Test runs (`/browse`): the texture browser opened for a slot. */
    void OpenBrowser(
      const int slot
    ) noexcept
    {
      mTool = 2;
      mBrowseSlot = slot;
      mBrowseOpen = true;
    }
    /** Test runs (`/masklayer`): the Texture tool on this layer. */
    void SetMaskLayer(
      const int layer
    ) noexcept
    {
      mTool = 2;
      mMaskLayer = layer;
    }

    /** The terrain brush as the panel sets it (Flatten's height is the stroke's, set by the viewport). */
    /** The brush with the hovered symmetry mode when one is hovered (the map's preview), else the current one. */
    [[nodiscard]] HeightBrush PreviewHeightBrush() const noexcept
    {
      HeightBrush brush = CurrentHeightBrush();
      if (mSymmetryHover >= 0) {
        brush.symmetry = static_cast<Symmetry>(mSymmetryHover);
      }
      return brush;
    }
    [[nodiscard]] HeightBrush CurrentHeightBrush() const noexcept
    {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mBrushMode);
      brush.symmetry = static_cast<Symmetry>(mSymmetry);
      brush.radius = mRadius;
      // A negative strength does the mode's opposite (FAF Studio's inversion).
      brush.strength = std::abs(mStrength);
      if (mStrength < 0.0f) {
        brush.mode = InvertedHeightMode(brush.mode);
      }
      brush.falloff = mFalloff;
      brush.turns = mNWay;
      brush.setTo = mSetHeight * 128.0f;
      brush.terraceStep = mTerraceStep * 128.0f;
      brush.erodeTalus = mErodeTalus;
      brush.shape = static_cast<BrushShape>(mBrushShape);
      brush.shapeImage = mShapeImage.get();
      brush.stampMode = static_cast<StampMode>(mStampMode);
      brush.shapeAngle = mShapeAngle;
      brush.noiseScale = mNoiseScale;
      brush.noiseOctaves = mNoiseOctaves;
      brush.noiseRoughness = mNoiseRoughness;
      brush.planeSet = mPlaneSet;
      brush.planeX = mPlaneX;
      brush.planeZ = mPlaneZ;
      brush.planeC = mPlaneC;
      brush.stamp = mStamp.get();
      brush.stampHeight = mStampHeight * 128.0f;
      brush.limitHeight = mLimitHeight;
      brush.limitLow = mLimitLow * 128.0f;
      brush.limitHigh = mLimitHigh * 128.0f;
      brush.limitSlope = mLimitSlope;
      brush.limitMaxSlope = std::tan(mLimitSlopeDegrees * 0.0174532925f);
      return brush;
    }

    /** Plane mode: a picked point (game units: x, height, z); the plane goes through the last three. */
    void AddPlanePoint(float x, float height, float z) noexcept;
    /** The Path brush: its clicked points (x, ground height, z), in order. */
    void AddPathPoint(
      const float x,
      const float height,
      const float z
    )
    {
      mPathPoints.push_back({x, z, height});
    }
    [[nodiscard]] const std::vector<TerrainPathPoint>& PathPoints() const noexcept
    {
      return mPathPoints;
    }
    void RemoveLastPathPoint() noexcept
    {
      if (!mPathPoints.empty()) {
        mPathPoints.pop_back();
      }
    }
    void ClearPathPoints() noexcept
    {
      mPathPoints.clear();
    }
    /** The path's options: the brush's width (its diameter) and falloff, the panel's mode, depth and loop. */
    [[nodiscard]] PathOptions CurrentPathOptions() const noexcept
    {
      PathOptions o;
      o.mode = static_cast<PathMode>(mPathMode);
      o.width = mRadius * 2.0f;
      o.falloff = mFalloff;
      o.depth = mPathDepth;
      o.closed = mPathClosed;
      return o;
    }
    void RequestPathApply() noexcept
    {
      mPathApply = true;
    }
    [[nodiscard]] bool TakePathApply() noexcept
    {
      return std::exchange(mPathApply, false);
    }
    /** Off: the brush lays dabs a third of its radius apart along the mouse's way (nothing while held still). */
    [[nodiscard]] bool Airbrush() const noexcept
    {
      return mAirbrush;
    }
    /** What the last height stroke did (ground moved up and down), under the brush's sliders. */
    /** Why the Texture tool won't paint the chosen layer (empty: it will). */
    void SetPaintNote(
      std::string text
    )
    {
      mPaintNote = std::move(text);
    }
    void SetStrokeStats(
      std::string text
    )
    {
      mStrokeStats = std::move(text);
    }
    void ClearPlanePoints() noexcept
    {
      mPlanePoints = 0;
      mPlaneSet = false;
    }
    /** The picked points, oldest first, for the view to mark. */
    [[nodiscard]] int PlanePoints(float (&x)[3], float (&height)[3], float (&z)[3]) const noexcept;

    /** Stamp strokes (FAF Studio's stamp.lua): each dab's turn, size and place, and how far apart dabs fall. */
    struct StampStroke
    {
      float turn = 0.0f; // degrees
      bool randomTurn = false;
      float sizeJitter = 0.0f;     // each dab's radius varies by up to this share
      float placeJitter = 0.0f;    // each dab moves by up to this share of the radius
      float spacing = 0.0f;        // between dabs, a share of the stamp's width; 0: one per click
      bool baseFromStroke = false; // Max, Min, Replace: from the ground under the stroke's first dab, not each dab's
    };
    [[nodiscard]] StampStroke CurrentStampStroke() const noexcept
    {
      return {mStampTurn, mStampRandomTurn, mStampSizeJitter, mStampPlaceJitter, mStampSpacing, mStampBaseFromStroke};
    }
    /** Test runs (`/stampstroke <spacing>,<random turn>,<size jitter>,<place jitter>,<mode>`; shares, 0/1, a
     * StampMode). */
    void SetStampStroke(
      const float spacing,
      const bool randomTurn,
      const float sizeJitter,
      const float placeJitter,
      const int mode
    ) noexcept
    {
      mStampSpacing = spacing;
      mStampRandomTurn = randomTurn;
      mStampSizeJitter = sizeJitter;
      mStampPlaceJitter = placeJitter;
      mStampMode = std::clamp(mode, 0, 4);
    }
    /** The brush library's folder (`%LOCALAPPDATA%\FAForever\Editor\brushes`); its images are listed again. */
    void SetBrushFolder(std::filesystem::path folder);
    [[nodiscard]] const std::filesystem::path& BrushFolder() const noexcept
    {
      return mBrushFolder;
    }
    /** Lists the brush folder's images again (after an import). */
    void RescanBrushes();
    /** The Import button: pick images to copy into the brush folder. */
    [[nodiscard]] bool TakeBrushImportRequest() noexcept
    {
      return std::exchange(mBrushImportRequested, false);
    }
    /** The stamp's source: 1 to 9 a procedural shape (BrushShape), from 10 the brush folder's images in order. */
    bool ChooseStampSource(int index);
    /** The brush shape from the brush folder's image `index`. */
    bool ChooseShapeImage(int index);

    /** Stamp mode: the image the Stamp image button loaded. */
    [[nodiscard]] bool TakeStampRequest() noexcept
    {
      return std::exchange(mStampRequested, false);
    }
    void SetStamp(
      HeightStamp stamp,
      std::string name
    )
    {
      mStamp = std::make_shared<HeightStamp>(std::move(stamp));
      mStampName = std::move(name);
    }

    /** Test runs (`/symcheck`): the Terrain tool with this symmetry (the panel's index), then Check or Copy. */
    void SetSymmetry(
      const int index,
      const int turns
    ) noexcept
    {
      mTool = mTool == 2 ? 2 : 1; // the Texture tool checks the masks
      mSymmetry = index;
      mNWay = turns;
    }
    /**
     * A newly opened map's symmetry as DetectSymmetry found it, and how far its centre is off the map's middle (height
     * samples).
     */
    void SetDetectedSymmetry(
      const DetectedSymmetry& found,
      const float offsetX,
      const float offsetZ
    ) noexcept
    {
      const int index = found.symmetry == Symmetry::None ? -1 : static_cast<int>(found.symmetry);
      const int turns = found.turns;
      mDetectedSymmetry = index;
      mDetectedMatch = found.matched;
      mDetectedStarts = found.startsMatched;
      mDetectedResources = found.resourcesMatched;
      mDetectedOffsetX = offsetX;
      mDetectedOffsetZ = offsetZ;
      if (index >= 0) {
        mSymmetry = index;
        mNWay = index == 9 ? turns : mNWay;
      } else {
        mSymmetry = 0;
      }
    }
    void RequestCheck() noexcept
    {
      mCheckRequested = true;
    }
    void RequestImport() noexcept
    {
      mImportRequested = true;
    }
    /** Test runs (`/brush`): the Terrain tool with this brush mode (a HeightBrushMode). */
    void SetBrushMode(
      const int mode
    ) noexcept
    {
      mTool = 1;
      mBrushMode = mode;
    }
    /** Test runs (`/maskoptions <target>,<scatter>,<min slope degrees>,<build up>`). */
    void SetMaskOptions(
      const float target,
      const float scatter,
      const float minSlopeDegrees,
      const bool buildUp
    ) noexcept
    {
      mMaskTarget = std::clamp(target, 0.05f, 1.0f);
      mMaskScatter = std::clamp(scatter, 0.0f, 1.0f);
      mMaskMinSlopeDegrees = std::clamp(minSlopeDegrees, 0.0f, 60.0f);
      mMaskBuildUp = buildUp;
    }
    void DrawShapePicker();
    /** Test runs (`/brushshape`): the height brush's shape (a BrushShape) and turn in degrees. */
    void SetBrushShape(
      const int shape,
      const float angle
    ) noexcept
    {
      mBrushShape = shape < 0 || shape >= kBrushShapeCount ? 0 : shape;
      mShapeAngle = angle;
    }
    /** Test runs (`/erodetalus`): the Erode brush's talus slope. */
    void SetErodeTalus(
      const float talus
    ) noexcept
    {
      mErodeTalus = talus;
    }
    void RequestRepair() noexcept
    {
      mRepairRequested = true;
    }

    /** The height field's Import and Export buttons, taken by the app each frame (it asks for the file). */
    [[nodiscard]] bool TakeImportRequest() noexcept
    {
      return std::exchange(mImportRequested, false);
    }
    /** The Markers tool's Import / Export of FAForeverMapEditor's `.fafmapmarkers`, taken by the app (it asks for the
     * file). */
    [[nodiscard]] bool TakeMarkerFileImport() noexcept
    {
      return std::exchange(mMarkerFileImport, false);
    }
    [[nodiscard]] bool TakeMarkerFileExport() noexcept
    {
      return std::exchange(mMarkerFileExport, false);
    }
    /** The Units tool's Import / Export of FAForeverMapEditor's `.scunits`, taken by the app. */
    [[nodiscard]] bool TakeUnitFileImport() noexcept
    {
      return std::exchange(mUnitFileImport, false);
    }
    [[nodiscard]] bool TakeUnitFileExport() noexcept
    {
      return std::exchange(mUnitFileExport, false);
    }
    /** The Texture tool's layer files: what was asked (LayerFileAsk) and for which slot, taken by the app. */
    enum class LayerFileAsk
    {
      None,
      ImportLayer,
      ExportLayer,
      ImportSet,
      ExportSet,
    };
    [[nodiscard]] LayerFileAsk TakeLayerFileAsk(
      int& slot
    ) noexcept
    {
      slot = mLayerFileSlot;
      return std::exchange(mLayerFileAsk, LayerFileAsk::None);
    }
    [[nodiscard]] bool TakeExportRequest() noexcept
    {
      return std::exchange(mExportRequested, false);
    }
    /** Heights times this on import and export. */
    [[nodiscard]] float HeightScale() const noexcept
    {
      return mHeightScale;
    }
    /** The exported image's width in samples, 0 for the map's own. */
    [[nodiscard]] int ExportWidth() const noexcept
    {
      return kExportWidths[mExportSize];
    }

    /** The symmetry check's buttons, taken by the view each frame. */
    [[nodiscard]] bool TakeCheckRequest() noexcept
    {
      return std::exchange(mCheckRequested, false);
    }
    /**
     * Make symmetric's options for the chosen symmetry; the centre is the detected one (as its offset from the middle,
     * `offsetX` / `offsetZ`) when the chosen symmetry is the detected one, else the middle (both 0).
     */
    [[nodiscard]] SymmetrizeOptions CurrentSymmetrize(
      float& offsetX,
      float& offsetZ
    ) const noexcept
    {
      SymmetrizeOptions options;
      options.symmetry = static_cast<Symmetry>(mSymmetry);
      options.turns = mNWay;
      options.part = mSymPart;
      options.combine = static_cast<SymmetryCombine>(mSymCombine);
      options.seam = mSymSeam;
      const bool detected = mSymmetry == mDetectedSymmetry;
      offsetX = detected ? mDetectedOffsetX : 0.0f;
      offsetZ = detected ? mDetectedOffsetZ : 0.0f;
      return options;
    }
    [[nodiscard]] bool SymmetrizeMasksToo() const noexcept
    {
      return mSymMasks;
    }
    [[nodiscard]] bool SymmetrizeTypesToo() const noexcept
    {
      return mSymTypes;
    }
    /** Test runs (`/symoptions <part>,<combine>,<seam>,<masks>,<types>`). */
    void SetSymmetrizeOptions(
      const int part,
      const int combine,
      const float seam,
      const bool masks,
      const bool types
    ) noexcept
    {
      mSymPart = std::max(0, part);
      mSymCombine = std::clamp(combine, 0, 3);
      mSymSeam = std::max(0.0f, seam);
      mSymMasks = masks;
      mSymTypes = types;
    }
    [[nodiscard]] bool TakeRepairRequest() noexcept
    {
      return std::exchange(mRepairRequested, false);
    }
    /** Whether the view marks the vertices whose copies differ. */
    [[nodiscard]] bool ShowDifferences() const noexcept
    {
      return mShowDifferences;
    }

    /** The check's result for the panel, for the symmetry it checked (`checked` 0: nothing to show). */
    void SetCheckResult(
      const int checked,
      const int differing,
      const int largestWords,
      const HeightBrush& checkedWith,
      const bool masks = false
    ) noexcept
    {
      mCheckedMasks = masks;
      mChecked = checked;
      mDiffering = differing;
      mLargest = largestWords;
      mCheckedSymmetry = static_cast<int>(checkedWith.symmetry);
      mCheckedTurns = checkedWith.turns;
    }

    /** True if the last check was made with the panel's current symmetry. */
    [[nodiscard]] bool CheckIsCurrent() const noexcept
    {
      return mChecked > 0 && mCheckedSymmetry == mSymmetry && (mSymmetry != 9 || mCheckedTurns == mNWay) &&
        mCheckedMasks == TextureToolActive();
    }

  private:
    void DrawTerrain();
    void DrawTexture();
    void DrawWater();
    void DrawProps();
    void DrawTerrainTypes();
    void DrawDecals();
    void DrawMarkers();
    void DrawUnits();
    void DrawSelect();
    void DrawFalloffCurve();
    void DrawArrange();
    void DrawBrush(bool withModes);
    void DrawSymmetry(bool withCheck = true);
    void DrawLimits();

    int mTool = 1;
    std::vector<std::string> mToolKeys;
    /** The Units tool's browser (ui/EdUnitBrowser.cpp): the units by group, its chips' picks, tiles or a list. */
    void DrawUnitBrowser();
    std::vector<EdUnitInfo> mUnitInfos;
    EdUnitFilter mUnitBrowse;
    bool mUnitGrid = true;
    bool mReadOnly = false;

    int mBrushMode = 0;
    float mRadius = 14.0f;
    float mStrength = 0.5f;
    float mFalloff = 0.6f;
    int mSymmetry = 6; // both axes
    int mNWay = 3;
    ViewFrame mViewFrame;
    float mMinimapRect[4]{};
    int mLayerMoveFrom = -1;
    PickFilter mPickable;
    MapTextureRow mMapTextureRows[4];
    int mMapTextureKind = 0;
    MapTextureOp mMapTextureOp = MapTextureOp::None;
    std::string mMapTextureFile;
    bool mMapTextureRaise = false;
    int mLayerMoveTo = -1;
    bool mCameraAsk = false;
    float mCameraAskX = 0.0f;
    float mCameraAskZ = 0.0f;
    bool mLimitHeight = false;
    float mLimitLow = 0.0f;
    float mLimitHigh = 100.0f;
    bool mLimitSlope = false;
    float mLimitSlopeDegrees = 30.0f;
    float mSetHeight = 20.0f;
    float mTerraceStep = 5.0f;
    float mErodeTalus = 0.6f;
    int mBrushShape = 0; // BrushShape
    float mShapeAngle = 0.0f;
    float mNoiseScale = 8.0f;
    int mNoiseOctaves = 2;
    float mNoiseRoughness = 0.5f;
    float mPlanePointX[3]{};
    std::vector<TerrainPathPoint> mPathPoints;
    int mPathMode = static_cast<int>(PathMode::Ramp);
    float mPathDepth = 4.0f;
    bool mPathClosed = false;
    bool mPathApply = false;
    bool mAirbrush = true;
    std::string mStrokeStats;
    std::string mPaintNote;
    bool mBrowseNormals = false; // the browser picks the normal map alone
    bool mBrowseRelief = true;   // normal maps shown as lit relief
    float mPlanePointH[3]{};
    float mPlanePointZ[3]{};
    int mPlanePoints = 0;
    bool mPlaneSet = false;
    double mPlaneX = 0.0;
    double mPlaneZ = 0.0;
    double mPlaneC = 0.0;
    std::shared_ptr<HeightStamp> mStamp;
    int mStampMode = 0; // StampMode
    float mStampTurn = 0.0f;
    bool mStampRandomTurn = false;
    float mStampSizeJitter = 0.0f;
    float mStampPlaceJitter = 0.0f;
    float mStampSpacing = 0.0f;
    bool mStampBaseFromStroke = false;
    std::filesystem::path mBrushFolder;
    std::vector<BrushImage> mBrushImages;
    std::shared_ptr<ShapeGrid> mShapeImage;
    std::string mShapeImageName;
    bool mBrushImportRequested = false;
    std::string mStampName;
    float mStampHeight = 20.0f;
    bool mStampRequested = false;
    int mMarkerType = 0;
    int mDecalMode = 0; // 0 Place, 1 Select

    static constexpr int kExportWidths[] = {0, 257, 513, 1025, 2049, 4097};
    bool mImportRequested = false;
    bool mMarkerFileImport = false;
    bool mMarkerFileExport = false;
    bool mUnitFileImport = false;
    bool mUnitFileExport = false;
    int mTexturePaint = 0;
    bool mOpenArmies = false;
    std::string mUnitTreeArmy;
    UnitGroup mUnitTree;
    std::vector<std::string> mGroupPath;
    char mGroupName[64]{};
    GroupAsk mGroupAsk = GroupAsk::None;
    UnitWreckAsk mUnitWreckAsk;
    bool mUnitWreckAsked = false;
    std::vector<std::pair<std::string, std::string>> mUnitSelectionNow;
    UnitGroupAsk mUnitGroupAsk;
    bool mUnitGroupAsked = false;
    std::vector<ViewRing> mViewRings;
    bool mModelsLoading = false;
    std::vector<std::uint32_t> mLiveSelection;
    bool mShowGameUnits = true;
    std::set<std::pair<std::string, std::string>> mPreviewHiddenUnits;
    std::set<std::string> mPreviewHiddenMarkers;
    void DrawUnitGroup(const UnitGroup& group, std::vector<std::string>& path);
    int mTerrainTypeCode = 81;
    bool mShowTerrainTypes = true;
    bool mShowSlope = false;
    bool mShowHeights = false;
    bool mShowKmGrid = false;
    std::string mCursorText;
    std::string mRulerText;
    int mTypeUnderCursor = -1;
    char mTerrainTypeFilter[64]{};
    std::vector<TerrainTypeInfo> mTerrainTypes;
    LayerFileAsk mLayerFileAsk = LayerFileAsk::None;
    int mLayerFileSlot = 1;
    bool mExportRequested = false;
    float mHeightScale = 1.0f;
    int mExportSize = 0;

    int mMaskLayer = 0;
    int mMaskMode = 0;
    bool mLowerAbove = true;
    bool mShaderBrowserOpen = false;
    LayerConvertOptions mConvertOptions;
    LayerConvertPlan mConvertPlan;
    std::string mConvertPlanKey;
    std::vector<std::string> mConvertReport;
    bool mConvertRequested = false;
    std::string mBrowsedShader;
    float mMaskTarget = 1.0f;
    float mMaskScatter = 0.0f;
    float mMaskMinSlopeDegrees = 0.0f;
    bool mMaskBuildUp = false; // FAF Studio's stroke model by default
    std::vector<std::string> mLayerNames;
    std::vector<LayerSlot> mSlots;
    int mChangedSlot = -1;
    LayerSlot mChangedValue;
    EdTextureLibrary mLibrary;
    void DrawLayerSlots();
    void DrawTextureBrowser();
    int mBrowseSlot = -1;
    bool mBrowseOpen = false;
    /** A layer slot to make a texture for in the Material Editor (its button here and in the texture browser). */
    int mMaterialAsk = -1;
    char mBrowseFilter[64]{};
    std::vector<MaskRule> mRules;
    int mSymmetryHover = -1;
    void DrawMaskGenerator();
    std::vector<MaskGenRule> mGenRules;
    MaskGenTarget mGenTarget;
    int mGenRevision = 0;
    std::string mGenPresetAsk;
    bool mGenApply = false;
    bool mGenOpen = false;
    std::uint64_t mGenPreviewImage = 0;
    float mGenCoverage = 0.0f;
    std::string mGenNote;
    void DrawRecipes();
    int mRecipeStyle = 0;
    RecipeKnobs mRecipeKnobs;
    std::array<int, 9> mRecipeOverride{-1, -1, -1, -1, -1, -1, -1, -1, -1};
    std::array<GroundKind, 9> mRecipeDetected{};
    std::array<std::string, 9> mRecipeNames;
    int mRecipeCap = 8;
    bool mRecipeApply = false;
    bool mRecipesOpen = false;
    std::string mRecipeResult;
    bool mFollowSymmetry = true;
    bool mSelectAny = false; // something is selected (Arrange's buttons)
    std::string mHudOverride;
    bool mErosionOpen = false;
    bool mScToolsOpen = false;
    ScAsk mScAsk = ScAsk::None;
    PadSettings mPadSettings;
    SlopeLimitSettings mSlope;
    bool mPadsApplied = false;
    bool mPadsStale = false;
    std::string mScStatus;
    std::string mSlopeReport;
    std::string mRampReport;
    bool mInteropOpen = false;
    InteropAsk mInteropAsk = InteropAsk::None;
    int mInteropBrowse = 0;
    char mInteropImportPath[1024]{};
    char mInteropExportPath[1024]{};
    ImportSettings mImport;
    bool mInteropLive = false;
    bool mInteropSidecar = true;
    int mInteropExportSize = 0;
    float mInteropExportScale = 1.0f;
    bool mInteropCanRevert = false;
    std::string mInteropLinkNote;
    std::string mInteropStatus;
    std::string mInteropProbe;
    ErosionAsk mErosionAsk = ErosionAsk::None;
    std::string mErosionSolver = "hydraulic";
    std::string mErosionPreset = "hills";
    std::map<std::string, ErosionValues> mErosionValues;
    std::string mErosionStatus;
    bool mErosionPreviewShown = false;
    ErosionMaskChoice mErosionMasks;
    int mMapCounts[4] = {0, 0, 0, 0};
    FillOptions mFill;
    bool mFillRequest = false;
    std::string mFillMessage;
    ArrangeOp mArrangeRequest = ArrangeOp::Count;
    int mArrangeSnap = 0; // the grid step 1 << n: 1, 2, 4, 8
    std::string mArrangeMessage;
    std::uint64_t mMinimapImage = 0;
    SlopeView mSlopeView;
    std::array<int, 9> mLayerTypeOverride{-1, -1, -1, -1, -1, -1, -1, -1, -1};
    bool mTypesFromLayersAsk = false;
    bool mTypesOnlyDefault = false;
    void DrawTypesFromLayers();
    std::array<float, 10> mOptimalTiles{};
    int mThemeIndex = 1;
    ThemeOp mThemeOp = ThemeOp::None;
    bool mThemeTrying = false;
    std::vector<std::string> mThemePreview;
    bool mLayersShown = false;
    void DrawThemes();
    bool mRulesRequested = false;

    bool mCheckedMasks = false;
    float mCoverage[8]{};
    bool mHasCoverage = false;
    bool mShowWeight = false;
    std::vector<std::string> mPropBlueprints;
    std::function<std::uint64_t(const std::string&)> mPropPictures;
    std::string mPropBlueprint;
    int mPropMode = 0;
    float mPropDensity = 8.0f;
    bool mPropRandomTurn = true;
    std::vector<PropPaintEntry> mPaintList;
    bool mPaintSetImport = false;
    bool mPaintSetExport = false;
    std::string mPropDetails;
    std::string mReclaimSummary;
    std::vector<std::string> mReclaimRows;
    char mPropFilter[64]{};
    int mAirGridCount = 16;
    bool mAirGridReplace = true;
    bool mAirGridAsked = false;
    bool mEditBorder = false;
    bool mBorderCentred = false;
    bool mShowProps = true;
    bool mShowUnits = true;
    SelectionProperties mSelectionProperties;
    PropertyEdit mPropertyEdit;
    std::string mSelectSelected;
    std::string mSelectHover;
    std::vector<SaveEntry> mMarkerSelection;
    bool mConnectNodes = false;
    std::vector<CheckPin> mCheckPins;
    std::vector<PathQuad> mPathQuads;
    bool mShowPathing = false;
    std::vector<PathQuad> mShipQuads;
    int mPathingLayer = 0;
    WaterState mWater;
    bool mWaterEditing = false;
    int mWaveCount = 0;
    std::vector<WavePattern> mWavePatterns;
    int mWavePattern = 0;
    float mWaveDepth = 2.0f;
    float mWaveDensity = 0.25f;
    float mWaveSpacing = 4.0f;
    float mWaveCentre = 0.0f;
    float mWaveRange = 180.0f;
    WaveAsk mWaveAsk = WaveAsk::None;
    bool mWaterChanged = false;
    bool mWaterFinal = false;
    bool mWaterSunFollows = true;
    bool mWaterMaskPaint = false;
    bool mWavePick = false;
    // The water textures' picker: the slot it is for (-1 closed), the game's textures listed once, the search.
    int mWaterTexturePick = -1;
    bool mWaterTexturePickOpen = false;
    std::vector<std::string> mGameTextures;
    char mWaterTextureFilter[64]{};
    void DrawWaterTexturePicker();
    bool mWaveSymmetric = false;
    bool mWaveDelete = false;
    int mWaveSelectionCount = 0;
    int mWaterMaskKind = 0;
    int mWaterMaskValue = 255;
    WaterMaskBrush mWaterMaskBrush;
    bool mWaterTakeLightingSun = false;
    bool mWaterImport = false;
    bool mWaterExport = false;
    void DrawWaterBodies();
    std::vector<WaterBody> mBodies;
    std::string mBodiesError;
    int mBody = -1;
    bool mBodiesEditing = false;
    bool mBodyDragging = false;
    bool mBodiesChanged = false;
    bool mBodiesFinal = false;
    bool mBodyIsNew = false;
    WaterPick mWaterPick = WaterPick::None;
    std::vector<std::string> mBodyReport;
    std::vector<std::string> mBodyLog;
    std::vector<std::pair<std::string, std::string>> mUnitTypes;
    std::string mUnitType;
    std::string mUnitArmy;
    int mUnitMode = 0;
    bool mUnitRandomTurn = false;
    char mUnitFilter[64]{};
    int mUnitSelectionCount = 0;
    bool mShowRangeRings = true;
    bool mDrawChain = false;
    char mChainName[64] = "Chain_01";
    bool mGiveUnits = false;
    std::vector<DecalTexture> mDecalTextures;
    bool mDecalTexturesListed = false;
    std::string mDecalTexture;
    char mDecalFilter[64]{};
    int mDecalTypeFilter = 0;
    float mDecalSize[2] = {32.0f, 32.0f};
    float mDecalTurn = 0.0f;
    bool mDecalRandomTurn = false;
    bool mDecalWithPair = true;
    float mDecalOverlap = 0.1f;
    DecalBrush mDecalBrush;
    float mDecalSizeVariation = 0.0f;
    DecalPathAction mDecalPathAction = DecalPathAction::None;
    int mDecalPathPoints = 0;
    int mDecalPathDecals = 0;
    float mDecalCutoff = 0.0f;
    int mDecalSelectionCount = 0;
    bool mShowGrid = false;
    bool mSnap = false;
    float mGridStep = 1.0f;
    bool mKeepOnGround = true;
    std::set<std::string> mHiddenMarkerTypes;
    std::vector<std::string> mAskSelect;
    bool mAskSelectAdd = false;
    bool mAskSelectSet = false;
    std::string mAskFrame;
    std::array<float, 2> mAskPoint{};
    bool mAskPointSet = false;
    int mDetectedSymmetry = -2; // -2: no map opened yet
    float mDetectedMatch = 0.0f;
    int mDetectedStarts = 0;
    int mDetectedResources = 0;
    float mDetectedOffsetX = 0.0f;
    float mDetectedOffsetZ = 0.0f;
    // Make symmetric: the source part, how copies combine (SymmetryCombine), the seam, and the layers it reaches.
    int mSymPart = 0;
    int mSymCombine = 0;
    float mSymSeam = 0.0f;
    bool mSymMasks = false;
    bool mSymTypes = false;
    std::vector<std::string> mArmies;
    std::vector<std::string> mExtraArmies;
    std::vector<ScenarioTeam> mTeams;
    std::vector<ScenarioTeam> mTeamsChange;
    bool mTeamsChanged = false;
    char mExtraBuffer[256]{};
    bool mExtraChanged = false;
    std::string mMarkerEditName;
    std::string mMarkerEditKey;
    std::string mMarkerEditValue;
    char mMarkerEditBuffer[256]{};
    /** A typed marker field's own copy while it is held (a number, a vector, a colour). */
    MarkerValue mMarkerTyped;
    float mMarkerTypedColour[4] = {0.0f, 0.0f, 0.0f, 1.0f};
    std::string mMarkerEditing;
    std::optional<std::array<int, 4>> mArea;
    int mMapWidth = 0;
    int mMapHeight = 0;
    bool mAreaChanged = false;
    std::optional<std::array<int, 4>> mAreaChange;
    MaskOp mMaskOp = MaskOp::None;
    std::vector<std::string> mShaders;
    std::string mShader;
    std::string mShaderChange;
    float mMapSizeUnits = 0.0f;

    bool mCheckRequested = false;
    bool mRepairRequested = false;
    bool mShowDifferences = true;
    int mChecked = 0;
    int mDiffering = 0;
    int mLargest = 0;
    int mCheckedSymmetry = -1;
    int mCheckedTurns = 0;
  };
} // namespace faf::editor
