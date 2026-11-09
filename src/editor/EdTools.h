#pragma once

#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdMaskBrush.h"
#include "editor/doc/EdWater.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdTextureLibrary.h"

#include <cmath>
#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * The tool box, as the mockup lays it out (tmp/claude/map-editor/editor-mockup.html): a strip of tool icons
   * and, beside it, the chosen tool's settings (brush modes, size, strength, falloff, the symmetry modes with
   * their diagrams, limits). The settings are kept here; the tools act on a map from stages 3 to 6 of the plan.
   */
  class EdTools
  {
  public:
    /** Draws the panel's contents into the current ImGui window. */
    void Draw();

    /** Whether the Terrain tool is the chosen one (the viewport's left button paints heights). */
    [[nodiscard]] bool TerrainToolActive() const noexcept { return mTool == 1; }
    /** The Select tool (the viewport's left button picks and moves objects) and the Props tool. */
    [[nodiscard]] bool SelectToolActive() const noexcept { return mTool == 0; }
    [[nodiscard]] bool PropsToolActive() const noexcept { return mTool == 4; }
    /** The Props tool's settings: the blueprint placed, Single / Scatter / Erase, props a second, random turn. */
    enum class PropMode
    {
      Single,
      Scatter,
      Erase,
    };
    [[nodiscard]] const std::string& PropBlueprint() const noexcept { return mPropBlueprint; }
    [[nodiscard]] PropMode CurrentPropMode() const noexcept { return static_cast<PropMode>(mPropMode); }
    [[nodiscard]] float PropDensity() const noexcept { return mPropDensity; }
    [[nodiscard]] bool RandomPropTurn() const noexcept { return mPropRandomTurn; }
    /** The chosen prop's reclaim, scale and LODs, for the panel. */
    void SetPropDetails(std::string details) { mPropDetails = std::move(details); }
    /** The prop blueprints the rules have (their ids), for the palette. */
    void SetPropBlueprints(std::vector<std::string> blueprints) { mPropBlueprints = std::move(blueprints); }
    [[nodiscard]] bool HasPropBlueprints() const noexcept { return !mPropBlueprints.empty(); }
    /** The Markers tool. */
    [[nodiscard]] bool MarkersToolActive() const noexcept { return mTool == 6; }
    /** The Check's results on the map, for the view's pins: where, and how bad (0 error, 1 warning, 2 note). */
    struct CheckPin
    {
      float x;
      float z;
      int level;
    };
    void SetCheckPins(std::vector<CheckPin> pins) { mCheckPins = std::move(pins); }
    [[nodiscard]] const std::vector<CheckPin>& CheckPins() const noexcept { return mCheckPins; }
    /** The Water tool's panel: the map's water as it is, and a change it made (`final` when a drag or a click ended). */
    [[nodiscard]] bool WaterToolActive() const noexcept { return mTool == 3; }
    void SetWater(const WaterState& water)
    {
      if (!mWaterEditing) {
        mWater = water;
      }
    }
    [[nodiscard]] bool TakeWaterChange(WaterState& water, bool& final)
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
    /** The Units tool: Place (the chosen unit type in the chosen army, with symmetric copies) or Select. */
    [[nodiscard]] bool UnitsToolActive() const noexcept { return mTool == 7; }
    [[nodiscard]] bool UnitPlaceMode() const noexcept { return mUnitMode == 0; }
    [[nodiscard]] const std::string& UnitType() const noexcept { return mUnitType; }
    [[nodiscard]] const std::string& UnitArmy() const noexcept { return mUnitArmy; }
    [[nodiscard]] bool RandomUnitTurn() const noexcept { return mUnitRandomTurn; }
    /** The unit blueprints the rules have: id and name. */
    void SetUnitTypes(std::vector<std::pair<std::string, std::string>> types) { mUnitTypes = std::move(types); }
    [[nodiscard]] bool HasUnitTypes() const noexcept { return !mUnitTypes.empty(); }
    void SetUnitSelectionCount(const int count) noexcept { mUnitSelectionCount = count; }
    /** Test runs (`/unittool <type>,<army>[,select]`). */
    void SetUnitTool(std::string type, std::string army, const bool select)
    {
      mTool = 7;
      mUnitType = std::move(type);
      mUnitArmy = std::move(army);
      mUnitMode = select ? 1 : 0;
    }
    /** The Decals tool: Place (a click places the chosen texture with its symmetric copies) or Select (pick, drag, delete). */
    [[nodiscard]] bool DecalsToolActive() const noexcept { return mTool == 5; }
    [[nodiscard]] bool DecalPlaceMode() const noexcept { return mDecalMode == 0; }
    /** Path mode: clicks lay a curve's points; decals follow it end to end when placed. */
    [[nodiscard]] bool DecalPathMode() const noexcept { return mDecalMode == 2; }
    /** How much each decal along a path overlaps the next (0 to 0.9 of its length). */
    [[nodiscard]] float DecalOverlap() const noexcept { return mDecalOverlap; }
    /** What the panel's path buttons asked for, taken once. */
    enum class DecalPathAction
    {
      None,
      Place,
      RemoveLast,
      Clear,
    };
    [[nodiscard]] DecalPathAction TakeDecalPathAction() noexcept { return std::exchange(mDecalPathAction, DecalPathAction::None); }
    /** The path's points and the decals it would place, for the panel. */
    void SetDecalPathInfo(const int points, const int decals) noexcept
    {
      mDecalPathPoints = points;
      mDecalPathDecals = decals;
    }
    [[nodiscard]] const std::string& DecalTexturePath() const noexcept { return mDecalTexture; }
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
    [[nodiscard]] float DecalSizeX() const noexcept { return mDecalSize[0]; }
    [[nodiscard]] float DecalSizeZ() const noexcept { return mDecalSize[1]; }
    /** The heading in radians; a random one when Random turn is on. */
    [[nodiscard]] float DecalTurnDegrees() const noexcept { return mDecalTurn; }
    [[nodiscard]] bool RandomDecalTurn() const noexcept { return mDecalRandomTurn; }
    /** The far cutoff distance (0: the decal works one out from its size). */
    [[nodiscard]] float DecalCutoff() const noexcept { return mDecalCutoff; }
    /** How many decals the view has selected, for the panel. */
    void SetDecalSelectionCount(const int count) noexcept { mDecalSelectionCount = count; }
    /** Test runs (`/decaltool <texture>[,select]`): the Decals tool with this texture and mode. */
    void SetDecalTool(std::string texture, const int mode)
    {
      mTool = 5;
      mDecalTexture = std::move(texture);
      mDecalMode = mode;
    }
    /** The map's playable area (x0, z0, x1, z1) as it is, and the map's size, for the panel. */
    void SetPlayableArea(const std::optional<std::array<int, 4>>& area, const int width, const int height)
    {
      mArea = area;
      mMapWidth = width;
      mMapHeight = height;
    }
    /** A change the panel asked for: the new area, or none to remove it. */
    [[nodiscard]] bool TakePlayableAreaChange(std::optional<std::array<int, 4>>& area)
    {
      if (!mAreaChanged) {
        return false;
      }
      mAreaChanged = false;
      area = mAreaChange;
      return true;
    }

    /** The Markers tool's type to place (an entry of MarkerTypes()). */
    [[nodiscard]] const MarkerType& PlaceMarkerType() const noexcept { return MarkerTypes()[static_cast<std::size_t>(mMarkerType)]; }
    /** The markers the view has selected (copies of their entries), for the properties panel. */
    void SetMarkerSelection(std::vector<SaveEntry> selection) { mMarkerSelection = std::move(selection); }
    /** A property of the selected marker the panel changed (`key` "name" renames it). */
    [[nodiscard]] bool TakeMarkerEdit(std::string& marker, std::string& key, std::string& value)
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
    void SetArmies(std::vector<std::string> armies, std::vector<std::string> extra)
    {
      mArmies = std::move(armies);
      mExtraArmies = std::move(extra);
    }
    /** The scenario's teams, for the panel's slot order and its FFA check; a change it asks for, taken once. */
    void SetTeams(std::vector<ScenarioTeam> teams) { mTeams = std::move(teams); }
    [[nodiscard]] bool TakeTeamsChange(std::vector<ScenarioTeam>& teams)
    {
      if (!mTeamsChanged) {
        return false;
      }
      mTeamsChanged = false;
      teams = mTeamsChange;
      return true;
    }
    [[nodiscard]] bool TakeExtraArmiesChange(std::string& extra)
    {
      if (!mExtraChanged) {
        return false;
      }
      mExtraChanged = false;
      extra = mExtraBuffer;
      return true;
    }

    /** The Markers panel: the types it hides (not drawn, not picked), and what it asks the view for. */
    [[nodiscard]] const std::set<std::string>& HiddenMarkerTypes() const noexcept { return mHiddenMarkerTypes; }
    [[nodiscard]] std::set<std::string>& HiddenMarkerTypes() noexcept { return mHiddenMarkerTypes; }
    /** Select these markers (`add`: Ctrl, toggles them in the selection); the Markers tool comes up to edit them. */
    void AskMarkerSelect(std::vector<std::string> names, const bool add)
    {
      mAskSelect = std::move(names);
      mAskSelectAdd = add;
      mAskSelectSet = true;
      mTool = 6;
    }
    void AskMarkerFrame(std::string name) { mAskFrame = std::move(name); }
    [[nodiscard]] bool TakeMarkerSelect(std::vector<std::string>& names, bool& add)
    {
      if (!mAskSelectSet) {
        return false;
      }
      mAskSelectSet = false;
      names = std::move(mAskSelect);
      add = mAskSelectAdd;
      return true;
    }
    [[nodiscard]] bool TakeMarkerFrame(std::string& name)
    {
      if (mAskFrame.empty()) {
        return false;
      }
      name = std::exchange(mAskFrame, {});
      return true;
    }
    [[nodiscard]] const std::vector<SaveEntry>& MarkerSelection() const noexcept { return mMarkerSelection; }
    /** The layer textures and their thumbnails (the Info panel shows the map's layers with them too). */
    [[nodiscard]] EdTextureLibrary& Library() noexcept { return mLibrary; }

    /** The build grid around the cursor, snapping to its cells, and its step in game units (toolbar). */
    [[nodiscard]] bool ShowGrid() const noexcept { return mShowGrid; }
    void SetShowGrid(const bool show) noexcept { mShowGrid = show; }
    [[nodiscard]] bool SnapToGrid() const noexcept { return mSnap; }
    void SetSnapToGrid(const bool snap) noexcept { mSnap = snap; }
    [[nodiscard]] float GridStep() const noexcept { return mGridStep; }
    /** The move gizmo keeps objects on the ground (X, Z and free moves); off, they keep their height. Never below it. */
    [[nodiscard]] bool KeepOnGround() const noexcept { return mKeepOnGround; }
    void SetKeepOnGround(const bool keep) noexcept { mKeepOnGround = keep; }
    void SetGridStep(const float step) noexcept { mGridStep = step; }

    /** The Markers tool's connect mode: a click on a path node links it to the selection. */
    [[nodiscard]] bool ConnectPathNodes() const noexcept { return mConnectNodes; }
    void SetConnectPathNodes(const bool connect) noexcept { mConnectNodes = connect; }
    /** Test runs (`/markertool`): the Markers tool placing this type. */
    void SetMarkerTool(const std::string& type) noexcept
    {
      mTool = 6;
      for (std::size_t i = 0; i < MarkerTypes().size(); ++i) {
        if (type == MarkerTypes()[i].type) {
          mMarkerType = static_cast<int>(i);
        }
      }
    }

    /** How many objects the view has selected, for the Select tool's panel. */
    void SetSelectionCount(const int count) noexcept { mSelectionCount = count; }
    /** Test runs (`/proptool`): the Props tool with this blueprint and mode. */
    void SetPropTool(std::string blueprint, const int mode) noexcept
    {
      mTool = 4;
      mPropBlueprint = std::move(blueprint);
      mPropMode = mode;
    }
    void SetTool(const int tool) noexcept { mTool = tool; }

    /** Whether the Texture tool is the chosen one (the viewport's left button paints a layer's mask). */
    [[nodiscard]] bool TextureToolActive() const noexcept { return mTool == 2; }

    /** The texture brush as the panel sets it: the brush's shape, the layer, the mode. */
    [[nodiscard]] MaskBrush CurrentMaskBrush() const noexcept
    {
      MaskBrush brush;
      brush.shape = CurrentHeightBrush();
      brush.mode = static_cast<MaskBrushMode>(mMaskMode);
      brush.layer = mMaskLayer;
      brush.lowerAbove = mLowerAbove;
      return brush;
    }
    /** The open map's layer texture paths (lower, strata 1-8, upper), for the layer list. */
    void SetLayerNames(std::vector<std::string> names) { mLayerNames = std::move(names); }

    /** One of the map's ten texture slots (lower, strata 1-8, upper): albedo and normal map, each with its size in game units. */
    struct LayerSlot
    {
      std::string albedo;
      std::string normals;
      float albedoSize = 4.0f;
      float normalsSize = 4.0f;
      bool operator==(const LayerSlot& other) const
      {
        return albedo == other.albedo && normals == other.normals && albedoSize == other.albedoSize && normalsSize == other.normalsSize;
      }
    };
    /** The open map's slots as the terrain has them, each frame. */
    void SetLayerSlots(std::vector<LayerSlot> slots) { mSlots = std::move(slots); }
    /** A slot the panel changed (its texture or size): the app applies it. */
    [[nodiscard]] bool TakeLayerChange(int& slot, LayerSlot& value)
    {
      if (mChangedSlot < 0) {
        return false;
      }
      slot = std::exchange(mChangedSlot, -1);
      value = mChangedValue;
      return true;
    }
    /** Each stratum's share of the map (0..1), for the paint list. */
    void SetCoverage(const float (&coverage)[8]) noexcept
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
      Import,
      Export,
    };
    [[nodiscard]] MaskOp TakeMaskOp() noexcept { return std::exchange(mMaskOp, MaskOp::None); }
    [[nodiscard]] int MaskLayer() const noexcept { return mMaskLayer; }
    /** Whether the view colours the paint layer's weight on the terrain. */
    [[nodiscard]] bool ShowLayerWeight() const noexcept { return mShowWeight; }
    void SetShowLayerWeight(const bool show) noexcept { mShowWeight = show; }
    /** The terrain shaders the game data has, and the map's. */
    void SetShaders(std::vector<std::string> shaders, std::string current)
    {
      mShaders = std::move(shaders);
      mShader = std::move(current);
    }
    [[nodiscard]] bool TakeShaderChange(std::string& shader)
    {
      if (mShaderChange.empty()) {
        return false;
      }
      shader = std::exchange(mShaderChange, {});
      return true;
    }

    /** Apply rules to whole map was pressed; the rules. */
    [[nodiscard]] bool TakeRulesRequest() noexcept { return std::exchange(mRulesRequested, false); }
    [[nodiscard]] const std::vector<MaskRule>& Rules() const noexcept { return mRules; }
    /** Test runs (`/maskrule`): one more rule, then Apply. */
    void AddRule(const MaskRule& rule)
    {
      mTool = 2;
      mRules.push_back(rule);
    }
    void RequestRules() noexcept { mRulesRequested = true; }
    /** Test runs (`/browse`): the texture browser opened for a slot. */
    void OpenBrowser(const int slot) noexcept
    {
      mTool = 2;
      mBrowseSlot = slot;
      mBrowseOpen = true;
    }
    /** Test runs (`/masklayer`): the Texture tool on this layer. */
    void SetMaskLayer(const int layer) noexcept
    {
      mTool = 2;
      mMaskLayer = layer;
    }

    /** The terrain brush as the panel sets it (Flatten's height is the stroke's, set by the viewport). */
    [[nodiscard]] HeightBrush CurrentHeightBrush() const noexcept
    {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mBrushMode);
      brush.symmetry = static_cast<Symmetry>(mSymmetry);
      brush.radius = mRadius;
      brush.strength = mStrength;
      brush.falloff = mFalloff;
      brush.turns = mNWay;
      brush.setTo = mSetHeight * 128.0f;
      brush.terraceStep = mTerraceStep * 128.0f;
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
    void ClearPlanePoints() noexcept
    {
      mPlanePoints = 0;
      mPlaneSet = false;
    }
    /** The picked points, oldest first, for the view to mark. */
    [[nodiscard]] int PlanePoints(float (&x)[3], float (&height)[3], float (&z)[3]) const noexcept;

    /** Stamp mode: the image the Stamp image button loaded. */
    [[nodiscard]] bool TakeStampRequest() noexcept { return std::exchange(mStampRequested, false); }
    void SetStamp(HeightStamp stamp, std::string name)
    {
      mStamp = std::make_shared<HeightStamp>(std::move(stamp));
      mStampName = std::move(name);
    }

    /** Test runs (`/symcheck`): the Terrain tool with this symmetry (the panel's index), then Check or Copy. */
    void SetSymmetry(const int index, const int turns) noexcept
    {
      mTool = mTool == 2 ? 2 : 1; // the Texture tool checks the masks
      mSymmetry = index;
      mNWay = turns;
    }
    /** A newly opened map's symmetry as DetectSymmetry found it (the panel's index and turns; -1: none found). */
    void SetDetectedSymmetry(const int index, const int turns, const float matched) noexcept
    {
      mDetectedSymmetry = index;
      mDetectedMatch = matched;
      if (index >= 0) {
        mSymmetry = index;
        mNWay = index == 9 ? turns : mNWay;
      } else {
        mSymmetry = 0;
      }
    }
    void RequestCheck() noexcept { mCheckRequested = true; }
    void RequestImport() noexcept { mImportRequested = true; }
    /** Test runs (`/brush`): the Terrain tool with this brush mode (a HeightBrushMode). */
    void SetBrushMode(const int mode) noexcept
    {
      mTool = 1;
      mBrushMode = mode;
    }
    void RequestRepair() noexcept { mRepairRequested = true; }

    /** The height field's Import and Export buttons, taken by the app each frame (it asks for the file). */
    [[nodiscard]] bool TakeImportRequest() noexcept { return std::exchange(mImportRequested, false); }
    [[nodiscard]] bool TakeExportRequest() noexcept { return std::exchange(mExportRequested, false); }
    /** Heights times this on import and export. */
    [[nodiscard]] float HeightScale() const noexcept { return mHeightScale; }
    /** The exported image's width in samples, 0 for the map's own. */
    [[nodiscard]] int ExportWidth() const noexcept { return kExportWidths[mExportSize]; }

    /** The symmetry check's buttons, taken by the view each frame. */
    [[nodiscard]] bool TakeCheckRequest() noexcept { return std::exchange(mCheckRequested, false); }
    [[nodiscard]] bool TakeRepairRequest() noexcept { return std::exchange(mRepairRequested, false); }
    /** Whether the view marks the vertices whose copies differ. */
    [[nodiscard]] bool ShowDifferences() const noexcept { return mShowDifferences; }

    /** The check's result for the panel, for the symmetry it checked (`checked` 0: nothing to show). */
    void SetCheckResult(const int checked, const int differing, const int largestWords, const HeightBrush& checkedWith, const bool masks = false) noexcept
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
      return mChecked > 0 && mCheckedSymmetry == mSymmetry && (mSymmetry != 9 || mCheckedTurns == mNWay) && mCheckedMasks == TextureToolActive();
    }

  private:
    void DrawStrip();
    void DrawTerrain();
    void DrawTexture();
    void DrawWater();
    void DrawProps();
    void DrawDecals();
    void DrawMarkers();
    void DrawUnits();
    void DrawSelect();
    void DrawBrush(bool withModes);
    void DrawSymmetry(bool withCheck = true);
    void DrawLimits();

    int mTool = 1;
    int mBrushMode = 0;
    float mRadius = 14.0f;
    float mStrength = 0.5f;
    float mFalloff = 0.6f;
    int mSymmetry = 6; // both axes
    int mNWay = 3;
    bool mLimitHeight = false;
    float mLimitLow = 0.0f;
    float mLimitHigh = 100.0f;
    bool mLimitSlope = false;
    float mLimitSlopeDegrees = 30.0f;
    float mSetHeight = 20.0f;
    float mTerraceStep = 5.0f;
    float mPlanePointX[3]{};
    float mPlanePointH[3]{};
    float mPlanePointZ[3]{};
    int mPlanePoints = 0;
    bool mPlaneSet = false;
    double mPlaneX = 0.0;
    double mPlaneZ = 0.0;
    double mPlaneC = 0.0;
    std::shared_ptr<HeightStamp> mStamp;
    std::string mStampName;
    float mStampHeight = 20.0f;
    bool mStampRequested = false;
    int mMarkerType = 0;
    int mDecalMode = 0; // 0 Place, 1 Select

    static constexpr int kExportWidths[] = {0, 257, 513, 1025, 2049, 4097};
    bool mImportRequested = false;
    bool mExportRequested = false;
    float mHeightScale = 1.0f;
    int mExportSize = 0;

    int mMaskLayer = 0;
    int mMaskMode = 0;
    bool mLowerAbove = true;
    std::vector<std::string> mLayerNames;
    std::vector<LayerSlot> mSlots;
    int mChangedSlot = -1;
    LayerSlot mChangedValue;
    EdTextureLibrary mLibrary;
    void DrawLayerSlots();
    void DrawTextureBrowser();
    int mBrowseSlot = -1;
    bool mBrowseOpen = false;
    char mBrowseFilter[64]{};
    std::vector<MaskRule> mRules;
    bool mRulesRequested = false;

    bool mCheckedMasks = false;
    float mCoverage[8]{};
    bool mHasCoverage = false;
    bool mShowWeight = false;
    std::vector<std::string> mPropBlueprints;
    std::string mPropBlueprint;
    int mPropMode = 0;
    float mPropDensity = 8.0f;
    bool mPropRandomTurn = true;
    std::string mPropDetails;
    char mPropFilter[64]{};
    int mSelectionCount = 0;
    std::vector<SaveEntry> mMarkerSelection;
    bool mConnectNodes = false;
    std::vector<CheckPin> mCheckPins;
    WaterState mWater;
    bool mWaterEditing = false;
    bool mWaterChanged = false;
    bool mWaterFinal = false;
    std::vector<std::pair<std::string, std::string>> mUnitTypes;
    std::string mUnitType;
    std::string mUnitArmy;
    int mUnitMode = 0;
    bool mUnitRandomTurn = false;
    char mUnitFilter[64]{};
    int mUnitSelectionCount = 0;
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
    int mDetectedSymmetry = -2; // -2: no map opened yet
    float mDetectedMatch = 0.0f;
    std::vector<std::string> mArmies;
    std::vector<std::string> mExtraArmies;
    std::vector<ScenarioTeam> mTeams;
    std::vector<ScenarioTeam> mTeamsChange;
    bool mTeamsChanged = false;
    char mExtraBuffer[256]{};
    bool mExtraEditing = false;
    bool mExtraChanged = false;
    std::string mMarkerEditName;
    std::string mMarkerEditKey;
    std::string mMarkerEditValue;
    char mMarkerEditBuffer[256]{};
    std::string mMarkerEditing;
    std::optional<std::array<int, 4>> mArea;
    int mMapWidth = 0;
    int mMapHeight = 0;
    bool mAreaChanged = false;
    std::optional<std::array<int, 4>> mAreaChange;
    void DrawPlayableArea();
    MaskOp mMaskOp = MaskOp::None;
    std::vector<std::string> mShaders;
    std::string mShader;
    std::string mShaderChange;

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
