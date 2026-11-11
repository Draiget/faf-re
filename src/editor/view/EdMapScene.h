#pragma once

#include <array>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <map>
#include <vector>

#include <Windows.h>

#include "editor/graph/EdTextureGraph.h"
#include "editor/tools/EdViewAids.h"
#include "editor/tools/EdTerrainTypes.h"
#include "editor/doc/EdLayerPreset.h"
#include "editor/doc/EdUnitPreset.h"
#include "editor/doc/EdMarkerPreset.h"
#include "editor/EdTools.h"
#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnits.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdMarkers.h"

namespace moho
{
  class CameraImpl;
  class CWldMap;
  class MeshInstance;
  class SimpleRenderWorldView;
} // namespace moho

namespace faf::editor
{
  class EdDocument;
  class EdTools;

  /**
   * The opened map in the game's viewport between plays (board task WPE.3). The renderer draws the map in
   * `moho::sWldMap` through its world views, as the original editor did (`REN_SetWldMap`, 0x007FA150).
   * While a map is open and no play runs, the scene puts the document's map there and registers one world
   * view with its own camera (made the way the strategic preview render makes one). It leaves before a
   * play's session takes the map over, and before the document drops its map.
   *
   * Camera: middle mouse button drag orbits (turns and tilts around the point looked at), Shift + middle
   * drag or right drag pans (the ground follows the cursor), WASD or the arrows move (Shift faster), the
   * wheel zooms toward the point under the cursor without changing the camera's tilt or turn; Home frames
   * the whole map.
   *
   * With the Terrain tool, the left button paints the height brush (EdHeightBrush.cpp) under the cursor
   * while it is held, with the Tools panel's mode, size, strength, falloff and symmetry; Flatten flattens to
   * the height under the stroke's first point.
   */
  class EdMapScene
  {
  public:
    explicit EdMapScene(EdDocument& document);
    ~EdMapScene();
    EdMapScene(const EdMapScene&) = delete;
    EdMapScene& operator=(const EdMapScene&) = delete;

    /** Each frame, after the play's frame logic: attaches, follows the window's size, or leaves. */
    void Update(float frameSeconds, bool playIdle);

    /** Leaves the viewport (the document is about to drop its map). */
    void Detach();

    /** The tool settings the left mouse button acts with (the Tools panel's). */
    void SetTools(EdTools* tools) noexcept { mTools = tools; }

    /** Replaces the map's heights from a height image, resampled to the map's size, as one undo step. */
    bool ImportHeights(const std::filesystem::path& file, float scale, std::string& message);
    /** Writes the map's heights as a height image, `width` samples wide (0: the map's own size). */
    bool ExportHeights(const std::filesystem::path& file, int width, float scale, std::string& message);
    /** The point the orbit camera looks at (on the ground): where the particle editor's preview emits. */
    void ViewTarget(float& x, float& y, float& z) const noexcept
    {
      x = mTargetX;
      y = mTargetY;
      z = mTargetZ;
    }
    /** The map's heights in game units for the material editor's map nodes (null without a map). */
    [[nodiscard]] std::shared_ptr<TerrainSource> TerrainHeights();

    /** The open map's ten texture slots (lower, strata 1-8, upper) as the terrain has them. */
    [[nodiscard]] std::vector<EdTools::LayerSlot> LayerSlots() const;
    /** The paint layer's mask cleared, or read from / written to a grey image (PNG, RAW: 0-255 as 0-65535). */
    bool ClearMaskLayer(int layer, std::string& message);
    bool ImportMaskLayer(int layer, const std::filesystem::path& file, std::string& message);
    bool ExportMaskLayer(int layer, const std::filesystem::path& file, std::string& message);
    /** Each stratum's share of the map, once the masks are read. */
    [[nodiscard]] bool MaskCoverage(float (&coverage)[8]) const;
    /** The terrain shaders the game's terrain effect marks composite (the ones a map may name), and the map's. */
    [[nodiscard]] std::vector<std::string> TerrainShaders();
    [[nodiscard]] std::string TerrainShader() const;
    /** Sets the map's terrain shader, as one undo step. */
    void ChangeTerrainShader(const std::string& shader);

    /**
     * Shows in-memory DDS files in a slot's albedo and normal map (the material editor's Live Update) without changing
     * what the map names or saves; an empty one leaves that texture as it is. RestoreLayerSlot puts the slot's own
     * files back. A slot without a size gets `emptySize`.
     */
    void PreviewLayerSlot(int slot, const std::vector<std::uint8_t>& albedo, const std::vector<std::uint8_t>& normals, float emptySize);
    void RestoreLayerSlot(int slot);
    /** Stratum `layer`'s (0-7) mask from a grey image over the whole map, as one undo step. */
    bool SetMaskLayer(int layer, const TexImage& image, std::string& message);

    /** Changes one slot as the Tools panel asked, as one undo step. */
    void ChangeLayerSlot(int slot, const EdTools::LayerSlot& value);
    /**
     * Layers from a settings file, with the terrain shader when `shader` isn't empty: what differs is changed as one
     * undo step. Returns how many slots (and the shader) changed.
     */
    int ApplyLayerSettings(const std::string& shader, const std::vector<std::pair<int, LayerSettings>>& layers);
    /** The ten layers as the files hold them. */
    [[nodiscard]] std::vector<LayerSettings> LayerSettingsNow() const;

    /** The selected markers' entries, for the panel. */
    [[nodiscard]] std::vector<SaveEntry> SelectedMarkers() const;
    /** The selected markers' names (empty when none). */
    [[nodiscard]] const std::vector<std::string>& SelectedMarkerNames() const noexcept { return mMarkerSelection; }
    /** Adds a `.fafmapmarkers` file's markers as one undo step and selects them; false with `error`. */
    bool ImportMarkerFile(const std::string& text, MarkerImport& result, std::string& error);
    /** The units an export writes: the selected ones, or every unit of `army` when none is selected. */
    [[nodiscard]] std::vector<SaveUnit> UnitsToExport(const std::string& army) const;
    /**
     * Adds a `.scunits` file's units to `army` (its INITIAL group) under new UNIT_n names, on the ground, as one undo
     * step, and selects them; `moved` when they came from off this map. False with `error`.
     */
    bool ImportUnitFile(const std::string& text, const std::string& army, std::vector<std::string>& names, bool& moved, std::string& error);
    /** Changes a property of a marker ("name" renames it), as one undo step. */
    void EditMarker(const std::string& marker, const std::string& key, const std::string& value);
    /** An air path node grid `count` a side over the playable area (or the map), as one undo step; `replace` removes the air nodes there were. */
    void FillAirGrid(int count, bool replace);
    /** The move gizmo's parts: an arrow per axis and the free square in its middle. */
    enum class GizmoPart
    {
      None,
      X,
      Y,
      Z,
      Free,
    };
    /** What the Select tool picks: one kind of thing at a time, the kind last clicked. */
    enum class PickKind
    {
      None,
      Prop,
      Marker,
      Unit,
      Decal,
    };
    /** The Select tool's panel: what is selected and what is under the cursor, in words. */
    [[nodiscard]] std::string SelectionText() const;
    /** The selection's active (first) item for the Properties panel, and an edit of it as one undo step. */
    [[nodiscard]] SelectionProperties SelectionPropertiesNow() const;
    void ApplyPropertyEdit(const PropertyEdit& edit);
    [[nodiscard]] std::string HoverText() const;
    /** The Decals tool's path: its points, and how many decals it would place (the cursor as its next point). */
    [[nodiscard]] int DecalPathPointCount() const noexcept { return static_cast<int>(mDecalPath.size()); }
    [[nodiscard]] int DecalPathDecalCount() const noexcept { return mDecalPathPreview; }
    /** Lays the path's decals with their symmetric copies as one undo step, and starts a new path. */
    void PlaceDecalPath();
    void RemoveLastDecalPathPoint()
    {
      if (!mDecalPath.empty()) {
        mDecalPath.pop_back();
      }
    }
    void ClearDecalPath() { mDecalPath.clear(); }
    /** A prop blueprint's reclaim, scale and mesh, for the Props panel ("" when the rules don't have it). */
    [[nodiscard]] std::string PropDetails(const std::string& blueprint) const;
    /** How many units the Units tool has selected, for its panel. */
    [[nodiscard]] int UnitSelectionCount() const noexcept { return static_cast<int>(mUnitSelection.size()); }
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& UnitSelection() const noexcept { return mUnitSelection; }
    /** The panels' Select: these units (army, name) selected. */
    void SelectUnits(std::vector<std::pair<std::string, std::string>> units) { mUnitSelection = std::move(units); }
    /** Moves `names` of `army` into the group `path` (made when missing); one undo step. False when nothing changed. */
    bool MoveUnitsToGroup(const std::string& army, const std::vector<std::string>& names, const std::vector<std::string>& path);
    /** Whether the armies' units are drawn (test runs wait for it). */
    [[nodiscard]] bool UnitsReady() const noexcept { return !mUnitRefs.empty(); }
    /** How many decals the Decals tool has selected, for its panel. */
    [[nodiscard]] int DecalSelectionCount() const noexcept { return static_cast<int>(mDecalSelection.size()); }
    /** Selects markers by name (`add` toggles them in the selection instead), for the Markers panel. */
    void SelectMarkers(const std::vector<std::string>& names, bool add);
    /** Moves the camera over a marker, at most `distance` away. */
    void FrameMarker(const std::string& name, float distance = 140.0f);
    /** The view to the point (x, z) of the map, from no farther than `distance`. */
    void FramePoint(float x, float z, float distance = 80.0f);
    /** Test runs (`/selectunit <army>,<unit>`): that unit selected and the view on it. */
    void SelectUnit(const std::string& army, const std::string& name);
    /** Sets the scenario's teams (the panel's slot order, the FFA repair), as one undo step. */
    void ChangeTeams(const std::vector<ScenarioTeam>& teams);
    /** Sets the scenario's extra armies (names split on spaces), as one undo step. */
    void ChangeExtraArmies(const std::string& armies);
    /**
     * Places markers of the Markers tool's type at (x, z) and its symmetric copies, as one undo step. With `connect`,
     * a path node placed while a node of its type is selected is linked to it (each copy to its copy), so clicks lay a path.
     */
    void PlaceMarkers(float x, float z, bool connect = false);
    /**
     * Links each selected path node to `target`, or unlinks it when they are linked, with the symmetric copies of the
     * pair, as one undo step; `target` becomes the selection, so the next click continues from it.
     */
    void LinkSelectionTo(const std::string& target);

    /** Sets or removes the playable area as one undo step. */
    void ChangePlayableArea(const std::optional<EdDocument::PlayableRect>& area);

    /** Removes the selected props (Edit > Delete selection, the Delete key), as one undo step. */
    /** Edit > Delete: the active tool's selection (decals, markers, or props). */
    void DeleteSelected()
    {
      if (mTools != nullptr && mTools->UnitsToolActive()) {
        DeleteSelectedUnits();
      } else if (mTools != nullptr && mTools->DecalsToolActive()) {
        DeleteSelectedDecals();
      } else if (mTools != nullptr && mTools->MarkersToolActive()) {
        DeleteSelectedMarkers();
      } else {
        DeleteSelection();
      }
    }

    /** Undoes or redoes the newest height stroke (Ctrl+Z, Ctrl+Y); false when there is none. */
    bool Undo();
    bool Redo();

    [[nodiscard]] bool Attached() const noexcept { return mMap != nullptr; }

    /** The game viewport window's messages while attached; true when the scene used one. */
    bool OnWindowMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

  private:
    void Attach(moho::CWldMap& map);
    void FrameWholeMap();
    void ApplyCamera();
    /** The ground (terrain or water) under a point of the viewport, in its pixels; false off the map. */
    bool GroundAt(float x, float y, float& outX, float& outZ) const;
    void MoveWithKeys(float frameSeconds);
    /** The map's props as mesh instances, from the kept rules' blueprints once they are ready. */
    void CreateProps();
    void DeleteProps();

    /** One mesh per prop entry, at the entry's index (null when its blueprint or mesh is missing). */
    std::vector<moho::MeshInstance*> mProps;
    /**
     * The deposit props the game puts at each resource marker with `resource` on (ScenarioUtilities.lua CreateResources:
     * massDeposit01_prop.bp, hydrocarbonDeposit01_prop.bp), by marker name; kept at the markers each frame.
     */
    std::map<std::string, moho::MeshInstance*> mDeposits;
    void UpdateDeposits();
    void DeleteDeposits();
    bool mPropsDone = false;
    /** The armies' units from `_save.lua` (every group's), drawn as the game places them, and which unit each is. */
    struct UnitRef
    {
      std::string army;
      std::string name;
      Wm3::Vec3f position;
      float orientation[3];
    };
    std::vector<moho::MeshInstance*> mUnits;
    std::vector<UnitRef> mUnitRefs;
    void CreateUnits();
    void DeleteUnits();
    /** After an edit or undo of the armies' units: drawn again from the save. */
    void ReloadUnits();
    /** The Units tool's selection (army and unit name), a drag of it and its starts. */
    std::vector<std::pair<std::string, std::string>> mUnitSelection;
    bool mDragUnits = false;
    bool mUnitsMoved = false;
    float mUnitDragFromX = 0.0f;
    float mUnitDragFromZ = 0.0f;
    std::vector<Wm3::Vec3f> mUnitDragStart;
    EdDocument::SaveSnapshot mUnitBefore;
    std::uint32_t mUnitSeed = 0x2545F491u;
    /** The nearest unit to (x, z) within reach of the cursor (an index of mUnitRefs), or -1. */
    [[nodiscard]] int PickUnit(float x, float z) const;
    [[nodiscard]] int UnitRefIndex(const std::string& army, const std::string& name) const;
    /** Changes an army's unit groups in `_save.lua` (read, `change`, written back); false when it can't read them. */
    bool EditArmyUnits(const std::string& army, const std::function<void(UnitGroup&)>& change);
    void PlaceUnits(float x, float z);
    void DeleteSelectedUnits();
    [[nodiscard]] moho::MeshInstance* MakePropInstance(const moho::CWldPropEntry& entry) const;
    /** Deletes and makes again every prop's mesh (after undo). */
    void RebuildProps();
    bool UndoProps(bool redo);
    /** The prop nearest the ground point (x, z) within reach of the cursor, or -1. */
    [[nodiscard]] int PickProp(float x, float z) const;
    /** Props placed at (x, z) and its symmetric copies, with the Props tool's blueprint and turn. */
    /** Places the Props tool's prop at (x, z) with its copies; `yaw` below -100 takes a random turn (or none). */
    void PlaceProps(float x, float z, float yaw = -1000.0f);
    /**
     * The Props tool's Single mode shows the prop to come under the cursor, with its symmetric copies, at the turn
     * the next click places it with (a random turn is drawn before the click, so they match).
     */
    void UpdatePropPreview();
    void DeletePropPreview();
    void RollPropYaw();
    std::vector<moho::MeshInstance*> mPreview;
    std::string mPreviewBlueprint;
    float mNextPropYaw = 0.0f;
    mutable std::string mDetailsFor;
    mutable std::string mDetails;
    /** Props inside the brush at (x, z) and its copies removed. */
    void EraseProps(float x, float z);
    void MovePropTo(int index, const Wm3::Vec3f& position);
    void TurnSelection(float radians);
    void DeleteSelection();
    std::vector<int> mSelection;
    /** A Select-tool drag or a Props-tool stroke in progress: the props before it, for its undo step. */
    bool mObjectStroke = false;
    bool mObjectsChanged = false;
    EdDocument::PropSnapshot mObjectBefore;
    bool mDragSelection = false;
    float mDragFromX = 0.0f;
    float mDragFromZ = 0.0f;
    std::vector<Wm3::Vec3f> mDragStart;
    float mScatterDue = 0.0f;
    std::uint32_t mScatterSeed = 12345U;
    /** A stroke's props painted from the paint list, by blueprint (for the log). */
    std::map<std::string, int> mPaintCounts;
    void BeginObjectStroke();
    void EndObjectStroke();

    /** A terrain stroke in progress: the brush under the cursor each frame while the left button is held. */
    void PaintStroke(float frameSeconds);
    void EndStroke();
    /** Hands written samples back to the height field (its tiers and revision) and redraws their terrain. */
    void RefreshHeights(const std::vector<SampleRect>& rects);
    EdTools* mTools = nullptr;

    /** The symmetry check (EdSymmetryCheck.cpp) on the map's heights, its result to the Tools panel. */
    void RunSymmetryCheck();
    /** Copies the source part to the other copies, as one undo step. */
    void RepairSymmetry();
    /** The blocks of samples the last check found differing, drawn red while the panel shows differences. */
    std::vector<SampleRect> mDifferences;
    HeightBrush mCheckedWith;
    bool mCheckDone = false;
    bool mPainting = false;

    /** The Texture tool: the masks read into the document once, edit mode on (the original editor's). */
    void LoadMasks();
    void PaintMask(float frameSeconds);
    void EndMaskStroke();
    /** Writes texels of `layers` (bit k: stratum k) in the rectangles back into the map's mask textures. */
    void UploadMasks(const std::vector<SampleRect>& rects, unsigned layers);
    void ApplyRules();
    bool mPaintingMask = false;
    /** A terrain type stroke: the grid before it, and the overlay's runs (rebuilt when the grid changes). */
    bool mPaintingTypes = false;
    /** The slope view's runs (rebuilt when the heights change), and the ruler (Alt+drag): its ends, on while held. */
    std::vector<TerrainTypeRun> mSlopeRuns;
    std::uint64_t mSlopeHeights = 0;
    int mSlopeFrames = 0;
    bool mRuling = false;
    /** Box select (Shift + right drag): its corners on the screen while it is drawn. */
    bool mBoxing = false;
    /**
     * The clipboard (Ctrl+C, Ctrl+V at the cursor, Ctrl+D a copy beside): the copied selection of one kind, and the middle
     * of its places, from which a paste offsets each.
     */
    struct Clipboard
    {
      enum class Kind
      {
        None,
        Markers,
        Props,
        Units,
        Decals,
      };
      Kind kind = Kind::None;
      std::vector<SaveEntry> markers;
      std::vector<std::pair<moho::CWldPropEntry, PropRecord>> props;
      std::vector<std::pair<std::string, SaveUnit>> units;
      std::vector<DecalState> decals;
      float centre[2] = {0.0f, 0.0f};
    };
    Clipboard mClipboard;
    /** Copies the active tool's selection; returns how many. */
    std::size_t CopySelection();
    /** Puts the clipboard down with its middle at (x, z), as one undo step, and selects what it put. */
    void PasteAt(float x, float z);
    POINT mBoxFrom{};
    POINT mBoxTo{};
    [[nodiscard]] bool BoxSelectable() const;
    void FinishBoxSelect(bool add);
    bool mRulerShown = false;
    float mRulerFrom[2] = {0.0f, 0.0f};
    float mRulerTo[2] = {0.0f, 0.0f};
    std::vector<std::uint8_t> mTypesBefore;
    std::vector<TerrainTypeRun> mTypeRuns;
    int mTypeRunsRevision = -1;
    void PaintTypes();
    void EndTypeStroke();
    /** Ends a whole-mask change: the undo step, every layer uploaded, the coverage and a check made kept up to date. */
    void WholeMaskChanged(const SampleRect& whole);
    std::vector<std::string> mShaders;
    float mCoverage[8]{};
    bool mCoverageValid = false;
    void UpdateCoverage();
    /** The paint layer's weight as coloured quads over the ground, in blocks of mask texels; rebuilt when stale. */
    std::vector<moho::CD3DPrimBatcher::Vertex> mWeightQuads;
    int mWeightLayer = -1;
    bool mWeightStale = true;
    void BuildWeightQuads(int layer);
    /** The map's terrain shader by name; the engine checks it again when it next draws (byte0, its latch). */
    void SetTerrainShaderName(const std::string& shader);
    std::uint32_t mMaskSteps = 0;
    std::vector<std::uint8_t> mMaskPlane;
    bool UndoHeights(bool redo);
    bool UndoLayers(bool redo);
    bool UndoSaveData(bool redo);
    /** The playable area's border and the darkened ground outside it, rebuilt when the area or the heights change. */
    std::vector<moho::CD3DPrimBatcher::Vertex> mOutsideQuads;
    std::optional<EdDocument::PlayableRect> mOutsideFor;
    bool mOutsideStale = true;
    void BuildOutsideQuads(const EdDocument::PlayableRect& area);
    /** A Markers-tool drag of the border's edges: which edges (bits: left, top, right, bottom), and the area before. */
    int mBorderEdges = 0;
    /** The Markers tool: selected markers by name, a drag of them, and its start positions. */
    std::vector<std::string> mMarkerSelection;
    /** One thing the Select tool can pick: its kind and its index (a prop's, a marker's, a unit ref's, a decal's mIndex). */
    struct PickHit
    {
      PickKind kind = PickKind::None;
      int index = -1;
    };
    /** The marker, unit or prop nearest the cursor on screen, each within its own reach; the decal under it when none is. */
    [[nodiscard]] PickHit PickAnything(POINT at) const;
    /** The border's edges within reach of a ground point: 1 left, 2 top, 4 right, 8 bottom (a corner, two). */
    [[nodiscard]] int BorderEdgesAt(float groundX, float groundZ) const;
    /** The kind the Select tool works on: the last one clicked while it has a selection, else the first that has one. */
    [[nodiscard]] PickKind SelectedKind() const;
    void ClearAllSelections();
    /** Starts moving the selection of a kind: along the gizmo's part, or over the ground from (groundX, groundZ). */
    void BeginSelectionDrag(HWND window, PickKind kind, GizmoPart part, POINT at, float groundX, float groundZ);
    /**
     * A marker where the view shows it: on the ground under its x and z (the file's height can be stale after the
     * terrain changed, and the game places resources and armies on the ground), except a Camera Info, whose height counts.
     */
    bool ShownMarkerPosition(const SaveEntry& marker, float& x, float& y, float& z) const;
    /** Where a pick sits and how big its ring is, for the hover ring. */
    [[nodiscard]] bool PickPlace(const PickHit& hit, float& x, float& z, float& radius) const;
    PickKind mSelectKind = PickKind::None;
    /** The stroke under way was started with the right button: the brush's opposite (Raise/Lower, Paint/Erase). */
    bool mPaintInverted = false;
    float mStrokeStartHeight = 0.0f;
    /** The scenario's water bodies filled over the heights and put on the map, as the game's session does (EdWaterBodyView.cpp). */
    void RefreshWaterBodies();
    void DrawWaterBodyGuides(moho::CD3DPrimBatcher& batcher, const moho::CHeightField& field);
    /** The chosen body's handle under the cursor: an outline point's index, -1 the seed, -2 none. */
    [[nodiscard]] int WaterBodyHandleAt(POINT at) const;
    /** A press with the Water tool: a seed or an outline point placed, or a drag of one started; true when it took it. */
    bool WaterBodyPress(HWND window, POINT at);
    void WaterBodyDrag(POINT at);
    void WaterBodyRelease();
    std::string mWaterBodiesScenario;
    bool mWaterBodiesStale = true;
    int mWaterBodyHandle = -2;
    /** The adaptive tables as last read, for the ties drawn from resources to their armies. */
    std::string mAdaptiveText;
    AdaptiveTables mAdaptive;
    bool mPropsCulled = false;
    bool mUnitsCulled = false;
    bool mDragMarkers = false;
    bool mMarkersMoved = false;
    float mMarkerDragFromX = 0.0f;
    float mMarkerDragFromZ = 0.0f;
    std::vector<std::array<float, 3>> mMarkerDragStart;
    EdDocument::SaveSnapshot mMarkerBefore;
    /** The marker nearest (x, z) within reach of the cursor, or -1. */
    [[nodiscard]] int PickMarker(float x, float z) const;
    /**
     * The move gizmo over the selection (markers with the Markers tool, props with the Select tool): arrows along X,
     * Y (up) and Z, and a square in the middle for a free move over the ground. Dragging an arrow moves along it by
     * the cursor's move projected on the arrow on screen.
     */
    /** The selection's middle, where the gizmo stands; false when nothing it moves is selected. */
    [[nodiscard]] bool GizmoOrigin(Wm3::Vec3f& origin) const;
    /** The arms' length in world units: about the same on screen at any zoom. */
    [[nodiscard]] float GizmoLength() const noexcept { return mDistance * 0.07f; }
    [[nodiscard]] GizmoPart PickGizmo(POINT at) const;
    void DrawGizmo(moho::CD3DPrimBatcher& batcher);
    /** Starts a gizmo drag of `part` from the cursor at `at`. */
    void BeginGizmoDrag(GizmoPart part, POINT at);
    /** The drag's move so far, as a displacement in the world. */
    [[nodiscard]] Wm3::Vec3f GizmoDisplacement(POINT at) const;
    /** Where an object that started at `start` goes for `move`: snapped, on or above the ground. */
    [[nodiscard]] Wm3::Vec3f GizmoPlace(const Wm3::Vec3f& start, const Wm3::Vec3f& move, bool resource, bool unit = false) const;
    /** Where a unit rests at (x, z): the ground, or the sea's surface over it (the game's saves keep ships there). */
    [[nodiscard]] float UnitRestHeight(float x, float z) const;
    GizmoPart mGizmoDrag = GizmoPart::None;
    POINT mGizmoFrom{};
    Wm3::Vec3f mGizmoStart{};
    float mGizmoDragLength = 1.0f;
    float mGizmoGroundX = 0.0f;
    float mGizmoGroundZ = 0.0f;
    /** The middle of the grid cell holding `value` when the toolbar's Snap is on, else `value`. */
    [[nodiscard]] float SnapToGrid(float value) const;
    /** The Decals tool: selected decals by their map index, a drag of them, its starts. */
    std::vector<int> mDecalSelection;
    bool mDragDecals = false;
    bool mDecalsMoved = false;
    float mDecalDragFromX = 0.0f;
    float mDecalDragFromZ = 0.0f;
    std::vector<std::array<float, 3>> mDecalDragStart;
    EdDocument::DecalSnapshot mDecalBefore;
    std::uint32_t mDecalSeed = 0x9E3779B9u;
    std::vector<std::pair<float, float>> mDecalPath;
    int mDecalPathPreview = 0;
    /** The path's copy `c` under the symmetry, or empty when a point of it is off the map. */
    [[nodiscard]] std::vector<std::pair<float, float>> DecalPathCopy(const std::vector<std::pair<float, float>>& path, int c,
                                                                    int& copies) const;
    /** The topmost decal at (x, z) (the last drawn), by its map index, or -1. */
    [[nodiscard]] int PickDecal(float x, float z) const;
    /** Places the Decals tool's texture centred at (x, z), with its symmetric copies, as one undo step. */
    void PlaceDecals(float x, float z);
    void DeleteSelectedDecals();
    /** The selected decals' outlines, the one under the cursor, and in Place mode the decal to come. */
    void DrawDecalOutlines(moho::CD3DPrimBatcher& batcher, const moho::CHeightField& field);
    bool UndoDecals(bool redo);
    bool UndoWater(bool redo);
    bool UndoLighting(bool redo);
    bool UndoSkybox(bool redo);
    bool UndoWaves(bool redo);
    bool UndoTerrainTypes(bool redo);

  public:
    /** The ruler between two points (test runs, `/ruler`). */
    void SetRuler(float x0, float z0, float x1, float z1);
    /** Ctrl+C, Ctrl+V or Ctrl+D (`key` 'C', 'V' or 'D'), as the keyboard gives them and test runs (`/uiclicks ^D`). */
    void CtrlKey(char key);
    /** A Units-tool group ask on `army`'s tree: select a group's units, or change the tree as one undo step. */
    /** An army's settings in `_save.lua`, as one undo step. */
    void ChangeArmySettings(const std::string& army, const ArmySettings& settings);
    void ChangeUnitGroups(const std::string& army, EdTools::GroupAsk ask, const std::vector<std::string>& path, const std::string& name);
    /**
     * Moves `names` of `army` into its WRECKAGE group (wrecks from the start) or, `wreck` false, into its INITIAL group
     * (units from the start), each made when the army has none; one undo step.
     */
    void SetUnitsWreck(const std::string& army, const std::vector<std::string>& names, bool wreck);

  private:
    /** Whether the Markers panel hides this marker's type. */
    [[nodiscard]] bool MarkerHidden(const SaveEntry& marker) const;
    void DeleteSelectedMarkers();
    void DrawMarkers(moho::CD3DPrimBatcher& batcher, bool all);
    /**
     * Mass and hydrocarbon points as the game marks them: its splat textures draped on the ground, drawn from the
     * markers each frame (so they follow a drag). ScenarioUtilities.lua's CreateResources: `mass_marker.dds`
     * 2 x 2, `hydrocarbon_marker.dds` 6 x 6, heading 0.
     */
    void DrawResourceSplats(moho::CD3DPrimBatcher& batcher, const moho::CHeightField& field);
    boost::shared_ptr<moho::CD3DBatchTexture> mMassSplat;
    boost::shared_ptr<moho::CD3DBatchTexture> mHydroSplat;
    bool mSplatsLoaded = false;
    EdDocument::SaveSnapshot mBorderBefore;
    /** A size drag on one slot keeps adding to its undo step until something else happens. */
    bool mLayerDragJoin = false;
    int mLayerBatch = 0;
    /** Sets a texture slot's paths and sizes on the terrain (its textures load), the Info panel's facts too. */
    void SetLayerSlot(int slot, const std::string& albedo, const std::string& normals, float albedoSize, float normalsSize);
    bool UndoMasks(bool redo);
    /** Stamp mode: the click's stamp is down. */
    bool mStamped = false;

    /** Draws the brush rings on the terrain from the renderer's editor hook (`ED_SetHook`). */
    void DrawBrushRings();
    class RingHook;
    std::unique_ptr<RingHook> mRingHook;
    float mFlattenTo = 0.0f;
    POINT mCursor{};

    // Held movement keys (WASD and the arrows), and Shift for speed.
    bool mForward = false;
    bool mBack = false;
    bool mLeft = false;
    bool mRight = false;
    bool mFast = false;

    EdDocument& mDocument;
    moho::CWldMap* mMap = nullptr;
    moho::CameraImpl* mCamera = nullptr;
    std::unique_ptr<moho::SimpleRenderWorldView> mWorldView;

    // The orbit camera: the point it looks at, its heading and pitch (radians) and its distance from it.
    float mTargetX = 0.0f;
    float mTargetY = 0.0f;
    float mTargetZ = 0.0f;
    float mHeading = 3.14159265f;
    float mPitch = 1.0f;
    float mDistance = 500.0f;
    float mMapExtent = 512.0f;
    int mWidth = 0;
    int mHeight = 0;

    enum class Drag
    {
      None,
      Orbit,
      Pan,
    };
    Drag mDrag = Drag::None;
    POINT mDragFrom{};
  };
} // namespace faf::editor
