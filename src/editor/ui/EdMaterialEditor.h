#pragma once

#include "editor/graph/EdTextureGraph.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/ui/EdNodeCanvas.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The material editor (View > Material Editor), laid out as UE4's: a tab per open graph, a toolbar, a lit preview,
   * the selected node's Details, the node graph, Stats, and the node palette. A graph makes a terrain stratum's
   * textures (albedo, normal, mask) on the CPU (EdTextureGraph); every change shows at once in the nodes' thumbnails
   * and the preview. Graphs are files (`<name>.fafgraph.json`) in the open map's `editor` folder, or in the editor's
   * own folder without a map.
   */
  class EdMaterialEditor
  {
  public:
    EdMaterialEditor();
    ~EdMaterialEditor();
    EdMaterialEditor(const EdMaterialEditor&) = delete;
    EdMaterialEditor& operator=(const EdMaterialEditor&) = delete;

    void Draw(bool& open);

    /** The open map's folder when graphs may go beside it (a vault map), else empty: the editor's own folder. */
    void SetMapFolder(const std::filesystem::path& folder);
    /**
     * The open map's ten texture slots as the target list shows them (lower, strata 1-8, upper); empty without a map,
     * which turns Live Update and Apply off.
     */
    void SetSlotNames(std::vector<std::string> names);

    /** The live result for the map's terrain: in-memory DDS files for a slot (Live Update). */
    struct LiveImage
    {
      int slot = -1;
      std::vector<std::uint8_t> albedo;
      std::vector<std::uint8_t> normals;
    };
    [[nodiscard]] bool TakeLive(LiveImage& out);
    /** A slot the live result left: its own files go back. */
    [[nodiscard]] bool TakeRestore(int& slot);

    /** Apply: the graph baked at the bake size, for the app to write into the map's folder and set into the slot. */
    struct Bake
    {
      int slot = -1;
      std::string name;
      std::vector<std::uint8_t> albedo;  // BC3
      std::vector<std::uint8_t> normals; // BC1, empty for the upper slot or an unlinked Normal
      TexImagePtr mask;                  // the Mask output over the whole map, null when unlinked
    };
    [[nodiscard]] bool TakeApply(Bake& out);
    /** Test runs (`/materiallive <slot>`, `/materialapply <slot>`): Live Update into the slot on, or Apply into it. */
    void TestLive(const int slot)
    {
      mTargetSlot = slot;
      mLive = true;
    }
    void TestApply(const int slot) { mApplyAsk = slot; }
    /** What the app made of an Apply (shown in the toolbar). */
    void SetStatus(std::string status) { mStatus = std::move(status); }

    /** Gives the map nodes the open map's heights (asked when a graph needs them and on Refresh). */
    void SetTerrainSource(std::function<std::shared_ptr<TerrainSource>()> source) { mTerrainSource = std::move(source); }

    /** The window or one of its parts has the keyboard (the app's Ctrl+S / Ctrl+Z leave it alone). */
    [[nodiscard]] bool Focused() const noexcept { return mFocused; }

    /** Opens on a layer slot: a new graph if none is open, the slot as the target, Live Update on, the window in front. */
    void OpenForSlot(int slot);

    /** For test runs (`/materialeditor`): opens a new graph. */
    void NewGraph();
    /** Opens a graph file in a new tab (test runs: `/materialopen <file>`); false when it can't be read. */
    bool OpenFile(const std::filesystem::path& file) { return Open(file); }
    /** Selects the active graph's first node of the type (test runs: `/materialselect <type>`). */
    void SelectFirst(const std::string& type);
    /** The active graph's node count, 0 without one (test runs). */
    [[nodiscard]] std::size_t NodeCount() const;

  private:
    struct Thumb
    {
      std::uint64_t revision = 0;
      int size = 0;
      std::uint64_t image = 0;
    };

    struct Doc
    {
      std::string name;
      std::filesystem::path path;
      std::unique_ptr<NodeGraph> graph;
      std::unique_ptr<TextureGraphEvaluator> eval;
      EdNodeCanvas canvas;
      std::vector<std::string> undo;
      std::size_t undoAt = 0;
      std::uint64_t snapChanges = 0;
      std::uint64_t savedChanges = 0;
      std::map<int, Thumb> thumbs;
      bool usesTerrain = false;
      double lastMillis = 0.0;
      int lastComputed = 0;
    };

    Doc& Make(const std::string& name);
    void DrawToolbar();
    void DrawPreview(Doc& doc, float size);
    void DrawDetails(Doc& doc);
    void DrawStats(Doc& doc);
    void DrawPalette(Doc& doc);
    void DrawOpenPopup();
    void DrawSaveAsPopup();
    void Evaluate(Doc& doc);
    void UpdateThumbnails(Doc& doc);
    void Snapshot(Doc& doc);
    void Undo(Doc& doc, bool redo);
    bool Save(Doc& doc);
    bool Open(const std::filesystem::path& file);
    [[nodiscard]] std::filesystem::path Folder() const;
    [[nodiscard]] Doc* Active();
    [[nodiscard]] const Doc* Active() const;

    std::vector<std::unique_ptr<Doc>> mDocs;
    int mActive = -1;
    int mSelectTab = -1;
    std::filesystem::path mMapFolder;
    std::function<std::shared_ptr<TerrainSource>()> mTerrainSource;
    std::shared_ptr<TerrainSource> mTerrain;
    EdTextureLibrary mLibrary;

    // The preview: what it shows, its turn, and its image.
    int mPreviewMode = 0; // sphere, plane (2 x 2), albedo, normal, mask
    float mPreviewYaw = 0.6f;
    float mLightYaw = -0.7f;
    int mPreviewSize = 256;
    std::uint64_t mPreviewImage = 0;
    bool mPreviewStale = true;
    const Doc* mPreviewDoc = nullptr;

    char mPaletteFilter[64] = {};
    char mSaveAsName[64] = {};
    bool mOpenOpen = false;
    bool mOpenSaveAs = false;
    std::string mStatus;
    bool mFocused = false;

    // Live Update and Apply.
    void UpdateLive(Doc& doc);
    void StopLive();
    void ApplyBake(Doc& doc);
    std::vector<std::string> mSlotNames;
    int mTargetSlot = 1;
    bool mLive = false;
    int mLiveSlot = -1;
    bool mLiveStale = true;
    double mLiveSentAt = 0.0;
    int mBakeSize = 1024;
    LiveImage mLiveOut;
    bool mLiveReady = false;
    std::vector<int> mRestore;
    Bake mBakeOut;
    bool mBakeReady = false;
    int mApplyAsk = -1;
    bool mBringToFront = false;
  };

  /** A lit preview of a stratum's albedo and normal maps: `mode` 0 a sphere, 1 a 2 x 2 plane; BGRA rows. */
  std::vector<std::uint32_t> RenderMaterialPreview(const TexImage* albedo, const TexImage* normal, int mode, int size, float yaw, float lightYaw);
} // namespace faf::editor
