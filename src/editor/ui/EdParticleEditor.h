#pragma once

#include "editor/doc/EdEmitter.h"
#include "editor/graph/EdEffectGraph.h"
#include "editor/ui/EdNodeCanvas.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/view/EdParticlePreview.h"
#include "editor/view/EdParticleViewport.h"

#include <filesystem>
#include <memory>
#include <utility>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The particle editor (View > Particle Editor), a node graph as the material editor is (user ask 2026-11-11): an
   * effect's emitters as Emitter nodes fed by curve and texture nodes (ui/EdParticleGraph.cpp, graph/EdEffectGraph),
   * Details for the selected node (a Curve's keys on a graph), a palette; any game emitter or FAF effect template opens
   * as a graph, Save writes each emitter's .bp and the graph into the map's `effects/emitters` folder (a vault map),
   * else the editor's own folder. Beams and trails open as their keys. Every emitter plays in the particle view.
   */
  class EdParticleEditor
  {
  public:
    void Draw(bool& open);
    /** The Particle Browser (View > Particle Browser): every game effect in a grid; a click plays it in the preview. */
    void DrawBrowserWindow(bool& open);
    /** The browser asked to show the Particle Editor (Edit in the Particle Editor, File > Browse in it the other way). */
    [[nodiscard]] bool TakeOpenEditorAsk() noexcept { return std::exchange(mOpenEditorAsk, false); }
    [[nodiscard]] bool TakeOpenBrowserAsk() noexcept { return std::exchange(mOpenBrowserAsk, false); }
    /** "Place on the map": the effect's game path for a decoration at the view's centre; taken once. */
    [[nodiscard]] bool TakePlaceAsk(std::string& path)
    {
      if (mPlaceAsk.empty()) {
        return false;
      }
      path = std::exchange(mPlaceAsk, std::string());
      return true;
    }
    /** The open effect's path in the game's files: a game effect's own, or the map's copy once saved there; else empty. */
    [[nodiscard]] std::string GamePath() const;

    /** Where a vault map keeps its effects (`<map>`), empty without one: the editor's own folder then. */
    void SetMapFolder(const std::filesystem::path& folder, const std::string& mapFolderName);
    /** The particle view (its own 3D view of the effect alone), rendered by the app at the start of each frame. */
    [[nodiscard]] EdParticleViewport& Viewport() noexcept { return mViewport; }
    /** Emits the preview's particles for this frame (also while the window is closed: false stops it). */
    void Frame(bool showing);

    /** Test runs (`/particlebrowser <search>`): the browser's search set, its first match played. */
    void TestBrowse(const std::string& search);
    /** Test runs (`/particlenew beam|trail`): a new beam or trail. */
    void TestNew(const std::string& kind) { NewFlat(kind == "beam" ? "BeamBlueprint" : "TrailEmitterBlueprint"); }
    /** Test runs (`/particleopen <game path>`): opens a game emitter. */
    bool OpenGameEmitter(const std::string& path);
    /** Opens one of FAF's effect templates (its emitters played together) as a graph. */
    bool OpenTemplate(const EffectTemplate& effect);
    /** Test runs (`/particletemplate <name>`): opens that template. */
    bool TestTemplate(const std::string& name);

  private:
    void DrawToolbar();
    /** A beam's or trail's keys (they have no curves). */
    void DrawFlat();
    void NewFlat(const char* kind);
    void DrawBrowser();
    void Changed();
    /** Plays the effect from its start at the view's next spot, leaving the last particles out of sight. */
    void RestartPreview();
    bool Save(const std::filesystem::path& file);
    [[nodiscard]] std::filesystem::path Folder() const;

    EmitterBlueprint mEmitter = NewEmitter();
    /** A beam or trail is open instead of an emitter. */
    bool mFlatMode = false;
    FlatBlueprint mFlat;
    std::string mName = "new_emitter";
    std::filesystem::path mPath;
    bool mDirty = false;
    bool mPlaying = true;
    bool mLoop = true;
    std::filesystem::path mMapFolder;
    std::string mMapFolderName;
    std::string mStatus;
    EdParticlePreview mPreview;
    bool mPreviewStarted = false;

    // The game's emitters, for the browser.
    std::vector<std::string> mGameEmitters;
    bool mListed = false;
    bool mOpenBrowser = false;
    char mBrowserFilter[96] = {};
    std::vector<std::string> mParticleTextures;
    char mSaveName[96] = {};
    bool mOpenSave = false;
    /** The Preview pane: the middle of the 3D view, where the effect plays, magnified. */
    void DrawPreviewPane();
    EdParticleViewport mViewport;
    /** The view comes to the effect's size when one opens. */
    bool mFrameAsk = true;

    // The node graph (ui/EdParticleGraph.cpp): the effect's emitters as nodes, a preview per emitter.
    void SetGraph(const std::string& effectName, const std::vector<std::pair<std::string, EmitterBlueprint>>& emitters, const std::string& gamePaths);
    /** The emitters again from the graph when it changed (the previews follow). */
    void SyncGraph();
    void DrawGraphMode();
    void DrawNodeDetails();
    void DrawGraphPalette();
    /** A curve's keys edited on a graph (drag, double-click adds, right-click removes); true when they changed. */
    bool DrawCurveKeys(std::vector<EmitterKey>& keys, float& range, const EmitterCurveInfo* info);
    void GraphSnapshot();
    void GraphUndo(bool redo);
    bool SaveGraph(const std::string& effectName);
    void ListTemplates();
    std::unique_ptr<NodeGraph> mGraph;
    EdNodeCanvas mCanvas;
    std::string mEffectName = "new_effect";
    std::uint64_t mGraphBuilt = ~std::uint64_t{0};
    std::uint64_t mGraphClean = 0; // the graph's changes when opened or saved
    std::vector<std::pair<std::string, EmitterBlueprint>> mFxEmitters;
    std::vector<std::unique_ptr<EdParticlePreview>> mFx;
    std::vector<std::string> mGraphUndo;
    std::size_t mGraphUndoAt = 0;
    std::uint64_t mGraphSnap = 0;
    /** The open effect's paths in the game's files (';' between), as opened or as saved; empty for a new one. */
    std::string mEffectPaths;
    int mKeyDrag = -1;
    int mKeySelected = -1;
    char mPaletteFilter[64] = {};
    std::vector<EffectTemplate> mTemplates;
    bool mTemplatesListed = false;
    bool mBrowseTemplates = false;

    // The Particle Browser (ui/EdParticleBrowser.cpp).
    struct EffectInfo
    {
      std::string path;
      std::string name;
      int faction = 0;
      int kind = 0;
      bool read = false;
      int type = 0; // 1 emitter, 2 beam, 3 trail (0 until read)
      std::string texture;
      std::string ramp;
      int blendMode = 0;
    };
    void ListEffects();
    void ReadEffect(EffectInfo& info);
    std::vector<EffectInfo> mEffects;
    bool mEffectsListed = false;
    int mBrowseFaction = 0;
    int mBrowseKind = 0;
    int mBrowseType = 0;
    char mGridFilter[96] = {};
    std::string mBrowserPick;
    bool mOpenEditorAsk = false;
    bool mOpenBrowserAsk = false;
    std::string mPlaceAsk;
    /** The game effect last opened (its own path), empty for a new one. */
    std::string mGamePath;
    EdTextureLibrary mLibrary;
  };
} // namespace faf::editor
