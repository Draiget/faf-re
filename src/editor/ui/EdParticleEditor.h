#pragma once

#include "editor/doc/EdEmitter.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/view/EdParticlePreview.h"

#include <filesystem>
#include <utility>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The particle editor (View > Particle Editor), laid out as UE4's Cascade: the emitter's curves as a module stack
   * grouped as retail's emitter editor groups them (Direction, Rate, Lifetime; Forces; Spacial; Size and Rotation;
   * Animation and Selection), the selected curve's graph (keys dragged, added with a double-click, removed with a right
   * click; the random spread drawn as a band), and Details (lifetime, repeat, blend mode, frames, switches, textures).
   * It edits the game's emitter blueprints: any of the game's own opens as a start, and the result is saved as a .bp in
   * the map's `effects` folder (a vault map), else in the editor's own folder. The preview emits live at the view's
   * centre on the map (EdParticlePreview).
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

    /** Where a vault map keeps its effects (`<map>`), empty without one: the editor's own folder then. */
    void SetMapFolder(const std::filesystem::path& folder, const std::string& mapFolderName);
    /** The point the preview emits at (the view's centre on the ground). */
    void SetPlace(float x, float y, float z) { mPreview.SetPlace(x, y, z); }
    /** Emits the preview's particles for this frame (also while the window is closed: false stops it). */
    void Frame(bool showing);

    /** The 3D view's width over its height, for the Preview pane's square crop of it. */
    void SetViewAspect(const float aspect) noexcept { mViewAspect = aspect > 0.1f ? aspect : 1.0f; }
    /** The camera should come close to the effect (it opened, or Frame was pressed); taken once. */
    [[nodiscard]] bool TakeFrameAsk() noexcept { return std::exchange(mFrameAsk, false); }
    /** Test runs (`/particlebrowser <search>`): the browser's search set, its first match played. */
    void TestBrowse(const std::string& search);
    /** Test runs (`/particlenew beam|trail`): a new beam or trail. */
    void TestNew(const std::string& kind) { NewFlat(kind == "beam" ? "BeamBlueprint" : "TrailEmitterBlueprint"); }
    /** Test runs (`/particleopen <game path>`): opens a game emitter. */
    bool OpenGameEmitter(const std::string& path);

  private:
    void DrawToolbar();
    void DrawModules();
    void DrawCurve();
    void DrawDetails();
    /** A beam's or trail's keys (they have no curves). */
    void DrawFlat();
    void NewFlat(const char* kind);
    void DrawBrowser();
    void Changed();
    bool Save(const std::filesystem::path& file);
    [[nodiscard]] std::filesystem::path Folder() const;

    EmitterBlueprint mEmitter = NewEmitter();
    /** A beam or trail is open instead of an emitter. */
    bool mFlatMode = false;
    FlatBlueprint mFlat;
    std::string mName = "new_emitter";
    std::filesystem::path mPath;
    bool mDirty = false;
    int mCurve = kEmitRate;
    int mDragKey = -1;
    int mSelectedKey = -1;
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
    float mViewAspect = 1.6f;
    float mPreviewZoom = 0.22f; // half the crop's height, as a share of the view's
    bool mFrameAsk = true;

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
    EdTextureLibrary mLibrary;
  };
} // namespace faf::editor
