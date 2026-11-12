#include "editor/ui/EdParticleEditor.h"
#include "editor/ui/EdWorkspaces.h"
#include "editor/ui/EdUiScale.h"

#include "editor/doc/EdMapFile.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/view/EdParticleViewport.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/app/CScApp.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <utility>

namespace faf::editor
{
  namespace
  {
    std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    std::filesystem::path OwnFolder()
    {
      const char* const local = std::getenv("LOCALAPPDATA");
      return local != nullptr ? std::filesystem::path(local) / "FAForever" / "Editor" / "effects"
                              : std::filesystem::path("effects");
    }

    /** The file's name without `.bp` (and the `_emit` the game's files end in, as retail's editor names the id). */
    std::string BaseName(
      const std::string& path
    )
    {
      std::string name = path.substr(path.find_last_of("/\\") + 1);
      if (const std::size_t dot = name.rfind(".bp"); dot != std::string::npos) {
        name = name.substr(0, dot);
      }
      return name;
    }

  } // namespace

  void EdParticleEditor::SetMapFolder(
    const std::filesystem::path& folder,
    const std::string& mapFolderName
  )
  {
    mMapFolder = folder;
    mMapFolderName = mapFolderName;
  }

  std::filesystem::path EdParticleEditor::Folder() const
  {
    return mMapFolder.empty() ? OwnFolder() : mMapFolder / "effects" / "emitters";
  }

  void EdParticleEditor::Changed()
  {
    mDirty = true;
    if (mFlatMode) {
      mPreview.SetFlat(mFlat);
    }
  }

  void EdParticleEditor::OpenOther(
    std::function<void()> open
  )
  {
    SyncGraph(); // the graph's edits counted
    if (!mDirty) {
      open();
      return;
    }
    mPendingOpen = std::move(open);
    mAskUnsaved = true;
  }

  void EdParticleEditor::DrawUnsavedModal()
  {
    if (std::exchange(mAskUnsaved, false)) {
      ImGui::OpenPopup("Unsaved changes");
      gpg::Logf(
        "editor: particle editor: unsaved changes in %s, asked before opening another",
        (mFlatMode ? mName : mEffectName).c_str()
      );
    }
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("Unsaved changes", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      return;
    }
    const std::string name = mFlatMode ? mName : mEffectName;
    ImGui::Text("%s has changes that are not saved.", name.c_str());
    ImGui::TextDisabled("Opening another effect replaces it in the Particle Editor.");
    ImGui::Spacing();
    const auto proceed = [&] {
      if (mPendingOpen) {
        std::exchange(mPendingOpen, nullptr)();
      }
      ImGui::CloseCurrentPopup();
    };
    if (ImGui::Button("Save")) {
      const bool saved = mFlatMode ? Save(mPath.empty() ? Folder() / (mName + ".bp") : mPath) : SaveGraph(mEffectName);
      if (saved) {
        proceed();
      }
    }
    ImGui::SetItemTooltip("Saves it into %s, then opens the other", Folder().string().c_str());
    ImGui::SameLine();
    if (ImGui::Button("Don't save")) {
      mDirty = false;
      proceed();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      mPendingOpen = nullptr;
      ImGui::CloseCurrentPopup();
    }
    if (!mStatus.empty() && mStatus.rfind("Can't", 0) == 0) {
      ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.35f, 1.0f), "%s", mStatus.c_str());
    }
    ImGui::EndPopup();
  }

  void EdParticleEditor::ClearGraph()
  {
    if (mGraph) {
      mGraph->Clear();
      mGraphUndo = {mGraph->Save()};
      mGraphUndoAt = 0;
      mGraphSnap = mGraph->Changes();
      mGraphClean = mGraph->Changes();
      mGraphBuilt = mGraph->Changes();
    }
    mFxEmitters.clear();
    for (const auto& fx : mFx) {
      fx->SetPlaying(false);
    }
    mEffectName = "new_effect";
    mEffectPaths.clear();
    mKeyDrag = -1;
    mKeySelected = -1;
  }

  void EdParticleEditor::NewFlat(
    const char* kind
  )
  {
    ClearGraph();
    // A start as the game's own files have them.
    mFlat = {};
    mFlat.kind = kind;
    FlatValue value;
    const bool beam = std::string(kind) == "BeamBlueprint";
    mName = beam ? "new_beam" : "new_trail";
    value.kind = FlatValue::Kind::Text;
    value.text = mName;
    mFlat.Set("BlueprintId", value);
    const auto number = [&](const char* key, const float n) {
      FlatValue v;
      v.number = n;
      mFlat.Set(key, v);
    };
    const auto text = [&](const char* key, const char* s) {
      FlatValue v;
      v.kind = FlatValue::Kind::Text;
      v.text = s;
      mFlat.Set(key, v);
    };
    if (beam) {
      number("Lifetime", 10.0f);
      text("TextureName", "/textures/particles/beam_white_01.dds");
      number("Length", 30.0f);
      number("Thickness", 1.0f);
      FlatValue color;
      color.kind = FlatValue::Kind::Color;
      color.color = {1.0f, 0.6f, 0.2f, 1.0f};
      mFlat.Set("StartColor", color);
      color.color = {1.0f, 0.2f, 0.1f, 1.0f};
      mFlat.Set("EndColor", color);
    } else {
      number("Lifetime", -1.0f);
      number("TrailLength", 10.0f);
      number("Size", 1.0f);
      number("SortOrder", 0.0f);
      number("BlendMode", 3.0f);
      number("TextureRepeatRate", 0.05f);
      number("LODCutoff", 160.0f);
      text("RepeatTexture", "/textures/particles/air_contrail_01.dds");
      text("RampTexture", "/textures/particles/ramp_white_01.dds");
    }
    mFlatMode = true;
    mPath.clear();
    mDirty = false;
    Changed();
    RestartPreview();
  }

  void EdParticleEditor::Frame(
    const bool showing
  )
  {
    if (!showing) {
      return;
    }
    if (!mPreviewStarted) {
      // The renderer's clock runs between sessions from now on, so the preview's particles age and expire.
      moho::gAppIdleClock = true;
      if (mFlatMode) {
        mPreview.SetFlat(mFlat);
      } else if (!mGraph) {
        SetGraph("new_effect", {{"new_emitter", NewEmitter()}}, "");
      }
      RestartPreview();
      mPreviewStarted = true;
    }
    // It plays far off the map, where only the particle view looks.
    mPreview.SetPlace(mViewport.PlaceX(), EdParticleViewport::kPlaceY + mViewport.Opts().height, mViewport.PlaceZ());
    if (std::exchange(mFrameAsk, false)) {
      mViewport.Reset(mFlatMode ? 20.0f : 12.0f);
    }
    if (mFlatMode) {
      mPreview.SetPlaying(mPlaying);
      mPreview.SetLoop(mLoop);
      mPreview.Frame();
      return;
    }
    SyncGraph();
    for (const auto& fx : mFx) {
      fx->SetPlace(mViewport.PlaceX(), EdParticleViewport::kPlaceY + mViewport.Opts().height, mViewport.PlaceZ());
      fx->SetPlaying(mPlaying);
      fx->SetLoop(mLoop);
      fx->Frame();
    }
  }

  bool EdParticleEditor::OpenGameEmitter(
    const std::string& path
  )
  {
    std::string text;
    if (!ReadGameFile(path, text)) {
      mStatus = "Can't read " + path;
      return false;
    }
    EmitterBlueprint read;
    std::string error;
    if (!ParseEmitter(text, read, error)) {
      FlatBlueprint flat;
      std::string flatError;
      if (!ParseFlatBlueprint(text, flat, flatError)) {
        mStatus = path + ": " + error;
        return false;
      }
      ClearGraph();
      mFlat = std::move(flat);
      mFlatMode = true;
      mGamePath = path;
      mName = BaseName(path);
      mPath.clear();
      mDirty = false;
      mPreview.SetFlat(mFlat);
      RestartPreview();
      mFrameAsk = true;
      mStatus = "Opened " + path;
      return true;
    }
    mGamePath = path;
    mName = BaseName(path);
    mPath.clear(); // the game's own: Save writes a copy into the map's folder
    SetGraph(BaseName(path), {{BaseName(path), read}}, path);
    mStatus = "Opened " + path;
    return true;
  }

  bool EdParticleEditor::Save(
    const std::filesystem::path& file
  )
  {
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
      mStatus = "Can't write " + file.string();
      return false;
    }
    const std::string text = mFlatMode ? WriteFlatBlueprint(mFlat) : WriteEmitter(mEmitter);
    std::string crlf;
    for (const char c : text) {
      crlf += c == '\n' ? std::string("\r\n") : std::string(1, c);
    }
    out << crlf; // the game's own files have Windows line ends
    mPath = file;
    mDirty = false;
    mStatus = "Saved " + file.string();
    if (!mMapFolderName.empty() && file.parent_path() == Folder()) {
      mStatus += "; in the game: /maps/" + mMapFolderName + "/effects/emitters/" + file.filename().string();
    }
    return true;
  }

  void EdParticleEditor::Draw(
    bool& open
  )
  {
    // Opened whole, over most of the editor, and never folded to its title bar (user report: it opened collapsed).
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.85f, viewport->WorkSize.y * 0.8f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
      ImGuiCond_FirstUseEver,
      ImVec2(0.5f, 0.5f)
    );
    ImGui::SetNextWindowCollapsed(false, ImGuiCond_Always);
    if (!ImGui::Begin(Panel("Particle Editor"), &open, ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }
    DrawToolbar();
    if (mFlatMode) {
      // The preview large: about half the window (user ask: the left side bigger, to see the effect well).
      const float previewWidth = std::max(ImGui::GetContentRegionAvail().x * 0.48f, 320.0f);
      if (
        ImGui::BeginTable(
          "##flatlayout2", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail()
        )
      ) {
        ImGui::TableSetupColumn("preview", ImGuiTableColumnFlags_WidthFixed, previewWidth);
        ImGui::TableSetupColumn("keys", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        DrawPreviewPane();
        ImGui::TableSetColumnIndex(1);
        if (ImGui::BeginChild("##flat", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
          DrawFlat();
        }
        ImGui::EndChild();
        ImGui::EndTable();
      }
    } else {
      DrawGraphMode();
    }
    DrawBrowser();
    if (mOpenSave) {
      ImGui::OpenPopup("Save emitter as");
      mOpenSave = false;
    }
    if (ImGui::BeginPopup("Save emitter as")) {
      ImGui::InputText("Name", mSaveName, sizeof(mSaveName));
      ImGui::TextDisabled("Into %s", Folder().string().c_str());
      const std::string name = mSaveName;
      const bool valid = !name.empty() && name.find_first_of("\\/:*?\"<>| ") == std::string::npos;
      ImGui::BeginDisabled(!valid);
      if (ImGui::Button("Save")) {
        if (mFlatMode) {
          mName = name;
          (void)Save(Folder() / (name + ".bp"));
        } else {
          (void)SaveGraph(name);
        }
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndDisabled();
      ImGui::EndPopup();
    }
    DrawUnsavedModal();
    ImGui::End();
  }

  void EdParticleEditor::DrawStage()
  {
    // The controls first, along the top; the view fills the rest.
    ImGui::SetCursorPos(ImVec2(ImGui::GetStyle().WindowPadding.x, ImGui::GetStyle().WindowPadding.y));
    DrawPreviewOptions();
    ImGui::SameLine();
    ImGui::TextDisabled("  %s", mName.empty() ? "no effect" : mName.c_str());
    const float width = std::max(ImGui::GetContentRegionAvail().x, 64.0f);
    const float height = std::max(ImGui::GetContentRegionAvail().y, 64.0f);
    mViewport.SetSize(static_cast<int>(width), static_cast<int>(height));
    mViewport.MarkShown();
    if (const std::uint64_t image = mViewport.Image(); image != 0) {
      ImGui::Image(ImTextureRef(static_cast<ImTextureID>(image)), ImVec2(width, height));
    } else {
      ImGui::Dummy(ImVec2(width, height));
    }
    ImGui::SetItemKeyOwner(ImGuiKey_MouseWheelY);
    if (ImGui::IsItemHovered()) {
      const ImGuiIO& io = ImGui::GetIO();
      if (io.MouseWheel != 0.0f) {
        mViewport.Zoom(io.MouseWheel);
      }
      if (ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f) || ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f)) {
        mViewport.Turn(io.MouseDelta.x, io.MouseDelta.y);
      }
    }
  }

  void EdParticleEditor::DrawPreviewPane()
  {
    // In the Effects workspace the effect plays in the middle of the window instead (DrawStage).
    if (mStaged) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("The effect plays in the middle of the window.");
      ImGui::PopTextWrapPos();
      return;
    }
    // The particle view: the effect alone, in its own 3D view (EdParticleViewport), not the map. A drag turns round it,
    // the wheel comes closer; the options under it pick the ground, grid, background and height.
    const float width = std::max(ImGui::GetContentRegionAvail().x, 64.0f);
    const float height = std::clamp(ImGui::GetContentRegionAvail().y * 0.6f, 64.0f, width);
    mViewport.SetSize(static_cast<int>(width), static_cast<int>(height));
    mViewport.MarkShown();
    if (const std::uint64_t image = mViewport.Image(); image != 0) {
      ImGui::Image(ImTextureRef(static_cast<ImTextureID>(image)), ImVec2(width, height));
    } else {
      ImGui::Dummy(ImVec2(width, height));
    }
    ImGui::SetItemKeyOwner(ImGuiKey_MouseWheelY);
    if (ImGui::IsItemHovered()) {
      const ImGuiIO& io = ImGui::GetIO();
      if (io.MouseWheel != 0.0f) {
        mViewport.Zoom(io.MouseWheel);
      }
      if (ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f) || ImGui::IsMouseDragging(ImGuiMouseButton_Right, 0.0f)) {
        mViewport.Turn(io.MouseDelta.x, io.MouseDelta.y);
      }
      ImGui::SetTooltip("Drag to turn round the effect, the wheel to come closer");
    }
    DrawPreviewOptions();
  }

  void EdParticleEditor::DrawPreviewOptions()
  {
    EdParticleViewport::Options& options = mViewport.Opts();
    // The options as one row that wraps: each control as wide as its text, on the same line while it fits, else on the
    // next (user report: the height slider's text was cut).
    const ImGuiStyle& style = ImGui::GetStyle();
    const float rightEdge = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
    bool first = true;
    const auto flow = [&](const float width) {
      if (!first && ImGui::GetItemRectMax().x + style.ItemSpacing.x + width <= rightEdge) {
        ImGui::SameLine();
      }
      first = false;
    };
    const auto checkboxWidth = [&](const char* label) {
      return ImGui::GetFrameHeight() + style.ItemInnerSpacing.x + ImGui::CalcTextSize(label).x;
    };
    const auto buttonWidth = [&](const char* label) {
      return ImGui::CalcTextSize(label).x + style.FramePadding.x * 2.0f;
    };

    // Playing: pause, start again, loop (in both the Particle Editor and the Browser).
    flow(buttonWidth("Pause"));
    if (ImGui::Button(mPlaying ? "Pause" : "Play")) {
      mPlaying = !mPlaying;
    }
    flow(buttonWidth("Restart"));
    if (ImGui::Button("Restart")) {
      RestartPreview();
    }
    flow(checkboxWidth("Loop"));
    ImGui::Checkbox("Loop", &mLoop);
    ImGui::SetItemTooltip("Starts the effect again each time its Lifetime ends");

    static const char* const kBackgrounds[] = {"Night", "Grey", "Sky", "Black"};
    const float comboWidth =
      ImGui::CalcTextSize("Black").x + style.FramePadding.x * 2.0f + ImGui::GetFrameHeight() + style.ItemInnerSpacing.x;
    flow(comboWidth);
    ImGui::SetNextItemWidth(comboWidth);
    (void)ImGui::Combo("##bg", &options.background, kBackgrounds, 4);
    ImGui::SetItemTooltip("The view's background");
    flow(checkboxWidth("Ground"));
    ImGui::Checkbox("Ground", &options.ground);
    flow(checkboxWidth("Grid"));
    ImGui::Checkbox("Grid", &options.grid);
    ImGui::SetItemTooltip("A line every game unit, stronger every five; the emitter's spot in orange");
    flow(checkboxWidth("Turn"));
    ImGui::Checkbox("Turn", &options.turn);
    ImGui::SetItemTooltip("The camera turns slowly round the effect");
    // As wide as its longest text, and a little for the grab.
    const float sliderWidth =
      ImGui::CalcTextSize("above ground 30.0").x + style.FramePadding.x * 2.0f + ImGui::GetFrameHeight();
    flow(sliderWidth);
    ImGui::SetNextItemWidth(sliderWidth);
    ImGui::SliderFloat("##height", &options.height, 0.0f, 30.0f, "above ground %.1f");
    ImGui::SetItemTooltip("The emitter this high above the ground (most effects play on a unit, some way up)");
    flow(buttonWidth("Front"));
    if (ImGui::Button("Front")) {
      mViewport.Look(3.14159265f, 0.15f);
    }
    flow(buttonWidth("Side"));
    if (ImGui::Button("Side")) {
      mViewport.Look(1.5707963f, 0.15f);
    }
    flow(buttonWidth("Top"));
    if (ImGui::Button("Top")) {
      mViewport.Look(3.14159265f, 1.55f);
    }
    flow(buttonWidth("Reset"));
    if (ImGui::Button("Reset")) {
      mViewport.Reset(mFlatMode ? 20.0f : 12.0f);
    }
  }

  void EdParticleEditor::RestartPreview()
  {
    mViewport.NextSpot();
    mPreview.SetPlace(mViewport.PlaceX(), EdParticleViewport::kPlaceY + mViewport.Opts().height, mViewport.PlaceZ());
    mPreview.Restart();
    for (const auto& fx : mFx) {
      fx->Restart();
    }
  }

  std::string EdParticleEditor::GamePath() const
  {
    // An effect graph: its files as opened (the game's) or as saved into the map's folder, while it is as they are.
    if (!mFlatMode) {
      return mDirty ? std::string() : mEffectPaths;
    }
    // Edited and saved into the map's folder: the map's copy; untouched since opened: the game's own.
    if (!mPath.empty() && !mMapFolderName.empty() && mPath.parent_path() == Folder()) {
      return "/maps/" + mMapFolderName + "/effects/emitters/" + mPath.filename().string();
    }
    return mDirty ? std::string() : mGamePath;
  }

  void EdParticleEditor::NewEffect()
  {
    OpenOther([this] {
      mGamePath.clear();
      SetGraph("new_effect", {{"new_emitter", NewEmitter()}}, "");
    });
  }

  void EdParticleEditor::DrawToolbar()
  {
    if (!ImGui::BeginMenuBar()) {
      return;
    }
    if (ImGui::BeginMenu("File")) {
      if (ImGui::MenuItem("New beam")) {
        OpenOther([this] {
          NewFlat("BeamBlueprint");
        });
      }
      if (ImGui::MenuItem("New trail")) {
        OpenOther([this] {
          NewFlat("TrailEmitterBlueprint");
        });
      }
      if (ImGui::MenuItem("New effect")) {
        NewEffect();
      }
      if (ImGui::MenuItem("Browse the game's effects...")) {
        mOpenBrowserAsk = true;
      }
      if (ImGui::MenuItem("Open a game effect by name...")) {
        mOpenBrowser = true;
      }
      if (ImGui::MenuItem("Save", nullptr, false, true)) {
        if (!mFlatMode) {
          (void)SaveGraph(mEffectName);
        } else if (mPath.empty()) {
          std::snprintf(mSaveName, sizeof(mSaveName), "%s", mName.c_str());
          mOpenSave = true;
        } else {
          (void)Save(mPath);
        }
      }
      if (ImGui::MenuItem("Save as...")) {
        std::snprintf(mSaveName, sizeof(mSaveName), "%s", (mFlatMode ? mName : mEffectName).c_str());
        mOpenSave = true;
      }
      ImGui::EndMenu();
    }
    ImGui::Separator();
    ImGui::Text("%s%s", (mFlatMode ? mName : mEffectName).c_str(), mDirty ? " *" : "");
    ImGui::Separator();
    {
      const std::string place = GamePath();
      ImGui::BeginDisabled(place.empty());
      if (ImGui::Button("Place on the map")) {
        mPlaceAsk = place;
      }
      ImGui::EndDisabled();
      ImGui::SetItemTooltip(
        "%s",
        place.empty()
          ? "Save the effect into the map's folder first (or open a game effect): the map plays it by its path"
          : "An effect decoration at the middle of the map's view: an Effect marker the map's script plays the effect "
            "at"
      );
    }
    ImGui::SetItemTooltip("Starts the emitter again each time its Lifetime ends");
    {
      float age = mPreview.Age();
      unsigned long long emitted = mPreview.Emitted();
      if (!mFlatMode && !mFx.empty()) {
        age = mFx.front()->Age();
        emitted = 0;
        for (const auto& fx : mFx) {
          emitted += fx->Emitted();
        }
      }
      ImGui::TextDisabled("age %.0f ticks, %llu particles", static_cast<double>(age), emitted);
    }
    ImGui::SetItemTooltip("The preview emits at the centre of the map's view (10 ticks a second)");
    if (!mStatus.empty()) {
      ImGui::TextDisabled("%s", mStatus.c_str());
    }
    ImGui::EndMenuBar();
  }

  void EdParticleEditor::DrawFlat()
  {
    const bool beam = mFlat.kind == "BeamBlueprint";
    ImGui::SeparatorText(beam ? "Beam" : "Trail");
    ImGui::TextWrapped(
      "%s",
      beam ? "A beam is a textured strip between two points: weapons' beams, tractor and shield beams. The preview "
             "draws it from "
             "the view's centre, rising, for its Lifetime and again."
           : "A trail is a ribbon left behind a moving point: missiles' and aircraft's trails. The preview moves its "
             "emitter "
             "round the view's centre, a turn every 4 seconds."
    );
    ImGui::Spacing();
    bool changed = false;
    for (const FlatField& field : FlatFields(mFlat.kind)) {
      const FlatValue* present = mFlat.Find(field.key);
      FlatValue value;
      value.kind = field.kind;
      value.number = field.initial;
      value.flag = field.initial != 0.0f;
      value.color = field.initialColor;
      if (present != nullptr) {
        value = *present;
      }
      bool edited = false;
      ImGui::PushID(field.key);
      ImGui::SetNextItemWidth(Em(260.0f));
      switch (field.kind) {
      case FlatValue::Kind::Number:
        edited = ImGui::DragFloat(field.key, &value.number, 0.01f, 0.0f, 0.0f, "%.4g");
        break;
      case FlatValue::Kind::Bool:
        edited = ImGui::Checkbox(field.key, &value.flag);
        break;
      case FlatValue::Kind::Color:
        edited =
          ImGui::ColorEdit4(field.key, value.color.data(), ImGuiColorEditFlags_Float | ImGuiColorEditFlags_AlphaBar);
        break;
      case FlatValue::Kind::Text:
        if (field.texture) {
          ImGui::TextDisabled("%s", field.key);
          ImGui::PushItemWidth(260.0f);
          edited = mTexturePicker.Field(field.key, value.text, mParticleTextures, mLibrary, true);
          ImGui::PopItemWidth();
        } else {
          char buffer[160];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", value.text.c_str());
          if (ImGui::InputText(field.key, buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
            value.text = buffer;
            edited = true;
          }
        }
        break;
      case FlatValue::Kind::Raw:
        break;
      }
      ImGui::SetItemTooltip("%s", field.help);
      if (present == nullptr) {
        ImGui::SameLine();
        ImGui::TextDisabled("(not in the file: the engine's default)");
      }
      ImGui::PopID();
      if (edited) {
        value.kind = field.kind;
        mFlat.Set(field.key, value);
        changed = true;
      }
    }
    // Keys the editor doesn't know, as the file has them.
    for (const auto& [key, value] : mFlat.fields) {
      bool known = false;
      for (const FlatField& field : FlatFields(mFlat.kind)) {
        known = known || key == field.key;
      }
      if (!known) {
        ImGui::TextDisabled(
          "%s = %s (kept as written)",
          key.c_str(),
          value.kind == FlatValue::Kind::Number ? std::to_string(value.number).c_str() : value.text.c_str()
        );
      }
    }
    if (mParticleTextures.empty()) {
      if (moho::CVirtualFileSystem* vfs = moho::DISK_GetVFS(); vfs != nullptr) {
        fa::vector<fa::string> found;
        vfs->EnumerateFiles("/textures/particles", "*.dds", true, &found);
        for (const fa::string& file : found) {
          mParticleTextures.push_back(file.c_str());
        }
        std::sort(mParticleTextures.begin(), mParticleTextures.end());
      }
    }
    if (changed) {
      Changed();
    }
  }

  void EdParticleEditor::DrawBrowser()
  {
    if (mOpenBrowser) {
      ImGui::OpenPopup("Open a game effect");
      mOpenBrowser = false;
      if (!mListed) {
        mListed = true;
        if (moho::CVirtualFileSystem* vfs = moho::DISK_GetVFS(); vfs != nullptr) {
          fa::vector<fa::string> found;
          vfs->EnumerateFiles("/effects", "*.bp", true, &found);
          for (const fa::string& file : found) {
            mGameEmitters.push_back(file.c_str());
          }
          std::sort(mGameEmitters.begin(), mGameEmitters.end());
        }
      }
    }
    ImGui::SetNextWindowSize(ImVec2(Em(520.0f), Em(480.0f)), ImGuiCond_Appearing);
    if (!ImGui::BeginPopup("Open a game effect")) {
      return;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint(
      "##filter", "Search the game's effects (e.g. muzzle, smoke, beam, trail)", mBrowserFilter, sizeof(mBrowserFilter)
    );
    const std::string filter = Lower(mBrowserFilter);
    if (ImGui::BeginChild("##list", ImVec2(0.0f, 0.0f))) {
      int shown = 0;
      for (const std::string& path : mGameEmitters) {
        if (!filter.empty() && Lower(path).find(filter) == std::string::npos) {
          continue;
        }
        if (++shown > 400) {
          ImGui::TextDisabled("... more: search to narrow");
          break;
        }
        if (ImGui::Selectable(path.c_str())) {
          OpenOther([this, path] {
            (void)OpenGameEmitter(path);
          });
          ImGui::CloseCurrentPopup();
        }
      }
      ImGui::TextDisabled("%zu files", mGameEmitters.size());
    }
    ImGui::EndChild();
    ImGui::EndPopup();
  }
} // namespace faf::editor
