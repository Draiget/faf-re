#include "editor/ui/EdParticleEditor.h"

#include "editor/doc/EdMapFile.h"
#include "editor/ui/EdImGuiRenderer.h"
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
    std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    }

    std::filesystem::path OwnFolder()
    {
      const char* const local = std::getenv("LOCALAPPDATA");
      return local != nullptr ? std::filesystem::path(local) / "FAForever" / "Editor" / "effects" : std::filesystem::path("effects");
    }

    /** The file's name without `.bp` (and the `_emit` the game's files end in, as retail's editor names the id). */
    std::string BaseName(const std::string& path)
    {
      std::string name = path.substr(path.find_last_of("/\\") + 1);
      if (const std::size_t dot = name.rfind(".bp"); dot != std::string::npos) {
        name = name.substr(0, dot);
      }
      return name;
    }

    const char* const kFlagHelp[kEmitterFlagCount] = {
      "Directions are in the emitter's own frame (its bone's), not the world's",
      "Accelerations are in the emitter's own frame",
      "Particles fall (0.02 units a tick squared)",
      "Particles face along their direction of travel",
      "Particles take the bone's direction",
      "Particles lie flat on the ground instead of facing the camera",
      "Emits only while a player can see the emitter",
      "Catches up with the ticks a hidden emitter missed",
      "Created only when visible",
      "Particles start at the water's surface",
      "Emits only over water",
      "Particles slow down with air drag (the Resistance curve)",
      "Spreads a tick's particles along the path the emitter moved",
    };
  } // namespace

  void EdParticleEditor::SetMapFolder(const std::filesystem::path& folder, const std::string& mapFolderName)
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
    } else {
      mPreview.SetEmitter(mEmitter);
    }
  }

  void EdParticleEditor::NewFlat(const char* kind)
  {
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
    mPreview.Restart();
  }

  void EdParticleEditor::Frame(const bool showing)
  {
    if (!showing) {
      return;
    }
    if (!mPreviewStarted) {
      // The renderer's clock runs between sessions from now on, so the preview's particles age and expire.
      moho::gAppIdleClock = true;
      if (mFlatMode) {
        mPreview.SetFlat(mFlat);
      } else {
        mPreview.SetEmitter(mEmitter);
      }
      mPreview.Restart();
      mPreviewStarted = true;
    }
    mPreview.SetPlaying(mPlaying);
    mPreview.SetLoop(mLoop);
    mPreview.Frame();
  }

  bool EdParticleEditor::OpenGameEmitter(const std::string& path)
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
      mFlat = std::move(flat);
      mFlatMode = true;
      mName = BaseName(path);
      mPath.clear();
      mDirty = false;
      mPreview.SetFlat(mFlat);
      mPreview.Restart();
      mFrameAsk = true;
      mStatus = "Opened " + path;
      return true;
    }
    mFlatMode = false;
    mEmitter = std::move(read);
    mName = BaseName(path);
    mPath.clear(); // the game's own: Save asks for a name in the map's folder
    mDirty = false;
    mCurve = kEmitRate;
    mSelectedKey = -1;
    mPreview.SetEmitter(mEmitter);
    mPreview.Restart();
    mFrameAsk = true;
    mStatus = "Opened " + path;
    return true;
  }

  bool EdParticleEditor::Save(const std::filesystem::path& file)
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

  void EdParticleEditor::Draw(bool& open)
  {
    // Opened whole, over most of the editor, and never folded to its title bar (user report: it opened collapsed).
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.85f, viewport->WorkSize.y * 0.8f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
                            ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowCollapsed(false, ImGuiCond_Always);
    if (!ImGui::Begin("Particle Editor", &open, ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }
    DrawToolbar();
    if (mFlatMode) {
      // The preview large: about half the window (user ask: the left side bigger, to see the effect well).
      const float previewWidth = std::max(ImGui::GetContentRegionAvail().x * 0.48f, 320.0f);
      if (ImGui::BeginTable("##flatlayout2", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail())) {
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
    } else if (const float previewWidth = std::max(ImGui::GetContentRegionAvail().x * 0.4f, 320.0f);
               ImGui::BeginTable("##layout2", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail())) {
      // The preview large: about two fifths of the window (user ask: the left side bigger, to see the effect well).
      ImGui::TableSetupColumn("modules", ImGuiTableColumnFlags_WidthFixed, previewWidth);
      ImGui::TableSetupColumn("curve", ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn("details", ImGuiTableColumnFlags_WidthFixed, 320.0f);
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      // Cascade's corner: the preview over the module stack.
      DrawPreviewPane();
      if (ImGui::BeginChild("##modules", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawModules();
      }
      ImGui::EndChild();
      ImGui::TableSetColumnIndex(1);
      if (ImGui::BeginChild("##curve", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        DrawCurve();
      }
      ImGui::EndChild();
      ImGui::TableSetColumnIndex(2);
      if (ImGui::BeginChild("##details", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawDetails();
      }
      ImGui::EndChild();
      ImGui::EndTable();
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
        mName = name;
        (void)Save(Folder() / (name + ".bp"));
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndDisabled();
      ImGui::EndPopup();
    }
    ImGui::End();
  }

  void EdParticleEditor::DrawPreviewPane()
  {
    // The effect plays at the 3D view's centre (the camera's target): the pane shows a square around it, magnified,
    // from the view's own picture, so it plays here even where this window covers the view. The wheel zooms the crop;
    // Frame brings the camera close.
    // As wide as the column; at most three fifths of its height (the curve list stays under it). The crop has the pane's shape.
    const float width = std::max(ImGui::GetContentRegionAvail().x, 64.0f);
    const float height = std::clamp(ImGui::GetContentRegionAvail().y * 0.6f, 64.0f, width);
    const float halfV = std::clamp(mPreviewZoom, 0.03f, 0.5f);
    const float halfU = std::min(halfV * (width / height) / mViewAspect, 0.5f);
    const ImVec2 uv0(0.5f - halfU, 0.5f - halfV);
    const ImVec2 uv1(0.5f + halfU, 0.5f + halfV);
    ImGui::Image(ImTextureRef(static_cast<ImTextureID>(EdImGuiRenderer::kGameViewImage)), ImVec2(width, height), uv0, uv1);
    if (ImGui::IsItemHovered()) {
      const float wheel = ImGui::GetIO().MouseWheel;
      if (wheel != 0.0f) {
        mPreviewZoom = std::clamp(mPreviewZoom * (wheel > 0.0f ? 0.85f : 1.0f / 0.85f), 0.03f, 0.5f);
      }
      ImGui::SetTooltip("The effect, playing at the middle of the map's view. The wheel zooms; Frame brings the camera close.");
    }
    if (ImGui::Button("Frame")) {
      mFrameAsk = true;
    }
    ImGui::SetItemTooltip("Brings the map's camera close to the effect");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    float zoom = 1.0f / mPreviewZoom;
    if (ImGui::SliderFloat("##zoom", &zoom, 2.0f, 30.0f, "zoom %.1fx")) {
      mPreviewZoom = 1.0f / zoom;
    }
  }

  void EdParticleEditor::DrawToolbar()
  {
    if (!ImGui::BeginMenuBar()) {
      return;
    }
    if (ImGui::BeginMenu("File")) {
      if (ImGui::MenuItem("New beam")) {
        NewFlat("BeamBlueprint");
      }
      if (ImGui::MenuItem("New trail")) {
        NewFlat("TrailEmitterBlueprint");
      }
      if (ImGui::MenuItem("New emitter")) {
        mFlatMode = false;
        mEmitter = NewEmitter();
        mName = "new_emitter";
        mPath.clear();
        mDirty = false;
        Changed();
        mPreview.Restart();
      }
      if (ImGui::MenuItem("Open a game effect (emitter, beam, trail)...")) {
        mOpenBrowser = true;
      }
      if (ImGui::MenuItem("Save", nullptr, false, true)) {
        if (mPath.empty()) {
          std::snprintf(mSaveName, sizeof(mSaveName), "%s", mName.c_str());
          mOpenSave = true;
        } else {
          (void)Save(mPath);
        }
      }
      if (ImGui::MenuItem("Save as...")) {
        std::snprintf(mSaveName, sizeof(mSaveName), "%s", mName.c_str());
        mOpenSave = true;
      }
      ImGui::EndMenu();
    }
    ImGui::Separator();
    ImGui::Text("%s%s", mName.c_str(), mDirty ? " *" : "");
    ImGui::Separator();
    if (ImGui::Button(mPlaying ? "Pause" : "Play")) {
      mPlaying = !mPlaying;
    }
    if (ImGui::Button("Restart")) {
      mPreview.Restart();
    }
    ImGui::Checkbox("Loop", &mLoop);
    ImGui::SetItemTooltip("Starts the emitter again each time its Lifetime ends");
    ImGui::TextDisabled("age %.0f ticks, %llu particles", static_cast<double>(mPreview.Age()), static_cast<unsigned long long>(mPreview.Emitted()));
    ImGui::SetItemTooltip("The preview emits at the centre of the map's view (10 ticks a second)");
    if (!mStatus.empty()) {
      ImGui::TextDisabled("%s", mStatus.c_str());
    }
    ImGui::EndMenuBar();
  }

  void EdParticleEditor::DrawModules()
  {
    ImGui::SeparatorText("Emitter");
    ImGui::TextDisabled("%s", mEmitter.blueprintId.c_str());
    // The curves as modules, in retail's groups.
    bool open = true;
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      const EmitterCurveInfo& info = CurveInfo(c);
      if (info.group[0] != '\0') {
        ImGui::SetNextItemOpen(true, ImGuiCond_Once);
        open = ImGui::CollapsingHeader(info.group);
      }
      if (!open) {
        continue;
      }
      const EmitterCurve& curve = mEmitter.curves[static_cast<std::size_t>(c)];
      // A curve that varies (more than one key, or a spread) is marked, as Cascade marks a module with a distribution.
      bool varies = curve.keys.size() > 1;
      for (const EmitterKey& key : curve.keys) {
        varies = varies || key.z != 0.0f;
      }
      char label[96];
      std::snprintf(label, sizeof(label), "%s%s##c%d", info.caption, varies ? "  ~" : "", c);
      if (ImGui::Selectable(label, mCurve == c)) {
        mCurve = c;
        mSelectedKey = -1;
      }
      if (ImGui::IsItemHovered()) {
        const float value = curve.keys.empty() ? 0.0f : curve.keys.front().y;
        ImGui::SetTooltip("%s: %zu key(s), first %.3f%s", info.name, curve.keys.size(), static_cast<double>(value), varies ? "; varies over time or at random" : "");
      }
    }
  }

  void EdParticleEditor::DrawCurve()
  {
    EmitterCurve& curve = mEmitter.curves[static_cast<std::size_t>(mCurve)];
    const EmitterCurveInfo& info = CurveInfo(mCurve);
    ImGui::Text("%s", info.caption);
    ImGui::SameLine();
    ImGui::TextDisabled("(%s)", info.name);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90.0f);
    if (ImGui::DragFloat("Time range", &curve.xRange, 0.1f, 0.1f, 1000.0f, "%.2f")) {
      Changed();
    }
    ImGui::SetItemTooltip("The curve's time axis in ticks (10 a second): the emitter's Repeattime for the curves sampled per particle");

    // The graph: time across, the value up; the band is the random spread (y +- z / 2).
    const float range = curve.xRange > 0.0f ? curve.xRange : 1.0f;
    float low = info.viewMin;
    float high = info.viewMax;
    for (const EmitterKey& key : curve.keys) {
      low = std::min(low, key.y - std::fabs(key.z) * 0.5f);
      high = std::max(high, key.y + std::fabs(key.z) * 0.5f);
    }
    const float margin = (high - low) * 0.08f + 1e-3f;
    low -= margin;
    high += margin;
    const float keyPanel = ImGui::GetTextLineHeightWithSpacing() * 2.6f;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 size(std::max(ImGui::GetContentRegionAvail().x, 50.0f), std::max(ImGui::GetContentRegionAvail().y - keyPanel, 50.0f));
    ImGui::InvisibleButton("##graph", size, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const auto toScreen = [&](const float x, const float y) {
      return ImVec2(origin.x + x / range * size.x, origin.y + (1.0f - (y - low) / (high - low)) * size.y);
    };
    const auto fromScreen = [&](const ImVec2 p, float& x, float& y) {
      x = std::clamp((p.x - origin.x) / size.x * range, 0.0f, range);
      y = low + (1.0f - (p.y - origin.y) / size.y) * (high - low);
    };
    dl->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y), IM_COL32(26, 26, 30, 255));
    for (int i = 0; i <= 10; ++i) {
      const float gx = origin.x + size.x * static_cast<float>(i) / 10.0f;
      dl->AddLine(ImVec2(gx, origin.y), ImVec2(gx, origin.y + size.y), IM_COL32(45, 45, 50, 255));
      char text[32];
      std::snprintf(text, sizeof(text), "%.1f", static_cast<double>(range * static_cast<float>(i) / 10.0f));
      dl->AddText(ImVec2(gx + 2.0f, origin.y + size.y - ImGui::GetFontSize() - 2.0f), IM_COL32(120, 120, 130, 255), text);
    }
    for (int i = 0; i <= 4; ++i) {
      const float value = low + (high - low) * static_cast<float>(i) / 4.0f;
      const ImVec2 a = toScreen(0.0f, value);
      dl->AddLine(a, ImVec2(origin.x + size.x, a.y), IM_COL32(45, 45, 50, 255));
      char text[32];
      std::snprintf(text, sizeof(text), "%.2f", static_cast<double>(value));
      dl->AddText(ImVec2(origin.x + 3.0f, a.y - ImGui::GetFontSize()), IM_COL32(120, 120, 130, 255), text);
    }
    if (low < 0.0f && high > 0.0f) {
      const ImVec2 zero = toScreen(0.0f, 0.0f);
      dl->AddLine(zero, ImVec2(origin.x + size.x, zero.y), IM_COL32(80, 80, 90, 255));
    }
    // The curve and its spread, sampled as the game samples it (no random: the band's middle).
    constexpr int kSteps = 120;
    for (int i = 0; i < kSteps; ++i) {
      const float t0 = range * static_cast<float>(i) / kSteps;
      const float t1 = range * static_cast<float>(i + 1) / kSteps;
      const float y0 = EmitterCurveValue(curve, t0, 0.5f);
      const float y1 = EmitterCurveValue(curve, t1, 0.5f);
      const float s0 = (EmitterCurveValue(curve, t0, 1.0f) - y0);
      const float s1 = (EmitterCurveValue(curve, t1, 1.0f) - y1);
      if (std::fabs(s0) > 1e-5f || std::fabs(s1) > 1e-5f) {
        dl->AddQuadFilled(toScreen(t0, y0 - s0), toScreen(t1, y1 - s1), toScreen(t1, y1 + s1), toScreen(t0, y0 + s0), IM_COL32(240, 170, 80, 50));
      }
      dl->AddLine(toScreen(t0, y0), toScreen(t1, y1), IM_COL32(240, 170, 80, 255), 2.0f);
    }
    // Keys: drag to move, double-click on empty space to add, right-click to remove.
    const ImVec2 mouse = ImGui::GetIO().MousePos;
    int hoverKey = -1;
    for (std::size_t k = 0; k < curve.keys.size(); ++k) {
      const ImVec2 p = toScreen(curve.keys[k].x, curve.keys[k].y);
      if (hovered && std::hypot(mouse.x - p.x, mouse.y - p.y) < 8.0f) {
        hoverKey = static_cast<int>(k);
      }
    }
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      mDragKey = hoverKey;
      mSelectedKey = hoverKey;
    }
    if (mDragKey >= 0 && static_cast<std::size_t>(mDragKey) < curve.keys.size()) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        if (ImGui::GetIO().MouseDelta.x != 0.0f || ImGui::GetIO().MouseDelta.y != 0.0f) {
          fromScreen(mouse, curve.keys[static_cast<std::size_t>(mDragKey)].x, curve.keys[static_cast<std::size_t>(mDragKey)].y);
          Changed();
        }
      } else {
        mDragKey = -1;
      }
    }
    if (hovered && hoverKey < 0 && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
      EmitterKey key;
      fromScreen(mouse, key.x, key.y);
      curve.keys.push_back(key);
      std::stable_sort(curve.keys.begin(), curve.keys.end(), [](const EmitterKey& a, const EmitterKey& b) { return a.x < b.x; });
      mSelectedKey = -1;
      Changed();
    }
    if (hovered && hoverKey >= 0 && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
      curve.keys.erase(curve.keys.begin() + hoverKey);
      mSelectedKey = -1;
      Changed();
    }
    for (std::size_t k = 0; k < curve.keys.size(); ++k) {
      const ImVec2 p = toScreen(curve.keys[k].x, curve.keys[k].y);
      const bool lit = static_cast<int>(k) == mSelectedKey || static_cast<int>(k) == hoverKey;
      dl->AddCircleFilled(p, lit ? 6.0f : 4.5f, lit ? IM_COL32(255, 230, 120, 255) : IM_COL32(250, 250, 250, 255));
      if (curve.keys[k].z != 0.0f) {
        const ImVec2 a = toScreen(curve.keys[k].x, curve.keys[k].y - curve.keys[k].z * 0.5f);
        const ImVec2 b = toScreen(curve.keys[k].x, curve.keys[k].y + curve.keys[k].z * 0.5f);
        dl->AddLine(a, b, IM_COL32(240, 170, 80, 160), 1.0f);
      }
    }
    if (hovered && hoverKey >= 0) {
      const EmitterKey& key = curve.keys[static_cast<std::size_t>(hoverKey)];
      ImGui::SetTooltip("time %.2f, value %.3f, spread %.3f\nDrag to move; right-click removes", static_cast<double>(key.x), static_cast<double>(key.y),
                        static_cast<double>(key.z));
    } else if (hovered) {
      ImGui::SetTooltip("Double-click to add a key");
    }
    // The selected key's numbers.
    if (mSelectedKey >= 0 && static_cast<std::size_t>(mSelectedKey) < curve.keys.size()) {
      EmitterKey& key = curve.keys[static_cast<std::size_t>(mSelectedKey)];
      ImGui::SetNextItemWidth(110.0f);
      bool changed = ImGui::DragFloat("Time", &key.x, 0.05f, 0.0f, range, "%.3f");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(110.0f);
      changed |= ImGui::DragFloat("Value", &key.y, 0.01f, 0.0f, 0.0f, "%.3f");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(110.0f);
      changed |= ImGui::DragFloat("Spread", &key.z, 0.01f, 0.0f, 0.0f, "%.3f");
      ImGui::SetItemTooltip("Each sample is the value plus a random amount within half the spread either way");
      if (changed) {
        Changed();
      }
    } else {
      ImGui::TextDisabled("%zu key(s). Click a key to edit its numbers.", curve.keys.size());
    }
  }

  void EdParticleEditor::DrawDetails()
  {
    ImGui::SeparatorText("Details");
    bool changed = false;
    char id[128];
    std::snprintf(id, sizeof(id), "%s", mEmitter.blueprintId.c_str());
    ImGui::SetNextItemWidth(-90.0f);
    if (ImGui::InputText("Id", id, sizeof(id), ImGuiInputTextFlags_EnterReturnsTrue)) {
      mEmitter.blueprintId = id;
      changed = true;
    }
    ImGui::SetItemTooltip("FAF's blueprint loader replaces it with the file's path, which is how scripts name the emitter");
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("Lifetime", &mEmitter.lifetime, 0.1f, -1.0f, 1000.0f, "%.2f");
    ImGui::SetItemTooltip("Ticks the emitter lives (10 a second); -1: until the script destroys it");
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("Repeat time", &mEmitter.repeatTime, 0.1f, 0.1f, 1000.0f, "%.2f");
    ImGui::SetItemTooltip("Ticks after which the curves start over");
    int blend = std::clamp(static_cast<int>(mEmitter.blendMode), 0, 5);
    ImGui::SetNextItemWidth(-90.0f);
    if (ImGui::Combo("Blend", &blend, kEmitterBlendModes, 6)) {
      mEmitter.blendMode = static_cast<float>(blend);
      changed = true;
    }
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("Frames", &mEmitter.textureFrameCount, 0.1f, 1.0f, 64.0f, "%.0f");
    ImGui::SetItemTooltip("Animation frames across the texture (more than 1: an animated particle)");
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("Strips", &mEmitter.textureStripCount, 0.1f, 1.0f, 64.0f, "%.0f");
    ImGui::SetItemTooltip("Rows of the texture; Texture Selection picks one");
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("LOD cutoff", &mEmitter.lodCutoff, 1.0f, 0.0f, 2000.0f, "%.0f");
    ImGui::SetItemTooltip("The camera distance beyond which it doesn't emit");
    ImGui::SetNextItemWidth(-90.0f);
    changed |= ImGui::DragFloat("Sort order", &mEmitter.sortOrder, 0.1f, -100.0f, 100.0f, "%.2f");

    ImGui::SeparatorText("Textures");
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
    const auto picker = [&](const char* label, std::string& path) {
      ImGui::SetNextItemWidth(-90.0f);
      if (ImGui::BeginCombo(label, BaseName(path).c_str(), ImGuiComboFlags_HeightLarge)) {
        static char filter[64] = {};
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##filter", "Search", filter, sizeof(filter));
        for (const std::string& texture : mParticleTextures) {
          if (filter[0] != '\0' && Lower(texture).find(Lower(filter)) == std::string::npos) {
            continue;
          }
          if (ImGui::Selectable(texture.c_str(), Lower(texture) == Lower(path))) {
            path = texture;
            changed = true;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SetItemTooltip("%s", path.c_str());
    };
    picker("Texture", mEmitter.texture);
    picker("Ramp", mEmitter.rampTexture);
    ImGui::TextDisabled("The ramp colours each particle over its life (left to right) by Ramp Selection (top to bottom).");

    ImGui::SeparatorText("Switches");
    for (int f = 0; f < kEmitterFlagCount; ++f) {
      bool value = mEmitter.flags[static_cast<std::size_t>(f)];
      if (ImGui::Checkbox(FlagName(f), &value)) {
        mEmitter.flags[static_cast<std::size_t>(f)] = value;
        changed = true;
      }
      ImGui::SetItemTooltip("%s", kFlagHelp[f]);
    }
    ImGui::SeparatorText("Fidelity");
    changed |= ImGui::Checkbox("Low", &mEmitter.lowFidelity);
    ImGui::SameLine();
    changed |= ImGui::Checkbox("Medium", &mEmitter.medFidelity);
    ImGui::SameLine();
    changed |= ImGui::Checkbox("High", &mEmitter.highFidelity);
    ImGui::SetItemTooltip("The effects quality settings that show this emitter");
    if (!mEmitter.extra.empty()) {
      ImGui::SeparatorText("Kept as written");
      for (const auto& [key, value] : mEmitter.extra) {
        ImGui::TextDisabled("%s = %s", key.c_str(), value.c_str());
      }
    }
    ImGui::Spacing();
    ImGui::TextWrapped("A map's own emitter loads in a game started from FAF's lobby (its blueprint loader reads the map's folder); "
                       "a script then creates it by its path, e.g. CreateEmitterAtEntity(unit, army, '/maps/<map>/effects/emitters/<name>.bp').");
    if (changed) {
      Changed();
    }
  }

  void EdParticleEditor::DrawFlat()
  {
    const bool beam = mFlat.kind == "BeamBlueprint";
    ImGui::SeparatorText(beam ? "Beam" : "Trail");
    ImGui::TextWrapped("%s", beam ? "A beam is a textured strip between two points: weapons' beams, tractor and shield beams. The preview draws it from "
                                    "the view's centre, rising, for its Lifetime and again."
                                  : "A trail is a ribbon left behind a moving point: missiles' and aircraft's trails. The preview moves its emitter "
                                    "round the view's centre, a turn every 4 seconds.");
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
      ImGui::SetNextItemWidth(260.0f);
      switch (field.kind) {
      case FlatValue::Kind::Number:
        edited = ImGui::DragFloat(field.key, &value.number, 0.01f, 0.0f, 0.0f, "%.4g");
        break;
      case FlatValue::Kind::Bool:
        edited = ImGui::Checkbox(field.key, &value.flag);
        break;
      case FlatValue::Kind::Color:
        edited = ImGui::ColorEdit4(field.key, value.color.data(), ImGuiColorEditFlags_Float | ImGuiColorEditFlags_AlphaBar);
        break;
      case FlatValue::Kind::Text:
        if (field.texture) {
          if (ImGui::BeginCombo(field.key, value.text.empty() ? "(none)" : BaseName(value.text).c_str(), ImGuiComboFlags_HeightLarge)) {
            for (const std::string& texture : mParticleTextures) {
              if (ImGui::Selectable(texture.c_str(), Lower(texture) == Lower(value.text))) {
                value.text = texture;
                edited = true;
              }
            }
            ImGui::EndCombo();
          }
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
        ImGui::TextDisabled("%s = %s (kept as written)", key.c_str(), value.kind == FlatValue::Kind::Number ? std::to_string(value.number).c_str() : value.text.c_str());
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
    ImGui::SetNextWindowSize(ImVec2(520.0f, 480.0f), ImGuiCond_Appearing);
    if (!ImGui::BeginPopup("Open a game effect")) {
      return;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##filter", "Search the game's effects (e.g. muzzle, smoke, beam, trail)", mBrowserFilter, sizeof(mBrowserFilter));
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
          (void)OpenGameEmitter(path);
          ImGui::CloseCurrentPopup();
        }
      }
      ImGui::TextDisabled("%zu files", mGameEmitters.size());
    }
    ImGui::EndChild();
    ImGui::EndPopup();
  }
} // namespace faf::editor
