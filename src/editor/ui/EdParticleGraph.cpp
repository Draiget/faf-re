// The Particle Editor's node graph (user ask 2026-11-11: the particle editor as the shader editor, with nodes): an
// effect's emitters as Emitter nodes fed by curve and texture nodes (graph/EdEffectGraph), on the material editor's
// canvas, with Details for the selected node and a palette; every emitter plays in the particle view.

#include "editor/ui/EdParticleEditor.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"

#include "editor/doc/EdMapFile.h"
#include "imgui.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    std::string LowerName(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    std::string FileBase(
      const std::string& path
    )
    {
      std::string name = path.substr(path.find_last_of("/\\") + 1);
      if (const std::size_t dot = name.rfind(".bp"); dot != std::string::npos) {
        name = name.substr(0, dot);
      }
      return name;
    }

    /** The curve a Curve, Constant, Random Range or Over Time node holds on its own (its square's plot). */
    bool OwnCurve(
      const GraphNode& node,
      EmitterCurve& out
    )
    {
      const std::string& type = node.type->name;
      const auto f = [&](const std::size_t i) {
        return node.params[i].value[0];
      };
      out = {};
      out.xRange = 10.0f;
      if (type == kCurveNode) {
        out.xRange = f(0) > 0.0f ? f(0) : 10.0f;
        out.keys = CurveKeysFromText(node.params[1].text);
      } else if (type == kConstantNode) {
        out.keys = {{0.0f, f(0), f(1)}};
      } else if (type == "CurveRandom") {
        out.keys = {{5.0f, (f(0) + f(1)) * 0.5f, std::fabs(f(1) - f(0))}};
      } else if (type == "CurveOverLife") {
        out.keys = {{0.0f, f(0), f(2)}, {10.0f, f(1), f(2)}};
      } else {
        return false;
      }
      return true;
    }

    /** A curve's plot in a rectangle: its band (the spread) and its line. */
    void PlotCurve(
      ImDrawList* dl,
      const EmitterCurve& curve,
      const float x0,
      const float y0,
      const float x1,
      const float y1
    )
    {
      dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(20, 22, 26, 255));
      float low = 1e9f;
      float high = -1e9f;
      for (const EmitterKey& key : curve.keys) {
        low = std::min(low, key.y - std::fabs(key.z) * 0.5f);
        high = std::max(high, key.y + std::fabs(key.z) * 0.5f);
      }
      if (curve.keys.empty()) {
        low = 0.0f;
        high = 1.0f;
      }
      if (high - low < 1e-3f) {
        low -= 1.0f;
        high += 1.0f;
      }
      const float margin = (high - low) * 0.1f;
      low -= margin;
      high += margin;
      const float range = curve.xRange > 0.0f ? curve.xRange : 1.0f;
      const auto at = [&](const float t, const float v) {
        return ImVec2(x0 + t / range * (x1 - x0), y1 - (v - low) / (high - low) * (y1 - y0));
      };
      if (low < 0.0f && high > 0.0f) {
        dl->AddLine(at(0.0f, 0.0f), at(range, 0.0f), IM_COL32(70, 70, 80, 255));
      }
      constexpr int kSteps = 32;
      for (int i = 0; i < kSteps; ++i) {
        const float t0 = range * static_cast<float>(i) / kSteps;
        const float t1 = range * static_cast<float>(i + 1) / kSteps;
        const float y0v = EmitterCurveValue(curve, t0, 0.5f);
        const float y1v = EmitterCurveValue(curve, t1, 0.5f);
        const float s0 = EmitterCurveValue(curve, t0, 1.0f) - y0v;
        const float s1 = EmitterCurveValue(curve, t1, 1.0f) - y1v;
        if (std::fabs(s0) > 1e-5f || std::fabs(s1) > 1e-5f) {
          dl->AddQuadFilled(
            at(t0, y0v - s0), at(t1, y1v - s1), at(t1, y1v + s1), at(t0, y0v + s0), IM_COL32(110, 200, 120, 60)
          );
        }
        dl->AddLine(at(t0, y0v), at(t1, y1v), IM_COL32(110, 200, 120, 255), 2.0f);
      }
    }
  } // namespace

  void EdParticleEditor::SetGraph(
    const std::string& effectName,
    const std::vector<std::pair<std::string, EmitterBlueprint>>& emitters,
    const std::string& gamePaths
  )
  {
    if (!mGraph) {
      mGraph = std::make_unique<NodeGraph>(EffectNodeTypes());
      // Curves show their plot in the node's square, textures their picture; the Emitter and math nodes have none.
      mCanvas.SetHasSquare([](const NodeType& type) {
        return type.name == kCurveNode || type.name == kConstantNode || type.name == kTextureNode ||
          type.name == "CurveRandom" || type.name == "CurveOverLife";
      });
      mCanvas.SetDrawSquare(
        [](const GraphNode& node, ImDrawList* dl, const float x0, const float y0, const float x1, const float y1) {
        EmitterCurve curve;
        if (!OwnCurve(node, curve)) {
          return false;
        }
        PlotCurve(dl, curve, x0, y0, x1, y1);
        return true;
      }
      );
      mCanvas.SetThumbnails([this](const GraphNode& node) -> std::uint64_t {
        return node.type->name == kTextureNode ? mLibrary.Thumbnail(node.params[0].text, true) : 0;
      });
    }
    // The old effect's nodes go (BuildEffectGraph clears the graph), and with them what was picked on them.
    BuildEffectGraph(*mGraph, effectName, emitters);
    mKeyDrag = -1;
    mKeySelected = -1;
    mEffectName = effectName;
    mEffectPaths = gamePaths;
    mGraphClean = mGraph->Changes();
    mGraphBuilt = ~std::uint64_t{0};
    mGraphUndo = {mGraph->Save()};
    mGraphUndoAt = 0;
    mGraphSnap = mGraph->Changes();
    mCanvas.FrameAll();
    mCanvas.Select(0);
    mFlatMode = false;
    SyncGraph();
    RestartPreview();
    mFrameAsk = true;
  }

  void EdParticleEditor::SyncGraph()
  {
    if (!mGraph || mGraph->Changes() == mGraphBuilt) {
      return;
    }
    mGraphBuilt = mGraph->Changes();
    std::string error;
    if (!GraphEmitters(*mGraph, mFxEmitters, error)) {
      mFxEmitters.clear();
    }
    // A preview per emitter: kept (with its particles' age) while the count stays, the new settings taken.
    mFx.resize(mFxEmitters.size());
    for (std::size_t i = 0; i < mFxEmitters.size(); ++i) {
      if (!mFx[i]) {
        mFx[i] = std::make_unique<EdParticlePreview>();
        mFx[i]->Restart();
      }
      mFx[i]->SetEmitter(mFxEmitters[i].second);
    }
    mDirty = mGraph->Changes() != mGraphClean;
    if (!mFxEmitters.empty()) {
      mEmitter = mFxEmitters.front().second; // what the browser's summary shows
    }
  }

  bool EdParticleEditor::OpenTemplate(
    const EffectTemplate& effect
  )
  {
    std::vector<std::pair<std::string, EmitterBlueprint>> emitters;
    std::string paths;
    for (const std::string& path : effect.paths) {
      std::string text;
      EmitterBlueprint emitter;
      std::string error;
      if (!ReadGameFile(path, text) || !ParseEmitter(text, emitter, error)) {
        continue; // a beam or trail in the list, or a file FAF's data no longer has
      }
      emitters.emplace_back(FileBase(path), std::move(emitter));
      paths += (paths.empty() ? "" : ";") + path;
    }
    if (emitters.empty()) {
      mStatus = effect.name + ": none of its emitter files could be read";
      return false;
    }
    SetGraph(effect.name, emitters, paths);
    mStatus = "Opened the effect " + effect.name + " (" + std::to_string(emitters.size()) + " emitters)";
    return true;
  }

  void EdParticleEditor::ListTemplates()
  {
    if (mTemplatesListed) {
      return;
    }
    mTemplatesListed = true;
    std::string text;
    if (ReadGameFile("/lua/EffectTemplates.lua", text)) {
      mTemplates = ParseEffectTemplates(text);
      std::sort(mTemplates.begin(), mTemplates.end(), [](const EffectTemplate& a, const EffectTemplate& b) {
        return LowerName(a.name) < LowerName(b.name);
      });
    }
  }

  bool EdParticleEditor::TestTemplate(
    const std::string& name
  )
  {
    ListTemplates();
    for (const EffectTemplate& effect : mTemplates) {
      if (LowerName(effect.name) == LowerName(name)) {
        return OpenTemplate(effect);
      }
    }
    mStatus = "No effect template " + name;
    return false;
  }

  void EdParticleEditor::GraphSnapshot()
  {
    if (
      !mGraph || mGraph->Changes() == mGraphSnap || ImGui::IsMouseDown(ImGuiMouseButton_Left) ||
      ImGui::IsAnyItemActive()
    ) {
      return;
    }
    const std::string text = mGraph->Save();
    mGraphSnap = mGraph->Changes();
    if (!mGraphUndo.empty() && mGraphUndo[mGraphUndoAt] == text) {
      return;
    }
    mGraphUndo.resize(mGraphUndoAt + 1);
    mGraphUndo.push_back(text);
    if (mGraphUndo.size() > 200) {
      mGraphUndo.erase(mGraphUndo.begin());
    }
    mGraphUndoAt = mGraphUndo.size() - 1;
  }

  void EdParticleEditor::GraphUndo(
    const bool redo
  )
  {
    if (!mGraph || (redo ? mGraphUndoAt + 1 >= mGraphUndo.size() : mGraphUndoAt == 0)) {
      return;
    }
    mGraphUndoAt = redo ? mGraphUndoAt + 1 : mGraphUndoAt - 1;
    std::string error;
    (void)mGraph->Load(mGraphUndo[mGraphUndoAt], error);
    mGraphSnap = mGraph->Changes();
    mGraphClean = ~std::uint64_t{0};
  }

  bool EdParticleEditor::SaveGraph(
    const std::string& effectName
  )
  {
    SyncGraph();
    if (mFxEmitters.empty()) {
      mStatus = "Nothing to save: link an Emitter to the Effect output";
      return false;
    }
    const std::filesystem::path folder = Folder();
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    std::string paths;
    for (const auto& [name, emitter] : mFxEmitters) {
      const std::filesystem::path file = folder / (name + ".bp");
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      std::string text = WriteEmitter(emitter);
      std::string crlf;
      for (const char c : text) {
        crlf += c == '\n' ? std::string("\r\n") : std::string(1, c);
      }
      out << crlf; // the game's own files have Windows line ends
      if (!out) {
        mStatus = "Can't write " + file.string();
        return false;
      }
      if (!mMapFolderName.empty()) {
        paths += (paths.empty() ? "" : ";") + ("/maps/" + mMapFolderName + "/effects/emitters/" + name + ".bp");
      }
    }
    // The graph beside them, to open again as it was.
    {
      std::ofstream out(folder / (effectName + ".fafeffect.json"), std::ios::binary | std::ios::trunc);
      out << mGraph->Save();
    }
    mEffectName = effectName;
    mEffectPaths = paths;
    mGraphClean = mGraph->Changes();
    mDirty = false;
    mStatus = "Saved " + std::to_string(mFxEmitters.size()) + " emitter file(s) and the graph into " + folder.string();
    return true;
  }

  void EdParticleEditor::DrawGraphMode()
  {
    if (!mGraph) {
      SetGraph("new_effect", {{"new_emitter", NewEmitter()}}, "");
    }
    // Undo and redo while the window has the keyboard.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::IsAnyItemActive()) {
      const ImGuiIO& io = ImGui::GetIO();
      if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z)) {
        GraphUndo(io.KeyShift);
      } else if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Y)) {
        GraphUndo(true);
      }
    }
    const float previewWidth = std::max(ImGui::GetContentRegionAvail().x * 0.3f, 300.0f);
    if (
      ImGui::BeginTable(
        "##graphlayout", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail()
      )
    ) {
      ImGui::TableSetupColumn("left", ImGuiTableColumnFlags_WidthFixed, previewWidth);
      ImGui::TableSetupColumn("graph", ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn("palette", ImGuiTableColumnFlags_WidthFixed, 200.0f);
      ImGui::TableNextRow();
      // The particle view over the selected node's Details.
      ImGui::TableSetColumnIndex(0);
      DrawPreviewPane();
      if (ImGui::BeginChild("##nodedetails", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawNodeDetails();
      }
      ImGui::EndChild();
      // The graph, and a line of what it makes.
      ImGui::TableSetColumnIndex(1);
      const float statsHeight = ImGui::GetTextLineHeightWithSpacing() * 1.6f;
      if (
        ImGui::BeginChild(
          "##fxgraph",
          ImVec2(0.0f, ImGui::GetContentRegionAvail().y - statsHeight),
          ImGuiChildFlags_Borders,
          ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMove
        )
      ) {
        (void)mCanvas.Draw(*mGraph);
      }
      ImGui::EndChild();
      SyncGraph();
      ImGui::TextDisabled(
        "%zu emitter(s) linked to the Effect output, %zu nodes; Ctrl+Z / Ctrl+Y undo; right-click the graph for nodes",
        mFxEmitters.size(),
        mGraph->Nodes().size()
      );
      // The palette.
      ImGui::TableSetColumnIndex(2);
      if (ImGui::BeginChild("##fxpalette", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawGraphPalette();
      }
      ImGui::EndChild();
      ImGui::EndTable();
    }
    GraphSnapshot();
  }

  void EdParticleEditor::DrawGraphPalette()
  {
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##search", "Search", mPaletteFilter, sizeof(mPaletteFilter));
    std::map<std::string, std::vector<const NodeType*>> byCategory;
    const std::string filter = LowerName(mPaletteFilter);
    for (const auto& type : mGraph->Registry().All()) {
      if (
        type->isOutput ||
        (!filter.empty() && LowerName(type->title + " " + type->category).find(filter) == std::string::npos)
      ) {
        continue;
      }
      byCategory[type->category].push_back(type.get());
    }
    for (const auto& [category, types] : byCategory) {
      ImGui::SeparatorText(category.c_str());
      for (const NodeType* type : types) {
        ImGui::Selectable(type->title.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          (void)mCanvas.AddAtCentre(*mGraph, type->name);
        }
        if (ImGui::BeginDragDropSource()) {
          ImGui::SetDragDropPayload(EdNodeCanvas::kPalettePayload, type->name.data(), type->name.size());
          ImGui::Text("%s", type->title.c_str());
          ImGui::EndDragDropSource();
        }
        ImGui::SetItemTooltip("%s\n\nDouble-click or drag into the graph.", type->help.c_str());
      }
    }
  }

  void EdParticleEditor::DrawNodeDetails()
  {
    ImGui::SeparatorText("Details");
    const std::set<int>& selection = mCanvas.Selection();
    GraphNode* node = selection.size() == 1 ? mGraph->Find(*selection.begin()) : nullptr;
    if (node == nullptr) {
      ImGui::TextWrapped(
        "Select a node. An effect is its emitters played together: each Emitter node takes its curves from the "
        "nodes linked to its pins (a Constant is one value with a random spread, a Curve changes over the emitter's "
        "time) and its texture and colour ramp from Texture nodes."
      );
      return;
    }
    const NodeType& type = *node->type;
    const int id = node->id;
    ImGui::TextColored(ImVec4(0.95f, 0.85f, 0.55f, 1.0f), "%s", type.title.c_str());
    ImGui::TextWrapped("%s", type.help.c_str());
    // A Curve node: its keys on a graph; the pin it feeds gives the view's range and the caption.
    if (type.name == kCurveNode) {
      const EmitterCurveInfo* info = nullptr;
      for (const GraphLink& link : mGraph->Links()) {
        const GraphNode* to = link.fromNode == id ? mGraph->Find(link.toNode) : nullptr;
        if (to != nullptr && to->type->name == kEmitterNode && link.toPin < kEmitterCurveCount) {
          info = &CurveInfo(link.toPin);
        }
      }
      if (info != nullptr) {
        ImGui::TextDisabled("Feeds %s (%s)", info->caption, info->name);
      }
      float range = node->params[0].value[0];
      std::vector<EmitterKey> keys = CurveKeysFromText(node->params[1].text);
      if (DrawCurveKeys(keys, range, info)) {
        ParamValue value;
        value.value = {range, 0.0f, 0.0f, 0.0f};
        mGraph->SetParam(id, 0, value);
        value.text = CurveKeysText(keys);
        mGraph->SetParam(id, 1, value);
      }
      return;
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
    for (std::size_t p = 0; p < type.params.size(); ++p) {
      const ParamDef& def = type.params[p];
      ParamValue value = mGraph->Find(id)->params[p];
      bool changed = false;
      ImGui::PushID(static_cast<int>(p));
      ImGui::SetNextItemWidth(-120.0f);
      switch (def.kind) {
      case ParamKind::Float:
      case ParamKind::Int: {
        const float speed = std::max((def.max - def.min) / 400.0f, 0.001f);
        changed = FillDragFloat(def.name.c_str(), &value.value[0], speed, def.min, def.max, "%.3f");
        break;
      }
      case ParamKind::Bool: {
        bool on = value.value[0] > 0.5f;
        changed = ImGui::Checkbox(def.name.c_str(), &on);
        value.value[0] = on ? 1.0f : 0.0f;
        break;
      }
      case ParamKind::Choice: {
        const int current = std::clamp(static_cast<int>(value.value[0]), 0, static_cast<int>(def.choices.size()) - 1);
        if (ImGui::BeginCombo(def.name.c_str(), def.choices[static_cast<std::size_t>(current)].c_str())) {
          for (std::size_t c = 0; c < def.choices.size(); ++c) {
            if (ImGui::Selectable(def.choices[c].c_str(), static_cast<int>(c) == current)) {
              value.value[0] = static_cast<float>(c);
              changed = true;
            }
          }
          ImGui::EndCombo();
        }
        break;
      }
      case ParamKind::Text:
        if (type.name == kTextureNode) {
          // The game's particle textures: the picked one's picture, a click opens the browser of them all.
          changed = mTexturePicker.Field("##texture", value.text, mParticleTextures, mLibrary, true);
        } else {
          char buffer[160];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", value.text.c_str());
          if (ImGui::InputText(def.name.c_str(), buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
            value.text = buffer;
            changed = true;
          }
        }
        break;
      case ParamKind::Color:
        changed = ImGui::ColorEdit4(def.name.c_str(), value.value.data());
        break;
      }
      if (!def.help.empty()) {
        ImGui::SetItemTooltip("%s", def.help.c_str());
      }
      ImGui::PopID();
      if (changed) {
        mGraph->SetParam(id, p, value);
      }
    }
    mLibrary.Pump(4);
  }

  bool EdParticleEditor::DrawCurveKeys(
    std::vector<EmitterKey>& keys,
    float& range,
    const EmitterCurveInfo* info
  )
  {
    bool changed = false;
    ImGui::SetNextItemWidth(Em(120.0f));
    changed |= FillDragFloat("Time range", &range, 0.1f, 0.1f, 1000.0f, "%.2f");
    ImGui::SetItemTooltip("The curve's time axis in ticks (10 a second)");
    const float span = range > 0.0f ? range : 1.0f;
    float low = info != nullptr ? info->viewMin : 0.0f;
    float high = info != nullptr ? info->viewMax : 1.0f;
    for (const EmitterKey& key : keys) {
      low = std::min(low, key.y - std::fabs(key.z) * 0.5f);
      high = std::max(high, key.y + std::fabs(key.z) * 0.5f);
    }
    const float margin = (high - low) * 0.08f + 1e-3f;
    low -= margin;
    high += margin;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 size(
      std::max(ImGui::GetContentRegionAvail().x, 80.0f),
      std::clamp(ImGui::GetContentRegionAvail().y * 0.6f, 120.0f, 400.0f)
    );
    ImGui::InvisibleButton("##curvekeys", size, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const auto toScreen = [&](const float x, const float y) {
      return ImVec2(origin.x + x / span * size.x, origin.y + (1.0f - (y - low) / (high - low)) * size.y);
    };
    EmitterCurve curve{span, keys};
    std::stable_sort(curve.keys.begin(), curve.keys.end(), [](const EmitterKey& a, const EmitterKey& b) {
      return a.x < b.x;
    });
    PlotCurve(dl, curve, origin.x, origin.y, origin.x + size.x, origin.y + size.y);
    const ImVec2 mouse = ImGui::GetIO().MousePos;
    int hoverKey = -1;
    for (std::size_t k = 0; k < keys.size(); ++k) {
      const ImVec2 p = toScreen(keys[k].x, keys[k].y);
      if (hovered && std::hypot(mouse.x - p.x, mouse.y - p.y) < 8.0f) {
        hoverKey = static_cast<int>(k);
      }
    }
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
      mKeyDrag = hoverKey;
      mKeySelected = hoverKey;
    }
    if (mKeyDrag >= 0 && static_cast<std::size_t>(mKeyDrag) < keys.size()) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        if (ImGui::GetIO().MouseDelta.x != 0.0f || ImGui::GetIO().MouseDelta.y != 0.0f) {
          keys[static_cast<std::size_t>(mKeyDrag)].x = std::clamp((mouse.x - origin.x) / size.x * span, 0.0f, span);
          keys[static_cast<std::size_t>(mKeyDrag)].y = low + (1.0f - (mouse.y - origin.y) / size.y) * (high - low);
          changed = true;
        }
      } else {
        mKeyDrag = -1;
      }
    }
    if (hovered && hoverKey < 0 && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
      keys.push_back(
        {std::clamp((mouse.x - origin.x) / size.x * span, 0.0f, span),
         low + (1.0f - (mouse.y - origin.y) / size.y) * (high - low),
         0.0f}
      );
      changed = true;
    }
    if (hovered && hoverKey >= 0 && ImGui::IsMouseClicked(ImGuiMouseButton_Right) && keys.size() > 1) {
      keys.erase(keys.begin() + hoverKey);
      mKeySelected = -1;
      changed = true;
    }
    for (std::size_t k = 0; k < keys.size(); ++k) {
      const bool lit = static_cast<int>(k) == mKeySelected || static_cast<int>(k) == hoverKey;
      dl->AddCircleFilled(
        toScreen(keys[k].x, keys[k].y),
        lit ? 6.0f : 4.5f,
        lit ? IM_COL32(255, 230, 120, 255) : IM_COL32(250, 250, 250, 255)
      );
    }
    if (hovered) {
      ImGui::SetTooltip("%s", hoverKey >= 0 ? "Drag to move; right-click removes" : "Double-click to add a key");
    }
    if (mKeySelected >= 0 && static_cast<std::size_t>(mKeySelected) < keys.size()) {
      EmitterKey& key = keys[static_cast<std::size_t>(mKeySelected)];
      ImGui::SetNextItemWidth(Em(90.0f));
      changed |= FillDragFloat("Time", &key.x, 0.05f, 0.0f, span, "%.3f");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(90.0f));
      changed |= FillDragFloat("Value", &key.y, 0.01f, 0.0f, 0.0f, "%.3f");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(90.0f));
      changed |= FillDragFloat("Spread", &key.z, 0.01f, 0.0f, 0.0f, "%.3f");
    } else {
      ImGui::TextDisabled("%zu key(s). Click a key to edit its numbers.", keys.size());
    }
    // In time order once no key is being dragged (sorting under a drag would swap which key the mouse holds).
    if (mKeyDrag < 0) {
      std::stable_sort(keys.begin(), keys.end(), [](const EmitterKey& a, const EmitterKey& b) {
        return a.x < b.x;
      });
    }
    return changed;
  }
} // namespace faf::editor
