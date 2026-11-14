#include "editor/ui/EdGenerate.h"

#include "editor/tools/EdErosionSuite.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    constexpr const char* kExtension = ".fafgraph.json";
    constexpr int kThumbSize = 48;

    std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    /** A height's colour: low ground green, then brown, high ground pale (the thumbnails of height fields). */
    std::uint32_t HeightColour(
      const float t
    )
    {
      struct Stop
      {
        float at, r, g, b;
      };
      static constexpr Stop kStops[] = {
        {0.00f, 0.16f, 0.24f, 0.14f},
        {0.35f, 0.33f, 0.45f, 0.22f},
        {0.65f, 0.55f, 0.47f, 0.32f},
        {1.00f, 0.92f, 0.91f, 0.88f},
      };
      const float x = std::clamp(t, 0.0f, 1.0f);
      std::size_t i = 0;
      while (i + 2 < std::size(kStops) && x > kStops[i + 1].at) {
        ++i;
      }
      const Stop& a = kStops[i];
      const Stop& b = kStops[i + 1];
      const float f = (x - a.at) / std::max(1e-6f, b.at - a.at);
      const auto channel = [f](const float p, const float q) {
        return static_cast<std::uint32_t>(std::clamp(p + (q - p) * f, 0.0f, 1.0f) * 255.0f + 0.5f);
      };
      return 0xFF000000u | (channel(a.r, b.r) << 16) | (channel(a.g, b.g) << 8) | channel(a.b, b.b);
    }

    std::uint32_t Grey(
      const float t
    )
    {
      const auto v = static_cast<std::uint32_t>(std::clamp(t, 0.0f, 1.0f) * 255.0f + 0.5f);
      return 0xFF000000u | (v << 16) | (v << 8) | v;
    }

    /** "%" in a label shown through a printf format. */
    std::string Escaped(
      const std::string& text
    )
    {
      std::string out;
      for (const char c : text) {
        out += c;
        if (c == '%') {
          out += '%';
        }
      }
      return out;
    }
  } // namespace

  EdGenerate::EdGenerate()
    : mGraph(std::make_unique<NodeGraph>(TerrainNodeTypes()))
  {
    NewGraph();
  }

  EdGenerate::~EdGenerate()
  {
    for (const GalleryItem& item : mGallery) {
      if (item.image != 0) {
        mRetired.push_back(item.image);
      }
    }
    RetireThumbs();
    FreeRetired();
  }

  void EdGenerate::RetireThumbs()
  {
    for (const auto& [id, thumb] : mThumbs) {
      mRetired.push_back(thumb.image);
    }
    mThumbs.clear();
  }

  void EdGenerate::FreeRetired()
  {
    for (const std::uint64_t image : mRetired) {
      EdImGuiRenderer::DestroyImage(image);
    }
    mRetired.clear();
  }

  void EdGenerate::NewGraph()
  {
    mGraph = std::make_unique<NodeGraph>(TerrainNodeTypes());
    const int noise = mGraph->AddNode("perlin", 0.0f, 0.0f);
    const int range = mGraph->AddNode("range", 240.0f, 0.0f);
    const int out = mGraph->AddNode("out_height", 480.0f, 0.0f);
    (void)mGraph->Link(noise, 0, range, 0);
    (void)mGraph->Link(range, 0, out, 0);
    mName = "New graph";
    mNote = "Fractal noise scaled to heights: add nodes from the Nodes panel, or open a sample graph.";
    mLoadNote.clear();
    mSeed = 1;
    mSymmetry = "map";
    Open(mName, {}, false);
  }

  void EdGenerate::Open(
    const std::string& name,
    const std::string& text,
    const bool studio
  )
  {
    if (!text.empty()) {
      auto graph = std::make_unique<NodeGraph>(TerrainNodeTypes());
      std::string error;
      if (studio) {
        StudioGraphFacts facts;
        if (!ReadStudioGraph(text, *graph, facts, error)) {
          mStatus = "Can't read " + name + ": " + error;
          return;
        }
        mSeed = facts.seed;
        mSymmetry = facts.symmetry;
        mLoadNote.clear();
        if (!facts.unknownTypes.empty()) {
          mLoadNote = "Left out (not in this editor yet):";
          for (const std::string& type : facts.unknownTypes) {
            mLoadNote += " " + type;
          }
          mLoadNote += " (" + std::to_string(facts.droppedLinks) + " links).";
        }
      } else {
        std::string savedName;
        if (!LoadTerrainGraph(text, *graph, mSeed, savedName, error, &mSymmetry)) {
          mStatus = "Can't read " + name + ": " + error;
          return;
        }
        mLoadNote.clear();
      }
      mGraph = std::move(graph);
      mName = name;
    }
    RetireThumbs();
    mPreview.Clear();
    mReport = TerrainReport{};
    mCanvas = EdNodeCanvas{};
    mCanvas.SetThumbnails([this](const GraphNode& node) -> std::uint64_t {
      const auto found = mThumbs.find(node.id);
      return found != mThumbs.end() ? found->second.image : 0;
    });
    mCanvas.SetHasSquare([](const NodeType& type) {
      return !type.outputs.empty() || type.category == "outputs";
    });
    mCanvas.SetWarnings([this](const GraphNode& node) {
      return mPreview.Error(node.id);
    });
    mCanvas.FrameAll();
    mRefreshAsked = true;
    gpg::Logf(
      "editor: generate: opened %s (%zu nodes)%s%s",
      mName.c_str(),
      mGraph->Nodes().size(),
      mLoadNote.empty() ? "" : "; ",
      mLoadNote.c_str()
    );
  }

  bool EdGenerate::OpenShipped(
    const std::string& id
  )
  {
    for (const ShippedGraph& graph : ShippedTerrainGraphs()) {
      if (graph.id == id) {
        mNote = graph.note;
        Open(graph.name, graph.text, true);
        return true;
      }
    }
    return false;
  }

  bool EdGenerate::OpenFile(
    const std::filesystem::path& file
  )
  {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
      return false;
    }
    std::stringstream text;
    text << in.rdbuf();
    mNote.clear();
    Open(file.stem().stem().string(), text.str(), false);
    return true;
  }

  void EdGenerate::SelectFirst(
    const std::string& type
  )
  {
    for (const GraphNode& node : mGraph->Nodes()) {
      if (node.type->name == type) {
        mCanvas.Select(node.id);
        return;
      }
    }
  }

  std::filesystem::path EdGenerate::OwnFolder() const
  {
    const char* const local = std::getenv("LOCALAPPDATA");
    return local != nullptr ? std::filesystem::path(local) / "FAForever" / "Editor" / "terrain graphs"
                            : std::filesystem::path("terrain graphs");
  }

  void EdGenerate::Save()
  {
    std::string file;
    for (const char c : mName) {
      file += std::isalnum(static_cast<unsigned char>(c)) != 0 || c == ' ' || c == '-' || c == '_' ? c : '_';
    }
    if (file.empty()) {
      file = "graph";
    }
    std::error_code error;
    std::filesystem::create_directories(OwnFolder(), error);
    const std::filesystem::path path = OwnFolder() / (file + kExtension);
    std::ofstream out(path, std::ios::binary);
    out << SaveTerrainGraph(*mGraph, mSeed, mName, mSymmetry);
    mStatus = out ? "Saved " + path.string() : "Can't write " + path.string();
    gpg::Logf("editor: generate: %s", mStatus.c_str());
  }

  void EdGenerate::Evaluate()
  {
    TerrainGround ground;
    if (!mGround || !mGround(ground)) {
      mStatus = "Open a map: the graph runs on its ground.";
      return;
    }
    mGroundWidth = ground.width;
    ground.graphSymmetry = mSymmetry;
    const int step =
      mPreviewCap == 2 ? 1 : ErosionPreviewStep(ground.width, ground.height, mPreviewCap == 0 ? 257 : 513);
    mPreview.SetStep(step);
    mReport = mPreview.Evaluate(*mGraph, mSeed, ground);
    UpdateThumbnails();
    char text[256];
    const int samples = (ground.width - 1) / step + 1;
    (void)std::snprintf(
      text,
      sizeof(text),
      "Ran %d nodes (%d kept) in %.0f ms on %d x %d samples%s",
      mReport.evaluated,
      mReport.cached,
      mReport.ms,
      samples,
      samples,
      mReport.errors.empty() ? "." : "; some nodes have errors (outlined in red)."
    );
    mStatus = text;
    if (mReport.evaluated > 0) {
      gpg::Logf("editor: generate: %s", text);
    }
    if (mShowOnMap) {
      field::Grid heights;
      bool plain = true;
      if (mPreview.FinalHeight(*mGraph, ground, heights, &plain)) {
        mAsk = HeightsAsk{HeightsAsk::Kind::Preview, std::move(heights), plain};
        mAsked = true;
        mShownOnMap = true;
      } else {
        mStatus += " No Output: heights node with an input.";
      }
    }
  }

  void EdGenerate::UpdateThumbnails()
  {
    RetireThumbs();
    std::vector<float> small;
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kThumbSize) * kThumbSize);
    for (const GraphNode& node : mGraph->Nodes()) {
      const TerrainValue* value = nullptr;
      bool mask = false;
      for (const PinDef& pin : node.type->outputs) {
        value = mPreview.Value(node.id, pin.name);
        if (value != nullptr && value->grid != nullptr) {
          mask = pin.type == PinType::Mask;
          break;
        }
        value = nullptr;
      }
      if (value == nullptr && node.type->category == "outputs") {
        value = mPreview.Input(*mGraph, node.id, "a");
      }
      if (value == nullptr || value->grid == nullptr || value->grid->w < 2) {
        continue;
      }
      field::Downsample(*value->grid, kThumbSize, kThumbSize, small);
      if (small.size() != pixels.size()) {
        continue;
      }
      const auto [lo, hi] = std::minmax_element(small.begin(), small.end());
      const float span = std::max(1e-6f, *hi - *lo);
      for (std::size_t k = 0; k < pixels.size(); ++k) {
        const float t = mask ? small[k] : (small[k] - *lo) / span;
        pixels[k] = mask ? Grey(t) : HeightColour(t);
      }
      mThumbs[node.id].image = EdImGuiRenderer::CreateImage(kThumbSize, kThumbSize, pixels.data());
    }
  }

  void EdGenerate::Tick(
    const float seconds,
    const bool mapOpen
  )
  {
    if (!mapOpen) {
      mShownOnMap = false;
      return;
    }
    const std::string key = std::to_string(mGraph->Changes()) + "|" +
      std::to_string(reinterpret_cast<std::uintptr_t>(mGraph.get())) + "|" + std::to_string(mSeed) + "|" +
      std::to_string(mPreviewCap) + "|" + mSymmetry + "|" + (mShowOnMap ? "on" : "off");
    if (key != mPendingKey) {
      mPendingKey = key;
      mRest = 0.0f;
    }
    mRest += seconds;
    if (mRefreshAsked || (key != mEvaluatedKey && mRest >= 0.35f)) {
      mRefreshAsked = false;
      mEvaluatedKey = key;
      Evaluate();
    }
    // The variations follow the graph, its seed and its symmetry once a change has rested.
    const std::string galleryKey = std::to_string(mGraph->Changes()) + "|" +
      std::to_string(reinterpret_cast<std::uintptr_t>(mGraph.get())) + "|" + std::to_string(mSeed) + "|" + mSymmetry;
    if (mGalleryShown && galleryKey != mGalleryKey && mRest >= 0.35f) {
      mGalleryKey = galleryKey;
      UpdateGallery();
    }
    if (!mShowOnMap && mShownOnMap && !mAsked) {
      mAsk = HeightsAsk{};
      mAsk.kind = HeightsAsk::Kind::Revert;
      mAsked = true;
      mShownOnMap = false;
    }
    if (mBuildAsked && !mAsked) {
      mBuildAsked = false;
      TerrainGround ground;
      if (!mGround || !mGround(ground)) {
        mStatus = "Open a map: the graph runs on its ground.";
        return;
      }
      ground.graphSymmetry = mSymmetry;
      TerrainRun full(1);
      const TerrainReport report = full.Evaluate(*mGraph, mSeed, ground);
      field::Grid heights;
      bool plain = true;
      const bool hasHeights = report.errors.empty() && full.FinalHeight(*mGraph, ground, heights, &plain);
      // What it writes besides the heights, on the heights it is built with (the map's when the graph writes none).
      TerrainBuildWrites writes;
      std::string paintError;
      const field::Grid shape = hasHeights ? heights : field::Grid(ground.width, ground.height, 1.0f, 0.0f, 0.0f);
      const bool collected =
        report.errors.empty() && ground.hasPaint && full.BuildWrites(*mGraph, ground, shape, writes, paintError);
      const bool hasPaint = collected && !writes.Empty();
      if (!report.errors.empty()) {
        mStatus = "Build stopped: " + std::to_string(report.errors.size()) + " node(s) have errors (" +
          report.errors.begin()->second + ").";
      } else if (!paintError.empty()) {
        mStatus = "Build stopped: the ground kinds couldn't be resolved (" + paintError + ").";
      } else if (!hasHeights && !hasPaint) {
        mStatus = "Nothing to build: no output node with an input.";
        // Why an output wrote nothing ("Output: roughness / height atlas: the map's shader reads no atlas ...").
        for (const std::string& note : writes.notes) {
          mStatus += " " + note + ".";
        }
        gpg::Logf("editor: generate: %s", mStatus.c_str());
      } else {
        mAsk = HeightsAsk{HeightsAsk::Kind::Build, hasHeights ? std::move(heights) : field::Grid{}, plain};
        mAsk.writes = std::move(writes);
        mAsked = true;
        mShowOnMap = false;
        mShownOnMap = false;
        // The preview's key is the same: the run after Build doesn't put a preview back.
        mEvaluatedKey = mPendingKey = std::to_string(mGraph->Changes()) + "|" +
          std::to_string(reinterpret_cast<std::uintptr_t>(mGraph.get())) + "|" + std::to_string(mSeed) + "|" +
          std::to_string(mPreviewCap) + "|" + mSymmetry + "|off";
        char text[128];
        (void)std::snprintf(
          text, sizeof(text), "Built at full resolution: %d nodes in %.0f ms.", report.evaluated, report.ms
        );
        mStatus = text;
        gpg::Logf("editor: generate: %s", text);
      }
    }
  }

  bool EdGenerate::TakeHeightsAsk(
    HeightsAsk& out
  )
  {
    if (!mAsked) {
      return false;
    }
    mAsked = false;
    out = std::move(mAsk);
    mAsk = HeightsAsk{};
    return true;
  }

  // ---- panels -----------------------------------------------------------------------------------------------------

  void EdGenerate::DrawNodesPanel(
    bool& open
  )
  {
    FreeRetired();
    if (!ImGui::Begin(Panel("Nodes###GenerateNodes"), &open)) {
      ImGui::End();
      return;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##search", "Search nodes", mFilter, sizeof(mFilter));
    const std::string needle = Lower(mFilter);
    for (const auto& [category, title] : TerrainCategories()) {
      std::vector<const NodeType*> types;
      for (const auto& type : TerrainNodeTypes().All()) {
        if (type->category != category) {
          continue;
        }
        if (
          !needle.empty() &&
          Lower(type->title + " " + type->name + " " + title + " " + type->help).find(needle) == std::string::npos
        ) {
          continue;
        }
        types.push_back(type.get());
      }
      if (types.empty()) {
        continue;
      }
      ImGui::SetNextItemOpen(category != "raw", ImGuiCond_Once);
      if (!needle.empty()) {
        ImGui::SetNextItemOpen(true);
      }
      if (!ImGui::TreeNodeEx(title.c_str(), ImGuiTreeNodeFlags_SpanAvailWidth)) {
        continue;
      }
      for (const NodeType* type : types) {
        ImGui::Selectable(type->title.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          (void)mCanvas.AddAtCentre(*mGraph, type->name);
        }
        if (ImGui::BeginDragDropSource()) {
          ImGui::SetDragDropPayload(EdNodeCanvas::kPalettePayload, type->name.data(), type->name.size());
          ImGui::TextUnformatted(type->title.c_str());
          ImGui::EndDragDropSource();
        }
        EdSetItemTooltip("%s\n\nDouble-click or drag into the graph.", type->help.c_str());
      }
      ImGui::TreePop();
    }
    ImGui::End();
  }

  void EdGenerate::DrawGraphMenu()
  {
    if (!ImGui::BeginPopup("##graphs")) {
      return;
    }
    if (ImGui::MenuItem("New graph")) {
      NewGraph();
    }
    if (ImGui::MenuItem("Save")) {
      Save();
    }
    ImGui::SeparatorText("Sample graphs");
    for (const ShippedGraph& graph : ShippedTerrainGraphs()) {
      if (!graph.library && ImGui::MenuItem(graph.name.c_str())) {
        mNote = graph.note;
        Open(graph.name, graph.text, true);
      }
      if (!graph.library) {
        EdSetItemTooltip("%s", graph.note.c_str());
      }
    }
    if (ImGui::BeginMenu("Competitive layouts")) {
      for (const ShippedGraph& graph : ShippedTerrainGraphs()) {
        if (graph.library && ImGui::MenuItem(graph.name.c_str())) {
          mNote = graph.note;
          Open(graph.name, graph.text, true);
        }
        if (graph.library) {
          EdSetItemTooltip("%s", graph.note.c_str());
        }
      }
      ImGui::EndMenu();
    }
    std::error_code error;
    if (std::filesystem::is_directory(OwnFolder(), error)) {
      ImGui::SeparatorText("Saved");
      for (const auto& entry : std::filesystem::directory_iterator(OwnFolder(), error)) {
        const std::string file = entry.path().filename().string();
        if (file.size() <= std::strlen(kExtension) || file.rfind(kExtension) != file.size() - std::strlen(kExtension)) {
          continue;
        }
        const std::string name = file.substr(0, file.size() - std::strlen(kExtension));
        if (ImGui::MenuItem(name.c_str())) {
          std::ifstream in(entry.path(), std::ios::binary);
          std::stringstream text;
          text << in.rdbuf();
          mNote.clear();
          Open(name, text.str(), false);
        }
      }
    }
    ImGui::EndPopup();
  }

  void EdGenerate::DrawToolbar()
  {
    if (ImGui::Button((mName + "  " ICON_CHEVRON "##graphbutton").c_str())) {
      ImGui::OpenPopup("##graphs");
    }
    EdSetItemTooltip("Open a sample graph or a saved one, start a new graph, save this one.");
    DrawGraphMenu();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(110.0f));
    (void)FillDragInt("##seed", &mSeed, 0.2f, 0, 999999, "Seed %d");
    EdSetItemTooltip("The graph's seed: every noise and erosion in it takes its own seed from this one.");
    ImGui::SameLine();
    if (ImGui::Button("Next seed")) {
      ++mSeed;
    }
    ImGui::SameLine();
    static constexpr const char* kSizes[] = {"Preview 257", "Preview 513", "Preview at full size"};
    ImGui::SetNextItemWidth(Em(150.0f));
    (void)EdCombo("##previewsize", &mPreviewCap, kSizes, IM_ARRAYSIZE(kSizes));
    EdSetItemTooltip("How many samples a side the preview runs on (the map's own size can be slow with erosion).");
    ImGui::SameLine();
    {
      const std::vector<GraphSymmetryChoice>& choices = GraphSymmetryChoices();
      const char* shown = mSymmetry.c_str();
      for (const GraphSymmetryChoice& choice : choices) {
        if (mSymmetry == choice.id) {
          shown = choice.label;
        }
      }
      ImGui::SetNextItemWidth(Em(210.0f));
      if (EdBeginCombo("##graphsymmetry", (std::string("Symmetry: ") + shown).c_str())) {
        for (const GraphSymmetryChoice& choice : choices) {
          if (ImGui::Selectable(choice.label, mSymmetry == choice.id)) {
            mSymmetry = choice.id;
          }
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip(
        "The symmetry of the result: the heights, the paint and the terrain types are made symmetric where the graph "
        "writes them (the master part copied over the rest), so erosion and noise after a Symmetrize node can't break "
        "it. Scattered props aren't mirrored. \"Follow the map\" takes the editor's symmetry (the toolbar's)."
      );
    }
    ImGui::SameLine();
    ImGui::Checkbox("Show on the map", &mShowOnMap);
    EdSetItemTooltip(
      "The preview on the terrain as one undo step, replaced by the next one; Revert or unticking takes it off."
    );
    ImGui::SameLine();
    if (PrimaryButton("Build")) {
      mBuildAsked = true;
    }
    EdSetItemTooltip("Runs the graph at the map's full resolution and writes the heights as one undo step.");
    ImGui::SameLine();
    ImGui::BeginDisabled(!mShownOnMap);
    if (ImGui::Button("Revert")) {
      mShowOnMap = false;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Run again")) {
      mPreview.Clear();
      mRefreshAsked = true;
    }
    EdSetItemTooltip("Runs every node again, with the map's ground as it is now.");
    if (!mStatus.empty()) {
      // Wrapped: a build's status names everything it wrote and left out.
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", mStatus.c_str());
      ImGui::PopTextWrapPos();
    }
  }

  void EdGenerate::DrawGraphPanel(
    bool& open
  )
  {
    FreeRetired();
    if (!ImGui::Begin(
          Panel("Graph###GenerateGraph"), &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
        )) {
      ImGui::End();
      return;
    }
    DrawToolbar();
    if (
      ImGui::BeginChild(
        "##canvas",
        ImVec2(0.0f, 0.0f),
        ImGuiChildFlags_Borders,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMove
      )
    ) {
      (void)mCanvas.Draw(*mGraph);
    }
    ImGui::EndChild();
    ImGui::End();
  }

  void EdGenerate::DrawParams(
    GraphNode& node
  )
  {
    const NodeType& type = *node.type;
    const int id = node.id;
    for (std::size_t p = 0; p < type.params.size(); ++p) {
      const ParamDef& def = type.params[p];
      ParamValue value = mGraph->Find(id)->params[p];
      const std::string label = def.label.empty() ? def.name : def.label;
      bool linked = false;
      if (def.wire) {
        for (std::size_t pin = 0; pin < type.inputs.size(); ++pin) {
          if (type.inputs[pin].name == def.name && mGraph->InputLink(id, static_cast<int>(pin)) != nullptr) {
            linked = true;
          }
        }
      }
      bool changed = false;
      ImGui::PushID(static_cast<int>(p));
      ImGui::BeginDisabled(linked);
      switch (def.kind) {
      case ParamKind::Bool: {
        bool v = value.value[0] >= 0.5f;
        changed = ImGui::Checkbox(label.c_str(), &v);
        value.value[0] = v ? 1.0f : 0.0f;
        break;
      }
      case ParamKind::Choice: {
        ImGui::TextDisabled("%s", label.c_str());
        const int v =
          std::clamp(static_cast<int>(value.value[0] + 0.5f), 0, std::max(0, static_cast<int>(def.choices.size()) - 1));
        ImGui::SetNextItemWidth(-1.0f);
        if (EdBeginCombo("##choice", def.choices.empty() ? "?" : def.choices[static_cast<std::size_t>(v)].c_str())) {
          for (std::size_t c = 0; c < def.choices.size(); ++c) {
            if (ImGui::Selectable(def.choices[c].c_str(), static_cast<int>(c) == v)) {
              value.value[0] = static_cast<float>(c);
              changed = true;
            }
          }
          ImGui::EndCombo();
        }
        break;
      }
      case ParamKind::Text: {
        ImGui::TextDisabled("%s", label.c_str());
        char buffer[512];
        (void)std::snprintf(buffer, sizeof(buffer), "%s", value.text.c_str());
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputText("##text", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
          value.text = buffer;
          changed = true;
        }
        break;
      }
      default: {
        const std::string format = Escaped(label) + "  " + (def.format.empty() ? "%.3f" : def.format);
        ImGui::SetNextItemWidth(-1.0f);
        changed = FillSliderFloat("##number", &value.value[0], def.min, def.max, format.c_str());
        break;
      }
      }
      ImGui::EndDisabled();
      if (linked) {
        EdSetItemTooltip("Linked: the number pin of the same name drives it.");
      } else if (!def.help.empty()) {
        EdSetItemTooltip("%s", def.help.c_str());
      }
      ImGui::PopID();
      if (changed) {
        mGraph->SetParam(id, p, value);
      }
    }
    if (type.params.empty()) {
      ImGui::TextDisabled("This node has no settings.");
    }
  }

  void EdGenerate::DrawInspectorPanel(
    bool& open
  )
  {
    if (!ImGui::Begin(Panel("Inspector###GenerateInspector"), &open)) {
      ImGui::End();
      return;
    }
    const std::set<int>& selection = mCanvas.Selection();
    GraphNode* node = selection.size() == 1 ? mGraph->Find(*selection.begin()) : nullptr;
    if (node != nullptr) {
      ImGui::TextColored(ImVec4(0.95f, 0.85f, 0.55f, 1.0f), "%s", node->type->title.c_str());
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", node->type->help.c_str());
      ImGui::PopTextWrapPos();
      if (const std::string error = mPreview.Error(node->id); !error.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.4f, 1.0f), "%s", error.c_str());
        ImGui::PopTextWrapPos();
      }
      ImGui::Spacing();
      DrawParams(*node);
      ImGui::Spacing();
      ImGui::TextDisabled("Ran in %.1f ms", mPreview.NodeMs(node->id));
    } else {
      ImGui::SeparatorText("Graph");
      ImGui::TextUnformatted(mName.c_str());
      ImGui::PushTextWrapPos(0.0f);
      if (!mNote.empty()) {
        ImGui::TextDisabled("%s", mNote.c_str());
      }
      if (!mLoadNote.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.3f, 1.0f), "%s", mLoadNote.c_str());
      }
      ImGui::PopTextWrapPos();
      ImGui::Text("%zu nodes, %zu links", mGraph->Nodes().size(), mGraph->Links().size());
      if (!mReport.errors.empty()) {
        ImGui::SeparatorText("Errors");
        for (const auto& [id, error] : mReport.errors) {
          const GraphNode* n = mGraph->Find(id);
          if (
            ImGui::Selectable(
              (std::string(n != nullptr ? n->type->title : "?") + ": " + error + "##" + std::to_string(id)).c_str()
            )
          ) {
            mCanvas.Select(id);
          }
        }
      }
      ImGui::Spacing();
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled(
        "Select a node to edit its settings. Right-click the graph or drop a link on empty space to add a node; the "
        "wheel "
        "zooms, the right button drags the view, F frames, Del removes, Ctrl+D duplicates."
      );
      ImGui::PopTextWrapPos();
    }
    ImGui::SeparatorText("Variations");
    ImGui::SetNextItemWidth(-1.0f);
    (void)FillDragInt("##varseed", &mSeed, 0.2f, 0, 999999, "Seed %d");
    if (ImGui::Button("Previous") && mSeed > 0) {
      --mSeed;
    }
    ImGui::SameLine();
    if (ImGui::Button("Next")) {
      ++mSeed;
    }
    ImGui::SameLine();
    if (ImGui::Button("Random")) {
      mSeed = static_cast<int>((static_cast<unsigned>(mSeed) * 2654435761u + 12345u) % 100000u);
    }
    ImGui::Checkbox("Show six seeds", &mGalleryShown);
    EdSetItemTooltip("The result for this seed and the next five as small pictures; a click takes that seed.");
    if (mGalleryShown) {
      DrawGallery();
    }
    ImGui::End();
  }

  void EdGenerate::UpdateGallery()
  {
    for (const GalleryItem& item : mGallery) {
      if (item.image != 0) {
        mRetired.push_back(item.image);
      }
    }
    mGallery.clear();
    TerrainGround ground;
    if (!mGround || !mGround(ground)) {
      return;
    }
    ground.graphSymmetry = mSymmetry;
    constexpr int kSize = 64;
    const auto t0 = std::chrono::steady_clock::now();
    const int step = ErosionPreviewStep(ground.width, ground.height, 129);
    std::vector<float> small;
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSize) * kSize);
    int made = 0;
    for (int i = 0; i < 6; ++i) {
      GalleryItem item;
      item.seed = mSeed + i;
      TerrainRun run(step);
      const TerrainReport report = run.Evaluate(*mGraph, item.seed, ground);
      field::Grid heights;
      const bool hasHeights = report.errors.empty() && run.FinalHeight(*mGraph, ground, heights);
      item.noHeights = report.errors.empty() && !hasHeights;
      if (hasHeights && heights.w > 1) {
        field::Downsample(heights, kSize, kSize, small);
        if (small.size() == pixels.size()) {
          const auto [lo, hi] = std::minmax_element(small.begin(), small.end());
          const float span = std::max(1e-6f, *hi - *lo);
          for (std::size_t k = 0; k < pixels.size(); ++k) {
            pixels[k] = HeightColour((small[k] - *lo) / span);
          }
          item.image = EdImGuiRenderer::CreateImage(kSize, kSize, pixels.data());
          made += item.image != 0 ? 1 : 0;
        }
      }
      mGallery.push_back(item);
    }
    gpg::Logf(
      "editor: generate: variations for seeds %d to %d: %d pictures in %.0f ms",
      mSeed,
      mSeed + 5,
      made,
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count()
    );
  }

  void EdGenerate::DrawGallery()
  {
    if (mGallery.empty()) {
      ImGui::TextDisabled("Working out the variations...");
      return;
    }
    if (std::all_of(mGallery.begin(), mGallery.end(), [](const GalleryItem& item) {
      return item.noHeights;
    })) {
      ImGui::TextDisabled("The graph writes no heights: there is nothing to picture.");
      return;
    }
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const float size = std::max(Em(40.0f), (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f);
    for (std::size_t i = 0; i < mGallery.size(); ++i) {
      const GalleryItem& item = mGallery[i];
      if (i % 3 != 0) {
        ImGui::SameLine();
      }
      ImGui::BeginGroup();
      ImGui::PushID(static_cast<int>(i));
      const bool current = item.seed == mSeed;
      if (item.image != 0) {
        // The button adds its frame padding around the picture.
        const float picture = std::max(8.0f, size - ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::ImageButton("##variation", static_cast<ImTextureID>(item.image), ImVec2(picture, picture))) {
          mSeed = item.seed;
        }
      } else {
        ImGui::Button("failed", ImVec2(size, size));
      }
      if (current) {
        ImGui::GetWindowDrawList()->AddRect(
          ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), ImGui::GetColorU32(ImGuiCol_CheckMark), 2.0f, 0, 2.0f
        );
      }
      EdSetItemTooltip(item.image != 0 ? "Click to use this seed" : "The graph has errors with this seed");
      ImGui::TextDisabled("%s%d", current ? "> " : "", item.seed);
      ImGui::PopID();
      ImGui::EndGroup();
    }
  }
} // namespace faf::editor
