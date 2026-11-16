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
      if (studio) {
        const auto read = ReadStudioGraph(text, *graph);
        if (!read) {
          mStatus = "Can't read " + name + ": " + read.error();
          return;
        }
        const StudioGraphFacts& facts = *read;
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
        if (const auto loaded = LoadTerrainGraph(text, *graph, mSeed, savedName, &mSymmetry); !loaded) {
          mStatus = "Can't read " + name + ": " + loaded.error();
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
    mUndo.clear();
    mRedo.clear();
    mUndoTop.clear();
    mUndoChanges = ~std::uint64_t{0};
    if (mMaskNode != 0) {
      ShowAsMask(0);
    }
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

  std::string EdGenerate::GraphText() const
  {
    return SaveTerrainGraph(*mGraph, mSeed, mName, mSymmetry);
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
    UpdateMaskShown();
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
    TrackUndo();
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
      mBuilt = true;
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
      bool collected = false;
      if (report.errors.empty() && ground.hasPaint) {
        const auto built = full.BuildWrites(*mGraph, ground, shape, writes);
        collected = built.has_value();
        if (!built) {
          paintError = built.error();
        }
      }
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
          !needle.empty() && !Lower(type->title + " " + type->name + " " + title + " " + type->help).contains(needle)
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
        "it. Scattered props and decals are placed in its first part with their copies. \"Follow the map\" takes "
        "the editor's symmetry (the toolbar's)."
      );
    }
    SameLineIfFits(CheckboxWidth("Show on the map"));
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
    SameLineIfFits(ButtonWidth(ICON_UNDO));
    ImGui::BeginDisabled(mUndo.empty());
    if (ImGui::Button(ICON_UNDO "##graphundo")) {
      Undo();
    }
    ImGui::EndDisabled();
    EdSetItemTooltip("Undo the last graph edit (Ctrl+Z over the graph)");
    SameLineIfFits(ButtonWidth(ICON_REDO));
    ImGui::BeginDisabled(mRedo.empty());
    if (ImGui::Button(ICON_REDO "##graphredo")) {
      Redo();
    }
    ImGui::EndDisabled();
    EdSetItemTooltip("Redo (Ctrl+Y over the graph)");
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
    mGraphFocused = false;
    if (!ImGui::Begin(
          Panel("Graph###GenerateGraph"), &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
        )) {
      ImGui::End();
      return;
    }
    mGraphFocused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    if (mGraphFocused && !ImGui::IsAnyItemActive()) {
      const ImGuiIO& io = ImGui::GetIO();
      if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z)) {
        if (io.KeyShift) {
          Redo();
        } else {
          Undo();
        }
      } else if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Y)) {
        Redo();
      }
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

  void EdGenerate::TrackUndo()
  {
    // A drag or a slider is one step: taken when the mouse is up and nothing is being edited.
    if (!mGraph || ImGui::IsMouseDown(ImGuiMouseButton_Left) || ImGui::IsAnyItemActive()) {
      return;
    }
    if (mGraph->Changes() == mUndoChanges) {
      return;
    }
    std::string now = mGraph->Save();
    if (mUndoChanges != ~std::uint64_t{0} && now != mUndoTop) {
      mUndo.push_back(std::move(mUndoTop));
      if (mUndo.size() > 200) {
        mUndo.erase(mUndo.begin());
      }
      mRedo.clear();
    }
    mUndoTop = std::move(now);
    mUndoChanges = mGraph->Changes();
  }

  void EdGenerate::Undo()
  {
    TrackUndo();
    if (mUndo.empty()) {
      return;
    }
    mRedo.push_back(std::move(mUndoTop));
    mUndoTop = std::move(mUndo.back());
    mUndo.pop_back();
    (void)mGraph->Restore(mUndoTop);
    mUndoChanges = mGraph->Changes();
    gpg::Logf("editor: generate: undo (%zu left)", mUndo.size());
  }

  void EdGenerate::Redo()
  {
    if (mRedo.empty()) {
      return;
    }
    mUndo.push_back(std::move(mUndoTop));
    mUndoTop = std::move(mRedo.back());
    mRedo.pop_back();
    (void)mGraph->Restore(mUndoTop);
    mUndoChanges = mGraph->Changes();
    gpg::Logf("editor: generate: redo (%zu left)", mRedo.size());
  }

  bool EdGenerate::GraphKeepsChord(
    const std::string& chord
  ) const
  {
    if (!mGraphFocused) {
      return false;
    }
    for (const char* const kept :
         {"Ctrl+Z", "Ctrl+Y", "Ctrl+Shift+Z", "Ctrl+C", "Ctrl+V", "Ctrl+X", "Ctrl+D", "Delete", "Backspace", "F"}) {
      if (chord == kept) {
        return true;
      }
    }
    return false;
  }

  void EdGenerate::ShowAsMask(
    const int node
  )
  {
    mMaskNode = node;
    mMaskFrom.reset();
    if (node == 0) {
      mMaskGrid = field::Grid{};
      mMaskAsked = true;
      return;
    }
    UpdateMaskShown();
  }

  bool EdGenerate::TakeMaskAsk(
    field::Grid& out
  )
  {
    if (!std::exchange(mMaskAsked, false)) {
      return false;
    }
    out = mMaskNode != 0 ? mMaskGrid : field::Grid{};
    return true;
  }

  void EdGenerate::UpdateMaskShown()
  {
    if (mMaskNode == 0 || !mGraph) {
      return;
    }
    const GraphNode* node = mGraph->Find(mMaskNode);
    if (node == nullptr) {
      ShowAsMask(0);
      return;
    }
    const TerrainValue* value = nullptr;
    for (const PinDef& pin : node->type->outputs) {
      if (const TerrainValue* v = mPreview.Value(node->id, pin.name); v != nullptr && v->grid != nullptr) {
        value = v;
        break;
      }
    }
    if (value == nullptr || value->grid == mMaskFrom) {
      return; // not run yet, or the same result
    }
    mMaskFrom = value->grid;
    mMaskGrid = *value->grid;
    // A height or another range: shown as 0..1 of its own range.
    float lo = 1e30f;
    float hi = -1e30f;
    for (const float v : mMaskGrid.v) {
      lo = std::min(lo, v);
      hi = std::max(hi, v);
    }
    if ((lo < 0.0f || hi > 1.0f) && hi > lo) {
      for (float& v : mMaskGrid.v) {
        v = (v - lo) / (hi - lo);
      }
    }
    mMaskAsked = true;
    gpg::Logf(
      "editor: generate: node %d shown as a mask (%d x %d, range %.2f..%.2f)",
      mMaskNode,
      mMaskGrid.w,
      mMaskGrid.h,
      static_cast<double>(lo),
      static_cast<double>(hi)
    );
  }

  namespace
  {
    /**
     * The remap node's curve as a small editor (FAF Studio's curve inspector): drag a point, double-click adds one,
     * right-click removes one; the ends stay at x 0 and 1. True when `text` changed.
     */
    bool CurveEditor(
      std::string& text
    )
    {
      std::vector<std::pair<float, float>> points;
      {
        std::istringstream in(text);
        float x = 0.0f;
        float y = 0.0f;
        while (in >> x >> y) {
          points.emplace_back(std::clamp(x, 0.0f, 1.0f), std::clamp(y, 0.0f, 1.0f));
        }
      }
      if (points.size() < 2) {
        points = {{0.0f, 0.0f}, {1.0f, 1.0f}};
      }
      std::sort(points.begin(), points.end());
      const float side = std::max(Em(80.0f), std::min(ImGui::GetContentRegionAvail().x, Em(220.0f)));
      const ImVec2 a = ImGui::GetCursorScreenPos();
      const ImVec2 b(a.x + side, a.y + side);
      ImGui::InvisibleButton(
        "##curve", ImVec2(side, side), ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight
      );
      const bool hovered = ImGui::IsItemHovered();
      const bool active = ImGui::IsItemActive();
      ImDrawList* dl = ImGui::GetWindowDrawList();
      dl->AddRectFilled(a, b, IM_COL32(28, 28, 30, 255));
      for (int i = 1; i < 4; ++i) {
        const float t = side * static_cast<float>(i) / 4.0f;
        dl->AddLine(ImVec2(a.x + t, a.y), ImVec2(a.x + t, b.y), IM_COL32(50, 50, 54, 255));
        dl->AddLine(ImVec2(a.x, a.y + t), ImVec2(b.x, a.y + t), IM_COL32(50, 50, 54, 255));
      }
      dl->AddLine(ImVec2(a.x, b.y), ImVec2(b.x, a.y), IM_COL32(70, 70, 74, 255));
      dl->AddRect(a, b, IM_COL32(90, 90, 96, 255));
      const auto toScreen = [&](const float x, const float y) {
        return ImVec2(a.x + x * side, b.y - y * side);
      };
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      const float mx = std::clamp((mouse.x - a.x) / side, 0.0f, 1.0f);
      const float my = std::clamp((b.y - mouse.y) / side, 0.0f, 1.0f);
      int hover = -1;
      for (std::size_t i = 0; i < points.size(); ++i) {
        const ImVec2 p = toScreen(points[i].first, points[i].second);
        if (std::hypot(p.x - mouse.x, p.y - mouse.y) <= Em(7.0f)) {
          hover = static_cast<int>(i);
        }
      }
      ImGuiStorage* storage = ImGui::GetStateStorage();
      const ImGuiID dragKey = ImGui::GetID("##curvedrag");
      int drag = storage->GetInt(dragKey, -1);
      bool changed = false;
      if (ImGui::IsItemActivated() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        drag = hover;
      }
      const int last = static_cast<int>(points.size()) - 1;
      if (active && drag >= 0 && drag <= last) {
        float x = mx;
        if (drag == 0) {
          x = 0.0f;
        } else if (drag == last) {
          x = 1.0f;
        } else {
          x = std::clamp(mx, points[drag - 1].first + 0.01f, points[drag + 1].first - 0.01f);
        }
        if (points[drag].first != x || points[drag].second != my) {
          points[drag] = {x, my};
          changed = true;
        }
      }
      if (!active) {
        drag = -1;
      }
      storage->SetInt(dragKey, drag);
      if (hovered && hover < 0 && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        points.emplace_back(mx, my);
        std::sort(points.begin(), points.end());
        changed = true;
      }
      if (hovered && hover > 0 && hover < last && ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
        points.erase(points.begin() + hover);
        changed = true;
      }
      for (std::size_t i = 0; i + 1 < points.size(); ++i) {
        dl->AddLine(
          toScreen(points[i].first, points[i].second),
          toScreen(points[i + 1].first, points[i + 1].second),
          IM_COL32(250, 200, 80, 255),
          2.0f
        );
      }
      for (std::size_t i = 0; i < points.size(); ++i) {
        dl->AddCircleFilled(
          toScreen(points[i].first, points[i].second),
          Em(4.0f),
          static_cast<int>(i) == hover ? IM_COL32(255, 255, 255, 255) : IM_COL32(250, 200, 80, 255)
        );
      }
      if (changed) {
        text.clear();
        char pair[48];
        for (const auto& [x, y] : points) {
          (void)std::snprintf(
            pair, sizeof(pair), "%s%.3g %.3g", text.empty() ? "" : " ", static_cast<double>(x), static_cast<double>(y)
          );
          text += pair;
        }
      }
      return changed;
    }

    /** The scatter's "blueprint:weight" list (';' or new lines between). */
    std::vector<std::pair<std::string, int>> ScatterEntries(
      const std::string& text
    )
    {
      std::vector<std::pair<std::string, int>> entries;
      std::size_t at = 0;
      while (at < text.size()) {
        const std::size_t end = std::min(text.find_first_of(";\n", at), text.size());
        std::string item = text.substr(at, end - at);
        at = end + 1;
        item.erase(0, item.find_first_not_of(" \t\r"));
        item.erase(item.find_last_not_of(" \t\r") + 1);
        if (item.empty()) {
          continue;
        }
        int weight = 100;
        if (
          const std::size_t colon = item.rfind(':'); colon != std::string::npos && colon + 1 < item.size() &&
          std::isdigit(static_cast<unsigned char>(item[colon + 1])) != 0
        ) {
          weight = std::max(1, std::atoi(item.c_str() + colon + 1));
          item.resize(colon);
        }
        entries.emplace_back(item, weight);
      }
      return entries;
    }
  } // namespace

  void EdGenerate::DrawNodeHead(
    GraphNode& node
  )
  {
    const int id = node.id;
    char name[128];
    (void)std::snprintf(name, sizeof(name), "%s", node.name.c_str());
    ImGui::SetNextItemWidth(-1.0f);
    (void)ImGui::InputTextWithHint("##nodename", ("Name: " + node.type->title).c_str(), name, sizeof(name));
    if (ImGui::IsItemDeactivatedAfterEdit()) {
      mGraph->SetName(id, name);
    }
    EdSetItemTooltip("The node's own name on its title bar (empty: the type's)");
    bool wrote = false;
    if (!node.type->inputs.empty() && !node.type->outputs.empty()) {
      bool bypass = node.bypass;
      if (ImGui::Checkbox("Bypass", &bypass)) {
        mGraph->SetBypass(id, bypass);
      }
      EdSetItemTooltip(
        "Passes the first input linked in straight through to the outputs, as if the node weren't there"
      );
      wrote = true;
    }
    if (!node.type->outputs.empty()) {
      const bool shown = mMaskNode == id;
      const char* const label = shown ? "Take it off the map" : "Show on the map as a mask";
      if (wrote) {
        SameLineIfFits(ButtonWidth(label));
      }
      if (ImGui::Button(label)) {
        ShowAsMask(shown ? 0 : id);
      }
      EdSetItemTooltip("The node's first output on the terrain in red, scaled to its own range (the preview's run)");
    }
  }

  void EdGenerate::DrawNodeHelpers(
    GraphNode& node,
    const int part
  )
  {
    const NodeType& type = *node.type;
    const int id = node.id;
    const auto paramIndex = [&type](const char* name) -> int {
      for (std::size_t p = 0; p < type.params.size(); ++p) {
        if (type.params[p].name == name) {
          return static_cast<int>(p);
        }
      }
      return -1;
    };
    if (part == 1 && type.name == "remap") {
      if (const int p = paramIndex("points"); p >= 0) {
        ImGui::SeparatorText("Curve");
        std::string text = node.params[static_cast<std::size_t>(p)].text;
        if (CurveEditor(text)) {
          ParamValue value = node.params[static_cast<std::size_t>(p)];
          value.text = text;
          mGraph->SetParam(id, static_cast<std::size_t>(p), value);
        }
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled("Drag a point; double-click adds one, right-click removes one.");
        ImGui::PopTextWrapPos();
      }
    }
    if (part == 0 && type.name.starts_with("erode_")) {
      const std::string solver = type.name.substr(6);
      bool first = true;
      for (const ErosionPreset& preset : ErosionPresets()) {
        if (solver != preset.solver) {
          continue;
        }
        if (first) {
          ImGui::SeparatorText("Presets");
          first = false;
        } else {
          SameLineIfFits(ButtonWidth(preset.label));
        }
        if (ImGui::Button(preset.label)) {
          const ErosionValues values = ErosionPresetValues(preset);
          for (std::size_t p = 0; p < type.params.size(); ++p) {
            if (const auto found = values.find(type.params[p].name); found != values.end()) {
              ParamValue value = node.params[p];
              value.value[0] = static_cast<float>(found->second);
              mGraph->SetParam(id, p, value);
            }
          }
          gpg::Logf("editor: generate: erosion preset %s on node %d", preset.id, id);
        }
      }
    }
    if (part == 1 && type.name == "out_scatter") {
      if (const int p = paramIndex("entries"); p >= 0) {
        ImGui::SeparatorText("Blueprints and weights");
        std::vector<std::pair<std::string, int>> entries =
          ScatterEntries(node.params[static_cast<std::size_t>(p)].text);
        int total = 0;
        for (const auto& entry : entries) {
          total += entry.second;
        }
        bool changed = false;
        int remove = -1;
        if (
          !entries.empty() &&
          ImGui::BeginTable("##scatterlist", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerH)
        ) {
          ImGui::TableSetupColumn("Blueprint", ImGuiTableColumnFlags_WidthStretch);
          ImGui::TableSetupColumn("Weight", ImGuiTableColumnFlags_WidthFixed, Em(110.0f));
          ImGui::TableSetupColumn("##x", ImGuiTableColumnFlags_WidthFixed, Em(24.0f));
          for (std::size_t i = 0; i < entries.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char blueprint[256];
            (void)std::snprintf(blueprint, sizeof(blueprint), "%s", entries[i].first.c_str());
            ImGui::SetNextItemWidth(-1.0f);
            (void)ImGui::InputText("##bp", blueprint, sizeof(blueprint));
            if (ImGui::IsItemDeactivatedAfterEdit() && blueprint[0] != '\0') {
              entries[i].first = blueprint;
              changed = true;
            }
            ImGui::TableNextColumn();
            ImGui::SetNextItemWidth(-1.0f);
            const std::string share = "%d (" + std::to_string(total > 0 ? entries[i].second * 100 / total : 0) + "%%)";
            if (ImGui::DragInt("##w", &entries[i].second, 1.0f, 1, 1000, share.c_str())) {
              changed = true;
            }
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("x")) {
              remove = static_cast<int>(i);
            }
            ImGui::PopID();
          }
          ImGui::EndTable();
        }
        if (remove >= 0) {
          entries.erase(entries.begin() + remove);
          changed = true;
        }
        ImGui::SetNextItemWidth(-Em(60.0f));
        (void)ImGui::InputTextWithHint("##scatteradd", "Blueprint to add (.bp)", mScatterAdd, sizeof(mScatterAdd));
        ImGui::SameLine();
        ImGui::BeginDisabled(mScatterAdd[0] == '\0');
        if (ImGui::Button("Add##scatteradd")) {
          entries.emplace_back(mScatterAdd, 100);
          mScatterAdd[0] = '\0';
          changed = true;
        }
        ImGui::EndDisabled();
        if (changed) {
          std::string text;
          for (const auto& [blueprint, weight] : entries) {
            text += (text.empty() ? "" : ";") + blueprint + ":" + std::to_string(std::max(1, weight));
          }
          ParamValue value = node.params[static_cast<std::size_t>(p)];
          value.text = text;
          mGraph->SetParam(id, static_cast<std::size_t>(p), value);
        }
      }
    }
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
      DrawNodeHead(*node);
      DrawNodeHelpers(*node, 0);
      ImGui::Spacing();
      DrawParams(*node);
      DrawNodeHelpers(*node, 1);
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
        "zooms, the right button drags the view, F frames, Del removes, Ctrl+D duplicates, Ctrl+C / Ctrl+X / Ctrl+V "
        "copy, cut and paste (into another graph too), Ctrl+Z / Ctrl+Y undo and redo. A frame's title bar drags the "
        "nodes inside it."
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
