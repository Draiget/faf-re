#include "editor/ui/EdMaterialEditor.h"
#include "editor/ui/EdUiScale.h"

#include "editor/doc/EdMapFile.h"
#include "editor/graph/EdTextureBake.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "imgui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265358979323846f;
    constexpr const char* kExtension = ".fafgraph.json";
    constexpr int kThumbSize = 64;

    std::uint32_t Bgra(const float r, const float g, const float b)
    {
      const auto byte = [](const float v) { return static_cast<std::uint32_t>(std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f)); };
      return 0xFF000000U | (byte(r) << 16) | (byte(g) << 8) | byte(b);
    }

    /** A texture file from the game's files as an RGBA image (at most 1024 across: a graph's input needn't be finer). */
    bool LoadTexture(const std::string& path, TexImage& out)
    {
      gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
      std::string bytes;
      if (codec == nullptr || !ReadGameFile(path, bytes)) {
        return false;
      }
      gpg::gal::imaging::DecodeOptions options;
      options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      options.mipLevels = 1;
      gpg::gal::imaging::Image image;
      if (FAILED(codec->Decode(bytes.data(), bytes.size(), options, image)) || image.subresources.empty() ||
          image.format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        return false;
      }
      const auto& level = image.subresources.front();
      const int w = static_cast<int>(level.width);
      const int h = static_cast<int>(level.height);
      if (w <= 0 || h <= 0) {
        return false;
      }
      // Square, as the graph's images are; a rectangular texture is stretched to its width.
      const int size = std::min(w, 1024);
      out.Reset(size, 4);
      for (int y = 0; y < size; ++y) {
        const int sy = std::min(h - 1, y * h / size);
        const std::uint8_t* const row = image.bytes.data() + level.offset + static_cast<std::size_t>(sy) * level.rowPitch;
        for (int x = 0; x < size; ++x) {
          const std::uint8_t* const p = row + static_cast<std::size_t>(x * w / size) * 4U;
          float* const d = out.Pixel(x, y);
          d[0] = static_cast<float>(p[2]) / 255.0f;
          d[1] = static_cast<float>(p[1]) / 255.0f;
          d[2] = static_cast<float>(p[0]) / 255.0f;
          d[3] = static_cast<float>(p[3]) / 255.0f;
        }
      }
      return true;
    }

    std::filesystem::path OwnFolder()
    {
      const char* const local = std::getenv("LOCALAPPDATA");
      return local != nullptr ? std::filesystem::path(local) / "FAForever" / "Editor" / "graphs" : std::filesystem::path("graphs");
    }

    std::string NameOf(const std::filesystem::path& file)
    {
      std::string name = file.filename().string();
      const std::size_t at = name.rfind(kExtension);
      return at != std::string::npos ? name.substr(0, at) : name;
    }
  } // namespace

  std::vector<std::uint32_t> RenderMaterialPreview(const TexImage* albedo, const TexImage* normal, const int mode, const int size, const float yaw,
                                                   const float lightYaw)
  {
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(size) * size);
    // The light from above and in front, turned around the sphere by `lightYaw` (0: from the viewer).
    const float lx = std::sin(lightYaw) * 0.7f;
    const float lz = std::cos(lightYaw) * 0.7f;
    const float ly = 0.6f;
    const float ll = std::sqrt(lx * lx + ly * ly + lz * lz);
    const float light[3] = {lx / ll, ly / ll, lz / ll};
    const auto shade = [&](const float u, const float v, const float (&n)[3], const float (&t)[3], const float (&b)[3], const float facing) {
      float base[4] = {0.5f, 0.5f, 0.5f, 1.0f};
      if (albedo != nullptr) {
        albedo->Sample(u, v, base);
      }
      float tn[4] = {0.5f, 0.5f, 1.0f, 1.0f};
      if (normal != nullptr) {
        normal->Sample(u, v, tn);
      }
      const float nx = tn[0] * 2.0f - 1.0f;
      const float ny = tn[1] * 2.0f - 1.0f;
      const float nz = tn[2] * 2.0f - 1.0f;
      float w[3];
      for (int i = 0; i < 3; ++i) {
        w[i] = t[i] * nx + b[i] * ny + n[i] * nz;
      }
      const float wl = std::max(std::sqrt(w[0] * w[0] + w[1] * w[1] + w[2] * w[2]), 1e-5f);
      const float diffuse = std::max(0.0f, (w[0] * light[0] + w[1] * light[1] + w[2] * light[2]) / wl);
      const float lit = (0.4f + 0.8f * diffuse) * facing;
      return Bgra(base[0] * lit, base[1] * lit, base[2] * lit);
    };
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        std::uint32_t& out = pixels[static_cast<std::size_t>(y) * size + x];
        const float fy = (static_cast<float>(y) + 0.5f) / static_cast<float>(size);
        out = Bgra(0.10f + 0.06f * (1.0f - fy), 0.10f + 0.06f * (1.0f - fy), 0.12f + 0.07f * (1.0f - fy));
        if (mode == 1) {
          // Two by two repeats, flat, seen from above: a seam would show at the middle lines.
          const float u = (static_cast<float>(x) + 0.5f) / static_cast<float>(size) * 2.0f;
          const float v = fy * 2.0f;
          const float n[3] = {0.0f, 1.0f, 0.0f};
          const float t[3] = {1.0f, 0.0f, 0.0f};
          const float b[3] = {0.0f, 0.0f, 1.0f};
          out = shade(u, v, n, t, b, 1.0f);
          continue;
        }
        // An orthographic sphere filling 90% of the image.
        const float sx = ((static_cast<float>(x) + 0.5f) / static_cast<float>(size) * 2.0f - 1.0f) / 0.9f;
        const float sy = -(fy * 2.0f - 1.0f) / 0.9f;
        const float r2 = sx * sx + sy * sy;
        if (r2 > 1.0f) {
          continue;
        }
        const float sz = std::sqrt(1.0f - r2);
        const float n[3] = {sx, sy, sz};
        const float phi = std::atan2(sx, sz) + yaw;
        const float u = phi / (2.0f * kPi) * 2.0f; // the texture twice around
        const float v = std::acos(std::clamp(sy, -1.0f, 1.0f)) / kPi;
        const float t[3] = {std::cos(phi - yaw), 0.0f, -std::sin(phi - yaw)};
        const float b[3] = {n[1] * t[2] - n[2] * t[1], n[2] * t[0] - n[0] * t[2], n[0] * t[1] - n[1] * t[0]};
        out = shade(u, v, n, t, b, 0.85f + 0.15f * sz);
      }
    }
    return pixels;
  }

  EdMaterialEditor::EdMaterialEditor() = default;

  EdMaterialEditor::~EdMaterialEditor()
  {
    for (const auto& doc : mDocs) {
      for (const auto& [id, thumb] : doc->thumbs) {
        EdImGuiRenderer::DestroyImage(thumb.image);
      }
    }
    EdImGuiRenderer::DestroyImage(mPreviewImage);
  }

  void EdMaterialEditor::SetMapFolder(const std::filesystem::path& folder)
  {
    mMapFolder = folder;
  }

  void EdMaterialEditor::SetSlotNames(std::vector<std::string> names)
  {
    if (names.empty() && !mSlotNames.empty()) {
      // The map closed: nothing to show the result on, and nothing to put back.
      mLive = false;
      mLiveSlot = -1;
      mRestore.clear();
      mLiveReady = false;
    }
    mSlotNames = std::move(names);
  }

  bool EdMaterialEditor::TakeLive(LiveImage& out)
  {
    if (!mLiveReady) {
      return false;
    }
    out = std::move(mLiveOut);
    mLiveOut = {};
    mLiveReady = false;
    return true;
  }

  bool EdMaterialEditor::TakeRestore(int& slot)
  {
    if (mRestore.empty()) {
      return false;
    }
    slot = mRestore.front();
    mRestore.erase(mRestore.begin());
    return true;
  }

  bool EdMaterialEditor::TakeApply(Bake& out)
  {
    if (!mBakeReady) {
      return false;
    }
    out = std::move(mBakeOut);
    mBakeOut = {};
    mBakeReady = false;
    return true;
  }

  void EdMaterialEditor::StopLive()
  {
    if (mLiveSlot >= 0) {
      mRestore.push_back(mLiveSlot);
    }
    mLiveSlot = -1;
    mLiveReady = false;
  }

  void EdMaterialEditor::UpdateLive(Doc& doc)
  {
    if (!mLive || mSlotNames.empty()) {
      return;
    }
    if (mLiveSlot != mTargetSlot) {
      StopLive();
      mLiveSlot = mTargetSlot;
      mLiveStale = true;
    }
    // At most ten updates a second while a slider is dragged; the last change always goes out.
    const double now = ImGui::GetTime();
    if (!mLiveStale || now - mLiveSentAt < 0.1) {
      return;
    }
    const TexImagePtr albedo = doc.eval->Result("Albedo");
    const TexImagePtr normals = doc.eval->Result("Normal");
    LiveImage live;
    live.slot = mLiveSlot;
    std::string error;
    if (albedo != nullptr && !EncodeDds(*albedo, DdsKind::Bgra, live.albedo, error)) {
      mStatus = "Live: " + error;
    }
    if (normals != nullptr && mLiveSlot < 9 && !EncodeDds(*normals, DdsKind::Bgra, live.normals, error)) {
      mStatus = "Live: " + error;
    }
    mLiveOut = std::move(live);
    mLiveReady = true;
    mLiveStale = false;
    mLiveSentAt = now;
  }

  void EdMaterialEditor::ApplyBake(Doc& doc)
  {
    // The graph again at the bake size, apart from the preview's (its cache stays).
    TextureGraphEvaluator bake(*doc.graph);
    bake.SetSize(mBakeSize);
    bake.SetTextureLoader(LoadTexture);
    bake.SetTerrain(mTerrain);
    Bake out;
    out.slot = mTargetSlot;
    out.name = doc.name;
    std::string error;
    const TexImagePtr albedo = bake.Result("Albedo");
    if (albedo == nullptr) {
      mStatus = "Apply: link something to the output's Albedo first.";
      return;
    }
    if (!EncodeDds(*albedo, DdsKind::Bc3, out.albedo, error)) {
      mStatus = "Apply: " + error;
      return;
    }
    if (const TexImagePtr normals = bake.Result("Normal"); normals != nullptr && mTargetSlot < 9 && !EncodeDds(*normals, DdsKind::Bc1, out.normals, error)) {
      mStatus = "Apply: " + error;
      return;
    }
    if (mTargetSlot >= 1 && mTargetSlot <= 8) {
      out.mask = bake.Result("Mask");
    }
    mBakeOut = std::move(out);
    mBakeReady = true;
    StopLive();
    mLive = false;
  }

  std::filesystem::path EdMaterialEditor::Folder() const
  {
    return mMapFolder.empty() ? OwnFolder() : mMapFolder / "editor";
  }

  EdMaterialEditor::Doc* EdMaterialEditor::Active()
  {
    return mActive >= 0 && static_cast<std::size_t>(mActive) < mDocs.size() ? mDocs[static_cast<std::size_t>(mActive)].get() : nullptr;
  }

  const EdMaterialEditor::Doc* EdMaterialEditor::Active() const
  {
    return const_cast<EdMaterialEditor*>(this)->Active();
  }

  std::size_t EdMaterialEditor::NodeCount() const
  {
    const Doc* doc = Active();
    return doc != nullptr ? doc->graph->Nodes().size() : 0U;
  }

  void EdMaterialEditor::OpenForSlot(const int slot)
  {
    if (mDocs.empty()) {
      NewGraph();
    }
    mTargetSlot = std::clamp(slot, 0, 9);
    mLive = true;
    mLiveStale = true;
    mBringToFront = true;
  }

  void EdMaterialEditor::SelectFirst(const std::string& type)
  {
    if (mDocs.empty()) {
      NewGraph();
    }
    if (Doc* doc = Active()) {
      for (const GraphNode& node : doc->graph->Nodes()) {
        if (node.type->name == type) {
          doc->canvas.Select(node.id);
          return;
        }
      }
    }
  }

  EdMaterialEditor::Doc& EdMaterialEditor::Make(const std::string& name)
  {
    auto doc = std::make_unique<Doc>();
    doc->name = name;
    doc->graph = std::make_unique<NodeGraph>(TextureNodeTypes());
    doc->eval = std::make_unique<TextureGraphEvaluator>(*doc->graph);
    doc->eval->SetSize(mPreviewSize);
    doc->eval->SetTextureLoader(LoadTexture);
    TextureGraphEvaluator* eval = doc->eval.get();
    Doc* raw = doc.get();
    doc->canvas.SetWarnings([eval](const GraphNode& node) { return eval->Warning(node.id); });
    doc->canvas.SetThumbnails([raw](const GraphNode& node) {
      const auto found = raw->thumbs.find(node.id);
      return found != raw->thumbs.end() ? found->second.image : std::uint64_t{0};
    });
    mDocs.push_back(std::move(doc));
    mActive = static_cast<int>(mDocs.size()) - 1;
    mSelectTab = mActive;
    mPreviewStale = true;
    return *mDocs.back();
  }

  void EdMaterialEditor::NewGraph()
  {
    int n = 1;
    std::string name;
    do {
      name = "Material" + std::to_string(n++);
    } while (std::any_of(mDocs.begin(), mDocs.end(), [&](const auto& doc) { return doc->name == name; }));
    Doc& doc = Make(name);
    StartTextureGraph(*doc.graph);
    doc.undo = {doc.graph->Save()};
    doc.undoAt = 0;
    doc.snapChanges = doc.graph->Changes();
    doc.savedChanges = doc.graph->Changes() - 1; // new: unsaved
  }

  bool EdMaterialEditor::Open(const std::filesystem::path& file)
  {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
      mStatus = "Can't read " + file.string();
      return false;
    }
    std::stringstream text;
    text << in.rdbuf();
    Doc& doc = Make(NameOf(file));
    std::string error;
    if (!doc.graph->Load(text.str(), error)) {
      mStatus = file.filename().string() + ": " + error;
      mDocs.pop_back();
      mActive = static_cast<int>(mDocs.size()) - 1;
      return false;
    }
    if (doc.graph->OutputNode() == 0) {
      (void)doc.graph->AddNode("Output", 520.0f, 0.0f);
    }
    doc.path = file;
    doc.undo = {doc.graph->Save()};
    doc.undoAt = 0;
    doc.snapChanges = doc.graph->Changes();
    doc.savedChanges = doc.graph->Changes();
    doc.canvas.FrameAll();
    mStatus = "Opened " + file.string();
    return true;
  }

  bool EdMaterialEditor::Save(Doc& doc)
  {
    if (doc.path.empty()) {
      doc.path = Folder() / (doc.name + kExtension);
    }
    std::error_code ec;
    std::filesystem::create_directories(doc.path.parent_path(), ec);
    std::ofstream out(doc.path, std::ios::binary | std::ios::trunc);
    if (!out) {
      mStatus = "Can't write " + doc.path.string();
      return false;
    }
    out << doc.graph->Save();
    doc.savedChanges = doc.graph->Changes();
    mStatus = "Saved " + doc.path.string();
    return true;
  }

  void EdMaterialEditor::Snapshot(Doc& doc)
  {
    // One undo step per finished edit: nothing while a button is held (a drag, a slider).
    if (doc.graph->Changes() == doc.snapChanges || ImGui::IsMouseDown(ImGuiMouseButton_Left) || ImGui::IsAnyItemActive()) {
      return;
    }
    const std::string text = doc.graph->Save();
    doc.snapChanges = doc.graph->Changes();
    if (!doc.undo.empty() && doc.undo[doc.undoAt] == text) {
      return;
    }
    doc.undo.resize(doc.undoAt + 1);
    doc.undo.push_back(text);
    if (doc.undo.size() > 200) {
      doc.undo.erase(doc.undo.begin());
    }
    doc.undoAt = doc.undo.size() - 1;
  }

  void EdMaterialEditor::Undo(Doc& doc, const bool redo)
  {
    if (redo ? doc.undoAt + 1 >= doc.undo.size() : doc.undoAt == 0) {
      return;
    }
    doc.undoAt = redo ? doc.undoAt + 1 : doc.undoAt - 1;
    std::string error;
    (void)doc.graph->Load(doc.undo[doc.undoAt], error);
    doc.snapChanges = doc.graph->Changes();
    doc.savedChanges = ~std::uint64_t{0};
    mPreviewStale = true;
  }

  void EdMaterialEditor::Evaluate(Doc& doc)
  {
    // The map nodes read the open map's heights, fetched once and on Refresh.
    bool usesTerrain = false;
    for (const GraphNode& node : doc.graph->Nodes()) {
      usesTerrain = usesTerrain || node.type->category == "Map";
    }
    if (usesTerrain && mTerrain == nullptr && mTerrainSource) {
      mTerrain = mTerrainSource();
      for (const auto& other : mDocs) {
        other->eval->SetTerrain(mTerrain);
      }
    }
    if (doc.eval->Size() != mPreviewSize) {
      doc.eval->SetSize(mPreviewSize);
    }
    doc.lastComputed = doc.eval->EvaluateAll();
    if (doc.lastComputed > 0) {
      doc.lastMillis = 0.0;
      for (const GraphNode& node : doc.graph->Nodes()) {
        doc.lastMillis += doc.eval->Millis(node.id);
      }
      mPreviewStale = true;
      mLiveStale = true;
      UpdateThumbnails(doc);
    }
  }

  void EdMaterialEditor::UpdateThumbnails(Doc& doc)
  {
    for (auto it = doc.thumbs.begin(); it != doc.thumbs.end();) {
      if (doc.graph->Find(it->first) == nullptr) {
        EdImGuiRenderer::DestroyImage(it->second.image);
        it = doc.thumbs.erase(it);
      } else {
        ++it;
      }
    }
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kThumbSize) * kThumbSize);
    for (const GraphNode& node : doc.graph->Nodes()) {
      const TexImagePtr image = doc.eval->Output(node.id, 0);
      if (image == nullptr) {
        continue;
      }
      Thumb& thumb = doc.thumbs[node.id];
      if (thumb.revision == node.revision && thumb.size == doc.eval->Size() && thumb.image != 0) {
        continue;
      }
      for (int y = 0; y < kThumbSize; ++y) {
        for (int x = 0; x < kThumbSize; ++x) {
          float c[4];
          image->Sample((static_cast<float>(x) + 0.5f) / kThumbSize, (static_cast<float>(y) + 0.5f) / kThumbSize, c);
          pixels[static_cast<std::size_t>(y) * kThumbSize + x] = Bgra(c[0], c[1], c[2]);
        }
      }
      EdImGuiRenderer::DestroyImage(thumb.image);
      thumb.image = EdImGuiRenderer::CreateImage(kThumbSize, kThumbSize, pixels.data());
      thumb.revision = node.revision;
      thumb.size = doc.eval->Size();
    }
  }

  void EdMaterialEditor::Draw(bool& open)
  {
    // First shown over most of the editor, as a document window is.
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.8f, viewport->WorkSize.y * 0.8f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
                            ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    mFocused = false;
    if (std::exchange(mBringToFront, false)) {
      ImGui::SetNextWindowFocus();
      ImGui::SetNextWindowCollapsed(false);
    }
    ImGui::SetNextWindowCollapsed(false, ImGuiCond_Always);
    if (!ImGui::Begin("Material Editor", &open, ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }
    if (!open) {
      StopLive(); // closed: the terrain shows the map's own textures again
      mLive = false;
    }
    mFocused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    if (mDocs.empty()) {
      NewGraph();
    }
    DrawToolbar();

    // (1) A tab per open graph.
    if (ImGui::BeginTabBar("##graphs", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll)) {
      for (std::size_t i = 0; i < mDocs.size(); ++i) {
        Doc& doc = *mDocs[i];
        bool keep = true;
        ImGuiTabItemFlags flags = doc.graph->Changes() != doc.savedChanges ? ImGuiTabItemFlags_UnsavedDocument : 0;
        if (mSelectTab == static_cast<int>(i)) {
          flags |= ImGuiTabItemFlags_SetSelected;
        }
        if (ImGui::BeginTabItem((doc.name + "###doc" + std::to_string(reinterpret_cast<std::uintptr_t>(&doc))).c_str(), &keep, flags)) {
          mActive = static_cast<int>(i);
          ImGui::EndTabItem();
        }
        if (!keep) {
          for (const auto& [id, thumb] : doc.thumbs) {
            EdImGuiRenderer::DestroyImage(thumb.image);
          }
          mDocs.erase(mDocs.begin() + static_cast<std::ptrdiff_t>(i));
          mActive = std::min(mActive, static_cast<int>(mDocs.size()) - 1);
          mPreviewStale = true;
          break;
        }
      }
      ImGui::EndTabBar();
    }
    mSelectTab = -1;
    Doc* doc = Active();
    if (doc == nullptr) {
      ImGui::TextDisabled("No graph open: File > New graph.");
      DrawOpenPopup();
      DrawSaveAsPopup();
      ImGui::End();
      return;
    }
    if (mPreviewDoc != doc) {
      mPreviewDoc = doc;
      mPreviewStale = true;
    }

    // Undo and redo while the window has the keyboard.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::IsAnyItemActive()) {
      const ImGuiIO& io = ImGui::GetIO();
      if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Z)) {
        Undo(*doc, io.KeyShift);
      } else if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Y)) {
        Undo(*doc, true);
      } else if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S)) {
        (void)Save(*doc);
      }
    }

    Evaluate(*doc);

    if (ImGui::BeginTable("##layout", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail())) {
      ImGui::TableSetupColumn("left", ImGuiTableColumnFlags_WidthFixed, 300.0f);
      ImGui::TableSetupColumn("graph", ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableSetupColumn("palette", ImGuiTableColumnFlags_WidthFixed, 220.0f);
      ImGui::TableNextRow();

      // (3) The preview over (4) the Details.
      ImGui::TableSetColumnIndex(0);
      const float leftWidth = ImGui::GetContentRegionAvail().x;
      DrawPreview(*doc, leftWidth);
      if (ImGui::BeginChild("##details", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawDetails(*doc);
      }
      ImGui::EndChild();

      // (5) The graph over (6) the Stats.
      ImGui::TableSetColumnIndex(1);
      const float statsHeight = ImGui::GetTextLineHeightWithSpacing() * 4.5f;
      if (ImGui::BeginChild("##graph", ImVec2(0.0f, ImGui::GetContentRegionAvail().y - statsHeight), ImGuiChildFlags_Borders,
                            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMove)) {
        if (doc->canvas.Draw(*doc->graph)) {
          Evaluate(*doc);
        }
      }
      ImGui::EndChild();
      if (ImGui::BeginChild("##stats", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawStats(*doc);
      }
      ImGui::EndChild();

      // (7) The palette.
      ImGui::TableSetColumnIndex(2);
      if (ImGui::BeginChild("##palette", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        DrawPalette(*doc);
      }
      ImGui::EndChild();
      ImGui::EndTable();
    }
    Snapshot(*doc);
    if (mApplyAsk >= 0 && !mSlotNames.empty()) {
      mTargetSlot = std::exchange(mApplyAsk, -1);
      ApplyBake(*doc);
    }
    UpdateLive(*doc);
    DrawOpenPopup();
    DrawSaveAsPopup();
    ImGui::End();
  }

  void EdMaterialEditor::DrawToolbar()
  {
    Doc* doc = Active();
    if (ImGui::BeginMenuBar()) {
      if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("New graph")) {
          NewGraph();
        }
        if (ImGui::MenuItem("Open...")) {
          mOpenOpen = true;
        }
        if (ImGui::MenuItem("Save", "Ctrl+S", false, doc != nullptr)) {
          (void)Save(*doc);
        }
        if (ImGui::MenuItem("Save as...", nullptr, false, doc != nullptr)) {
          std::snprintf(mSaveAsName, sizeof(mSaveAsName), "%s", doc->name.c_str());
          mOpenSaveAs = true;
        }
        ImGui::EndMenu();
      }
      if (ImGui::BeginMenu("Edit")) {
        if (ImGui::MenuItem("Undo", "Ctrl+Z", false, doc != nullptr && doc->undoAt > 0)) {
          Undo(*doc, false);
        }
        if (ImGui::MenuItem("Redo", "Ctrl+Y", false, doc != nullptr && doc->undoAt + 1 < doc->undo.size())) {
          Undo(*doc, true);
        }
        ImGui::EndMenu();
      }
      // (2) The toolbar's buttons.
      ImGui::Separator();
      if (ImGui::Button("Save") && doc != nullptr) {
        (void)Save(*doc);
      }
      ImGui::SetItemTooltip("Writes the graph to %s", (Folder() / ((doc != nullptr ? doc->name : std::string("name")) + kExtension)).string().c_str());
      if (ImGui::Button("Home") && doc != nullptr) {
        doc->canvas.FrameAll();
      }
      ImGui::SetItemTooltip("Frames the whole graph (F frames the selection)");
      if (ImGui::Button("Refresh map")) {
        mTerrain.reset();
        for (const auto& each : mDocs) {
          each->eval->SetTerrain(nullptr);
        }
      }
      ImGui::SetItemTooltip("Reads the open map's heights again for the Map Height and Map Slope nodes");
      ImGui::SetNextItemWidth(Em(90.0f));
      static const int kSizes[] = {128, 256, 512, 1024};
      if (ImGui::BeginCombo("##size", (std::to_string(mPreviewSize) + " px").c_str())) {
        for (const int size : kSizes) {
          if (ImGui::Selectable((std::to_string(size) + " px").c_str(), size == mPreviewSize)) {
            mPreviewSize = size;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SetItemTooltip("The graph's working size: larger is finer and slower");

      // The slot the result goes into, live and on Apply.
      ImGui::Separator();
      const bool haveMap = !mSlotNames.empty();
      ImGui::BeginDisabled(!haveMap);
      ImGui::SetNextItemWidth(Em(190.0f));
      const std::string current = haveMap && mTargetSlot < static_cast<int>(mSlotNames.size()) ? mSlotNames[static_cast<std::size_t>(mTargetSlot)]
                                                                                               : std::string("(no map open)");
      if (ImGui::BeginCombo("##slot", current.c_str())) {
        for (std::size_t s = 0; s < mSlotNames.size(); ++s) {
          if (ImGui::Selectable(mSlotNames[s].c_str(), static_cast<int>(s) == mTargetSlot)) {
            mTargetSlot = static_cast<int>(s);
            mLiveStale = true;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SetItemTooltip("The map's texture slot the graph's result goes into");
      if (ImGui::Checkbox("Live Update", &mLive) && !mLive) {
        StopLive();
      }
      mLiveStale = mLiveStale || ImGui::IsItemDeactivatedAfterEdit();
      ImGui::SetItemTooltip("Shows the result on the map's terrain in that slot as you edit (not saved: Apply writes it into the map)");
      ImGui::EndDisabled();
      const bool canApply = haveMap && !mMapFolder.empty() && doc != nullptr;
      ImGui::BeginDisabled(!canApply);
      if (ImGui::Button("Apply") && doc != nullptr) {
        ApplyBake(*doc);
      }
      ImGui::EndDisabled();
      ImGui::SetItemTooltip("%s", canApply ? "Bakes the graph at the bake size into DDS files in the map's env/layers folder and sets the slot to them "
                                             "(one undo step); a linked Mask paints the stratum's mask"
                                           : "Apply writes into the map's own folder: open a map from your vault (the game's own maps can't be "
                                             "changed; File > Save as new map folder makes one)");
      ImGui::SetNextItemWidth(Em(80.0f));
      if (ImGui::BeginCombo("##bake", (std::to_string(mBakeSize) + " px").c_str())) {
        for (const int size : {512, 1024, 2048}) {
          if (ImGui::Selectable((std::to_string(size) + " px").c_str(), size == mBakeSize)) {
            mBakeSize = size;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SetItemTooltip("The size Apply bakes at");
      if (!mStatus.empty()) {
        ImGui::TextDisabled("%s", mStatus.c_str());
      }
      ImGui::EndMenuBar();
    }
  }

  void EdMaterialEditor::DrawPreview(Doc& doc, const float width)
  {
    static const char* const kModes[] = {"Sphere", "Plane 2x2", "Albedo", "Normal", "Mask"};
    ImGui::SetNextItemWidth(Em(110.0f));
    if (ImGui::Combo("##mode", &mPreviewMode, kModes, IM_ARRAYSIZE(kModes))) {
      mPreviewStale = true;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    float lightDegrees = mLightYaw * 180.0f / kPi;
    if (ImGui::SliderFloat("##light", &lightDegrees, -180.0f, 180.0f, "Light %.0f deg")) {
      mLightYaw = lightDegrees * kPi / 180.0f;
      mPreviewStale = true;
    }
    const float side = std::max(64.0f, width);
    if (mPreviewStale) {
      const TexImagePtr albedo = doc.eval->Result("Albedo");
      const TexImagePtr normal = doc.eval->Result("Normal");
      const TexImagePtr mask = doc.eval->Result("Mask");
      const int size = 256;
      std::vector<std::uint32_t> pixels;
      if (mPreviewMode <= 1) {
        pixels = RenderMaterialPreview(albedo.get(), normal.get(), mPreviewMode, size, mPreviewYaw, mLightYaw);
      } else {
        const TexImage* image = mPreviewMode == 2 ? albedo.get() : mPreviewMode == 3 ? normal.get() : mask.get();
        pixels.assign(static_cast<std::size_t>(size) * size, Bgra(0.1f, 0.1f, 0.12f));
        for (int y = 0; y < size && image != nullptr; ++y) {
          for (int x = 0; x < size; ++x) {
            float c[4];
            image->Sample((static_cast<float>(x) + 0.5f) / size, (static_cast<float>(y) + 0.5f) / size, c);
            pixels[static_cast<std::size_t>(y) * size + x] = Bgra(c[0], c[1], c[2]);
          }
        }
      }
      EdImGuiRenderer::DestroyImage(mPreviewImage);
      mPreviewImage = EdImGuiRenderer::CreateImage(size, size, pixels.data());
      mPreviewStale = false;
    }
    if (mPreviewImage != 0) {
      ImGui::Image(static_cast<ImTextureID>(mPreviewImage), ImVec2(side, side));
      // Dragging turns the sphere.
      if (ImGui::IsItemHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) {
        mPreviewYaw -= ImGui::GetIO().MouseDelta.x * 0.01f;
        mPreviewStale = mPreviewStale || ImGui::GetIO().MouseDelta.x != 0.0f;
      }
      ImGui::SetItemTooltip("The output's albedo lit through its normal map. Drag to turn the sphere.");
    }
  }

  void EdMaterialEditor::DrawDetails(Doc& doc)
  {
    ImGui::SeparatorText("Details");
    const std::set<int>& selection = doc.canvas.Selection();
    GraphNode* node = selection.size() == 1 ? doc.graph->Find(*selection.begin()) : nullptr;
    if (node == nullptr) {
      ImGui::TextWrapped("%s", selection.empty() ? "Select a node to edit its settings." : "Several nodes are selected.");
      ImGui::Spacing();
      ImGui::SeparatorText("Graph");
      ImGui::Text("Name: %s", doc.name.c_str());
      ImGui::TextDisabled("%s", (doc.path.empty() ? Folder() / (doc.name + kExtension) : doc.path).string().c_str());
      ImGui::Spacing();
      ImGui::TextWrapped("Right-click the graph (or drop a link on empty space) to add a node; drag from the palette on the right. "
                         "The wheel zooms, the right button drags the view, F frames, Del removes, Ctrl+D duplicates.");
      return;
    }
    const NodeType& type = *node->type;
    ImGui::TextColored(ImVec4(0.95f, 0.85f, 0.55f, 1.0f), "%s", type.title.c_str());
    ImGui::TextWrapped("%s", type.help.c_str());
    if (const std::string warning = doc.eval->Warning(node->id); !warning.empty()) {
      ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.35f, 1.0f), "%s", warning.c_str());
    }
    ImGui::Spacing();
    const int id = node->id;
    for (std::size_t p = 0; p < type.params.size(); ++p) {
      const ParamDef& def = type.params[p];
      ParamValue value = doc.graph->Find(id)->params[p];
      bool changed = false;
      ImGui::PushID(static_cast<int>(p));
      ImGui::SetNextItemWidth(-100.0f);
      switch (def.kind) {
      case ParamKind::Float:
        changed = ImGui::SliderFloat(def.name.c_str(), &value.value[0], def.min, def.max, "%.3f");
        break;
      case ParamKind::Int: {
        int v = static_cast<int>(std::lround(value.value[0]));
        changed = ImGui::SliderInt(def.name.c_str(), &v, static_cast<int>(def.min), static_cast<int>(def.max));
        value.value[0] = static_cast<float>(v);
        break;
      }
      case ParamKind::Bool: {
        bool v = value.value[0] > 0.5f;
        changed = ImGui::Checkbox(def.name.c_str(), &v);
        value.value[0] = v ? 1.0f : 0.0f;
        break;
      }
      case ParamKind::Color:
        changed = ImGui::ColorEdit4(def.name.c_str(), value.value.data(), ImGuiColorEditFlags_AlphaBar);
        break;
      case ParamKind::Choice: {
        int v = static_cast<int>(std::lround(value.value[0]));
        const char* current = v >= 0 && static_cast<std::size_t>(v) < def.choices.size() ? def.choices[static_cast<std::size_t>(v)].c_str() : "?";
        if (ImGui::BeginCombo(def.name.c_str(), current)) {
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
        char buffer[512];
        std::snprintf(buffer, sizeof(buffer), "%s", value.text.c_str());
        if (ImGui::InputText(def.name.c_str(), buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
          value.text = buffer;
          changed = true;
        }
        // The terrain textures the game data has: the picked one's picture, a click opens the browser of them all
        // (pictures in a grid, by biome folder). The path above still takes any file typed in.
        if (mLayerPaths.size() != mLibrary.Textures().size()) {
          mLayerPaths.clear();
          for (const LayerTexture& texture : mLibrary.Textures()) {
            mLayerPaths.push_back(texture.path);
          }
        }
        changed = mTexturePicker.Field("##pick", value.text, mLayerPaths, mLibrary, false) || changed;
        break;
      }
      }
      if (!def.help.empty()) {
        ImGui::SetItemTooltip("%s", def.help.c_str());
      }
      ImGui::PopID();
      if (changed) {
        doc.graph->SetParam(id, p, value);
      }
    }
    if (type.params.empty()) {
      ImGui::TextDisabled("This node has no settings.");
    }
    ImGui::Spacing();
    ImGui::TextDisabled("Computed in %.1f ms", doc.eval->Millis(id));
  }

  void EdMaterialEditor::DrawStats(Doc& doc)
  {
    int warnings = 0;
    for (const GraphNode& node : doc.graph->Nodes()) {
      warnings += doc.eval->Warning(node.id).empty() ? 0 : 1;
    }
    ImGui::BulletText("Nodes: %zu, links: %zu", doc.graph->Nodes().size(), doc.graph->Links().size());
    ImGui::BulletText("Size: %d x %d; last change: %d nodes computed, %.1f ms in all", doc.eval->Size(), doc.eval->Size(), doc.lastComputed,
                      doc.lastMillis);
    if (warnings > 0) {
      ImGui::BulletText("Warnings: %d (the nodes outlined in red)", warnings);
    } else {
      ImGui::BulletText("No warnings");
    }
  }

  void EdMaterialEditor::DrawPalette(Doc& doc)
  {
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##search", "Search", mPaletteFilter, sizeof(mPaletteFilter));
    std::map<std::string, std::vector<const NodeType*>> byCategory;
    for (const auto& type : doc.graph->Registry().All()) {
      if (type->isOutput) {
        continue;
      }
      std::string haystack = type->title + " " + type->category;
      std::string needle = mPaletteFilter;
      std::transform(haystack.begin(), haystack.end(), haystack.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      std::transform(needle.begin(), needle.end(), needle.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (needle.empty() || haystack.find(needle) != std::string::npos) {
        byCategory[type->category].push_back(type.get());
      }
    }
    for (const auto& [category, types] : byCategory) {
      ImGui::SetNextItemOpen(true, ImGuiCond_Once);
      if (mPaletteFilter[0] != '\0') {
        ImGui::SetNextItemOpen(true);
      }
      if (!ImGui::TreeNodeEx(category.c_str(), ImGuiTreeNodeFlags_SpanAvailWidth)) {
        continue;
      }
      for (const NodeType* type : types) {
        ImGui::Selectable(type->title.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
          (void)doc.canvas.AddAtCentre(*doc.graph, type->name);
        }
        if (ImGui::BeginDragDropSource()) {
          ImGui::SetDragDropPayload(EdNodeCanvas::kPalettePayload, type->name.data(), type->name.size());
          ImGui::Text("%s", type->title.c_str());
          ImGui::EndDragDropSource();
        }
        ImGui::SetItemTooltip("%s\n\nDouble-click or drag into the graph.", type->help.c_str());
      }
      ImGui::TreePop();
    }
  }

  void EdMaterialEditor::DrawOpenPopup()
  {
    if (mOpenOpen) {
      ImGui::OpenPopup("Open graph");
      mOpenOpen = false;
    }
    ImGui::SetNextWindowSizeConstraints(ImVec2(Em(360.0f), Em(120.0f)), ImVec2(Em(600.0f), Em(500.0f)));
    if (!ImGui::BeginPopup("Open graph")) {
      return;
    }
    int found = 0;
    for (const std::filesystem::path& folder : {Folder(), OwnFolder()}) {
      std::error_code ec;
      if (!std::filesystem::is_directory(folder, ec)) {
        continue;
      }
      ImGui::SeparatorText(folder.string().c_str());
      for (const auto& entry : std::filesystem::directory_iterator(folder, ec)) {
        const std::string file = entry.path().filename().string();
        if (file.size() <= std::strlen(kExtension) || file.rfind(kExtension) != file.size() - std::strlen(kExtension)) {
          continue;
        }
        ++found;
        if (ImGui::Selectable(NameOf(entry.path()).c_str())) {
          (void)Open(entry.path());
          ImGui::CloseCurrentPopup();
        }
      }
      if (folder == OwnFolder()) {
        break;
      }
    }
    if (found == 0) {
      ImGui::TextDisabled("No graphs saved yet (%s).", Folder().string().c_str());
    }
    ImGui::EndPopup();
  }

  void EdMaterialEditor::DrawSaveAsPopup()
  {
    if (mOpenSaveAs) {
      ImGui::OpenPopup("Save graph as");
      mOpenSaveAs = false;
    }
    if (!ImGui::BeginPopup("Save graph as")) {
      return;
    }
    ImGui::InputText("Name", mSaveAsName, sizeof(mSaveAsName));
    ImGui::TextDisabled("In %s", Folder().string().c_str());
    std::string name = mSaveAsName;
    const bool valid = !name.empty() && name.find_first_of("\\/:*?\"<>|") == std::string::npos;
    ImGui::BeginDisabled(!valid);
    if (ImGui::Button("Save") && Active() != nullptr) {
      Doc& doc = *Active();
      doc.name = name;
      doc.path = Folder() / (name + kExtension);
      (void)Save(doc);
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndDisabled();
    ImGui::EndPopup();
  }
} // namespace faf::editor
