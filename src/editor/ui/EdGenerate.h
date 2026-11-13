#pragma once

#include "editor/graph/EdTerrainGraph.h"
#include "editor/ui/EdNodeCanvas.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace faf::editor
{
  /**
   * The Generate workspace's terrain graph (the consolidated design's Terrain > Generate; FAF Studio's graph editor):
   * three panels around the map view. Nodes is the palette by group with a search; Graph is the toolbar (the shipped
   * and saved graphs, the seed, the preview's size, Show on the map, Build, Revert) over the node canvas; Inspector is
   * the selected node's settings and errors, the graph's notes and its seed's variations. A change runs the graph again
   * on a coarse grid once it has rested, every node's picture follows, and with Show on the map the result is on the
   * terrain as one undo step that the next preview replaces; Build runs it at full resolution as one undo step.
   */
  class EdGenerate
  {
  public:
    EdGenerate();
    ~EdGenerate();
    EdGenerate(const EdGenerate&) = delete;
    EdGenerate& operator=(const EdGenerate&) = delete;

    void DrawNodesPanel(bool& open);
    void DrawGraphPanel(bool& open);
    void DrawInspectorPanel(bool& open);

    /** The map's ground for a run (the view's GraphGround); false without a map. */
    void SetGroundSource(
      std::function<bool(TerrainGround&)> source
    )
    {
      mGround = std::move(source);
    }
    /** Each frame: runs the graph after a change has rested half a second, Build when asked. */
    void Tick(float seconds, bool mapOpen);

    /** What the view is asked to do with the heights. */
    struct HeightsAsk
    {
      enum class Kind : std::uint8_t
      {
        None,
        Preview,
        Build,
        Revert,
      } kind = Kind::None;
      field::Grid result; // no samples: the graph writes no heights
      bool plain = true;
      /** Build: what it writes besides the heights (the ground kinds, layers, terrain types). */
      TerrainBuildWrites writes;
    };
    [[nodiscard]] bool TakeHeightsAsk(HeightsAsk& out);
    /** What the view made of it (shown under the toolbar). */
    void SetStatus(
      std::string status
    )
    {
      if (!status.empty()) {
        mStatus = std::move(status);
      }
    }

    // Test runs (`/gentest`).
    bool OpenShipped(const std::string& id);
    /** A saved graph (`.fafgraph.json`) opened (test runs: `/gentest file:<path>`). */
    bool OpenFile(const std::filesystem::path& file);
    void SetShowOnMap(
      const bool show
    ) noexcept
    {
      mShowOnMap = show;
    }
    void AskBuild() noexcept
    {
      mBuildAsked = true;
    }
    void SetSeed(
      const int seed
    ) noexcept
    {
      mSeed = seed;
    }
    [[nodiscard]] int Seed() const noexcept
    {
      return mSeed;
    }
    [[nodiscard]] NodeGraph& Graph() noexcept
    {
      return *mGraph;
    }
    [[nodiscard]] const TerrainReport& LastReport() const noexcept
    {
      return mReport;
    }
    /** Selects the first node of a type (test runs, `/gentest`), for the inspector. */
    void SelectFirst(const std::string& type);

  private:
    void NewGraph();
    void Open(const std::string& name, const std::string& text, bool studio);
    void Evaluate();
    void UpdateThumbnails();
    void DrawToolbar();
    void DrawGraphMenu();
    void DrawParams(GraphNode& node);
    [[nodiscard]] std::filesystem::path OwnFolder() const;
    void Save();

    std::unique_ptr<NodeGraph> mGraph;
    EdNodeCanvas mCanvas;
    TerrainRun mPreview{4};
    std::function<bool(TerrainGround&)> mGround;
    std::string mName;
    std::string mNote;
    std::string mLoadNote; // node types a Studio graph had that this editor doesn't
    int mSeed = 1;
    int mPreviewCap = 1; // 0: 257, 1: 513, 2: the map's own samples
    bool mShowOnMap = false;
    bool mShownOnMap = false;
    bool mBuildAsked = false;
    bool mRefreshAsked = true;
    std::string mEvaluatedKey;
    std::string mPendingKey;
    float mRest = 0.0f;
    TerrainReport mReport;
    int mGroundWidth = 0;
    HeightsAsk mAsk;
    bool mAsked = false;
    std::string mStatus;
    char mFilter[64] = {};
    struct Thumb
    {
      std::uint64_t image = 0;
    };
    std::map<int, Thumb> mThumbs;
    /**
     * Pictures that were replaced: the frame being drawn may still show them (the graph runs after the panels are
     * drawn), so they are freed when the panels are drawn next.
     */
    std::vector<std::uint64_t> mRetired;
    void RetireThumbs();
    void FreeRetired();
  };
} // namespace faf::editor
