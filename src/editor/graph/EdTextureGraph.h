#pragma once

#include "editor/graph/EdNodeGraph.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace faf::editor
{
  // The material editor's texture graph: node types that make images (textures, noise, math, blends, adjustments,
  // normals, the map's height and slope), evaluated on the CPU one image per node. Everything a pattern makes tiles
  // (noise and cells wrap at the image's edge, blurs and normals read across it), because a stratum's texture repeats
  // over the ground. Spatial parameters are in the image's own units (0-1), so a 256 preview and a 2048 bake match.

  /** A square image: one channel (grey) or four (RGBA), 0-1, rows top to bottom. */
  struct TexImage
  {
    int size = 0;
    int channels = 1;
    std::vector<float> data;

    void Reset(int newSize, int newChannels, float fill = 0.0f);
    [[nodiscard]] float* Pixel(const int x, const int y) { return data.data() + (static_cast<std::size_t>(y) * size + x) * channels; }
    [[nodiscard]] const float* Pixel(const int x, const int y) const
    {
      return data.data() + (static_cast<std::size_t>(y) * size + x) * channels;
    }
    /** RGBA at (u, v), bilinear, wrapping (a grey image gives grey, grey, grey, 1). */
    void Sample(float u, float v, float (&out)[4]) const;
  };
  using TexImagePtr = std::shared_ptr<const TexImage>;

  /** The open map's heights for the terrain nodes: samples in rows, in game height units, `units` between samples. */
  struct TerrainSource
  {
    int width = 0;
    int height = 0;
    float units = 1.0f;
    std::vector<float> heights;
    /** The stratum masks, rows along z: one texel's eight weights in one word, byte k for stratum k + 1 (EdMaskBrush.h). */
    int maskWidth = 0;
    int maskHeight = 0;
    std::vector<std::uint64_t> masks;
  };

  /** The texture graph's node types (the palette). The output node is "Output". */
  const NodeTypeRegistry& TextureNodeTypes();

  /** A new graph's nodes: a noise into a gradient map into the output's albedo, and its height into the normal. */
  void StartTextureGraph(NodeGraph& graph);

  class TextureGraphEvaluator
  {
  public:
    /** Reads a texture file (a DDS from the VFS) into an RGBA image; false when it can't. */
    using TextureLoader = std::function<bool(const std::string& path, TexImage& out)>;

    explicit TextureGraphEvaluator(const NodeGraph& graph) : mGraph(&graph) {}

    void SetSize(int size);
    [[nodiscard]] int Size() const noexcept { return mSize; }
    void SetTextureLoader(TextureLoader loader);
    void SetTerrain(std::shared_ptr<const TerrainSource> terrain);

    /** Brings the node and what it needs up to date, computing only what changed. Returns the nodes computed. */
    int Evaluate(int id);
    /** Every node of the graph (the canvas's thumbnails). */
    int EvaluateAll();

    /** The node's output image (null before its evaluation or for a missing pin). */
    [[nodiscard]] TexImagePtr Output(int id, int pin) const;
    /** The image an input sees: its link's output, else the input's own value as a 1-pixel image. */
    [[nodiscard]] TexImagePtr Input(int id, int pin) const;
    /** What went wrong with the node last time (a texture that didn't load, no map for a terrain node). */
    [[nodiscard]] std::string Warning(int id) const;
    /** The node's last computing time in milliseconds. */
    [[nodiscard]] double Millis(int id) const;
    /** The image the output node's input holds, at the graph's size, in the pin's type (null when unlinked). */
    [[nodiscard]] TexImagePtr Result(const std::string& outputPin);
    /** Drops every cached image (the size or the textures changed). */
    void Invalidate();

  private:
    struct Cached
    {
      std::uint64_t revision = 0;
      int size = 0;
      std::vector<TexImagePtr> outputs;
      std::string warning;
      double millis = 0.0;
    };

    bool Compute(const GraphNode& node);

    const NodeGraph* mGraph;
    int mSize = 256;
    TextureLoader mLoader;
    std::shared_ptr<const TerrainSource> mTerrain;
    std::map<int, Cached> mCache;
    std::map<std::string, std::shared_ptr<TexImage>> mTextures;
  };
} // namespace faf::editor
