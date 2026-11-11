#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace faf::editor
{
  // A node graph's model, apart from its drawing (EdNodeCanvas) and from what its nodes compute (EdTextureGraph):
  // node types with typed pins and parameters, nodes, links, the order to evaluate them in, and the graph file.

  /**
   * What flows along a link. A grey image converts to a colour one (grey, opaque) and back (its luminance); the
   * particle graph's kinds (a curve, an emitter, a texture) link only to their own kind.
   */
  enum class PinType : std::uint8_t
  {
    Grey,
    Color,
    Curve,
    Emitter,
    Texture,
  };
  /** Whether an output of `from` may feed an input of `to`. */
  [[nodiscard]] bool PinsCompatible(PinType from, PinType to) noexcept;
  /** The kind's name for tooltips ("grey", "colour", "curve", ...). */
  [[nodiscard]] const char* PinTypeName(PinType type) noexcept;

  struct PinDef
  {
    std::string name;
    PinType type = PinType::Grey;
    /** An input's value while nothing is linked to it. */
    std::array<float, 4> initial{};
  };

  enum class ParamKind : std::uint8_t
  {
    Float,
    Int,
    Bool,
    Color,  // RGBA, 0-1
    Choice, // an index into `choices`
    Text,   // a texture path and the like
  };

  struct ParamDef
  {
    std::string name;
    ParamKind kind = ParamKind::Float;
    std::array<float, 4> initial{};
    float min = 0.0f;
    float max = 1.0f;
    std::vector<std::string> choices;
    std::string initialText;
    std::string help;
  };

  struct NodeType
  {
    std::string name;     // the file's name for it, never changed once graphs use it
    std::string title;    // shown in the header
    std::string category; // the palette's group
    std::string help;
    std::vector<PinDef> inputs;
    std::vector<PinDef> outputs;
    std::vector<ParamDef> params;
    /** The graph's output (one per graph, can't be deleted). */
    bool isOutput = false;
  };

  class NodeTypeRegistry
  {
  public:
    const NodeType& Add(NodeType type);
    [[nodiscard]] const NodeType* Find(const std::string& name) const;
    [[nodiscard]] const std::vector<std::unique_ptr<NodeType>>& All() const noexcept { return mTypes; }

  private:
    std::vector<std::unique_ptr<NodeType>> mTypes;
  };

  struct ParamValue
  {
    std::array<float, 4> value{};
    std::string text;
  };

  struct GraphNode
  {
    int id = 0;
    const NodeType* type = nullptr;
    float x = 0.0f;
    float y = 0.0f;
    std::vector<ParamValue> params;
    /** New whenever a parameter or an input link changes, unique in the graph's life: what an evaluator caches against. */
    std::uint64_t revision = 0;
  };

  struct GraphLink
  {
    int fromNode = 0;
    int fromPin = 0;
    int toNode = 0;
    int toPin = 0;
  };

  enum class LinkResult : std::uint8_t
  {
    Ok,
    BadPin,
    SameNode,
    Cycle,
    WrongType,
  };

  class NodeGraph
  {
  public:
    explicit NodeGraph(const NodeTypeRegistry& registry) : mRegistry(&registry) {}

    [[nodiscard]] const NodeTypeRegistry& Registry() const noexcept { return *mRegistry; }
    [[nodiscard]] const std::vector<GraphNode>& Nodes() const noexcept { return mNodes; }
    [[nodiscard]] const std::vector<GraphLink>& Links() const noexcept { return mLinks; }

    /** A node of the type at (x, y) with its parameters' initial values; its id, or 0 for an unknown type. */
    int AddNode(const std::string& type, float x, float y);
    /** Removes the node and its links (not the output node). */
    bool RemoveNode(int id);
    [[nodiscard]] GraphNode* Find(int id);
    [[nodiscard]] const GraphNode* Find(int id) const;
    /** The output node's id, 0 when the graph has none. */
    [[nodiscard]] int OutputNode() const;

    /** Sets a parameter and bumps the node's revision (and so its downstream's). */
    void SetParam(int id, std::size_t param, const ParamValue& value);
    void MoveNode(int id, float x, float y);

    /** Links an output to an input, replacing the input's link. A link that would close a loop is refused. */
    LinkResult Link(int fromNode, int fromPin, int toNode, int toPin);
    /** Removes the link into the input. */
    bool Unlink(int toNode, int toPin);
    [[nodiscard]] const GraphLink* InputLink(int toNode, int toPin) const;

    /** The nodes `id` feeds, directly or not, `id` first. */
    [[nodiscard]] std::vector<int> Downstream(int id) const;
    /** Every node before the nodes it feeds; false on a loop (the file was edited by hand). */
    bool Order(std::vector<int>& out) const;
    /** The nodes the output needs, in order: what an evaluation computes. */
    [[nodiscard]] std::vector<int> OrderFor(int id) const;

    /** Any change to nodes, links or parameters: what an editor saves against. */
    [[nodiscard]] std::uint64_t Changes() const noexcept { return mChanges; }

    /** The graph file (JSON): nodes with their parameters by name, links. */
    [[nodiscard]] std::string Save() const;
    /** Reads a graph file; unknown node types and parameters are dropped, missing parameters take their initial value. */
    bool Load(const std::string& text, std::string& error);
    void Clear();

  private:
    void Touch(int id);

    const NodeTypeRegistry* mRegistry;
    std::vector<GraphNode> mNodes;
    std::vector<GraphLink> mLinks;
    int mNextId = 1;
    std::uint64_t mChanges = 0;
    /** Never reset (not by Clear or Load either), so a cache can't mistake a reloaded node for the one it held. */
    std::uint64_t mRevisionSeed = 0;
  };
} // namespace faf::editor
