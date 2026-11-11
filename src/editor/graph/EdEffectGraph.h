#pragma once

#include "editor/doc/EdEmitter.h"
#include "editor/graph/EdNodeGraph.h"

#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  // The particle editor's node graph. A game effect is a set of emitter files played together (FAF's
  // lua/EffectTemplates.lua lists 700 such sets, played by CreateEffects: one CreateEmitterAtEntity each). As nodes:
  // an Effect output fed by Emitter nodes; an Emitter node holds the file's settings, and its 21 curves come in
  // through pins from Curve or Constant nodes (and the math nodes, which become plain keys when saved: the game reads
  // only the curves), its textures from Texture nodes. Any emitter file (and any template) turns into such a graph
  // and back without loss.

  /** The particle graph's node types (the palette). The output node is "Effect". */
  const NodeTypeRegistry& EffectNodeTypes();

  /** The node type names (the graph file's). */
  inline constexpr const char* kEffectOutput = "Effect";
  inline constexpr const char* kEmitterNode = "Emitter";
  inline constexpr const char* kCurveNode = "Curve";
  inline constexpr const char* kConstantNode = "Constant";
  inline constexpr const char* kTextureNode = "ParticleTexture";

  /** A curve's keys as a Curve node's text ("x y z; x y z") and back (unreadable parts skipped). */
  std::string CurveKeysText(const std::vector<EmitterKey>& keys);
  std::vector<EmitterKey> CurveKeysFromText(const std::string& text);

  /**
   * Adds an emitter's nodes at (x, y): its Emitter node (named `name`, the file's name without .bp), a Constant node
   * for each curve of one key and a Curve node for each other, its texture and ramp; all linked. Returns the Emitter
   * node's id.
   */
  int AddEmitterNodes(NodeGraph& graph, const EmitterBlueprint& emitter, const std::string& name, float x, float y);
  /** A whole graph for an effect of these emitters (name, blueprint): the Effect output fed by each. */
  void BuildEffectGraph(NodeGraph& graph, const std::string& effectName, const std::vector<std::pair<std::string, EmitterBlueprint>>& emitters);

  /**
   * The emitters the graph makes, in the Effect output's pin order (name, blueprint): every curve pin evaluated
   * through its nodes to keys, an unlinked one given the curve's starting key (as retail's editor gives a new emitter).
   * False with `error` when the graph has no output or nothing linked to it.
   */
  bool GraphEmitters(const NodeGraph& graph, std::vector<std::pair<std::string, EmitterBlueprint>>& out, std::string& error);

  /** One effect template of FAF's lua/EffectTemplates.lua: its name and its emitter files' paths. */
  struct EffectTemplate
  {
    std::string name;
    std::vector<std::string> paths;
  };
  /**
   * The templates that are plain lists of emitter paths (`Name = { EmtBpPath .. 'file.bp', '/effects/x.bp', }`, the
   * file's path variables resolved); one holding anything else (tables, calls) is left out.
   */
  std::vector<EffectTemplate> ParseEffectTemplates(const std::string& luaText);
} // namespace faf::editor
