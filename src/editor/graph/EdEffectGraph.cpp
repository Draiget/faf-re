#include "editor/graph/EdEffectGraph.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>

namespace faf::editor
{
  namespace
  {
    // The Emitter node's parameters, in order.
    enum EmitterParam : std::size_t
    {
      kName,
      kId,
      kLifetimeParam,
      kRepeat,
      kBlend,
      kFrames,
      kStrips,
      kLod,
      kSort,
      kFirstFlag,
      kLow = kFirstFlag + kEmitterFlagCount,
      kMed,
      kHigh,
    };
    // The Emitter node's inputs: the 21 curves, then the texture and the ramp.
    constexpr int kTexturePin = kEmitterCurveCount;
    constexpr int kRampPin = kEmitterCurveCount + 1;

    ParamDef Num(
      const char* name,
      const float initial,
      const float min,
      const float max,
      const char* help = ""
    )
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Float;
      def.initial = {initial, 0.0f, 0.0f, 0.0f};
      def.min = min;
      def.max = max;
      def.help = help;
      return def;
    }

    ParamDef Flag(
      const char* name,
      const bool initial,
      const char* help = ""
    )
    {
      ParamDef def = Num(name, initial ? 1.0f : 0.0f, 0.0f, 1.0f, help);
      def.kind = ParamKind::Bool;
      return def;
    }

    ParamDef Text(
      const char* name,
      const char* initial,
      const char* help = ""
    )
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Text;
      def.initialText = initial;
      def.help = help;
      return def;
    }

    ParamDef Choice(
      const char* name,
      std::vector<std::string> choices,
      const int initial
    )
    {
      ParamDef def;
      def.name = name;
      def.kind = ParamKind::Choice;
      def.initial = {static_cast<float>(initial), 0.0f, 0.0f, 0.0f};
      def.choices = std::move(choices);
      return def;
    }

    PinDef Pin(
      const char* name,
      const PinType type
    )
    {
      return PinDef{name, type, {}};
    }

    NodeTypeRegistry MakeTypes()
    {
      NodeTypeRegistry registry;
      // The output: up to twelve emitters played together (a template's list).
      {
        NodeType effect{
          kEffectOutput,
          "Effect",
          "Output",
          "What the graph makes: the emitters played together, as a game effect (an EffectTemplates list) is.",
          {},
          {},
          {},
          true
        };
        for (int i = 1; i <= 12; ++i) {
          effect.inputs.push_back(PinDef{"Emitter " + std::to_string(i), PinType::Emitter, {}});
        }
        effect.params = {Text("Name", "new_effect", "The effect's name")};
        registry.Add(std::move(effect));
      }
      // An emitter: its file's settings; its curves and textures through its pins.
      {
        NodeType emitter{
          kEmitterNode,
          "Emitter",
          "Emitters",
          "One emitter file: its settings here, its 21 curves and its textures from the nodes linked to its pins.",
          {},
          {Pin("Emitter", PinType::Emitter)},
          {},
          false
        };
        for (int c = 0; c < kEmitterCurveCount; ++c) {
          emitter.inputs.push_back(PinDef{CurveInfo(c).caption, PinType::Curve, {}});
        }
        emitter.inputs.push_back(Pin("Texture", PinType::Texture));
        emitter.inputs.push_back(Pin("Ramp", PinType::Texture));
        std::vector<std::string> blends(std::begin(kEmitterBlendModes), std::end(kEmitterBlendModes));
        emitter.params = {
          Text("Name", "new_emitter", "The file's name (without .bp)"),
          Text("Id", "new_emitter", "BlueprintId (FAF's loader replaces it with the file's path)"),
          Num("Lifetime", 10.0f, -1.0f, 200.0f, "Ticks the emitter lives (10 a second); -1: until destroyed"),
          Num("Repeat time", 10.0f, 0.1f, 200.0f, "Ticks after which its curves start over"),
          Choice("Blend", blends, 0),
          Num("Frames", 1.0f, 1.0f, 64.0f, "Animation frames across the texture"),
          Num("Strips", 1.0f, 1.0f, 64.0f, "Rows of the texture (Texture Selection picks one)"),
          Num("LOD cutoff", 100.0f, 0.0f, 2000.0f, "The camera distance beyond which it doesn't emit"),
          Num("Sort order", 0.0f, -100.0f, 100.0f)
        };
        for (int f = 0; f < kEmitterFlagCount; ++f) {
          emitter.params.push_back(
            Flag(FlagName(f), f == kEmitIfVisible || f == kCatchupEmit || f == kInterpolateEmission)
          );
        }
        emitter.params.push_back(Flag("Low fidelity", true));
        emitter.params.push_back(Flag("Medium fidelity", true));
        emitter.params.push_back(Flag("High fidelity", true));
        registry.Add(std::move(emitter));
      }
      registry.Add(
        {kCurveNode,
         "Curve",
         "Curves",
         "Keys over the emitter's time: each a time, a value and a random spread around it.",
         {},
         {Pin("Curve", PinType::Curve)},
         {Num("Time range", 10.0f, 0.1f, 200.0f, "The curve's time axis in ticks"),
          Text("Keys", "5 1 0", "time value spread; time value spread")},
         false}
      );
      registry.Add(
        {kConstantNode,
         "Constant",
         "Curves",
         "One value, with a random spread around it, for the whole time.",
         {},
         {Pin("Curve", PinType::Curve)},
         {Num("Value", 1.0f, -100.0f, 100.0f),
          Num(
            "Spread",
            0.0f,
            0.0f,
            100.0f,
            "Each particle gets the value plus a random amount within half of it either way"
          ),
          Num("Key at", 0.0f, 0.0f, 200.0f, "Where the file keeps its one key (no effect on the value)"),
          Num("Time range", -1.0f, -1.0f, 200.0f, "The file's time range for it (-1: the emitter's repeat time)")},
         false}
      );
      registry.Add(
        {"CurveRandom",
         "Random Range",
         "Curves",
         "Any value from Min to Max, picked for each particle.",
         {},
         {Pin("Curve", PinType::Curve)},
         {Num("Min", 0.0f, -100.0f, 100.0f), Num("Max", 1.0f, -100.0f, 100.0f)},
         false}
      );
      registry.Add(
        {"CurveOverLife",
         "Over Time",
         "Curves",
         "From one value at the start of the emitter's time to another at its end.",
         {},
         {Pin("Curve", PinType::Curve)},
         {Num("From", 0.0f, -100.0f, 100.0f), Num("To", 1.0f, -100.0f, 100.0f), Num("Spread", 0.0f, 0.0f, 100.0f)},
         false}
      );
      registry.Add(
        {"CurveScale",
         "Multiply",
         "Math",
         "The curve times a factor (its spread too).",
         {Pin("Curve", PinType::Curve)},
         {Pin("Curve", PinType::Curve)},
         {Num("Factor", 2.0f, -100.0f, 100.0f)},
         false}
      );
      registry.Add(
        {"CurveAdd",
         "Add",
         "Math",
         "The curve plus an amount.",
         {Pin("Curve", PinType::Curve)},
         {Pin("Curve", PinType::Curve)},
         {Num("Amount", 1.0f, -100.0f, 100.0f)},
         false}
      );
      registry.Add(
        {kTextureNode,
         "Texture",
         "Textures",
         "A particle texture or colour ramp from the game's files.",
         {},
         {Pin("Texture", PinType::Texture)},
         {Text("Texture", "/textures/particles/smoke_white_01.dds", "The texture's path")},
         false}
      );
      return registry;
    }

    float F(
      const GraphNode& node,
      const std::size_t param
    )
    {
      return node.params[param].value[0];
    }

    void SetF(
      NodeGraph& graph,
      const int id,
      const std::size_t param,
      const float value
    )
    {
      ParamValue v;
      v.value = {value, 0.0f, 0.0f, 0.0f};
      graph.SetParam(id, param, v);
    }

    void SetText(
      NodeGraph& graph,
      const int id,
      const std::size_t param,
      const std::string& text
    )
    {
      ParamValue v;
      v.text = text;
      graph.SetParam(id, param, v);
    }

    /** The curve a node's output makes (`range`: the emitter's repeat time, for nodes without one). */
    EmitterCurve EvaluateCurve(
      const NodeGraph& graph,
      const int id,
      const float range,
      const int depth = 0
    )
    {
      EmitterCurve curve;
      curve.xRange = range;
      const GraphNode* node = graph.Find(id);
      if (node == nullptr || depth > 64) {
        return curve;
      }
      const std::string& type = node->type->name;
      const auto input = [&]() {
        const GraphLink* link = graph.InputLink(id, 0);
        return link != nullptr ? EvaluateCurve(graph, link->fromNode, range, depth + 1) : EmitterCurve{range, {}};
      };
      if (type == kCurveNode) {
        curve.xRange = F(*node, 0) >= 0.0f ? F(*node, 0) : range;
        curve.keys = CurveKeysFromText(node->params[1].text);
      } else if (type == kConstantNode) {
        curve.xRange = F(*node, 3) >= 0.0f ? F(*node, 3) : range; // a file's 0 kept as 0
        curve.keys = {{F(*node, 2), F(*node, 0), F(*node, 1)}};
      } else if (type == "CurveRandom") {
        curve.keys = {{range * 0.5f, (F(*node, 0) + F(*node, 1)) * 0.5f, std::fabs(F(*node, 1) - F(*node, 0))}};
      } else if (type == "CurveOverLife") {
        curve.keys = {{0.0f, F(*node, 0), F(*node, 2)}, {range, F(*node, 1), F(*node, 2)}};
      } else if (type == "CurveScale") {
        curve = input();
        for (EmitterKey& key : curve.keys) {
          key.y *= F(*node, 0);
          key.z *= std::fabs(F(*node, 0));
        }
      } else if (type == "CurveAdd") {
        curve = input();
        for (EmitterKey& key : curve.keys) {
          key.y += F(*node, 0);
        }
      }
      return curve;
    }

    std::string Number(
      const float value
    )
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%.9g", static_cast<double>(value));
      return text;
    }
  } // namespace

  const NodeTypeRegistry& EffectNodeTypes()
  {
    static const NodeTypeRegistry types = MakeTypes();
    return types;
  }

  std::string CurveKeysText(
    const std::vector<EmitterKey>& keys
  )
  {
    std::string out;
    for (const EmitterKey& key : keys) {
      out += (out.empty() ? "" : "; ") + Number(key.x) + " " + Number(key.y) + " " + Number(key.z);
    }
    return out;
  }

  std::vector<EmitterKey> CurveKeysFromText(
    const std::string& text
  )
  {
    std::vector<EmitterKey> keys;
    std::size_t at = 0;
    while (at <= text.size()) {
      const std::size_t end = text.find(';', at);
      const std::string part = text.substr(at, end == std::string::npos ? std::string::npos : end - at);
      at = end == std::string::npos ? text.size() + 1 : end + 1;
      float v[3] = {0.0f, 0.0f, 0.0f};
      int n = 0;
      const char* p = part.c_str();
      while (n < 3 && *p != '\0') {
        char* next = nullptr;
        const float value = std::strtof(p, &next);
        if (next == p) {
          ++p;
          continue;
        }
        v[n++] = value;
        p = next;
      }
      if (n >= 2) {
        keys.push_back({v[0], v[1], v[2]});
      }
    }
    return keys;
  }

  int AddEmitterNodes(
    NodeGraph& graph,
    const EmitterBlueprint& e,
    const std::string& name,
    const float x,
    const float y
  )
  {
    const int emitter = graph.AddNode(kEmitterNode, x, y);
    SetText(graph, emitter, kName, name);
    SetText(graph, emitter, kId, e.blueprintId);
    SetF(graph, emitter, kLifetimeParam, e.lifetime);
    SetF(graph, emitter, kRepeat, e.repeatTime);
    SetF(graph, emitter, kBlend, e.blendMode);
    SetF(graph, emitter, kFrames, e.textureFrameCount);
    SetF(graph, emitter, kStrips, e.textureStripCount);
    SetF(graph, emitter, kLod, e.lodCutoff);
    SetF(graph, emitter, kSort, e.sortOrder);
    for (int f = 0; f < kEmitterFlagCount; ++f) {
      SetF(
        graph, emitter, kFirstFlag + static_cast<std::size_t>(f), e.flags[static_cast<std::size_t>(f)] ? 1.0f : 0.0f
      );
    }
    SetF(graph, emitter, kLow, e.lowFidelity ? 1.0f : 0.0f);
    SetF(graph, emitter, kMed, e.medFidelity ? 1.0f : 0.0f);
    SetF(graph, emitter, kHigh, e.highFidelity ? 1.0f : 0.0f);
    // The curves in three columns to its left, the textures under them.
    constexpr float kColumn = 210.0f;
    constexpr float kRow = 170.0f;
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      const EmitterCurve& curve = e.curves[static_cast<std::size_t>(c)];
      const float nx = x - kColumn * static_cast<float>(3 - c % 3);
      const float ny = y + kRow * static_cast<float>(c / 3);
      int node = 0;
      if (curve.keys.size() == 1) {
        node = graph.AddNode(kConstantNode, nx, ny);
        SetF(graph, node, 0, curve.keys[0].y);
        SetF(graph, node, 1, curve.keys[0].z);
        SetF(graph, node, 2, curve.keys[0].x);
        SetF(graph, node, 3, curve.xRange);
      } else {
        node = graph.AddNode(kCurveNode, nx, ny);
        SetF(graph, node, 0, curve.xRange);
        SetText(graph, node, 1, CurveKeysText(curve.keys));
      }
      (void)graph.Link(node, 0, emitter, c);
    }
    const float textureY = y + kRow * 7.0f;
    for (const auto& [pin, path] : {std::pair{kTexturePin, e.texture}, std::pair{kRampPin, e.rampTexture}}) {
      const int texture = graph.AddNode(kTextureNode, x - kColumn * (pin == kTexturePin ? 2.0f : 1.0f), textureY);
      SetText(graph, texture, 0, path);
      (void)graph.Link(texture, 0, emitter, pin);
    }
    return emitter;
  }

  void BuildEffectGraph(
    NodeGraph& graph,
    const std::string& effectName,
    const std::vector<std::pair<std::string, EmitterBlueprint>>& emitters
  )
  {
    graph.Clear();
    const float outputX = 300.0f;
    const int output = graph.AddNode(kEffectOutput, outputX, 0.0f);
    SetText(graph, output, 0, effectName);
    // Each emitter a block of its own, stacked down the left.
    for (std::size_t i = 0; i < emitters.size() && i < 12; ++i) {
      const int emitter =
        AddEmitterNodes(graph, emitters[i].second, emitters[i].first, 0.0f, static_cast<float>(i) * 1450.0f);
      (void)graph.Link(emitter, 0, output, static_cast<int>(i));
    }
  }

  bool GraphEmitters(
    const NodeGraph& graph,
    std::vector<std::pair<std::string, EmitterBlueprint>>& out,
    std::string& error
  )
  {
    out.clear();
    const int output = graph.OutputNode();
    if (output == 0) {
      error = "the graph has no Effect output";
      return false;
    }
    const GraphNode* effect = graph.Find(output);
    for (std::size_t pin = 0; pin < effect->type->inputs.size(); ++pin) {
      const GraphLink* link = graph.InputLink(output, static_cast<int>(pin));
      const GraphNode* node = link != nullptr ? graph.Find(link->fromNode) : nullptr;
      if (node == nullptr || node->type->name != kEmitterNode) {
        continue;
      }
      EmitterBlueprint e;
      e.blueprintId = node->params[kId].text;
      e.lifetime = F(*node, kLifetimeParam);
      e.repeatTime = F(*node, kRepeat);
      e.blendMode = F(*node, kBlend);
      e.textureFrameCount = F(*node, kFrames);
      e.textureStripCount = F(*node, kStrips);
      e.lodCutoff = F(*node, kLod);
      e.sortOrder = F(*node, kSort);
      for (int f = 0; f < kEmitterFlagCount; ++f) {
        e.flags[static_cast<std::size_t>(f)] = F(*node, kFirstFlag + static_cast<std::size_t>(f)) > 0.5f;
      }
      e.lowFidelity = F(*node, kLow) > 0.5f;
      e.medFidelity = F(*node, kMed) > 0.5f;
      e.highFidelity = F(*node, kHigh) > 0.5f;
      for (int c = 0; c < kEmitterCurveCount; ++c) {
        if (const GraphLink* curveLink = graph.InputLink(node->id, c)) {
          e.curves[static_cast<std::size_t>(c)] = EvaluateCurve(graph, curveLink->fromNode, e.repeatTime);
        } else {
          // Unlinked: the curve's starting key, as retail's editor starts a new emitter.
          const EmitterCurveInfo& info = CurveInfo(c);
          e.curves[static_cast<std::size_t>(c)] =
            EmitterCurve{e.repeatTime, {{e.repeatTime * 0.5f, info.initialValue, info.initialSpread}}};
        }
      }
      const auto texture = [&](const int texturePin) {
        const GraphLink* textureLink = graph.InputLink(node->id, texturePin);
        const GraphNode* t = textureLink != nullptr ? graph.Find(textureLink->fromNode) : nullptr;
        return t != nullptr ? t->params[0].text : std::string();
      };
      e.texture = texture(kTexturePin);
      e.rampTexture = texture(kRampPin);
      out.emplace_back(node->params[kName].text, std::move(e));
    }
    if (out.empty()) {
      error = "no emitter is linked to the Effect output";
      return false;
    }
    return true;
  }

  std::vector<EffectTemplate> ParseEffectTemplates(
    const std::string& luaText
  )
  {
    // Comments out first (`--[[ ]]` and `--`).
    std::string text;
    for (std::size_t i = 0; i < luaText.size();) {
      if (luaText.compare(i, 4, "--[[") == 0) {
        const std::size_t end = luaText.find("]]", i + 4);
        i = end == std::string::npos ? luaText.size() : end + 2;
      } else if (luaText.compare(i, 2, "--") == 0) {
        const std::size_t end = luaText.find('\n', i);
        i = end == std::string::npos ? luaText.size() : end;
      } else {
        text += luaText[i++];
      }
    }
    std::map<std::string, std::string> variables;
    std::vector<EffectTemplate> templates;
    std::size_t at = 0;
    const auto isName = [](const char c) {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    };
    while (at < text.size()) {
      // A top-level assignment: at a line's start, `Name = 'text'` or `Name = { ... }`.
      if ((at == 0 || text[at - 1] == '\n') && isName(text[at])) {
        std::size_t end = at;
        while (end < text.size() && isName(text[end])) {
          ++end;
        }
        const std::string name = text.substr(at, end - at);
        std::size_t p = end;
        while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) {
          ++p;
        }
        if (p < text.size() && text[p] == '=' && (p + 1 >= text.size() || text[p + 1] != '=')) {
          ++p;
          while (p < text.size() && std::isspace(static_cast<unsigned char>(text[p])) != 0) {
            ++p;
          }
          if (p < text.size() && (text[p] == '\'' || text[p] == '"')) {
            const char quote = text[p];
            const std::size_t close = text.find(quote, p + 1);
            if (close != std::string::npos) {
              variables[name] = text.substr(p + 1, close - p - 1);
            }
          } else if (p < text.size() && text[p] == '{') {
            // The table to its matching brace; a nested table or anything but paths: not a plain list.
            int depth = 0;
            std::size_t close = p;
            for (; close < text.size(); ++close) {
              depth += text[close] == '{' ? 1 : text[close] == '}' ? -1 : 0;
              if (depth == 0) {
                break;
              }
            }
            const std::string body = text.substr(p + 1, close > p ? close - p - 1 : 0);
            EffectTemplate made;
            made.name = name;
            bool plain = body.find('{') == std::string::npos;
            std::size_t q = 0;
            while (plain && q < body.size()) {
              const std::size_t comma = body.find(',', q);
              std::string item = body.substr(q, comma == std::string::npos ? std::string::npos : comma - q);
              q = comma == std::string::npos ? body.size() : comma + 1;
              item.erase(0, item.find_first_not_of(" \t\r\n"));
              item.erase(item.find_last_not_of(" \t\r\n") + 1);
              if (item.empty()) {
                continue;
              }
              std::string prefix;
              const std::size_t dots = item.find("..");
              if (dots != std::string::npos) {
                std::string variable = item.substr(0, dots);
                variable.erase(variable.find_last_not_of(" \t") + 1);
                const auto found = variables.find(variable);
                if (found == variables.end()) {
                  plain = false;
                  break;
                }
                prefix = found->second;
                item = item.substr(dots + 2);
                item.erase(0, item.find_first_not_of(" \t"));
              }
              if (item.size() < 2 || (item.front() != '\'' && item.front() != '"') || item.back() != item.front()) {
                plain = false;
                break;
              }
              made.paths.push_back(prefix + item.substr(1, item.size() - 2));
            }
            if (plain && !made.paths.empty()) {
              templates.push_back(std::move(made));
            }
            at = close;
          }
        }
      }
      const std::size_t next = text.find('\n', at);
      at = next == std::string::npos ? text.size() : next + 1;
    }
    return templates;
  }
} // namespace faf::editor
