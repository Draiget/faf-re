#include "editor/graph/EdTerrainGraph.h"

#include "editor/graph/EdTerrainEval.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    struct Catalogue
    {
      NodeTypeRegistry registry;
      std::map<std::string, terrain::NodeBehaviour> behaviours;
      Catalogue()
      {
        terrain::BuildCatalogue(registry, behaviours);
      }
    };
    const Catalogue& TheCatalogue()
    {
      static const Catalogue catalogue;
      return catalogue;
    }

    std::string Number(
      const double value
    )
    {
      char text[48];
      (void)std::snprintf(text, sizeof(text), "%.9g", value);
      return text;
    }

    const ParamDef* FindParam(
      const NodeType& type,
      const std::string& name
    )
    {
      for (const ParamDef& p : type.params) {
        if (p.name == name) {
          return &p;
        }
      }
      return nullptr;
    }

    int PinIndex(
      const std::vector<PinDef>& pins,
      const std::string& name
    )
    {
      for (std::size_t i = 0; i < pins.size(); ++i) {
        if (pins[i].name == name) {
          return static_cast<int>(i);
        }
      }
      return -1;
    }

    /** A parameter's value as the evaluation reads it: a choice's id, a bool 0 / 1, text as it is. */
    void ReadParam(
      const ParamDef& def,
      const ParamValue& value,
      terrain::Values& out
    )
    {
      switch (def.kind) {
      case ParamKind::Choice: {
        const int index = std::clamp(
          static_cast<int>(value.value[0] + 0.5f), 0, std::max(0, static_cast<int>(def.choiceIds.size()) - 1)
        );
        out.text[def.name] =
          def.choiceIds.empty() ? std::to_string(index) : def.choiceIds[static_cast<std::size_t>(index)];
        break;
      }
      case ParamKind::Text:
        out.text[def.name] = value.text;
        break;
      case ParamKind::Bool:
        out.num[def.name] = value.value[0] >= 0.5f ? 1.0 : 0.0;
        break;
      default:
        out.num[def.name] = static_cast<double>(value.value[0]);
        break;
      }
    }
  } // namespace

  namespace terrain
  {
    const std::map<std::string, NodeBehaviour>& Behaviours()
    {
      return TheCatalogue().behaviours;
    }

    field::GridPtr Env::Op(
      const std::string& name,
      const std::initializer_list<Arg> args,
      std::map<std::string, field::Grid>* extra
    ) const
    {
      return Op(name, std::vector<Arg>(args), extra);
    }

    field::GridPtr Env::Op(
      const std::string& name,
      const std::vector<Arg>& args,
      std::map<std::string, field::Grid>* extra
    ) const
    {
      field::OpArgs op;
      for (const Arg& arg : args) {
        switch (arg.kind) {
        case Arg::Kind::Number:
          op.p.num[arg.key] = arg.number;
          break;
        case Arg::Kind::Text:
          op.p.str[arg.key] = arg.text;
          break;
        case Arg::Kind::List:
          op.p.arr[arg.key] = arg.list;
          break;
        case Arg::Kind::Grid:
          if (arg.grid != nullptr) {
            op.in[arg.key] = arg.grid;
          }
          break;
        }
      }
      op.extra = extra;
      auto out = std::make_shared<field::Grid>();
      std::string error;
      if (!field::RunOp(name, op, *out, error)) {
        Fail(name + ": " + error);
      }
      return out;
    }
  } // namespace terrain

  const NodeTypeRegistry& TerrainNodeTypes()
  {
    return TheCatalogue().registry;
  }

  const std::vector<std::pair<std::string, std::string>>& TerrainCategories()
  {
    static const std::vector<std::pair<std::string, std::string>> kCategories = {
      {"sources", "Sources"},
      {"gen", "Generators"},
      {"shape", "Shape"},
      {"combine", "Combine"},
      {"erosion", "Erosion"},
      {"analysis", "Analysis and masks"},
      {"paths", "Paths"},
      {"sc", "SC terrain (pads, symmetry, pathing)"},
      {"color", "Colour"},
      {"numbers", "Numbers"},
      {"outputs", "Outputs"},
      {"organise", "Organise"},
      {"raw", "Field ops (generic)"},
    };
    return kCategories;
  }

  double TerrainParamNumber(
    const GraphNode& node,
    const std::string& name,
    const double fallback
  )
  {
    for (std::size_t p = 0; p < node.type->params.size() && p < node.params.size(); ++p) {
      if (node.type->params[p].name == name) {
        return static_cast<double>(node.params[p].value[0]);
      }
    }
    return fallback;
  }

  std::string TerrainParamText(
    const GraphNode& node,
    const std::string& name
  )
  {
    for (std::size_t p = 0; p < node.type->params.size() && p < node.params.size(); ++p) {
      if (node.type->params[p].name == name) {
        terrain::Values values;
        ReadParam(node.type->params[p], node.params[p], values);
        const auto found = values.text.find(name);
        return found != values.text.end() ? found->second : Number(values.N(name));
      }
    }
    return {};
  }

  void TerrainRun::SetStep(
    const int step
  )
  {
    const int s = std::max(1, step);
    if (s != mStep) {
      mStep = s;
      Clear();
    }
  }

  void TerrainRun::Clear()
  {
    mCache.clear();
    mLike.reset();
    mLikeKey.clear();
    mBase.reset();
    mBaseRevision = ~0ULL;
  }

  field::GridPtr TerrainRun::Like(
    const TerrainGround& ground
  )
  {
    const std::string key = std::to_string(ground.width) + "x" + std::to_string(ground.height) + "@" +
      std::to_string(mStep) + "w" + Number(ground.water);
    if (mLike != nullptr && key == mLikeKey) {
      return mLike;
    }
    mCache.clear();
    mBase.reset();
    mBaseRevision = ~0ULL;
    const int w = (ground.width - 1) / mStep + 1;
    const int h = (ground.height - 1) / mStep + 1;
    mLike = std::make_shared<field::Grid>(w, h, static_cast<float>(mStep), 0.0f, 0.0f);
    mLikeKey = key;
    return mLike;
  }

  field::GridPtr TerrainRun::BaseHere(
    const TerrainGround& ground
  )
  {
    if (mBase != nullptr && mBaseRevision == ground.revision) {
      return mBase;
    }
    auto full = std::make_shared<field::Grid>(ground.width, ground.height, 1.0f, 0.0f, 0.0f);
    if (ground.heights != nullptr && ground.heights->size() == full->v.size()) {
      full->v = *ground.heights;
    }
    if (mStep == 1) {
      mBase = full;
    } else {
      field::OpArgs args;
      args.in["a"] = full;
      args.in["like"] = mLike;
      auto coarse = std::make_shared<field::Grid>();
      std::string error;
      if (!field::RunOp("resample", args, *coarse, error)) {
        terrain::Fail("resample: " + error);
      }
      mBase = coarse;
    }
    mBaseRevision = ground.revision;
    return mBase;
  }

  TerrainReport TerrainRun::Evaluate(
    const NodeGraph& graph,
    const int seed,
    const TerrainGround& ground,
    const std::set<int>* only
  )
  {
    using Clock = std::chrono::steady_clock;
    const auto started = Clock::now();
    TerrainReport report;
    if (ground.width < 2 || ground.height < 2) {
      return report;
    }
    const field::GridPtr like = Like(ground);
    const auto& behaviours = terrain::Behaviours();
    std::vector<int> order;
    if (!graph.Order(order)) {
      // A loop (a hand-edited file): what is ordered still runs.
    }
    std::set<int> seen;
    for (const int id : order) {
      seen.insert(id);
      if (only != nullptr && only->count(id) == 0) {
        continue;
      }
      const GraphNode* node = graph.Find(id);
      if (node == nullptr) {
        continue;
      }
      Entry& entry = mCache[id];
      const auto failed = [&](const std::string& message, const bool upstream) {
        entry = Entry{};
        entry.error = message;
        entry.upstream = upstream;
        if (!upstream) {
          report.errors[id] = message;
        }
      };
      const auto behaviour = behaviours.find(node->type->name);
      if (behaviour == behaviours.end()) {
        failed("unknown node type " + node->type->name, false);
        continue;
      }
      // The inputs and the key: the parameters, the versions of the inputs, the grid.
      terrain::Inputs ins;
      std::string key = node->type->name + "|";
      std::string blocked;
      bool blockedUp = false;
      for (std::size_t pin = 0; pin < node->type->inputs.size(); ++pin) {
        const PinDef& def = node->type->inputs[pin];
        const GraphLink* link = graph.InputLink(id, static_cast<int>(pin));
        if (link == nullptr) {
          continue;
        }
        const GraphNode* from = graph.Find(link->fromNode);
        const std::string& fromPin = from->type->outputs[static_cast<std::size_t>(link->fromPin)].name;
        const auto up = mCache.find(link->fromNode);
        const TerrainValue* value = nullptr;
        if (up != mCache.end()) {
          const auto out = up->second.outs.find(fromPin);
          if (out != up->second.outs.end()) {
            value = &out->second;
          }
        }
        if (value == nullptr) {
          if (only == nullptr || only->count(link->fromNode) != 0) {
            blocked = "input " + def.name + " has no value";
            if (up != mCache.end() && !up->second.error.empty()) {
              blocked += " (" + up->second.error + ")";
            }
            blockedUp = true;
          }
          continue;
        }
        ins[def.name] = value;
        key += def.name + "=" + std::to_string(up->second.version) + ":" + fromPin + ";";
      }
      // The inputs a node can't run without: `a` (but a generic op node's are all optional), both slopes of Height
      // from slopes, a path node's points. The others (b, mask, the noise of Warp) have a fallback.
      if (blocked.empty() && node->type->category != "raw") {
        for (const PinDef& def : node->type->inputs) {
          if (def.name == "a" && def.type != PinType::Number && ins.count("a") == 0) {
            blocked = "input a is not linked";
          }
        }
      }
      if (
        node->type->name == "height_from_gradient" && blocked.empty() && (ins.count("dx") == 0 || ins.count("dz") == 0)
      ) {
        blocked = "inputs dx and dz must both be linked";
      }
      if (node->type->name == "path_shape" || node->type->name == "path_mask" || node->type->name == "path_dist") {
        if (ins.count("pts") == 0 && blocked.empty()) {
          blocked = "input pts is not linked";
        }
      }
      if (!blocked.empty()) {
        failed(blocked, blockedUp);
        continue;
      }
      terrain::Values values;
      for (std::size_t p = 0; p < node->type->params.size() && p < node->params.size(); ++p) {
        const ParamDef& def = node->type->params[p];
        ReadParam(def, node->params[p], values);
        if (def.wire) {
          const auto wired = ins.find(def.name);
          if (wired != ins.end() && wired->second->isNumber) {
            values.num[def.name] = wired->second->number;
          }
        }
      }
      for (const auto& [name, number] : values.num) {
        key += name + "=" + Number(number) + ";";
      }
      for (const auto& [name, text] : values.text) {
        key += name + "=" + text + ";";
      }
      key += "|" + mLikeKey + "|seed" + std::to_string(seed);
      std::set<std::string> wanted;
      for (const GraphLink& link : graph.Links()) {
        if (link.fromNode == id) {
          wanted.insert(node->type->outputs[static_cast<std::size_t>(link.fromPin)].name);
        }
      }
      for (const std::string& w : wanted) {
        key += "|w" + w;
      }
      if (node->type->name == "terrain") {
        key += "|base" + std::to_string(ground.revision);
      }
      if (node->type->name == "pad_flatten") {
        key += "|pads" + ground.padSignature;
      }
      if (entry.key == key && entry.error.empty()) {
        ++report.cached;
        continue;
      }
      terrain::Env env;
      env.like = like;
      env.cell = like->cell;
      env.step = mStep;
      env.W = static_cast<float>(ground.width - 1);
      env.H = static_cast<float>(ground.height - 1);
      env.water = ground.water;
      env.graphSeed = seed;
      env.nodeId = id;
      env.wanted = wanted;
      env.ground = &ground;
      env.base = [this, &ground] {
        return BaseHere(ground);
      };
      const auto t0 = Clock::now();
      try {
        terrain::Outputs outs = behaviour->second.eval(env, values, ins);
        entry = Entry{};
        entry.key = key;
        entry.version = ++mVersion;
        entry.outs = std::move(outs);
        entry.ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        ++report.evaluated;
      } catch (const std::exception& e) {
        failed(e.what(), false);
      }
    }
    // Nodes no longer in the graph give their results back.
    for (auto it = mCache.begin(); it != mCache.end();) {
      it = graph.Find(it->first) == nullptr || seen.count(it->first) == 0 ? mCache.erase(it) : std::next(it);
    }
    report.ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
    return report;
  }

  const TerrainValue* TerrainRun::Value(
    const int node,
    const std::string& pin
  ) const
  {
    const auto found = mCache.find(node);
    if (found == mCache.end()) {
      return nullptr;
    }
    const auto out = found->second.outs.find(pin);
    return out != found->second.outs.end() ? &out->second : nullptr;
  }

  std::string TerrainRun::Error(
    const int node
  ) const
  {
    const auto found = mCache.find(node);
    return found != mCache.end() ? found->second.error : std::string();
  }

  double TerrainRun::NodeMs(
    const int node
  ) const
  {
    const auto found = mCache.find(node);
    return found != mCache.end() ? found->second.ms : 0.0;
  }

  const TerrainValue* TerrainRun::Input(
    const NodeGraph& graph,
    const int node,
    const std::string& pin
  ) const
  {
    const GraphNode* n = graph.Find(node);
    if (n == nullptr) {
      return nullptr;
    }
    const int index = PinIndex(n->type->inputs, pin);
    const GraphLink* link = index >= 0 ? graph.InputLink(node, index) : nullptr;
    if (link == nullptr) {
      return nullptr;
    }
    const GraphNode* from = graph.Find(link->fromNode);
    return Value(link->fromNode, from->type->outputs[static_cast<std::size_t>(link->fromPin)].name);
  }

  bool TerrainRun::FinalHeight(
    const NodeGraph& graph,
    const TerrainGround& ground,
    field::Grid& out,
    bool* plain
  )
  {
    std::vector<int> order;
    (void)graph.Order(order);
    field::GridPtr current;
    bool any = false;
    bool isPlain = true;
    terrain::Env env;
    for (const int id : order) {
      const GraphNode* node = graph.Find(id);
      if (node == nullptr || node->type->name != "out_height") {
        continue;
      }
      const TerrainValue* in = Input(graph, id, "a");
      if (in == nullptr || in->grid == nullptr) {
        continue;
      }
      if (current == nullptr) {
        // The base on this grid, as the Map heights node sees it (made here when no node read it).
        current = BaseHere(ground);
      }
      const TerrainValue* wiredStrength = Input(graph, id, "strength");
      const double strength = wiredStrength != nullptr && wiredStrength->isNumber
        ? wiredStrength->number
        : TerrainParamNumber(*node, "strength", 1.0);
      const std::string mode = TerrainParamText(*node, "mode");
      const TerrainValue* maskValue = Input(graph, id, "mask");
      const field::GridPtr mask = maskValue != nullptr ? maskValue->grid : nullptr;
      any = true;
      if (mode == "replace" && strength >= 0.9999 && mask == nullptr) {
        current = in->grid;
        continue;
      }
      isPlain = false;
      if (mode == "add") {
        const field::GridPtr gained =
          env.Op("affine", {{"a", in->grid}, {"mul", TerrainParamNumber(*node, "gain", 1.0)}, {"add", 0.0}});
        current =
          env.Op("blend", {{"a", current}, {"b", gained}, {"mode", "add"}, {"opacity", strength}, {"mask", mask}});
      } else {
        current =
          env.Op("blend", {{"a", current}, {"b", in->grid}, {"mode", "normal"}, {"opacity", strength}, {"mask", mask}});
      }
    }
    if (!any) {
      return false;
    }
    out = *current;
    if (plain != nullptr) {
      *plain = isPlain;
    }
    return true;
  }

  // ---- Studio's graph files ---------------------------------------------------------------------------------------

  namespace
  {
    /** A Lua table literal as Studio writes graph files (`['key'] = value`, nested tables, numbers, strings, bools). */
    struct LuaValue
    {
      enum class Kind : std::uint8_t
      {
        Nil,
        Number,
        String,
        Bool,
        Table,
      } kind = Kind::Nil;
      double number = 0.0;
      std::string text;
      bool flag = false;
      std::vector<LuaValue> list;                           // the array part
      std::vector<std::pair<std::string, LuaValue>> fields; // the keyed part, in file order

      [[nodiscard]] const LuaValue* Get(
        const std::string& key
      ) const
      {
        for (const auto& [k, v] : fields) {
          if (k == key) {
            return &v;
          }
        }
        return nullptr;
      }
      [[nodiscard]] double Num(
        const std::string& key,
        const double fallback
      ) const
      {
        const LuaValue* v = Get(key);
        return v != nullptr && v->kind == Kind::Number ? v->number : fallback;
      }
      [[nodiscard]] std::string Str(
        const std::string& key
      ) const
      {
        const LuaValue* v = Get(key);
        return v != nullptr && v->kind == Kind::String ? v->text : std::string();
      }
    };

    class LuaReader
    {
    public:
      explicit LuaReader(
        const std::string& text
      )
        : mText(text)
      {}

      bool Value(
        LuaValue& out
      )
      {
        Skip();
        if (mAt >= mText.size()) {
          return Error("the file ends early");
        }
        const char c = mText[mAt];
        if (c == '{') {
          return Table(out);
        }
        if (c == '\'' || c == '"') {
          out.kind = LuaValue::Kind::String;
          return String(out.text);
        }
        if (mText.compare(mAt, 4, "true") == 0) {
          mAt += 4;
          out.kind = LuaValue::Kind::Bool;
          out.flag = true;
          return true;
        }
        if (mText.compare(mAt, 5, "false") == 0) {
          mAt += 5;
          out.kind = LuaValue::Kind::Bool;
          return true;
        }
        if (mText.compare(mAt, 3, "nil") == 0) {
          mAt += 3;
          return true;
        }
        const char* begin = mText.c_str() + mAt;
        char* end = nullptr;
        const double number = std::strtod(begin, &end);
        if (end == begin) {
          return Error("unexpected text");
        }
        mAt += static_cast<std::size_t>(end - begin);
        out.kind = LuaValue::Kind::Number;
        out.number = number;
        return true;
      }

      /** `Name = value` at the top of the file. */
      bool Assignment(
        const std::string& name,
        LuaValue& out
      )
      {
        for (;;) {
          Skip();
          if (mAt >= mText.size()) {
            return Error("no " + name + " = { ... } in the file");
          }
          if (mText.compare(mAt, name.size(), name) == 0) {
            mAt += name.size();
            Skip();
            if (mAt < mText.size() && mText[mAt] == '=') {
              ++mAt;
              return Value(out);
            }
          }
          while (mAt < mText.size() && mText[mAt] != '\n') {
            ++mAt;
          }
        }
      }

      [[nodiscard]] const std::string& Message() const noexcept
      {
        return mError;
      }

    private:
      bool Error(
        const std::string& message
      )
      {
        std::size_t line = 1;
        for (std::size_t i = 0; i < mAt && i < mText.size(); ++i) {
          line += mText[i] == '\n' ? 1 : 0;
        }
        mError = message + " (line " + std::to_string(line) + ")";
        return false;
      }
      void Skip()
      {
        while (mAt < mText.size()) {
          const char c = mText[mAt];
          if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++mAt;
          } else if (mText.compare(mAt, 2, "--") == 0) {
            while (mAt < mText.size() && mText[mAt] != '\n') {
              ++mAt;
            }
          } else {
            break;
          }
        }
      }
      bool String(
        std::string& out
      )
      {
        const char quote = mText[mAt++];
        while (mAt < mText.size() && mText[mAt] != quote) {
          char c = mText[mAt++];
          if (c == '\\' && mAt < mText.size()) {
            c = mText[mAt++];
            c = c == 'n' ? '\n' : c == 't' ? '\t' : c;
          }
          out += c;
        }
        if (mAt >= mText.size()) {
          return Error("a string doesn't end");
        }
        ++mAt;
        return true;
      }
      bool Table(
        LuaValue& out
      )
      {
        out.kind = LuaValue::Kind::Table;
        ++mAt; // {
        for (;;) {
          Skip();
          if (mAt >= mText.size()) {
            return Error("a table doesn't end");
          }
          if (mText[mAt] == '}') {
            ++mAt;
            return true;
          }
          std::string key;
          bool keyed = false;
          if (mText[mAt] == '[') {
            ++mAt;
            LuaValue k;
            if (!Value(k)) {
              return false;
            }
            key = k.kind == LuaValue::Kind::String ? k.text : Number(k.number);
            Skip();
            if (mAt >= mText.size() || mText[mAt] != ']') {
              return Error("expected ]");
            }
            ++mAt;
            keyed = true;
          } else if (std::isalpha(static_cast<unsigned char>(mText[mAt])) != 0 || mText[mAt] == '_') {
            const std::size_t start = mAt;
            std::size_t end = mAt;
            while (end < mText.size() &&
                   (std::isalnum(static_cast<unsigned char>(mText[end])) != 0 || mText[end] == '_')) {
              ++end;
            }
            std::size_t after = end;
            while (after < mText.size() && (mText[after] == ' ' || mText[after] == '\t')) {
              ++after;
            }
            const std::string word = mText.substr(start, end - start);
            if (after < mText.size() && mText[after] == '=' && word != "true" && word != "false" && word != "nil") {
              key = word;
              mAt = after;
              keyed = true;
            }
          }
          if (keyed) {
            Skip();
            if (mAt >= mText.size() || mText[mAt] != '=') {
              return Error("expected =");
            }
            ++mAt;
          }
          LuaValue value;
          if (!Value(value)) {
            return false;
          }
          if (keyed) {
            out.fields.emplace_back(key, std::move(value));
          } else {
            out.list.push_back(std::move(value));
          }
          Skip();
          if (mAt < mText.size() && (mText[mAt] == ',' || mText[mAt] == ';')) {
            ++mAt;
          }
        }
      }

      const std::string& mText;
      std::size_t mAt = 0;
      std::string mError;
    };
  } // namespace

  bool ReadStudioGraph(
    const std::string& text,
    NodeGraph& graph,
    StudioGraphFacts& facts,
    std::string& error
  )
  {
    LuaReader reader(text);
    LuaValue root;
    if (!reader.Assignment("Graph", root) || root.kind != LuaValue::Kind::Table) {
      error = reader.Message().empty() ? "no Graph table" : reader.Message();
      return false;
    }
    facts = StudioGraphFacts{};
    facts.name = root.Str("name");
    facts.seed = static_cast<int>(root.Num("seed", 1.0));
    const LuaValue* nodes = root.Get("nodes");
    if (nodes == nullptr || nodes->kind != LuaValue::Kind::Table) {
      error = "the graph has no nodes";
      return false;
    }
    graph.Clear();
    std::set<int> present;
    for (const LuaValue& n : nodes->list) {
      const std::string typeName = n.Str("type");
      const int id = static_cast<int>(n.Num("id", 0.0));
      const NodeType* type = graph.Registry().Find(typeName);
      if (type == nullptr) {
        if (std::find(facts.unknownTypes.begin(), facts.unknownTypes.end(), typeName) == facts.unknownTypes.end()) {
          facts.unknownTypes.push_back(typeName);
        }
        continue;
      }
      if (
        graph.AddNodeAs(id, typeName, static_cast<float>(n.Num("x", 0.0)), static_cast<float>(n.Num("y", 0.0))) == 0
      ) {
        continue;
      }
      present.insert(id);
      const LuaValue* params = n.Get("params");
      if (params == nullptr) {
        continue;
      }
      for (std::size_t p = 0; p < type->params.size(); ++p) {
        const ParamDef& def = type->params[p];
        const LuaValue* v = params->Get(def.name);
        if (v == nullptr) {
          continue;
        }
        ParamValue value;
        value.value = def.initial;
        value.text = def.initialText;
        switch (def.kind) {
        case ParamKind::Choice: {
          const std::string id2 = v->kind == LuaValue::Kind::String ? v->text : Number(v->number);
          for (std::size_t i = 0; i < def.choiceIds.size(); ++i) {
            if (def.choiceIds[i] == id2) {
              value.value[0] = static_cast<float>(i);
            }
          }
          break;
        }
        case ParamKind::Bool:
          value.value[0] = v->kind == LuaValue::Kind::Bool ? (v->flag ? 1.0f : 0.0f) : (v->number >= 0.5 ? 1.0f : 0.0f);
          break;
        case ParamKind::Text:
          if (v->kind == LuaValue::Kind::String) {
            value.text = v->text;
          } else if (v->kind == LuaValue::Kind::Table) {
            // A curve: { {x, y}, ... } as "x y x y".
            value.text.clear();
            for (const LuaValue& point : v->list) {
              for (const LuaValue& coordinate : point.list) {
                value.text += (value.text.empty() ? "" : " ") + Number(coordinate.number);
              }
            }
          }
          break;
        default:
          if (v->kind == LuaValue::Kind::Number) {
            value.value[0] = static_cast<float>(v->number);
          } else if (v->kind == LuaValue::Kind::Bool) {
            value.value[0] = v->flag ? 1.0f : 0.0f;
          }
          break;
        }
        graph.SetParam(id, p, value);
      }
    }
    if (const LuaValue* wires = root.Get("wires"); wires != nullptr) {
      for (const LuaValue& w : wires->list) {
        if (w.list.size() < 4) {
          continue;
        }
        const int from = static_cast<int>(w.list[0].number);
        const int to = static_cast<int>(w.list[2].number);
        const GraphNode* fromNode = graph.Find(from);
        const GraphNode* toNode = graph.Find(to);
        if (fromNode == nullptr || toNode == nullptr) {
          ++facts.droppedLinks;
          continue;
        }
        const int out = PinIndex(fromNode->type->outputs, w.list[1].text);
        const int in = PinIndex(toNode->type->inputs, w.list[3].text);
        if (out < 0 || in < 0 || graph.Link(from, out, to, in) != LinkResult::Ok) {
          ++facts.droppedLinks;
        }
      }
    }
    return true;
  }
} // namespace faf::editor
