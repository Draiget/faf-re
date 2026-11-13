#pragma once

// The terrain graph's node evaluations (EdTerrainNodes.cpp) and the run that calls them (EdTerrainGraph.cpp): what a
// node's evaluation is given (its parameters, its inputs, the grid it works on) and how it calls the field library's
// ops. Internal to those two files.

#include "editor/graph/EdTerrainGraph.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <initializer_list>
#include <stdexcept>

namespace faf::editor::terrain
{
  /** One argument of an op: a number, a word, a field or a list of numbers. A null field is left out (an optional
   * input). */
  struct Arg
  {
    std::string key;
    enum class Kind : std::uint8_t
    {
      Number,
      Text,
      Grid,
      List,
    } kind = Kind::Number;
    double number = 0.0;
    std::string text;
    field::GridPtr grid;
    std::vector<double> list;

    Arg(
      const char* k,
      const double v
    )
      : key(k)
      , number(v)
    {}
    Arg(
      const char* k,
      const float v
    )
      : key(k)
      , number(static_cast<double>(v))
    {}
    Arg(
      const char* k,
      const int v
    )
      : key(k)
      , number(static_cast<double>(v))
    {}
    Arg(
      const char* k,
      const char* v
    )
      : key(k)
      , kind(Kind::Text)
      , text(v)
    {}
    Arg(
      const char* k,
      std::string v
    )
      : key(k)
      , kind(Kind::Text)
      , text(std::move(v))
    {}
    Arg(
      const char* k,
      field::GridPtr v
    )
      : key(k)
      , kind(Kind::Grid)
      , grid(std::move(v))
    {}
    Arg(
      const char* k,
      std::vector<double> v
    )
      : key(k)
      , kind(Kind::List)
      , list(std::move(v))
    {}
  };

  /** A node's parameters as its evaluation reads them: numbers (a linked number pin overrides its parameter), choices
   * by id, words. */
  struct Values
  {
    std::map<std::string, double> num;
    std::map<std::string, std::string> text;
    [[nodiscard]] double N(
      const std::string& key
    ) const
    {
      const auto found = num.find(key);
      return found != num.end() ? found->second : 0.0;
    }
    [[nodiscard]] bool B(
      const std::string& key
    ) const
    {
      return N(key) >= 0.5;
    }
    [[nodiscard]] const std::string& S(
      const std::string& key
    ) const
    {
      static const std::string kNone;
      const auto found = text.find(key);
      return found != text.end() ? found->second : kNone;
    }
  };

  using Inputs = std::map<std::string, const TerrainValue*>;
  using Outputs = std::map<std::string, TerrainValue>;

  /** What an evaluation works in: the grid, the map's size, the water, the seed, the outputs that are linked. */
  struct Env
  {
    field::GridPtr like; // the grid every generator takes its size and placement from
    float cell = 1.0f;   // map units between samples
    int step = 1;
    float W = 0.0f; // the map's size in units
    float H = 0.0f;
    float water = 0.0f;
    int graphSeed = 1;
    int nodeId = 0;
    std::set<std::string> wanted; // output pins something is linked to
    const TerrainGround* ground = nullptr;
    std::function<field::GridPtr()> base; // the map's heights on this grid (a node of its own owns the copy)

    [[nodiscard]] int Seed(
      const double n
    ) const
    {
      const long long s = static_cast<long long>(graphSeed) * 1009 + static_cast<long long>(nodeId) * 101 +
        static_cast<long long>(std::floor(n));
      return static_cast<int>(s % 1000003);
    }
    [[nodiscard]] int Units(
      const double units
    ) const
    {
      return std::max(1, static_cast<int>(std::floor(units / cell + 0.5)));
    }
    /** Runs an op; a failure throws (the node shows the error). `extra` takes an op's further results. */
    field::GridPtr Op(
      const std::string& name,
      std::initializer_list<Arg> args,
      std::map<std::string, field::Grid>* extra = nullptr
    ) const;
    field::GridPtr Op(
      const std::string& name,
      const std::vector<Arg>& args,
      std::map<std::string, field::Grid>* extra = nullptr
    ) const;
    field::GridPtr Const(
      const double value
    ) const
    {
      return Op("const", {{"like", like}, {"value", value}});
    }
    /** Clamped (f - lo) / (hi - lo): a noise's raw range to 0..1 by fixed numbers (the preview and the full run agree).
     */
    field::GridPtr Fit(
      const field::GridPtr& f,
      const double lo,
      const double hi
    ) const
    {
      return Op(
        "clamp",
        {{"a", Op("affine", {{"a", f}, {"mul", 1.0 / (hi - lo)}, {"add", -lo / (hi - lo)}})}, {"lo", 0.0}, {"hi", 1.0}}
      );
    }
  };

  using Eval = std::function<Outputs(const Env& E, const Values& v, const Inputs& ins)>;

  /** What a node type is in the run: how it evaluates and which kind of output it writes when built. */
  struct NodeBehaviour
  {
    Eval eval;
    std::string output; // "height", "layer", "types", "scatter" for the output nodes, else empty
  };

  /** The node types' behaviour by type name (built with the registry). */
  [[nodiscard]] const std::map<std::string, NodeBehaviour>& Behaviours();

  /** Fills the registry and the behaviours (EdTerrainNodes.cpp). */
  void BuildCatalogue(NodeTypeRegistry& registry, std::map<std::string, NodeBehaviour>& behaviours);

  /** A field output. */
  inline Outputs One(
    field::GridPtr f
  )
  {
    Outputs out;
    out["out"].grid = std::move(f);
    return out;
  }
  inline Outputs OneNumber(
    const double n
  )
  {
    Outputs out;
    out["out"].number = n;
    out["out"].isNumber = true;
    return out;
  }
  [[noreturn]] inline void Fail(
    const std::string& message
  )
  {
    throw std::runtime_error(message);
  }
  /** An input's field (nullptr when it isn't linked or isn't a field). */
  inline field::GridPtr In(
    const Inputs& ins,
    const char* name
  )
  {
    const auto found = ins.find(name);
    return found != ins.end() && found->second != nullptr ? found->second->grid : nullptr;
  }
} // namespace faf::editor::terrain
