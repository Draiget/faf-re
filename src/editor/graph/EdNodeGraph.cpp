#include "editor/graph/EdNodeGraph.h"

#include "editor/doc/EdJson.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <unordered_map>

namespace faf::editor
{
  namespace
  {
    /** How many numbers a parameter of the kind keeps in the file. */
    int NumbersOf(
      const ParamKind kind
    )
    {
      return kind == ParamKind::Color ? 4 : kind == ParamKind::Text ? 0 : 1;
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

    /** "[1, 2.5, 3]" into its numbers. */
    std::vector<float> Numbers(
      const std::string& array
    )
    {
      std::vector<float> out;
      const char* at = array.c_str();
      while (*at != '\0') {
        if (*at == '-' || *at == '.' || (*at >= '0' && *at <= '9')) {
          char* end = nullptr;
          out.push_back(std::strtof(at, &end));
          at = end != at ? end : at + 1;
        } else {
          ++at;
        }
      }
      return out;
    }
  } // namespace

  bool PinsCompatible(
    const PinType from,
    const PinType to
  ) noexcept
  {
    const auto image = [](const PinType type) {
      return type == PinType::Grey || type == PinType::Color;
    };
    return from == to || (image(from) && image(to));
  }

  const char* PinTypeName(
    const PinType type
  ) noexcept
  {
    switch (type) {
    case PinType::Grey:
      return "grey";
    case PinType::Color:
      return "colour";
    case PinType::Curve:
      return "curve";
    case PinType::Emitter:
      return "emitter";
    case PinType::Texture:
      return "texture";
    }
    return "?";
  }

  const NodeType& NodeTypeRegistry::Add(
    NodeType type
  )
  {
    mTypes.push_back(std::make_unique<NodeType>(std::move(type)));
    return *mTypes.back();
  }

  const NodeType* NodeTypeRegistry::Find(
    const std::string& name
  ) const
  {
    for (const auto& type : mTypes) {
      if (type->name == name) {
        return type.get();
      }
    }
    return nullptr;
  }

  int NodeGraph::AddNode(
    const std::string& typeName,
    const float x,
    const float y
  )
  {
    const NodeType* type = mRegistry->Find(typeName);
    if (type == nullptr || (type->isOutput && OutputNode() != 0)) {
      return 0;
    }
    GraphNode node;
    node.id = mNextId++;
    node.type = type;
    node.x = x;
    node.y = y;
    node.revision = ++mRevisionSeed;
    for (const ParamDef& def : type->params) {
      ParamValue value;
      value.value = def.initial;
      value.text = def.initialText;
      node.params.push_back(std::move(value));
    }
    mNodes.push_back(std::move(node));
    ++mChanges;
    return mNodes.back().id;
  }

  bool NodeGraph::RemoveNode(
    const int id
  )
  {
    const auto found = std::find_if(mNodes.begin(), mNodes.end(), [id](const GraphNode& node) {
      return node.id == id;
    });
    if (found == mNodes.end() || found->type->isOutput) {
      return false;
    }
    std::vector<int> fed;
    for (const GraphLink& link : mLinks) {
      if (link.fromNode == id) {
        fed.push_back(link.toNode);
      }
    }
    mLinks.erase(
      std::remove_if(
        mLinks.begin(),
        mLinks.end(),
        [id](const GraphLink& link) {
      return link.fromNode == id || link.toNode == id;
    }
      ),
      mLinks.end()
    );
    mNodes.erase(found);
    for (const int to : fed) {
      Touch(to);
    }
    ++mChanges;
    return true;
  }

  GraphNode* NodeGraph::Find(
    const int id
  )
  {
    for (GraphNode& node : mNodes) {
      if (node.id == id) {
        return &node;
      }
    }
    return nullptr;
  }

  const GraphNode* NodeGraph::Find(
    const int id
  ) const
  {
    return const_cast<NodeGraph*>(this)->Find(id);
  }

  int NodeGraph::OutputNode() const
  {
    for (const GraphNode& node : mNodes) {
      if (node.type->isOutput) {
        return node.id;
      }
    }
    return 0;
  }

  void NodeGraph::SetParam(
    const int id,
    const std::size_t param,
    const ParamValue& value
  )
  {
    GraphNode* node = Find(id);
    if (node == nullptr || param >= node->params.size()) {
      return;
    }
    if (node->params[param].value == value.value && node->params[param].text == value.text) {
      return;
    }
    node->params[param] = value;
    Touch(id);
  }

  void NodeGraph::MoveNode(
    const int id,
    const float x,
    const float y
  )
  {
    if (GraphNode* node = Find(id); node != nullptr && (node->x != x || node->y != y)) {
      node->x = x;
      node->y = y;
      ++mChanges;
    }
  }

  LinkResult NodeGraph::Link(
    const int fromNode,
    const int fromPin,
    const int toNode,
    const int toPin
  )
  {
    const GraphNode* from = Find(fromNode);
    const GraphNode* to = Find(toNode);
    if (
      from == nullptr || to == nullptr || fromPin < 0 || toPin < 0 ||
      static_cast<std::size_t>(fromPin) >= from->type->outputs.size() ||
      static_cast<std::size_t>(toPin) >= to->type->inputs.size()
    ) {
      return LinkResult::BadPin;
    }
    if (fromNode == toNode) {
      return LinkResult::SameNode;
    }
    if (!PinsCompatible(
          from->type->outputs[static_cast<std::size_t>(fromPin)].type,
          to->type->inputs[static_cast<std::size_t>(toPin)].type
        )) {
      return LinkResult::WrongType;
    }
    // A loop: `to` already feeds `from`.
    const std::vector<int> fedByTo = Downstream(toNode);
    if (std::find(fedByTo.begin(), fedByTo.end(), fromNode) != fedByTo.end()) {
      return LinkResult::Cycle;
    }
    mLinks.erase(
      std::remove_if(
        mLinks.begin(),
        mLinks.end(),
        [&](const GraphLink& link) {
      return link.toNode == toNode && link.toPin == toPin;
    }
      ),
      mLinks.end()
    );
    mLinks.push_back({fromNode, fromPin, toNode, toPin});
    Touch(toNode);
    return LinkResult::Ok;
  }

  bool NodeGraph::Unlink(
    const int toNode,
    const int toPin
  )
  {
    const auto before = mLinks.size();
    mLinks.erase(
      std::remove_if(
        mLinks.begin(),
        mLinks.end(),
        [&](const GraphLink& link) {
      return link.toNode == toNode && link.toPin == toPin;
    }
      ),
      mLinks.end()
    );
    if (mLinks.size() == before) {
      return false;
    }
    Touch(toNode);
    return true;
  }

  const GraphLink* NodeGraph::InputLink(
    const int toNode,
    const int toPin
  ) const
  {
    for (const GraphLink& link : mLinks) {
      if (link.toNode == toNode && link.toPin == toPin) {
        return &link;
      }
    }
    return nullptr;
  }

  std::vector<int> NodeGraph::Downstream(
    const int id
  ) const
  {
    std::vector<int> out{id};
    for (std::size_t i = 0; i < out.size(); ++i) {
      for (const GraphLink& link : mLinks) {
        if (link.fromNode == out[i] && std::find(out.begin(), out.end(), link.toNode) == out.end()) {
          out.push_back(link.toNode);
        }
      }
    }
    return out;
  }

  bool NodeGraph::Order(
    std::vector<int>& out
  ) const
  {
    out.clear();
    std::unordered_map<int, int> waiting;
    for (const GraphNode& node : mNodes) {
      waiting[node.id] = 0;
    }
    for (const GraphLink& link : mLinks) {
      ++waiting[link.toNode];
    }
    std::vector<int> ready;
    for (const GraphNode& node : mNodes) {
      if (waiting[node.id] == 0) {
        ready.push_back(node.id);
      }
    }
    while (!ready.empty()) {
      const int id = ready.front();
      ready.erase(ready.begin());
      out.push_back(id);
      for (const GraphLink& link : mLinks) {
        if (link.fromNode == id && --waiting[link.toNode] == 0) {
          ready.push_back(link.toNode);
        }
      }
    }
    return out.size() == mNodes.size();
  }

  std::vector<int> NodeGraph::OrderFor(
    const int id
  ) const
  {
    std::vector<int> out;
    std::vector<int> visiting;
    const std::function<void(int)> visit = [&](const int at) {
      if (
        std::find(out.begin(), out.end(), at) != out.end() ||
        std::find(visiting.begin(), visiting.end(), at) != visiting.end()
      ) {
        return;
      }
      visiting.push_back(at);
      for (const GraphLink& link : mLinks) {
        if (link.toNode == at) {
          visit(link.fromNode);
        }
      }
      visiting.pop_back();
      out.push_back(at);
    };
    if (Find(id) != nullptr) {
      visit(id);
    }
    return out;
  }

  void NodeGraph::Touch(
    const int id
  )
  {
    for (const int at : Downstream(id)) {
      if (GraphNode* node = Find(at)) {
        node->revision = ++mRevisionSeed;
      }
    }
    ++mChanges;
  }

  std::string NodeGraph::Save() const
  {
    std::string out = "{\n  \"graph\": \"fafgraph\",\n  \"version\": 1,\n  \"nodes\": [\n";
    for (std::size_t n = 0; n < mNodes.size(); ++n) {
      const GraphNode& node = mNodes[n];
      // The node's own fields before its parameters: JsonValue finds a key's first use.
      out += "    {\"id\": " + std::to_string(node.id) + ", \"type\": " + JsonQuoted(node.type->name) +
        ", \"x\": " + JsonNumber(node.x) + ", \"y\": " + JsonNumber(node.y) + ", \"params\": {";
      for (std::size_t p = 0; p < node.params.size(); ++p) {
        const ParamDef& def = node.type->params[p];
        out += (p == 0 ? "" : ", ") + JsonQuoted(def.name) + ": ";
        if (def.kind == ParamKind::Text) {
          out += JsonQuoted(node.params[p].text);
        } else {
          out += "[";
          for (int i = 0; i < NumbersOf(def.kind); ++i) {
            out += (i == 0 ? "" : ", ") + JsonNumber(node.params[p].value[static_cast<std::size_t>(i)]);
          }
          out += "]";
        }
      }
      out += "}}";
      out += n + 1 < mNodes.size() ? ",\n" : "\n";
    }
    out += "  ],\n  \"links\": [\n";
    for (std::size_t l = 0; l < mLinks.size(); ++l) {
      const GraphLink& link = mLinks[l];
      const GraphNode* from = Find(link.fromNode);
      const GraphNode* to = Find(link.toNode);
      out += "    {\"from\": " + std::to_string(link.fromNode) +
        ", \"out\": " + JsonQuoted(from->type->outputs[static_cast<std::size_t>(link.fromPin)].name) +
        ", \"to\": " + std::to_string(link.toNode) +
        ", \"in\": " + JsonQuoted(to->type->inputs[static_cast<std::size_t>(link.toPin)].name) + "}";
      out += l + 1 < mLinks.size() ? ",\n" : "\n";
    }
    out += "  ]\n}\n";
    return out;
  }

  bool NodeGraph::Load(
    const std::string& text,
    std::string& error
  )
  {
    std::string kind;
    if (!JsonValue(text, "graph", kind) || kind != "fafgraph") {
      error = "not a graph file";
      return false;
    }
    std::string nodes;
    std::string links;
    if (!JsonValue(text, "nodes", nodes)) {
      error = "no nodes";
      return false;
    }
    (void)JsonValue(text, "links", links);
    Clear();
    for (const std::string& object : JsonObjects(nodes)) {
      const std::size_t paramsAt = object.find("\"params\"");
      const std::string head = object.substr(0, paramsAt);
      std::string typeName;
      float id = 0.0f;
      float x = 0.0f;
      float y = 0.0f;
      if (!JsonValue(head, "type", typeName) || !JsonFloat(head, "id", id)) {
        continue;
      }
      (void)JsonFloat(head, "x", x);
      (void)JsonFloat(head, "y", y);
      const NodeType* type = mRegistry->Find(typeName);
      if (type == nullptr) {
        continue; // a node type this editor doesn't have
      }
      GraphNode node;
      node.id = static_cast<int>(id);
      node.type = type;
      node.x = x;
      node.y = y;
      node.revision = ++mRevisionSeed;
      std::string params;
      if (paramsAt != std::string::npos) {
        (void)JsonValue(object.substr(paramsAt), "params", params);
      }
      for (const ParamDef& def : type->params) {
        ParamValue value;
        value.value = def.initial;
        value.text = def.initialText;
        std::string saved;
        if (!params.empty() && JsonValue(params, def.name, saved)) {
          if (def.kind == ParamKind::Text) {
            value.text = saved;
          } else {
            const std::vector<float> numbers = Numbers(saved);
            for (std::size_t i = 0; i < numbers.size() && i < 4; ++i) {
              value.value[i] = numbers[i];
            }
          }
        }
        node.params.push_back(std::move(value));
      }
      if (Find(node.id) != nullptr || (type->isOutput && OutputNode() != 0)) {
        continue;
      }
      mNextId = std::max(mNextId, node.id + 1);
      mNodes.push_back(std::move(node));
    }
    for (const std::string& object : JsonObjects(links)) {
      float from = 0.0f;
      float to = 0.0f;
      std::string out;
      std::string in;
      if (
        !JsonFloat(object, "from", from) || !JsonFloat(object, "to", to) || !JsonValue(object, "out", out) ||
        !JsonValue(object, "in", in)
      ) {
        continue;
      }
      const GraphNode* fromNode = Find(static_cast<int>(from));
      const GraphNode* toNode = Find(static_cast<int>(to));
      if (fromNode == nullptr || toNode == nullptr) {
        continue;
      }
      (void)Link(fromNode->id, PinIndex(fromNode->type->outputs, out), toNode->id, PinIndex(toNode->type->inputs, in));
    }
    mChanges = 0;
    return true;
  }

  void NodeGraph::Clear()
  {
    mNodes.clear();
    mLinks.clear();
    mNextId = 1;
    ++mChanges;
  }
} // namespace faf::editor
