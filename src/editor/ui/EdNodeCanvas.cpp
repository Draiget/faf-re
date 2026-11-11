#include "editor/ui/EdNodeCanvas.h"

#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <vector>

namespace faf::editor
{
  namespace
  {
    // Node layout in graph units.
    constexpr float kNodeW = 170.0f;
    constexpr float kHeader = 24.0f;
    constexpr float kRow = 20.0f;
    constexpr float kThumb = 100.0f;
    constexpr float kPinRadius = 5.0f;

    std::size_t Rows(const NodeType& type)
    {
      return std::max(type.inputs.size(), type.outputs.size());
    }

    bool HasThumbnail(const NodeType& type)
    {
      return !type.outputs.empty();
    }

    float NodeHeight(const NodeType& type)
    {
      return kHeader + 6.0f + static_cast<float>(Rows(type)) * kRow + (HasThumbnail(type) ? kThumb + 10.0f : 4.0f);
    }

    float PinY(const GraphNode& node, const int pin)
    {
      return node.y + kHeader + 6.0f + (static_cast<float>(pin) + 0.5f) * kRow;
    }

    ImU32 PinColor(const PinType type)
    {
      switch (type) {
      case PinType::Color: return IM_COL32(240, 170, 80, 255);
      case PinType::Curve: return IM_COL32(110, 200, 120, 255);
      case PinType::Emitter: return IM_COL32(240, 110, 90, 255);
      case PinType::Texture: return IM_COL32(110, 160, 255, 255);
      default: return IM_COL32(190, 190, 190, 255);
      }
    }

    bool ContainsNoCase(const std::string& text, const char* filter)
    {
      if (filter == nullptr || filter[0] == '\0') {
        return true;
      }
      std::string a = text;
      std::string b = filter;
      const auto lower = [](std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      };
      lower(a);
      lower(b);
      return a.find(b) != std::string::npos;
    }
  } // namespace

  std::uint32_t NodeCategoryColor(const std::string& category)
  {
    static const std::map<std::string, ImU32> colors = {
      {"Output", IM_COL32(110, 80, 60, 255)},   {"Textures", IM_COL32(40, 90, 150, 255)}, {"Constants", IM_COL32(50, 100, 50, 255)},
      {"Math", IM_COL32(75, 105, 80, 255)},     {"Noise", IM_COL32(100, 70, 140, 255)},   {"Adjust", IM_COL32(40, 110, 115, 255)},
      {"Blend", IM_COL32(140, 95, 45, 255)},    {"UV", IM_COL32(140, 50, 50, 255)},       {"Normal", IM_COL32(70, 70, 150, 255)},
      {"Channels", IM_COL32(90, 90, 90, 255)},  {"Map", IM_COL32(110, 110, 40, 255)},
    };
    const auto found = colors.find(category);
    return found != colors.end() ? found->second : IM_COL32(80, 80, 80, 255);
  }

  void EdNodeCanvas::Select(const int id)
  {
    mSelection.clear();
    if (id != 0) {
      mSelection.insert(id);
    }
  }

  int EdNodeCanvas::AddAtCentre(NodeGraph& graph, const std::string& type)
  {
    const float x = (mCanvasW * 0.5f) / mZoom - mPanX - kNodeW * 0.5f;
    const float y = (mCanvasH * 0.5f) / mZoom - mPanY - 40.0f;
    const int id = graph.AddNode(type, std::round(x), std::round(y));
    if (id != 0) {
      Select(id);
    }
    return id;
  }

  void EdNodeCanvas::Frame(const NodeGraph& graph, const bool selectionOnly)
  {
    float minX = 1e9f;
    float minY = 1e9f;
    float maxX = -1e9f;
    float maxY = -1e9f;
    for (const GraphNode& node : graph.Nodes()) {
      if (selectionOnly && mSelection.count(node.id) == 0) {
        continue;
      }
      minX = std::min(minX, node.x);
      minY = std::min(minY, node.y);
      maxX = std::max(maxX, node.x + kNodeW);
      maxY = std::max(maxY, node.y + NodeHeight(*node.type));
    }
    if (minX > maxX || mCanvasW <= 0.0f) {
      return;
    }
    const float w = maxX - minX + 80.0f;
    const float h = maxY - minY + 80.0f;
    mZoom = std::clamp(std::min(mCanvasW / w, mCanvasH / h), 0.25f, 1.5f);
    mPanX = mCanvasW / mZoom * 0.5f - (minX + maxX) * 0.5f;
    mPanY = mCanvasH / mZoom * 0.5f - (minY + maxY) * 0.5f;
  }

  bool EdNodeCanvas::Draw(NodeGraph& graph)
  {
    const std::uint64_t changesBefore = graph.Changes();
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 size = ImGui::GetContentRegionAvail();
    if (size.x < 10.0f || size.y < 10.0f) {
      return false;
    }
    mCanvasX = origin.x;
    mCanvasY = origin.y;
    mCanvasW = size.x;
    mCanvasH = size.y;
    if (mFrameNext) {
      Frame(graph, false);
      mFrameNext = false;
    }

    ImGui::InvisibleButton("##canvas", size, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight | ImGuiButtonFlags_MouseButtonMiddle);
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(origin, ImVec2(origin.x + size.x, origin.y + size.y), true);
    dl->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y), IM_COL32(24, 24, 26, 255));

    const auto toScreen = [&](const float gx, const float gy) { return ImVec2(origin.x + (gx + mPanX) * mZoom, origin.y + (gy + mPanY) * mZoom); };
    const ImVec2 mouse = ImGui::GetIO().MousePos;
    const float mouseGX = (mouse.x - origin.x) / mZoom - mPanX;
    const float mouseGY = (mouse.y - origin.y) / mZoom - mPanY;

    // The grid: fine lines every 16 units, strong ones every 128.
    for (const float step : {16.0f, 128.0f}) {
      const float px = step * mZoom;
      if (px < 6.0f) {
        continue;
      }
      const ImU32 color = step > 16.0f ? IM_COL32(50, 50, 54, 255) : IM_COL32(34, 34, 37, 255);
      for (float x = std::fmod(mPanX * mZoom, px); x < size.x; x += px) {
        dl->AddLine(ImVec2(origin.x + x, origin.y), ImVec2(origin.x + x, origin.y + size.y), color);
      }
      for (float y = std::fmod(mPanY * mZoom, px); y < size.y; y += px) {
        dl->AddLine(ImVec2(origin.x, origin.y + y), ImVec2(origin.x + size.x, origin.y + y), color);
      }
    }

    // What the mouse is over: a pin first, then the topmost node.
    PinHit pinHit;
    int nodeHit = 0;
    const float pinReach = (kPinRadius + 4.0f);
    for (auto it = graph.Nodes().rbegin(); it != graph.Nodes().rend() && hovered; ++it) {
      const GraphNode& node = *it;
      for (std::size_t i = 0; i < node.type->inputs.size() && pinHit.node == 0; ++i) {
        if (std::hypot(mouseGX - node.x, mouseGY - PinY(node, static_cast<int>(i))) <= pinReach) {
          pinHit = {node.id, static_cast<int>(i), false};
        }
      }
      for (std::size_t i = 0; i < node.type->outputs.size() && pinHit.node == 0; ++i) {
        if (std::hypot(mouseGX - (node.x + kNodeW), mouseGY - PinY(node, static_cast<int>(i))) <= pinReach) {
          pinHit = {node.id, static_cast<int>(i), true};
        }
      }
      if (nodeHit == 0 && mouseGX >= node.x && mouseGX <= node.x + kNodeW && mouseGY >= node.y && mouseGY <= node.y + NodeHeight(*node.type)) {
        nodeHit = node.id;
      }
      if (pinHit.node != 0) {
        break;
      }
    }

    ImGuiIO& io = ImGui::GetIO();
    // Zoom at the mouse.
    if (hovered && io.MouseWheel != 0.0f) {
      const float old = mZoom;
      mZoom = std::clamp(mZoom * (io.MouseWheel > 0.0f ? 1.15f : 1.0f / 1.15f), 0.2f, 2.5f);
      mPanX = (mouse.x - origin.x) / mZoom - (mouse.x - origin.x) / old + mPanX;
      mPanY = (mouse.y - origin.y) / mZoom - (mouse.y - origin.y) / old + mPanY;
    }
    // Pan with the right or middle button; a right click that didn't move opens the palette.
    if (hovered && (ImGui::IsMouseClicked(ImGuiMouseButton_Right) || ImGui::IsMouseClicked(ImGuiMouseButton_Middle))) {
      mDrag = Drag::Pan;
      mRightMoved = false;
      mDragStartX = mouse.x;
      mDragStartY = mouse.y;
    }
    if (mDrag == Drag::Pan) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Right) || ImGui::IsMouseDown(ImGuiMouseButton_Middle)) {
        mPanX += io.MouseDelta.x / mZoom;
        mPanY += io.MouseDelta.y / mZoom;
        if (std::hypot(mouse.x - mDragStartX, mouse.y - mDragStartY) > 4.0f) {
          mRightMoved = true;
        }
      } else {
        mDrag = Drag::None;
        if (!mRightMoved && ImGui::IsMouseReleased(ImGuiMouseButton_Right)) {
          mPopupX = mouseGX;
          mPopupY = mouseGY;
          mPopupPin = {};
          mPopupFilter[0] = '\0';
          mPopupFocus = true;
          ImGui::OpenPopup("##palette");
        }
      }
    }

    // The left button.
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && mDrag == Drag::None) {
      mDragStartX = mouseGX;
      mDragStartY = mouseGY;
      if (pinHit.node != 0) {
        if (io.KeyAlt) {
          if (pinHit.output) {
            std::vector<GraphLink> cut;
            for (const GraphLink& link : graph.Links()) {
              if (link.fromNode == pinHit.node && link.fromPin == pinHit.pin) {
                cut.push_back(link);
              }
            }
            for (const GraphLink& link : cut) {
              (void)graph.Unlink(link.toNode, link.toPin);
            }
          } else {
            (void)graph.Unlink(pinHit.node, pinHit.pin);
          }
        } else if (!pinHit.output && graph.InputLink(pinHit.node, pinHit.pin) != nullptr) {
          // Picks the link up from the input: it hangs from its output again.
          const GraphLink link = *graph.InputLink(pinHit.node, pinHit.pin);
          (void)graph.Unlink(pinHit.node, pinHit.pin);
          mLinkFrom = {link.fromNode, link.fromPin, true};
          mDrag = Drag::Link;
        } else {
          mLinkFrom = pinHit;
          mDrag = Drag::Link;
        }
      } else if (nodeHit != 0) {
        if (io.KeyCtrl) {
          if (mSelection.count(nodeHit) != 0) {
            mSelection.erase(nodeHit);
          } else {
            mSelection.insert(nodeHit);
          }
        } else if (mSelection.count(nodeHit) == 0) {
          if (!io.KeyShift) {
            mSelection.clear();
          }
          mSelection.insert(nodeHit);
        }
        mDrag = mSelection.count(nodeHit) != 0 ? Drag::Move : Drag::None;
      } else {
        if (!io.KeyCtrl && !io.KeyShift) {
          mSelection.clear();
        }
        mDrag = Drag::Box;
      }
    }
    if (mDrag == Drag::Move) {
      if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        const float dx = io.MouseDelta.x / mZoom;
        const float dy = io.MouseDelta.y / mZoom;
        if (dx != 0.0f || dy != 0.0f) {
          for (const int id : mSelection) {
            if (const GraphNode* node = graph.Find(id)) {
              graph.MoveNode(id, node->x + dx, node->y + dy);
            }
          }
        }
      } else {
        // Whole units, so the file doesn't keep fractions of a pixel.
        for (const int id : mSelection) {
          if (const GraphNode* node = graph.Find(id)) {
            graph.MoveNode(id, std::round(node->x), std::round(node->y));
          }
        }
        mDrag = Drag::None;
      }
    }
    if (mDrag == Drag::Box && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
      const float x0 = std::min(mDragStartX, mouseGX);
      const float x1 = std::max(mDragStartX, mouseGX);
      const float y0 = std::min(mDragStartY, mouseGY);
      const float y1 = std::max(mDragStartY, mouseGY);
      if (x1 - x0 > 2.0f || y1 - y0 > 2.0f) {
        for (const GraphNode& node : graph.Nodes()) {
          if (node.x + kNodeW >= x0 && node.x <= x1 && node.y + NodeHeight(*node.type) >= y0 && node.y <= y1) {
            mSelection.insert(node.id);
          }
        }
      }
      mDrag = Drag::None;
    }
    if (mDrag == Drag::Link && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
      mDrag = Drag::None;
      if (pinHit.node != 0 && pinHit.output != mLinkFrom.output) {
        const PinHit& from = mLinkFrom.output ? mLinkFrom : pinHit;
        const PinHit& to = mLinkFrom.output ? pinHit : mLinkFrom;
        (void)graph.Link(from.node, from.pin, to.node, to.pin);
      } else if (pinHit.node == 0 && nodeHit == 0) {
        // Dropped on nothing: the palette, and the new node links to the pin.
        mPopupX = mouseGX;
        mPopupY = mouseGY;
        mPopupPin = mLinkFrom;
        mPopupFilter[0] = '\0';
        mPopupFocus = true;
        ImGui::OpenPopup("##palette");
      }
    }

    // Keys while the mouse is over the canvas.
    if (hovered && !ImGui::IsAnyItemActive()) {
      if (ImGui::IsKeyPressed(ImGuiKey_Delete) || ImGui::IsKeyPressed(ImGuiKey_Backspace)) {
        for (const int id : mSelection) {
          (void)graph.RemoveNode(id);
        }
        mSelection.clear();
      }
      if (ImGui::IsKeyPressed(ImGuiKey_F)) {
        Frame(graph, !mSelection.empty());
      }
      if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_D) && !mSelection.empty()) {
        // Duplicates the selection with the links between its nodes, 40 units down and right.
        std::map<int, int> copies;
        for (const int id : mSelection) {
          const GraphNode* node = graph.Find(id);
          if (node == nullptr || node->type->isOutput) {
            continue;
          }
          const GraphNode original = *node;
          const int copy = graph.AddNode(original.type->name, original.x + 40.0f, original.y + 40.0f);
          for (std::size_t p = 0; p < original.params.size(); ++p) {
            graph.SetParam(copy, p, original.params[p]);
          }
          copies[id] = copy;
        }
        const std::vector<GraphLink> links = graph.Links();
        for (const GraphLink& link : links) {
          const auto from = copies.find(link.fromNode);
          const auto to = copies.find(link.toNode);
          if (from != copies.end() && to != copies.end()) {
            (void)graph.Link(from->second, link.fromPin, to->second, link.toPin);
          }
        }
        mSelection.clear();
        for (const auto& [original, copy] : copies) {
          mSelection.insert(copy);
        }
      }
    }

    // A node dragged in from the palette panel.
    if (ImGui::BeginDragDropTarget()) {
      if (const ImGuiPayload* payload = ImGui::AcceptDragDropPayload(kPalettePayload)) {
        const std::string type(static_cast<const char*>(payload->Data), static_cast<std::size_t>(payload->DataSize));
        if (const int id = graph.AddNode(type, std::round(mouseGX - kNodeW * 0.5f), std::round(mouseGY - 12.0f)); id != 0) {
          Select(id);
        }
      }
      ImGui::EndDragDropTarget();
    }

    // Links.
    const float thickness = std::max(1.5f, 2.5f * mZoom);
    const auto curve = [&](const ImVec2 a, const ImVec2 b, const ImU32 color) {
      const float reach = std::max(40.0f * mZoom, std::fabs(b.x - a.x) * 0.5f);
      dl->AddBezierCubic(a, ImVec2(a.x + reach, a.y), ImVec2(b.x - reach, b.y), b, color, thickness);
    };
    for (const GraphLink& link : graph.Links()) {
      const GraphNode* from = graph.Find(link.fromNode);
      const GraphNode* to = graph.Find(link.toNode);
      const bool lit = mSelection.count(link.fromNode) != 0 || mSelection.count(link.toNode) != 0;
      const ImU32 color = lit ? IM_COL32(255, 255, 255, 255) : PinColor(from->type->outputs[static_cast<std::size_t>(link.fromPin)].type);
      curve(toScreen(from->x + kNodeW, PinY(*from, link.fromPin)), toScreen(to->x, PinY(*to, link.toPin)), color);
    }
    if (mDrag == Drag::Link) {
      if (const GraphNode* from = graph.Find(mLinkFrom.node)) {
        const ImVec2 pin = mLinkFrom.output ? toScreen(from->x + kNodeW, PinY(*from, mLinkFrom.pin)) : toScreen(from->x, PinY(*from, mLinkFrom.pin));
        if (mLinkFrom.output) {
          curve(pin, mouse, IM_COL32(255, 255, 255, 200));
        } else {
          curve(mouse, pin, IM_COL32(255, 255, 255, 200));
        }
      }
    }

    // Nodes.
    const bool showText = mZoom >= 0.35f;
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * mZoom);
    ImFont* font = ImGui::GetFont();
    const float fontSize = ImGui::GetFontSize();
    for (const GraphNode& node : graph.Nodes()) {
      const NodeType& type = *node.type;
      const ImVec2 a = toScreen(node.x, node.y);
      const ImVec2 b = toScreen(node.x + kNodeW, node.y + NodeHeight(type));
      if (b.x < origin.x || a.x > origin.x + size.x || b.y < origin.y || a.y > origin.y + size.y) {
        continue;
      }
      const float rounding = 4.0f * mZoom;
      dl->AddRectFilled(ImVec2(a.x + 3.0f, a.y + 3.0f), ImVec2(b.x + 3.0f, b.y + 3.0f), IM_COL32(0, 0, 0, 90), rounding);
      dl->AddRectFilled(a, b, IM_COL32(36, 36, 40, 245), rounding);
      dl->AddRectFilled(a, ImVec2(b.x, a.y + kHeader * mZoom), NodeCategoryColor(type.category), rounding, ImDrawFlags_RoundCornersTop);
      const std::string warning = mWarning ? mWarning(node) : std::string();
      const bool selected = mSelection.count(node.id) != 0;
      const ImU32 outline = !warning.empty() ? IM_COL32(230, 70, 60, 255) : selected ? IM_COL32(250, 200, 80, 255) : IM_COL32(15, 15, 15, 255);
      dl->AddRect(a, b, outline, rounding, 0, selected || !warning.empty() ? 2.0f : 1.0f);
      if (showText) {
        dl->AddText(font, fontSize, ImVec2(a.x + 7.0f * mZoom, a.y + (kHeader * mZoom - fontSize) * 0.5f), IM_COL32(240, 240, 240, 255),
                    type.title.c_str());
      }
      for (std::size_t i = 0; i < type.inputs.size(); ++i) {
        const ImVec2 p = toScreen(node.x, PinY(node, static_cast<int>(i)));
        const ImU32 color = PinColor(type.inputs[i].type);
        if (graph.InputLink(node.id, static_cast<int>(i)) != nullptr) {
          dl->AddCircleFilled(p, kPinRadius * mZoom, color);
        } else {
          dl->AddCircle(p, kPinRadius * mZoom, color, 0, 1.5f);
        }
        if (showText) {
          dl->AddText(font, fontSize, ImVec2(p.x + 10.0f * mZoom, p.y - fontSize * 0.5f), IM_COL32(200, 200, 200, 255), type.inputs[i].name.c_str());
        }
      }
      for (std::size_t i = 0; i < type.outputs.size(); ++i) {
        const ImVec2 p = toScreen(node.x + kNodeW, PinY(node, static_cast<int>(i)));
        const ImU32 color = PinColor(type.outputs[i].type);
        bool linked = false;
        for (const GraphLink& link : graph.Links()) {
          linked = linked || (link.fromNode == node.id && link.fromPin == static_cast<int>(i));
        }
        if (linked) {
          dl->AddCircleFilled(p, kPinRadius * mZoom, color);
        } else {
          dl->AddCircle(p, kPinRadius * mZoom, color, 0, 1.5f);
        }
        if (showText) {
          const ImVec2 textSize = font->CalcTextSizeA(fontSize, 1e9f, 0.0f, type.outputs[i].name.c_str());
          dl->AddText(font, fontSize, ImVec2(p.x - 10.0f * mZoom - textSize.x, p.y - fontSize * 0.5f), IM_COL32(200, 200, 200, 255),
                      type.outputs[i].name.c_str());
        }
      }
      if (HasThumbnail(type) && mThumbnail) {
        if (const std::uint64_t image = mThumbnail(node); image != 0) {
          const float top = node.y + kHeader + 6.0f + static_cast<float>(Rows(type)) * kRow + 4.0f;
          const ImVec2 ta = toScreen(node.x + (kNodeW - kThumb) * 0.5f, top);
          const ImVec2 tb = toScreen(node.x + (kNodeW + kThumb) * 0.5f, top + kThumb);
          dl->AddImage(static_cast<ImTextureID>(image), ta, tb);
          dl->AddRect(ta, tb, IM_COL32(10, 10, 10, 255));
        }
      }
      if (hovered && nodeHit == node.id && pinHit.node == 0 && mDrag == Drag::None &&
          mouseGY <= node.y + kHeader) {
        ImGui::SetTooltip("%s%s%s", type.help.c_str(), warning.empty() ? "" : "\n\n", warning.c_str());
      }
    }
    ImGui::PopFont();

    if (mDrag == Drag::Box) {
      const ImVec2 a = toScreen(mDragStartX, mDragStartY);
      dl->AddRectFilled(a, mouse, IM_COL32(250, 200, 80, 30));
      dl->AddRect(a, mouse, IM_COL32(250, 200, 80, 180));
    }
    if (pinHit.node != 0 && mDrag == Drag::None) {
      const GraphNode* node = graph.Find(pinHit.node);
      const PinDef& pin = pinHit.output ? node->type->outputs[static_cast<std::size_t>(pinHit.pin)] : node->type->inputs[static_cast<std::size_t>(pinHit.pin)];
      ImGui::SetTooltip("%s (%s)%s", pin.name.c_str(), PinTypeName(pin.type),
                        pinHit.output ? "\nDrag to an input to link; Alt+click cuts its links" : "\nDrag from an output to link; Alt+click cuts it");
    }
    dl->PopClipRect();

    DrawPalettePopup(graph);
    return graph.Changes() != changesBefore;
  }

  bool EdNodeCanvas::PaletteList(NodeGraph& graph, const char* filter, const float x, const float y)
  {
    std::map<std::string, std::vector<const NodeType*>> byCategory;
    for (const auto& type : graph.Registry().All()) {
      if (type->isOutput) {
        continue;
      }
      if (ContainsNoCase(type->title, filter) || ContainsNoCase(type->category, filter)) {
        byCategory[type->category].push_back(type.get());
      }
    }
    for (const auto& [category, types] : byCategory) {
      ImGui::TextDisabled("%s", category.c_str());
      for (const NodeType* type : types) {
        if (ImGui::Selectable(("  " + type->title).c_str())) {
          const int id = graph.AddNode(type->name, std::round(x), std::round(y));
          if (id != 0 && mPopupPin.node != 0) {
            // The pin the palette came from links to the new node's first pin of the other side.
            // The new node's first pin of a kind that fits (a curve to a curve, an image to an image).
            const GraphNode* made = graph.Find(id);
            const GraphNode* from = graph.Find(mPopupPin.node);
            if (mPopupPin.output) {
              const PinType type = from->type->outputs[static_cast<std::size_t>(mPopupPin.pin)].type;
              for (std::size_t i = 0; i < made->type->inputs.size(); ++i) {
                if (PinsCompatible(type, made->type->inputs[i].type)) {
                  (void)graph.Link(mPopupPin.node, mPopupPin.pin, id, static_cast<int>(i));
                  break;
                }
              }
            } else {
              const PinType type = from->type->inputs[static_cast<std::size_t>(mPopupPin.pin)].type;
              for (std::size_t i = 0; i < made->type->outputs.size(); ++i) {
                if (PinsCompatible(made->type->outputs[i].type, type)) {
                  (void)graph.Link(id, static_cast<int>(i), mPopupPin.node, mPopupPin.pin);
                  graph.MoveNode(id, std::round(x - kNodeW), std::round(y));
                  break;
                }
              }
            }
          }
          Select(id);
          return true;
        }
        if (ImGui::IsItemHovered() && !type->help.empty()) {
          ImGui::SetTooltip("%s", type->help.c_str());
        }
      }
    }
    return false;
  }

  void EdNodeCanvas::DrawPalettePopup(NodeGraph& graph)
  {
    ImGui::SetNextWindowSizeConstraints(ImVec2(220.0f, 0.0f), ImVec2(320.0f, 420.0f));
    if (!ImGui::BeginPopup("##palette")) {
      return;
    }
    if (mPopupFocus) {
      ImGui::SetKeyboardFocusHere();
      mPopupFocus = false;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##filter", "Search nodes", mPopupFilter, sizeof(mPopupFilter));
    ImGui::Separator();
    if (PaletteList(graph, mPopupFilter, mPopupX, mPopupY)) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
} // namespace faf::editor
