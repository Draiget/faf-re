#include "editor/ui/EdCodeEditor.h"

#include "editor/doc/EdLuaSyntax.h"
#include "editor/ui/EdFonts.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <functional>
#include <vector>

namespace faf::editor
{
  namespace
  {
    int Grow(ImGuiInputTextCallbackData* const data)
    {
      if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* const text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<std::size_t>(data->BufTextLen));
        data->Buf = text->data();
      }
      return 0;
    }

    // Colours as VS Code's dark theme has them, which most mappers know.
    ImU32 ColourOf(const LuaSpanKind kind)
    {
      switch (kind) {
        case LuaSpanKind::Keyword:
          return IM_COL32(197, 134, 192, 255);
        case LuaSpanKind::Constant:
          return IM_COL32(86, 156, 214, 255);
        case LuaSpanKind::String:
          return IM_COL32(206, 145, 120, 255);
        case LuaSpanKind::Comment:
          return IM_COL32(106, 153, 85, 255);
        case LuaSpanKind::Number:
          return IM_COL32(181, 206, 168, 255);
        case LuaSpanKind::Call:
          return IM_COL32(220, 220, 170, 255);
        case LuaSpanKind::Engine:
          return IM_COL32(78, 201, 176, 255);
        case LuaSpanKind::Operator:
          return IM_COL32(180, 180, 180, 255);
        default:
          return IM_COL32(212, 212, 212, 255);
      }
    }

    /** The spans of the last text coloured (again only when the text changed). */
    struct Cache
    {
      std::size_t hash = 0;
      std::size_t size = ~std::size_t{0};
      std::vector<LuaSpan> spans;
      std::vector<std::size_t> lineStarts;
    };

    int gScrollTo = 0;
  } // namespace

  void LuaCodeScrollTo(const int line)
  {
    gScrollTo = line;
  }

  bool LuaCodeInput(const char* const id, std::string& text, const int errorLine, const float height)
  {
    static Cache cache;
    ImGui::PushFont(gMonoFont, 0.0f);
    const float lineHeight = ImGui::GetFontSize();
    const ImGuiStyle& style = ImGui::GetStyle();

    // The gutter: as wide as the last line's number.
    const std::size_t lineCount = static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n')) + 1;
    const float gutterWidth = ImGui::CalcTextSize(std::to_string(lineCount).c_str()).x + 18.0f;
    const ImVec2 gutterAt = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(gutterWidth, height));
    ImGui::SameLine(0.0f, 0.0f);

    // The input, its own text transparent (ImGui then doesn't draw it; the caret and selection it still draws).
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_InputTextCursor, IM_COL32(230, 230, 230, 255));
    // A code editor's dark ground (the theme's blue frame is for fields), the selection as VS Code shows it.
    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 30, 255));
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, IM_COL32(38, 79, 120, 255));
    const bool changed = ImGui::InputTextMultiline(id, text.data(), text.capacity() + 1, ImVec2(-1.0f, height),
                                                   ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize, &Grow, &text);
    ImGui::PopStyleColor(4);
    const ImGuiID inputId = ImGui::GetItemID();

    // Its child window (InputTextMultiline's own, named as BeginChildEx names it): where the text lies and how far scrolled.
    ImGuiWindow* const parent = ImGui::GetCurrentWindow();
    char childName[512];
    ImFormatString(childName, sizeof(childName), "%s/%s_%08X", parent->Name, id, inputId);
    ImGuiWindow* const child = ImGui::FindWindowByName(childName);
    if (child == nullptr) {
      ImGui::PopFont();
      return changed;
    }
    if (gScrollTo > 0) {
      ImGui::SetScrollY(child, std::max(0.0f, (static_cast<float>(gScrollTo) - 1.0f) * lineHeight - height * 0.33f));
      gScrollTo = 0;
    }

    // The spans, again when the text changed.
    const std::size_t hash = std::hash<std::string>{}(text);
    if (hash != cache.hash || text.size() != cache.size) {
      cache.hash = hash;
      cache.size = text.size();
      cache.spans = LuaSpans(text);
      cache.lineStarts.assign(1, 0);
      for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') {
          cache.lineStarts.push_back(i + 1);
        }
      }
    }

    float scrollX = 0.0f;
    if (const ImGuiInputTextState* const state = ImGui::GetInputTextState(inputId); state != nullptr) {
      scrollX = state->Scroll.x;
    }
    const ImVec2 origin(child->Pos.x + style.FramePadding.x - scrollX, child->Pos.y + style.FramePadding.y - child->Scroll.y);
    const ImRect clip = child->InnerClipRect;
    ImDrawList* const dl = child->DrawList;
    ImFont* const font = ImGui::GetFont();
    const float size = ImGui::GetFontSize();
    dl->PushClipRect(clip.Min, clip.Max, false);
    const int first = std::max(0, static_cast<int>((child->Scroll.y - style.FramePadding.y) / lineHeight));
    const int last = std::min(static_cast<int>(cache.lineStarts.size()) - 1, first + static_cast<int>(height / lineHeight) + 2);
    // The first span reaching the first visible line.
    std::size_t s = 0;
    if (first <= last && !cache.spans.empty()) {
      const std::size_t from = cache.lineStarts[static_cast<std::size_t>(first)];
      s = static_cast<std::size_t>(std::upper_bound(cache.spans.begin(), cache.spans.end(), from,
                                                    [](const std::size_t at, const LuaSpan& span) { return at < span.end; }) -
                                   cache.spans.begin());
    }
    const char* const base = text.c_str();
    for (int line = first; line <= last; ++line) {
      const std::size_t lineStart = cache.lineStarts[static_cast<std::size_t>(line)];
      std::size_t lineEnd = line + 1 < static_cast<int>(cache.lineStarts.size()) ? cache.lineStarts[static_cast<std::size_t>(line) + 1] - 1 : text.size();
      lineEnd = std::min(lineEnd, text.size());
      const float y = origin.y + static_cast<float>(line) * lineHeight;
      if (line + 1 == errorLine) {
        dl->AddRectFilled(ImVec2(clip.Min.x, y), ImVec2(clip.Max.x, y + lineHeight), IM_COL32(200, 60, 50, 70));
      }
      float x = origin.x;
      while (s < cache.spans.size() && cache.spans[s].start < lineEnd) {
        const LuaSpan& span = cache.spans[s];
        const std::size_t a = std::max(span.start, lineStart);
        const std::size_t b = std::min(span.end, lineEnd);
        if (b > a) {
          const float width = font->CalcTextSizeA(size, FLT_MAX, 0.0f, base + a, base + b).x;
          if (x + width >= clip.Min.x && x <= clip.Max.x) {
            font->RenderText(dl, size, ImVec2(x, y), ColourOf(span.kind), ImVec4(clip.Min.x, clip.Min.y, clip.Max.x, clip.Max.y), base + a, base + b);
          }
          x += width;
        }
        if (span.end > lineEnd) {
          break; // it goes on to the next line
        }
        ++s;
      }
    }
    dl->PopClipRect();

    // Line numbers, beside the visible lines.
    ImDrawList* const gutter = ImGui::GetWindowDrawList();
    gutter->PushClipRect(ImVec2(gutterAt.x, child->Pos.y), ImVec2(gutterAt.x + gutterWidth, child->Pos.y + child->Size.y), true);
    for (int line = first; line <= last; ++line) {
      const std::string number = std::to_string(line + 1);
      const float y = origin.y + static_cast<float>(line) * lineHeight;
      const float w = ImGui::CalcTextSize(number.c_str()).x;
      gutter->AddText(ImVec2(gutterAt.x + gutterWidth - 8.0f - w, y),
                      line + 1 == errorLine ? IM_COL32(240, 110, 90, 255) : IM_COL32(110, 118, 129, 255), number.c_str());
    }
    gutter->PopClipRect();
    ImGui::PopFont();
    return changed;
  }
} // namespace faf::editor
