#include "editor/ui/EdCodeEditor.h"
#include "editor/ui/EdControls.h"

#include "editor/doc/EdLuaApi.h"
#include "editor/doc/EdLuaSyntax.h"
#include "editor/ui/EdFonts.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  namespace
  {
    /**
     * The assistant's state (one code input is edited at a time): where the caret is, the completion list open, the
     * picked row, and a completion to put in at the next callback.
     */
    struct Assist
    {
      std::string* text = nullptr;
      int cursor = 0;
      bool open = false;
      int selected = 0;
      std::vector<const EdLuaApiEntry*> items;
      EdLuaWord word;
      std::string insert;   // the name to put in place of the word's prefix
      bool asked = false;   // Ctrl+Space: open even before two letters
      bool changed = false; // the text changed this frame (typing opens the list)
    };

    Assist& Help()
    {
      static Assist assist;
      return assist;
    }

    int Grow(
      ImGuiInputTextCallbackData* const data
    )
    {
      Assist& a = Help();
      if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* const text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<std::size_t>(data->BufTextLen));
        data->Buf = text->data();
        return 0;
      }
      // Tab while the list is open, or a completion waiting: the picked name in place of what was typed of it.
      if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion && a.open && !a.items.empty()) {
        a.insert =
          a.items[static_cast<std::size_t>(std::clamp(a.selected, 0, static_cast<int>(a.items.size()) - 1))]->name;
      }
      if (!a.insert.empty()) {
        const int start = static_cast<int>(a.word.start);
        const int length = std::max(0, data->CursorPos - start);
        if (start >= 0 && start + length <= data->BufTextLen) {
          data->DeleteChars(start, length);
          data->InsertChars(start, a.insert.c_str());
        }
        a.insert.clear();
        a.open = false;
      }
      a.cursor = data->CursorPos;
      return 0;
    }

    /** A tooltip-like window at a screen point that never takes the keyboard (the code input keeps it). */
    bool BeginFloat(
      const char* const id,
      const ImVec2 at
    )
    {
      ImGui::SetNextWindowPos(at);
      constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs;
      return ImGui::Begin(id, nullptr, kFlags);
    }

    /** A signature with the `argument`-th parameter (0-based; -1: none) in the accent of a call's name. */
    void DrawSignature(
      const EdLuaApiEntry& entry,
      const int argument
    )
    {
      const std::string head = LuaSignature(entry);
      const std::size_t open = head.find('(');
      const std::size_t close = head.rfind(')');
      if (argument < 0 || open == std::string::npos || close == std::string::npos) {
        ImGui::TextUnformatted(head.c_str());
        return;
      }
      // Split the parameters at top-level commas.
      std::vector<std::pair<std::size_t, std::size_t>> parts;
      std::size_t from = open + 1;
      for (std::size_t i = open + 1; i <= close; ++i) {
        if (i == close || head[i] == ',') {
          parts.emplace_back(from, i);
          from = i + 1;
        }
      }
      ImGui::TextUnformatted(head.c_str(), head.c_str() + open + 1);
      for (std::size_t k = 0; k < parts.size(); ++k) {
        ImGui::SameLine(0.0f, 0.0f);
        const auto [a, b] = parts[k];
        if (static_cast<int>(k) == argument) {
          ImGui::TextColored(ImVec4(0.86f, 0.86f, 0.67f, 1.0f), "%.*s", static_cast<int>(b - a), head.c_str() + a);
        } else {
          ImGui::TextDisabled("%.*s", static_cast<int>(b - a), head.c_str() + a);
        }
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::TextUnformatted(k + 1 < parts.size() ? "," : ")");
      }
      if (close + 1 < head.size()) {
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::TextDisabled("%s", head.c_str() + close + 1);
      }
    }

    // Colours as VS Code's dark theme has them, which most mappers know.
    ImU32 ColourOf(
      const LuaSpanKind kind
    )
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

  void LuaCodeScrollTo(
    const int line
  )
  {
    gScrollTo = line;
  }

  bool LuaCodeInput(
    const char* const id,
    std::string& text,
    const int errorLine,
    const float height,
    EdCodeMarks* const marks
  )
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

    // While the completion list is open it takes Up, Down and Escape (locked from the input for this frame) and Tab
    // inserts the picked name; Ctrl+Space opens it.
    Assist& assist = Help();
    if (assist.text != &text) {
      assist = Assist{};
      assist.text = &text;
    }
    const ImGuiID listKeys = ImGui::GetID("##luacompletionkeys");
    // A key the list takes is hidden from the input while it runs: the multiline input claims Up and Down for itself
    // each frame (SetKeyOwner without a lock), so a lock can't keep them from it. Its state is put back after.
    ImGuiKey taken = ImGuiKey_None;
    if (assist.open && !assist.items.empty()) {
      const int count = static_cast<int>(assist.items.size());
      if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
        assist.selected = (assist.selected + 1) % count;
        taken = ImGuiKey_DownArrow;
      } else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
        assist.selected = (assist.selected + count - 1) % count;
        taken = ImGuiKey_UpArrow;
      } else if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        assist.open = false;
        ImGui::SetKeyOwner(ImGuiKey_Escape, listKeys, ImGuiInputFlags_LockThisFrame);
      }
    }
    ImGuiKeyData kept{};
    if (taken != ImGuiKey_None) {
      ImGuiKeyData* const data = ImGui::GetKeyData(taken);
      kept = *data;
      data->Down = false;
      data->DownDuration = -1.0f;
    }
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Space)) {
      assist.asked = true;
      ImGui::SetKeyOwner(ImGuiKey_Space, listKeys, ImGuiInputFlags_LockThisFrame);
    }
    const ImGuiInputTextFlags tab =
      assist.open && !assist.items.empty() ? ImGuiInputTextFlags_CallbackCompletion : ImGuiInputTextFlags_AllowTabInput;

    // The input, its own text transparent (ImGui then doesn't draw it; the caret and selection it still draws).
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_InputTextCursor, IM_COL32(230, 230, 230, 255));
    // A code editor's dark ground (the theme's blue frame is for fields), the selection as VS Code shows it.
    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(30, 30, 30, 255));
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, IM_COL32(38, 79, 120, 255));
    const bool changed = ImGui::InputTextMultiline(
      id,
      text.data(),
      text.capacity() + 1,
      ImVec2(-1.0f, height),
      tab | ImGuiInputTextFlags_CallbackResize | ImGuiInputTextFlags_CallbackAlways,
      &Grow,
      &text
    );
    ImGui::PopStyleColor(4);
    if (taken != ImGuiKey_None) {
      *ImGui::GetKeyData(taken) = kept;
    }
    const ImGuiID inputId = ImGui::GetItemID();
    const bool active = ImGui::IsItemActive();
    assist.changed = changed;

    // Its child window (InputTextMultiline's own, named as BeginChildEx names it): where the text lies and how far
    // scrolled.
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
    const ImVec2 origin(
      child->Pos.x + style.FramePadding.x - scrollX, child->Pos.y + style.FramePadding.y - child->Scroll.y
    );
    const ImRect clip = child->InnerClipRect;
    ImDrawList* const dl = child->DrawList;
    ImFont* const font = ImGui::GetFont();
    const float size = ImGui::GetFontSize();
    dl->PushClipRect(clip.Min, clip.Max, false);
    const int first = std::max(0, static_cast<int>((child->Scroll.y - style.FramePadding.y) / lineHeight));
    const int last =
      std::min(static_cast<int>(cache.lineStarts.size()) - 1, first + static_cast<int>(height / lineHeight) + 2);
    // The first span reaching the first visible line.
    std::size_t s = 0;
    if (first <= last && !cache.spans.empty()) {
      const std::size_t from = cache.lineStarts[static_cast<std::size_t>(first)];
      s =
        static_cast<std::size_t>(
          std::upper_bound(cache.spans.begin(), cache.spans.end(), from, [](const std::size_t at, const LuaSpan& span) {
        return at < span.end;
      }) - cache.spans.begin()
        );
    }
    const char* const base = text.c_str();
    for (int line = first; line <= last; ++line) {
      const std::size_t lineStart = cache.lineStarts[static_cast<std::size_t>(line)];
      std::size_t lineEnd = line + 1 < static_cast<int>(cache.lineStarts.size())
        ? cache.lineStarts[static_cast<std::size_t>(line) + 1] - 1
        : text.size();
      lineEnd = std::min(lineEnd, text.size());
      const float y = origin.y + static_cast<float>(line) * lineHeight;
      if (line + 1 == errorLine) {
        dl->AddRectFilled(ImVec2(clip.Min.x, y), ImVec2(clip.Max.x, y + lineHeight), IM_COL32(200, 60, 50, 70));
      }
      if (marks != nullptr && line + 1 == marks->pausedLine) {
        dl->AddRectFilled(ImVec2(clip.Min.x, y), ImVec2(clip.Max.x, y + lineHeight), IM_COL32(220, 190, 60, 70));
      }
      float x = origin.x;
      while (s < cache.spans.size() && cache.spans[s].start < lineEnd) {
        const LuaSpan& span = cache.spans[s];
        const std::size_t a = std::max(span.start, lineStart);
        const std::size_t b = std::min(span.end, lineEnd);
        if (b > a) {
          const float width = font->CalcTextSizeA(size, FLT_MAX, 0.0f, base + a, base + b).x;
          if (x + width >= clip.Min.x && x <= clip.Max.x) {
            font->RenderText(
              dl,
              size,
              ImVec2(x, y),
              ColourOf(span.kind),
              ImVec4(clip.Min.x, clip.Min.y, clip.Max.x, clip.Max.y),
              base + a,
              base + b
            );
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
    gutter->PushClipRect(
      ImVec2(gutterAt.x, child->Pos.y), ImVec2(gutterAt.x + gutterWidth, child->Pos.y + child->Size.y), true
    );
    // A click on a line's number: the debugger's breakpoint there (EdCodeMarks).
    if (marks != nullptr) {
      marks->clickedLine = 0;
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      if (
        ImGui::IsMouseClicked(ImGuiMouseButton_Left) && mouse.x >= gutterAt.x && mouse.x < gutterAt.x + gutterWidth &&
        mouse.y >= child->Pos.y && mouse.y < child->Pos.y + child->Size.y && ImGui::IsWindowHovered()
      ) {
        const int line = static_cast<int>((mouse.y - origin.y) / lineHeight);
        if (line >= 0 && line < static_cast<int>(cache.lineStarts.size())) {
          marks->clickedLine = line + 1;
        }
      }
    }
    for (int line = first; line <= last; ++line) {
      const std::string number = std::to_string(line + 1);
      const float y = origin.y + static_cast<float>(line) * lineHeight;
      const float w = ImGui::CalcTextSize(number.c_str()).x;
      if (
        marks != nullptr &&
        std::find(marks->breakpoints.begin(), marks->breakpoints.end(), line + 1) != marks->breakpoints.end()
      ) {
        gutter->AddCircleFilled(
          ImVec2(gutterAt.x + 6.0f, y + lineHeight * 0.5f), lineHeight * 0.28f, IM_COL32(220, 70, 60, 255)
        );
      }
      gutter->AddText(
        ImVec2(gutterAt.x + gutterWidth - 8.0f - w, y),
        line + 1 == errorLine ? IM_COL32(240, 110, 90, 255) : IM_COL32(110, 118, 129, 255),
        number.c_str()
      );
    }
    gutter->PopClipRect();

    // Where a text index is on the screen (its line's top-left of the character).
    const auto screenOf = [&](const std::size_t index) {
      const std::size_t at = std::min(index, text.size());
      const auto line = static_cast<std::size_t>(
        std::upper_bound(cache.lineStarts.begin(), cache.lineStarts.end(), at) - cache.lineStarts.begin() - 1
      );
      const std::size_t start = cache.lineStarts[line];
      const float x = font->CalcTextSizeA(size, FLT_MAX, 0.0f, base + start, base + at).x;
      return ImVec2(origin.x + x, origin.y + static_cast<float>(line) * lineHeight);
    };

    // The completion list: opened by typing two letters of a name (or a module's '.' / a method's ':'), or
    // Ctrl+Space; it follows the word as it is typed and closes when the caret leaves it.
    const std::size_t caret = static_cast<std::size_t>(std::clamp(assist.cursor, 0, static_cast<int>(text.size())));
    if (active) {
      const EdLuaWord word = LuaWordBefore(text, caret);
      const bool typedEnough = word.prefix.size() >= 2 || (word.separator != 0 && !word.qualifier.empty());
      if ((assist.changed && typedEnough) || assist.asked || (assist.open && (typedEnough || word.separator != 0))) {
        const bool same = word.prefix.rfind(assist.word.prefix, 0) == 0 && word.start == assist.word.start;
        assist.word = word;
        assist.items = LuaCompletions(word, 12);
        assist.open = !assist.items.empty() && (assist.open || assist.changed || assist.asked);
        if (!same) {
          assist.selected = 0;
        }
        // Nothing more to offer: the name is typed out.
        if (assist.items.size() == 1 && word.prefix == assist.items.front()->name) {
          assist.open = false;
        }
      } else if (!typedEnough) {
        assist.open = false;
      }
      assist.asked = false;
    } else {
      assist.open = false;
    }
    if (assist.open && !assist.items.empty()) {
      const ImVec2 at = screenOf(assist.word.start);
      if (BeginFloat("##luacompletions", ImVec2(at.x, at.y + lineHeight + 2.0f))) {
        for (std::size_t i = 0; i < assist.items.size(); ++i) {
          const EdLuaApiEntry& entry = *assist.items[i];
          const bool picked = static_cast<int>(i) == assist.selected;
          if (picked) {
            const ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddRectFilled(
              p,
              ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y + ImGui::GetTextLineHeight()),
              ImGui::GetColorU32(ImGuiCol_Header)
            );
          }
          ImGui::TextUnformatted(entry.name);
          ImGui::SameLine();
          ImGui::TextDisabled("(%s)%s%s", entry.params, entry.owner[0] != 0 ? "  " : "", entry.owner);
        }
        const EdLuaApiEntry& picked = *assist.items[static_cast<std::size_t>(
          std::clamp(assist.selected, 0, static_cast<int>(assist.items.size()) - 1)
        )];
        if (picked.doc[0] != 0) {
          ImGui::Separator();
          ImGui::PushTextWrapPos(ImGui::GetFontSize() * 30.0f);
          ImGui::TextDisabled("%s", picked.doc);
          ImGui::PopTextWrapPos();
        }
        ImGui::TextDisabled("Tab inserts, Up/Down pick, Esc closes");
      }
      ImGui::End();
    } else if (active) {
      // Inside a known call's parentheses: its signature over the caret, the argument at the caret marked.
      EdLuaCall call;
      if (LuaCallAt(text, caret, call)) {
        if (const EdLuaApiEntry* const entry = LuaApiForCall(call.qualifier, call.separator, call.name)) {
          const ImVec2 at = screenOf(caret);
          if (BeginFloat("##luasignature", ImVec2(at.x, at.y - lineHeight * 1.6f - 4.0f))) {
            DrawSignature(*entry, call.argument);
          }
          ImGui::End();
        }
      }
    }

    // Hover: a known function under the mouse, its signature and what it does.
    if (ImGui::IsMouseHoveringRect(clip.Min, clip.Max) && !assist.open) {
      const ImVec2 mouse = ImGui::GetIO().MousePos;
      const int line = static_cast<int>((mouse.y - origin.y) / lineHeight);
      if (line >= 0 && line < static_cast<int>(cache.lineStarts.size())) {
        const std::size_t start = cache.lineStarts[static_cast<std::size_t>(line)];
        std::size_t end = line + 1 < static_cast<int>(cache.lineStarts.size())
          ? cache.lineStarts[static_cast<std::size_t>(line) + 1] - 1
          : text.size();
        end = std::min(end, text.size());
        // The character under the mouse.
        std::size_t at = start;
        float x = origin.x;
        while (at < end) {
          const float w = font->CalcTextSizeA(size, FLT_MAX, 0.0f, base + at, base + at + 1).x;
          if (mouse.x < x + w) {
            break;
          }
          x += w;
          ++at;
        }
        // The word around it.
        std::size_t wordEnd = at;
        while (wordEnd < end &&
               (std::isalnum(static_cast<unsigned char>(text[wordEnd])) != 0 || text[wordEnd] == '_')) {
          ++wordEnd;
        }
        if (wordEnd > at || (at > start && (std::isalnum(static_cast<unsigned char>(text[at - 1])) != 0))) {
          const EdLuaWord word = LuaWordBefore(text, wordEnd);
          if (const EdLuaApiEntry* const entry = LuaApiForCall(word.qualifier, word.separator, word.prefix)) {
            EdBeginTooltip();
            DrawSignature(*entry, -1);
            if (entry->doc[0] != 0) {
              ImGui::PushTextWrapPos(ImGui::GetFontSize() * 34.0f);
              ImGui::TextDisabled("%s", entry->doc);
              ImGui::PopTextWrapPos();
            }
            ImGui::EndTooltip();
          }
        }
      }
    }
    ImGui::PopFont();
    return changed;
  }
} // namespace faf::editor
