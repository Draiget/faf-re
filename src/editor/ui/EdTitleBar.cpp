#include "editor/ui/EdTitleBar.h"

#include <algorithm>
#include <cmath>

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWindowChrome.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] EdChromeRect RectOf(
      const ImVec2& min,
      const ImVec2& max,
      const ImVec2& origin
    )
    {
      return EdChromeRect{min.x - origin.x, min.y - origin.y, max.x - min.x, max.y - min.y};
    }

    [[nodiscard]] ImU32 Mix(
      const ImVec4& a,
      const ImVec4& b,
      const float t
    )
    {
      return ImGui::ColorConvertFloat4ToU32(
        ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t)
      );
    }

    /** Windows 11's caption glyphs, drawn with lines one pixel wide at 10 px, scaled with the UI. */
    void DrawCaptionGlyph(
      ImDrawList* const dl,
      const EdHit which,
      const ImVec2 centre,
      const bool maximised,
      const ImU32 colour
    )
    {
      const float s = std::round(Em(10.0f) * 0.5f);
      const float w = std::max(1.0f, std::round(Em(1.0f)));
      const ImVec2 c(std::floor(centre.x) + 0.5f, std::floor(centre.y) + 0.5f);
      if (which == EdHit::Minimize) {
        dl->AddLine(ImVec2(c.x - s, c.y), ImVec2(c.x + s, c.y), colour, w);
      } else if (which == EdHit::Maximize) {
        if (maximised) {
          // Restore: two overlapping squares.
          const float o = std::round(s * 0.4f);
          dl->AddRect(ImVec2(c.x - s, c.y - s + o), ImVec2(c.x + s - o, c.y + s), colour, Em(1.5f), 0, w);
          dl->PathLineTo(ImVec2(c.x - s + o, c.y - s + o));
          dl->PathLineTo(ImVec2(c.x - s + o, c.y - s));
          dl->PathLineTo(ImVec2(c.x + s, c.y - s));
          dl->PathLineTo(ImVec2(c.x + s, c.y + s - o));
          dl->PathLineTo(ImVec2(c.x + s - o, c.y + s - o));
          dl->PathStroke(colour, 0, w);
        } else {
          dl->AddRect(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), colour, Em(1.5f), 0, w);
        }
      } else if (which == EdHit::Close) {
        dl->AddLine(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), colour, w);
        dl->AddLine(ImVec2(c.x + s, c.y - s), ImVec2(c.x - s, c.y + s), colour, w);
      }
    }
  } // namespace

  void DrawMenuItems(
    EdCommands& commands,
    const std::vector<EdMenuItem>& items
  )
  {
    for (const EdMenuItem& item : items) {
      if (item.separator) {
        ImGui::Separator();
        continue;
      }
      if (item.command.empty()) {
        if (ImGui::BeginMenu(MenuLabelText(item.label).c_str())) {
          if (item.provider) {
            const std::vector<EdMenuItem> made = item.provider();
            DrawMenuItems(commands, made);
          } else {
            DrawMenuItems(commands, item.items);
          }
          ImGui::EndMenu();
        }
        continue;
      }
      const EdCommand* const command = commands.Find(item.command);
      if (command == nullptr) {
        continue;
      }
      const std::string why = commands.WhyNot(item.command);
      const std::string label = MenuLabelText(item.label.empty() ? command->title : item.label);
      // The first of the command's chords beside it, as Windows menus show one.
      const std::string keys = command->keys.substr(0, command->keys.find(','));
      ImGui::PushID(item.command.c_str());
      const bool clicked = ImGui::MenuItem(
        label.c_str(), keys.empty() ? nullptr : keys.c_str(), commands.Checked(item.command), why.empty()
      );
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayNormal)) {
        if (!why.empty()) {
          ImGui::SetTooltip("Not now: %s", why.c_str());
        } else if (!command->description.empty()) {
          ImGui::SetTooltip("%s", command->description.c_str());
        }
      }
      ImGui::PopID();
      if (clicked) {
        (void)commands.Run(item.command);
      }
    }
  }

  float DrawTitleBar(
    EdCommands& commands,
    const std::vector<EdMenu>& menus,
    const EdTitleInfo& info,
    const std::function<void()>& openPalette
  )
  {
    EdWindowChrome& chrome = WindowChrome();
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const ImVec2 origin = viewport->Pos;
    const float height = std::round(Em(34.0f));
    const float fontSize = ImGui::GetFontSize();
    chrome.height = height;
    chrome.controls.clear();

    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
      ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar |
      ImGuiWindowFlags_NoBringToFrontOnFocus;
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImVec4 bar = style.Colors[chrome.active ? ImGuiCol_TitleBgActive : ImGuiCol_TitleBg];
    const ImVec2 panelFramePadding = style.FramePadding; // the panels', for the menus' rows
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(9.0f), std::floor((height - fontSize) * 0.5f)));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(Em(2.0f), style.ItemSpacing.y));
    ImGui::PushStyleColor(ImGuiCol_MenuBarBg, bar);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, bar);
    if (ImGui::Begin("##TitleBar", nullptr, kFlags) && ImGui::BeginMenuBar()) {
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const float rowTop = viewport->WorkPos.y;
      const float rowMid = rowTop + height * 0.5f;
      const ImVec4 text = style.Colors[chrome.active ? ImGuiCol_Text : ImGuiCol_TextDisabled];

      // Where the title and the menus' cursor goes so their text sits on the row's middle, as the tabs' does: the
      // menu bar draws text its line's text offset (the row's tall frame padding) below the cursor.
      const float textTop = std::round(rowMid - fontSize * 0.5f) - ImGui::GetCurrentWindow()->DC.CurrLineTextBaseOffset;

      // The app's mark: a rounded square in the accent's colours (the mockup's logo).
      {
        const float size = std::round(Em(18.0f));
        const ImVec2 at(ImGui::GetCursorScreenPos().x + Em(10.0f), std::round(rowMid - size * 0.5f));
        const ImVec4 a = style.Colors[ImGuiCol_CheckMark];
        const ImVec4 b = style.Colors[ImGuiCol_PlotHistogram];
        // A button: the start screen (File > Start screen), lit under the mouse.
        const ImVec2 cursor = ImGui::GetCursorScreenPos();
        const ImVec2 hitMin(cursor.x + Em(4.0f), rowTop + Em(4.0f));
        const ImVec2 hitMax(at.x + size + Em(6.0f), rowTop + height - Em(4.0f));
        ImGui::SetCursorScreenPos(hitMin);
        const bool pressed = ImGui::InvisibleButton("##appmark", ImVec2(hitMax.x - hitMin.x, hitMax.y - hitMin.y));
        const bool hovered = ImGui::IsItemHovered();
        chrome.controls.push_back(RectOf(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), origin));
        if (hovered || ImGui::IsItemActive()) {
          dl->AddRectFilled(
            hitMin,
            hitMax,
            ImGui::GetColorU32(ImGui::IsItemActive() ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered),
            Em(6.0f)
          );
          ImGui::SetTooltip("Open the start screen");
        }
        dl->AddRectFilledMultiColor(
          at, ImVec2(at.x + size, at.y + size), Mix(a, b, 0.0f), Mix(a, b, 0.5f), Mix(a, b, 1.0f), Mix(a, b, 0.5f)
        );
        dl->AddRect(
          at,
          ImVec2(at.x + size, at.y + size),
          hovered ? ImGui::GetColorU32(ImGui::IsItemActive() ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered)
                  : ImGui::ColorConvertFloat4ToU32(bar),
          Em(4.0f),
          0,
          Em(3.0f)
        );
        if (pressed) {
          (void)commands.Run("file.home");
        }
        ImGui::SetCursorScreenPos(cursor);
        ImGui::Dummy(ImVec2(size + Em(18.0f), fontSize));
      }

      // The map's name, a dot while it has unsaved changes, and what a play is doing.
      {
        ImGui::PushStyleColor(ImGuiCol_Text, text);
        // On the row's middle, as the workspace tabs are (the menu bar's own line sat a few pixels lower).
        ImGui::SetCursorScreenPos(ImVec2(ImGui::GetCursorScreenPos().x, textTop));
        ImGui::TextUnformatted(info.document.empty() ? "FAF Map Editor" : info.document.c_str());
        ImGui::PopStyleColor();
        if (info.modified) {
          ImGui::SameLine(0.0f, Em(5.0f));
          ImGui::TextColored(ImVec4(0.96f, 0.70f, 0.28f, 1.0f), "\xE2\x97\x8F");
          if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Unsaved changes");
          }
        }
        if (!info.state.empty()) {
          ImGui::SameLine(0.0f, Em(8.0f));
          ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.45f, 1.0f), "%s", info.state.c_str());
        }
        ImGui::SameLine(0.0f, Em(14.0f));
      }

      // The menus. Alt or F10 opens one through the window's message handler (chrome.openMenu). Each label sits on
      // the row's middle with room around it (ImGui spaces menu labels by the item spacing, which the row keeps
      // small), lit the tabs' height and shape under the mouse or while open (ImGui's own light is the text's box).
      // (A menu label takes about two and a half times the item spacing round it.)
      // The light reaches Em(7) past a label's text on each side; the labels' gap (about 2.5 times this spacing) leaves
      // room between two lights.
      ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(Em(9.0f), style.ItemSpacing.y));
      dl->ChannelsSplit(2);
      const float litHeight = std::round(Em(24.0f));
      for (std::size_t i = 0; i < menus.size(); ++i) {
        const std::string label = MenuLabelText(menus[i].label);
        if (chrome.openMenu == static_cast<int>(i)) {
          ImGui::OpenPopup(label.c_str());
        }
        dl->ChannelsSetCurrent(1);
        ImGui::SetCursorScreenPos(ImVec2(ImGui::GetCursorScreenPos().x, textTop));
        // The menu's popup is made inside BeginMenu: it takes the padding pushed here, not the row's (none).
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(10.0f), Em(7.0f)));
        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        const bool open = ImGui::BeginMenu(label.c_str());
        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar();
        const ImVec2 labelMin = ImGui::GetItemRectMin();
        const ImVec2 labelMax = ImGui::GetItemRectMax();
        chrome.controls.push_back(RectOf(labelMin, labelMax, origin));
        if (open || ImGui::IsItemHovered()) {
          dl->ChannelsSetCurrent(0);
          // Round the text, not the item: ImGui's item already spans half the gap to each neighbour.
          const float middle = (labelMin.x + labelMax.x) * 0.5f;
          const float half = ImGui::CalcTextSize(label.c_str()).x * 0.5f + Em(7.0f);
          dl->AddRectFilled(
            ImVec2(std::round(middle - half), std::round(rowMid - litHeight * 0.5f)),
            ImVec2(std::round(middle + half), std::round(rowMid + litHeight * 0.5f)),
            ImGui::GetColorU32(open ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered),
            Em(6.0f)
          );
          dl->ChannelsSetCurrent(1);
        }
        if (open) {
          // The mockup's menu rows: room between them and to their sides (the row's frame padding is its own).
          ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, panelFramePadding);
          ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(Em(12.0f), Em(9.0f)));
          ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(10.0f), Em(7.0f)));
          DrawMenuItems(commands, menus[i].items);
          ImGui::PopStyleVar(3);
          ImGui::EndMenu();
        }
      }
      dl->ChannelsMerge();
      ImGui::PopStyleVar();
      chrome.openMenu = -1;

      // The workspace tabs: the one shown filled, the others as text; each runs its command (so its keys and the
      // palette do the same). Their rects are controls: a click there isn't a drag of the window.
      if (!info.tabs.empty()) {
        ImGui::SameLine(0.0f, Em(16.0f));
        const float h = std::round(Em(24.0f));
        for (std::size_t i = 0; i < info.tabs.size(); ++i) {
          const EdTitleInfo::Tab& tab = info.tabs[i];
          const bool active = static_cast<int>(i) == info.activeTab;
          if (tab.groupStart && i > 0) {
            // The rule between groups (the mockup's: Terrain to Mission, Effects to Materials, Review).
            const float x = std::round(ImGui::GetCursorScreenPos().x + Em(4.0f));
            dl->AddLine(
              ImVec2(x + 0.5f, std::round(rowMid - Em(9.0f))),
              ImVec2(x + 0.5f, std::round(rowMid + Em(9.0f))),
              ImGui::GetColorU32(ImGuiCol_Border)
            );
            ImGui::SetCursorScreenPos(ImVec2(x + Em(6.0f), ImGui::GetCursorScreenPos().y));
          }
          const std::string text = tab.icon.empty() ? tab.label : tab.icon + "  " + tab.label;
          const ImVec2 size(ImGui::CalcTextSize(text.c_str()).x + Em(20.0f), h);
          const ImVec2 at(ImGui::GetCursorScreenPos().x, std::round(rowMid - h * 0.5f));
          ImGui::SetCursorScreenPos(at);
          ImGui::PushID(tab.command.c_str());
          const bool clicked = ImGui::InvisibleButton("##tab", size);
          const bool hovered = ImGui::IsItemHovered();
          ImGui::PopID();
          const ImVec2 max(at.x + size.x, at.y + size.y);
          chrome.controls.push_back(RectOf(at, max, origin));
          // The mockup's: the shown one in the accent's soft fill and colour, a hovered one on the panels' grey.
          if (active) {
            dl->AddRectFilled(at, max, AccentU32(0.16f), Em(6.0f));
          } else if (hovered) {
            dl->AddRectFilled(at, max, ImGui::GetColorU32(ImGuiCol_WindowBg), Em(6.0f));
          }
          const ImU32 ink = active ? AccentU32() : ImGui::GetColorU32(hovered ? ImGuiCol_Text : ImGuiCol_TextDisabled);
          dl->AddText(ImVec2(at.x + Em(10.0f), (at.y + max.y - fontSize) * 0.5f), ink, text.c_str());
          if (hovered && ImGui::BeginTooltip()) {
            // "Layout workspace · Alt+4", then what it is for.
            const std::string title =
              tab.label + " workspace" + (tab.keys.empty() ? std::string() : " \xC2\xB7 " + tab.keys);
            if (gBoldFont != nullptr) {
              ImGui::PushFont(gBoldFont, 0.0f);
            }
            ImGui::TextUnformatted(title.c_str());
            if (gBoldFont != nullptr) {
              ImGui::PopFont();
            }
            const EdCommand* const command = commands.Find(tab.command);
            const std::string& about =
              !tab.about.empty() ? tab.about : (command != nullptr ? command->description : tab.about);
            if (!about.empty()) {
              ImGui::PushTextWrapPos(ImGui::GetFontSize() * 24.0f);
              ImGui::TextUnformatted(about.c_str());
              ImGui::PopTextWrapPos();
            }
            ImGui::EndTooltip();
          }
          if (clicked) {
            (void)commands.Run(tab.command);
          }
          ImGui::SameLine(0.0f, Em(2.0f));
        }
      }

      // The search box in the middle of what is left: it opens the command palette.
      const float buttons = chrome.own ? std::round(Em(46.0f)) * 3.0f : 0.0f;
      const float right = viewport->WorkPos.x + viewport->WorkSize.x - buttons;
      {
        const float width = std::min(Em(300.0f), std::max(0.0f, right - ImGui::GetCursorScreenPos().x - Em(40.0f)));
        if (width > Em(120.0f)) {
          const float x = std::max(
            ImGui::GetCursorScreenPos().x + Em(20.0f), viewport->WorkPos.x + (viewport->WorkSize.x - width) * 0.5f
          );
          const float h = std::round(Em(24.0f));
          const ImVec2 at(x, std::round(rowMid - h * 0.5f));
          ImGui::SetCursorScreenPos(at);
          ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(10.0f), (h - fontSize) * 0.5f));
          ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, Em(6.0f));
          ImGui::PushStyleColor(ImGuiCol_Button, style.Colors[ImGuiCol_FrameBg]);
          ImGui::PushStyleColor(ImGuiCol_ButtonHovered, style.Colors[ImGuiCol_FrameBgHovered]);
          ImGui::PushStyleColor(ImGuiCol_ButtonActive, style.Colors[ImGuiCol_FrameBgActive]);
          ImGui::PushStyleColor(ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled]);
          if (ImGui::Button("##search", ImVec2(width, h)) && openPalette) {
            openPalette();
          }
          const ImVec2 min = ImGui::GetItemRectMin();
          const ImVec2 max = ImGui::GetItemRectMax();
          chrome.controls.push_back(RectOf(min, max, origin));
          const ImU32 dim = ImGui::GetColorU32(ImGuiCol_Text);
          // A magnifier, the words, and the keys at the right end.
          const ImVec2 glass(min.x + Em(14.0f), (min.y + max.y) * 0.5f - Em(1.0f));
          dl->AddCircle(glass, Em(4.5f), dim, 0, Em(1.4f));
          dl->AddLine(
            ImVec2(glass.x + Em(3.2f), glass.y + Em(3.2f)),
            ImVec2(glass.x + Em(6.5f), glass.y + Em(6.5f)),
            dim,
            Em(1.4f)
          );
          dl->AddText(
            ImVec2(min.x + Em(26.0f), (min.y + max.y - fontSize) * 0.5f), dim, "Search commands, panels, maps"
          );
          const char* const keys = "Ctrl K";
          const float kw = ImGui::CalcTextSize(keys).x;
          dl->AddText(ImVec2(max.x - kw - Em(10.0f), (min.y + max.y - fontSize) * 0.5f), dim, keys);
          ImGui::PopStyleColor(4);
          ImGui::PopStyleVar(2);
        }
      }

      // Windows 11's caption buttons: the window's message handler answers HTMINBUTTON, HTMAXBUTTON and HTCLOSE over
      // them (so Windows shows its snap layouts over maximise), and tells this which one the mouse is on.
      if (chrome.own) {
        const float bw = std::round(Em(46.0f));
        const EdHit kinds[3] = {EdHit::Minimize, EdHit::Maximize, EdHit::Close};
        EdChromeRect* const rects[3] = {&chrome.minimize, &chrome.maximize, &chrome.close};
        for (int i = 0; i < 3; ++i) {
          const ImVec2 min(right + bw * static_cast<float>(i), rowTop);
          const ImVec2 max(min.x + bw, rowTop + height);
          *rects[i] = RectOf(min, max, origin);
          const bool hot = chrome.hot == kinds[i];
          const bool held = chrome.pressed == kinds[i] && hot;
          ImU32 fill = 0;
          ImU32 glyph = ImGui::ColorConvertFloat4ToU32(text);
          if (kinds[i] == EdHit::Close && (hot || held)) {
            fill = held ? IM_COL32(148, 32, 22, 255) : IM_COL32(196, 43, 28, 255);
            glyph = IM_COL32(255, 255, 255, 255);
          } else if (hot || held) {
            fill = ImGui::GetColorU32(held ? ImGuiCol_HeaderActive : ImGuiCol_HeaderHovered);
          }
          if (fill != 0) {
            dl->AddRectFilled(min, max, fill);
          }
          DrawCaptionGlyph(
            dl, kinds[i], ImVec2((min.x + max.x) * 0.5f, (min.y + max.y) * 0.5f), chrome.maximised, glyph
          );
        }
      } else {
        chrome.minimize = chrome.maximize = chrome.close = EdChromeRect{};
      }
      // The layout in the log when it changes (test runs read where the buttons are).
      static float loggedHeight = -1.0f;
      static float loggedClose = -1.0f;
      if (loggedHeight != chrome.height || loggedClose != chrome.close.x) {
        loggedHeight = chrome.height;
        loggedClose = chrome.close.x;
        gpg::Logf(
          "editor: title row %.0f px high, %zu controls, buttons at x %.0f/%.0f/%.0f (%.0f wide)",
          static_cast<double>(chrome.height),
          chrome.controls.size(),
          static_cast<double>(chrome.minimize.x),
          static_cast<double>(chrome.maximize.x),
          static_cast<double>(chrome.close.x),
          static_cast<double>(chrome.close.w)
        );
      }
      ImGui::EndMenuBar();
    }
    ImGui::End();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(5);
    return height;
  }
} // namespace faf::editor
