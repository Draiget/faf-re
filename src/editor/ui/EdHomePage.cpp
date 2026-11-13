// The start screen, "Home" (design §8 Files): EdShell's members that draw it, in the mockup's look (home.css).

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdFafApi.h"
#include "editor/EdPlay.h"
#include "editor/ui/EdCards.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdHomeModel.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kUploads = "home.uploads";
    constexpr const char* kPopular = "home.popular";
    constexpr const char* kTyped = "home.search";

    /** A section's heading: the mockup's small dimmed capitals (.hm-sh h2). */
    void Heading(
      const char* const text
    )
    {
      std::string caps = text;
      for (char& ch : caps) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
      }
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::PushFont(gBoldFont, std::round(ImGui::GetFontSize() * 0.8f));
      ImGui::TextUnformatted(caps.c_str());
      ImGui::PopFont();
      ImGui::PopStyleColor();
      ImGui::Dummy(ImVec2(0.0f, Em(2.0f)));
    }

    /** A title inside a card: the text's size, bold, bright. */
    void Subheading(
      const char* const text
    )
    {
      ImGui::PushFont(gBoldFont, 0.0f);
      ImGui::TextUnformatted(text);
      ImGui::PopFont();
    }

    /** A kind's colour (0xRRGGBB) at this opacity. */
    ImU32 KindU32(
      const unsigned int rgb,
      const float alpha = 1.0f
    )
    {
      return IM_COL32((rgb >> 16) & 0xFFU, (rgb >> 8) & 0xFFU, rgb & 0xFFU, static_cast<int>(alpha * 255.0f));
    }

    /** The mockup's text-1: between the bright and the dimmed text. */
    ImU32 SoftInkU32()
    {
      const ImVec4 text = ImGui::GetStyleColorVec4(ImGuiCol_Text);
      const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
      return ImGui::GetColorU32(
        ImVec4((text.x * 2.0f + dim.x) / 3.0f, (text.y * 2.0f + dim.y) / 3.0f, (text.z * 2.0f + dim.z) / 3.0f, 1.0f)
      );
    }

    /** Text in a font and size, cut at `right`. */
    void TextAt(
      ImDrawList* const dl,
      ImFont* const font,
      const float size,
      const ImVec2 at,
      const ImU32 ink,
      const char* const text,
      const float right
    )
    {
      dl->PushClipRect(ImVec2(at.x, at.y - size), ImVec2(right, at.y + size * 2.0f), true);
      dl->AddText(font != nullptr ? font : ImGui::GetFont(), size, at, ink, text);
      dl->PopClipRect();
    }

    /**
     * A row of the left column (.hm-ni): its icon, its words, maybe a key at the right; the page shown filled, a
     * hovered one lit.
     */
    bool NavItem(
      const char* const id,
      const char* const icon,
      const char* const label,
      const bool current,
      const char* const key = nullptr,
      const bool enabled = true
    )
    {
      const float height = std::round(Em(30.0f));
      const float width = ImGui::GetContentRegionAvail().x;
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const bool clicked = ImGui::InvisibleButton(id, ImVec2(width, height)) && enabled;
      const bool hovered = enabled && ImGui::IsItemHovered();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 to(at.x + width, at.y + height);
      if (current) {
        dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_ButtonHovered), Em(6.0f));
      } else if (hovered) {
        dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_Button), Em(6.0f));
      }
      ImU32 ink = current || hovered ? ImGui::GetColorU32(ImGuiCol_Text) : SoftInkU32();
      if (!enabled) {
        ink = ImGui::GetColorU32(ImGuiCol_TextDisabled);
      }
      const float y = std::round(at.y + (height - ImGui::GetFontSize()) * 0.5f);
      dl->AddText(ImVec2(at.x + Em(10.0f), y), current ? ImGui::GetColorU32(ImGuiCol_Text) : ink, icon);
      dl->AddText(ImVec2(at.x + Em(34.0f), y), ink, label);
      if (key != nullptr) {
        // The key on a quiet cap (.hm-ni kbd).
        const float size = std::round(ImGui::GetFontSize() * 0.78f);
        const ImVec2 text = ImGui::GetFont()->CalcTextSizeA(size, FLT_MAX, 0.0f, key);
        const ImVec2 capMax(to.x - Em(8.0f), std::round(at.y + height * 0.5f + text.y * 0.5f + Em(2.0f)));
        const ImVec2 capMin(capMax.x - text.x - Em(10.0f), std::round(at.y + height * 0.5f - text.y * 0.5f - Em(2.0f)));
        dl->AddRect(capMin, capMax, ImGui::GetColorU32(ImGuiCol_Border), Em(4.0f));
        dl->AddText(
          ImGui::GetFont(),
          size,
          ImVec2(capMin.x + Em(5.0f), capMin.y + Em(2.0f)),
          ImGui::GetColorU32(ImGuiCol_TextDisabled),
          key
        );
      }
      return clicked;
    }

    /** The rows of the left column sit nearly touching (.hm-nav gap: .1rem). */
    void PushNavSpacing()
    {
      ImGui::PushStyleVar(
        ImGuiStyleVar_ItemSpacing, ImVec2(ImGui::GetStyle().ItemSpacing.x, std::max(1.0f, std::round(Em(1.5f))))
      );
    }

    /** The mockup's small check (.hm-check): an accent box with a tick, the words dimmed. */
    bool SmallCheck(
      const char* const id,
      const char* const label,
      bool& value
    )
    {
      const float box = std::round(Em(14.0f));
      const float size = std::round(ImGui::GetFontSize() * 0.86f);
      const ImVec2 text = ImGui::GetFont()->CalcTextSizeA(size, FLT_MAX, 0.0f, label);
      const float height = std::max(box, text.y) + Em(4.0f);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const bool clicked = ImGui::InvisibleButton(id, ImVec2(box + Em(8.0f) + text.x, height));
      const bool hovered = ImGui::IsItemHovered();
      if (clicked) {
        value = !value;
      }
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 b0(at.x, std::round(at.y + (height - box) * 0.5f));
      const ImVec2 b1(b0.x + box, b0.y + box);
      if (value) {
        dl->AddRectFilled(b0, b1, AccentU32(hovered ? 0.88f : 1.0f), Em(3.0f));
        // The tick.
        const float s = box;
        dl->AddPolyline(
          std::array<ImVec2, 3>{
            ImVec2(b0.x + s * 0.24f, b0.y + s * 0.52f),
            ImVec2(b0.x + s * 0.43f, b0.y + s * 0.70f),
            ImVec2(b0.x + s * 0.77f, b0.y + s * 0.32f)
          }
            .data(),
          3,
          ImGui::GetColorU32(AccentText()),
          ImDrawFlags_None,
          std::max(1.5f, s * 0.14f)
        );
      } else {
        dl->AddRect(b0, b1, ImGui::GetColorU32(hovered ? ImGuiCol_Text : ImGuiCol_Border), Em(3.0f));
      }
      dl->AddText(
        ImGui::GetFont(),
        size,
        ImVec2(b1.x + Em(8.0f), std::round(at.y + (height - text.y) * 0.5f)),
        ImGui::GetColorU32(hovered ? ImGuiCol_Text : ImGuiCol_TextDisabled),
        label
      );
      return clicked;
    }

    /** Seconds since a file or folder changed, or a negative when it can't be read. */
    double SecondsSinceChanged(
      const std::string& path
    )
    {
      if (path.empty()) {
        return -1.0;
      }
      std::error_code error;
      const auto when = std::filesystem::last_write_time(std::filesystem::path(path), error);
      if (error) {
        return -1.0;
      }
      const auto age = std::filesystem::file_time_type::clock::now() - when;
      return std::chrono::duration<double>(age).count();
    }
  } // namespace

  void EdShell::ShowHome(
    const int page
  ) noexcept
  {
    mShowHome = true;
    mHomePage = std::clamp(page, 0, 2);
    mHomeFocusSearch = page == 0;
    mHomeFront = true;
  }

  void EdShell::DrawHome(
    const float top,
    const float bottom
  )
  {
    // File > Open, the Map panel's "Open a map..." and the vault's links show the start screen's pages, never a
    // window of their own.
    if (mBrowser.Open()) {
      mBrowser.Open() = false;
      ShowHome(mBrowser.TakeSelectVault() ? 2 : 1);
      gpg::Logf("editor: start screen: asked for page %d", mHomePage);
    }
    if (!mShowHome) {
      return;
    }
    // A map opening (from any of its pages, a recent card, New map): the start screen gives way.
    if (mDocument.GetState() == EdDocument::State::Loading) {
      mShowHome = false;
      return;
    }
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + top));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - top - bottom));
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    // The mockup's ground (bg-0), opaque: the panels behind mustn't show through a theme's see-through colours.
    ImVec4 ground = ImGui::GetStyleColorVec4(ImGuiCol_DockingEmptyBg);
    ground.w = 1.0f;
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ground);
    const bool shown = ImGui::Begin("Start###Home", nullptr, kFlags);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);
    if (shown) {
      // In front of the panels when it opens; not every frame, which would cover the dialogs opened over it
      // (Recover, Save changes?, Settings, New map). Docked panels can't come over it later (their host stays back).
      // Not over a dialog already open (the recovery offer opens on the first frame, before this).
      if (std::exchange(mHomeFront, false) && ImGui::GetTopMostPopupModal() == nullptr) {
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
      }

      // The left column (.hm-rail): the brand, the pages; at its foot Recover, the tour, Help, the open map's
      // Continue and the switch.
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(12.0f), Em(16.0f)));
      ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
      ImGui::BeginChild(
        "##homeleft",
        ImVec2(std::round(Em(236.0f)), 0.0f),
        ImGuiChildFlags_AlwaysUseWindowPadding,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse
      );
      ImGui::PopStyleColor();
      ImGui::PopStyleVar();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      {
        const ImVec2 at = ImGui::GetWindowPos();
        const ImVec2 size = ImGui::GetWindowSize();
        dl->AddLine(
          ImVec2(at.x + size.x - 0.5f, at.y),
          ImVec2(at.x + size.x - 0.5f, at.y + size.y),
          ImGui::GetColorU32(ImGuiCol_TableBorderLight)
        );
      }
      const float columnRight = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - Em(12.0f);
      {
        // The brand (.hm-brand): the mark on the accent's gradient, the name, what it makes.
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const float logo = std::round(Em(34.0f));
        const ImVec2 p0(at.x + Em(4.0f), at.y);
        const ImVec2 p1(p0.x + logo, p0.y + logo);
        const int first = dl->VtxBuffer.Size;
        dl->AddRectFilled(p0, p1, IM_COL32_WHITE, Em(8.0f));
        ImGui::ShadeVertsLinearColorGradientKeepAlpha(
          dl, first, dl->VtxBuffer.Size, p0, p1, IM_COL32(0x4E, 0xA1, 0xFF, 0xFF), IM_COL32(0x35, 0xC3, 0x9B, 0xFF)
        );
        const float iconSize = std::round(ImGui::GetFontSize() * 1.2f);
        const ImVec2 iconText = ImGui::GetFont()->CalcTextSizeA(iconSize, FLT_MAX, 0.0f, ICON_TERRAIN);
        dl->AddText(
          ImGui::GetFont(),
          iconSize,
          ImVec2(std::round(p0.x + (logo - iconText.x) * 0.5f), std::round(p0.y + (logo - iconText.y) * 0.5f)),
          IM_COL32(0x06, 0x12, 0x1F, 0xFF),
          ICON_TERRAIN
        );
        const float tx = p1.x + Em(10.0f);
        TextAt(
          dl,
          gBoldFont,
          std::round(ImGui::GetFontSize() * 1.08f),
          ImVec2(tx, p0.y - Em(1.0f)),
          InkU32(),
          "FAF Map Editor",
          columnRight
        );
        TextAt(
          dl,
          nullptr,
          std::round(ImGui::GetFontSize() * 0.82f),
          ImVec2(tx, p0.y + Em(19.0f)),
          ImGui::GetColorU32(ImGuiCol_TextDisabled),
          "Maps, missions, mods, effects",
          columnRight
        );
        ImGui::Dummy(ImVec2(0.0f, logo + Em(18.0f)));
      }
      static constexpr const char* kPages[] = {"Home", "On this computer", "FAF vault"};
      static constexpr const char* kPageIcons[] = {ICON_FRAME, ICON_OPEN, ICON_VAULT};
      PushNavSpacing();
      for (int i = 0; i < 3; ++i) {
        ImGui::PushID(i);
        if (NavItem("##page", kPageIcons[i], kPages[i], mHomePage == i)) {
          mHomePage = i;
          gpg::Logf("editor: start screen: page %s", kPages[i]);
        }
        ImGui::PopID();
      }
      ImGui::PopStyleVar();

      // The foot: a rule, the links, Continue, the switch; laid out from the column's bottom up.
      const bool open = mDocument.GetState() == EdDocument::State::Open;
      const float row = std::round(Em(30.0f)) + Em(1.0f) + ImGui::GetStyle().ItemSpacing.y * 2.0f;
      const float cardHeight = std::round(Em(56.0f));
      const float checkHeight = std::round(Em(26.0f));
      // Its height as the last frame measured it (an estimate the first time): the foot ends on the column's bottom
      // edge, never past it (a few pixels past, the column grew a scrollbar beside empty space; user report).
      ImGuiStorage* const storage = ImGui::GetStateStorage();
      const ImGuiID footKey = ImGui::GetID(open ? "##footopen" : "##footclosed");
      const float footEstimate = Em(12.0f) + row * 3.0f + (open ? cardHeight + Em(10.0f) : 0.0f) + checkHeight;
      const float foot = storage->GetFloat(footKey, footEstimate);
      const float footTop =
        std::max(ImGui::GetCursorPosY(), ImGui::GetWindowHeight() - ImGui::GetStyle().WindowPadding.y - foot);
      ImGui::SetCursorPosY(footTop);
      {
        const ImVec2 at = ImGui::GetCursorScreenPos();
        dl->AddLine(
          ImVec2(at.x, at.y + 0.5f), ImVec2(columnRight, at.y + 0.5f), ImGui::GetColorU32(ImGuiCol_TableBorderLight)
        );
        ImGui::Dummy(ImVec2(0.0f, Em(8.0f)));
      }
      // What these run says why it can't yet.
      struct Link
      {
        const char* command;
        const char* icon;
        const char* label;
        const char* key;
      };
      static constexpr Link kLinks[] = {
        {"file.recover", ICON_HISTORY, "Recover the autosave", nullptr},
        {"help.tour", ICON_HELP, "Take the 2-minute tour", nullptr},
        {"help.open", ICON_INFO, "Help", "F1"},
      };
      PushNavSpacing();
      for (const Link& link : kLinks) {
        const std::string why = mCommands != nullptr ? mCommands->WhyNot(link.command) : std::string("no commands");
        ImGui::PushID(link.command);
        if (NavItem("##link", link.icon, link.label, false, link.key, why.empty()) && mCommands != nullptr) {
          (void)mCommands->Run(link.command);
        }
        ImGui::PopID();
        if (!why.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          EdSetTooltip(
            "Not yet: %s", why == "no such command" ? "it comes with a later part of the editor" : why.c_str()
          );
        }
      }
      ImGui::PopStyleVar();
      // The open map: back to it (.hm-continue).
      if (open) {
        ImGui::Dummy(ImVec2(0.0f, Em(4.0f)));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const float width = ImGui::GetContentRegionAvail().x;
        const bool clicked = ImGui::InvisibleButton("##continue", ImVec2(width, cardHeight));
        const bool hovered = ImGui::IsItemHovered();
        if (clicked) {
          mShowHome = false;
        }
        const ImVec2 to(at.x + width, at.y + cardHeight);
        dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_WindowBg), Em(6.0f));
        dl->AddRect(at, to, hovered ? AccentU32() : ImGui::GetColorU32(ImGuiCol_Border), Em(6.0f));
        std::string title = mDocument.FolderName();
        std::string size;
        int players = 0;
        std::uint64_t picture = 0;
        (void)mBrowser.MapCard(mDocument.Path(), title, size, players, picture);
        const float pic = cardHeight - Em(16.0f);
        const ImVec2 q0(at.x + Em(8.0f), at.y + Em(8.0f));
        if (picture != 0) {
          dl->AddImageRounded(
            static_cast<ImTextureID>(picture),
            q0,
            ImVec2(q0.x + pic, q0.y + pic),
            ImVec2(0, 0),
            ImVec2(1, 1),
            IM_COL32_WHITE,
            Em(5.0f)
          );
        } else {
          dl->AddRectFilled(q0, ImVec2(q0.x + pic, q0.y + pic), ChipU32(), Em(5.0f));
        }
        const float tx = q0.x + pic + Em(10.0f);
        const float chevronWidth = ImGui::CalcTextSize(ICON_RIGHT).x;
        TextAt(
          dl,
          nullptr,
          std::round(ImGui::GetFontSize() * 0.84f),
          ImVec2(tx, at.y + Em(9.0f)),
          ImGui::GetColorU32(ImGuiCol_TextDisabled),
          "Continue",
          to.x - chevronWidth - Em(14.0f)
        );
        TextAt(
          dl,
          gBoldFont,
          ImGui::GetFontSize(),
          ImVec2(tx, at.y + Em(27.0f)),
          InkU32(),
          title.c_str(),
          to.x - chevronWidth - Em(14.0f)
        );
        dl->AddText(
          ImVec2(to.x - chevronWidth - Em(10.0f), std::round(at.y + (cardHeight - ImGui::GetFontSize()) * 0.5f)),
          SoftInkU32(),
          ICON_RIGHT
        );
        if (hovered) {
          ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        }
      }
      ImGui::Dummy(ImVec2(0.0f, Em(4.0f)));
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + Em(6.0f));
      (void)SmallCheck("##homeatstart", "Show this screen at start", mHomeAtStart);
      // What the foot took, for the next frame (the cursor is a line's spacing past its last item).
      storage->SetFloat(footKey, ImGui::GetCursorPosY() - ImGui::GetStyle().ItemSpacing.y - footTop);
      ImGui::EndChild();

      // The page (.hm-main), padded.
      ImGui::SameLine(0.0f, 0.0f);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(24.0f), Em(18.0f)));
      ImGui::BeginChild("##homepage", ImVec2(0.0f, 0.0f), ImGuiChildFlags_AlwaysUseWindowPadding);
      ImGui::PopStyleVar();
      switch (mHomePage) {
      case 1:
        mBrowser.DrawLocalPage();
        break;
      case 2:
        mBrowser.DrawVaultPage();
        break;
      default:
        DrawHomePage();
        break;
      }
      ImGui::EndChild();
    }
    ImGui::End();
  }

  void EdShell::DrawHomePage()
  {
    const float gap = Em(10.0f);
    EdFafSession& faf = mBrowser.Faf();
    const bool loggedIn = faf.GetState() == EdFafSession::State::LoggedIn;

    // One search over your maps and the vault (.hm-search): typing shows both lists, Enter the vault page with the
    // words.
    {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(36.0f), Em(10.0f)));
      ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, Em(8.0f));
      ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::GetStyleColorVec4(ImGuiCol_WindowBg));
      // The keyboard goes to the search when the screen opens: typing searches at once.
      if (std::exchange(mHomeFocusSearch, false)) {
        ImGui::SetKeyboardFocusHere();
      }
      if (
        ImGui::InputTextWithHint(
          "##homesearch", "Search your files and the FAF vault", mHomeSearch, sizeof(mHomeSearch)
        )
      ) {
        mHomeTypedAt = ImGui::GetTime();
      }
      const bool enter = ImGui::IsItemDeactivated() && ImGui::IsKeyPressed(ImGuiKey_Enter);
      const ImVec2 min = ImGui::GetItemRectMin();
      const ImVec2 max = ImGui::GetItemRectMax();
      ImGui::PopStyleColor();
      ImGui::PopStyleVar(2);
      ImGui::GetWindowDrawList()->AddText(
        ImVec2(min.x + Em(14.0f), std::round((min.y + max.y - ImGui::GetFontSize()) * 0.5f)),
        ImGui::GetColorU32(ImGuiCol_TextDisabled),
        ICON_SEARCH
      );
      if (enter && mHomeSearch[0] != 0) {
        gpg::Logf("editor: start screen: the vault page for \"%s\"", mHomeSearch);
        mBrowser.AskSearch(mHomeSearch);
        mBrowser.Open() = false;
        (void)mBrowser.TakeSelectVault();
        mHomePage = 2;
        return;
      }
    }
    ImGui::Dummy(ImVec2(0.0f, Em(14.0f)));
    if (mHomeSearch[0] != 0) {
      DrawHomeSearch(loggedIn);
      return;
    }

    // New: every kind the editor makes, as same-size tiles (.hm-tile) in the kind's colour.
    Heading("New");
    const std::vector<EdNewKind>& kinds = NewKinds();
    const EdCardGrid newGrid =
      CardGrid(ImGui::GetContentRegionAvail().x, Em(170.0f), gap, static_cast<int>(kinds.size()));
    const float newHeight = std::round(Em(56.0f));
    for (std::size_t i = 0; i < kinds.size(); ++i) {
      const EdNewKind& kind = kinds[i];
      if (i % static_cast<std::size_t>(newGrid.columns) != 0) {
        ImGui::SameLine(0.0f, gap);
      }
      const std::string why = mCommands != nullptr ? mCommands->WhyNot(kind.command) : std::string("no commands");
      const bool ready = why.empty();
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImGui::PushID(kind.command);
      const bool clicked = ImGui::InvisibleButton("##new", ImVec2(newGrid.cardWidth, newHeight));
      const bool hovered = ImGui::IsItemHovered();
      ImGui::PopID();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 to(at.x + newGrid.cardWidth, at.y + newHeight);
      const float alpha = ready ? 1.0f : 0.45f;
      dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_FrameBg), Em(8.0f));
      dl->AddRect(at, to, hovered && ready ? KindU32(kind.rgb) : ImGui::GetColorU32(ImGuiCol_Border), Em(8.0f));
      // The kind's icon on its colour, faint.
      const float tile = std::round(Em(34.0f));
      const ImVec2 t0(at.x + Em(12.0f), std::round(at.y + (newHeight - tile) * 0.5f));
      dl->AddRectFilled(t0, ImVec2(t0.x + tile, t0.y + tile), KindU32(kind.rgb, 0.18f * alpha), Em(7.0f));
      const float iconSize = std::round(ImGui::GetFontSize() * 1.15f);
      const ImVec2 iconText = ImGui::GetFont()->CalcTextSizeA(iconSize, FLT_MAX, 0.0f, kind.icon);
      dl->AddText(
        ImGui::GetFont(),
        iconSize,
        ImVec2(std::round(t0.x + (tile - iconText.x) * 0.5f), std::round(t0.y + (tile - iconText.y) * 0.5f)),
        KindU32(kind.rgb, alpha),
        kind.icon
      );
      const float tx = t0.x + tile + Em(12.0f);
      const ImU32 ink = ready ? InkU32() : ImGui::GetColorU32(ImGuiCol_TextDisabled);
      TextAt(dl, gBoldFont, ImGui::GetFontSize(), ImVec2(tx, at.y + Em(10.0f)), ink, kind.title, to.x - Em(8.0f));
      TextAt(
        dl,
        nullptr,
        std::round(ImGui::GetFontSize() * 0.84f),
        ImVec2(tx, at.y + Em(29.0f)),
        ImGui::GetColorU32(ImGuiCol_TextDisabled),
        kind.about,
        to.x - Em(8.0f)
      );
      if (hovered && !ready) {
        EdSetTooltip("Not yet: %s", why.c_str());
      } else if (hovered) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
      }
      if (clicked && ready && mCommands != nullptr) {
        gpg::Logf("editor: start screen: New %s", kind.title);
        (void)mCommands->Run(kind.command);
      }
    }
    ImGui::Dummy(ImVec2(0.0f, Em(18.0f)));

    // Recent at the left; the vault's rows at the right, on a card (.hm-card).
    const float side = std::min(Em(380.0f), ImGui::GetContentRegionAvail().x * 0.36f);
    const float gutter = Em(18.0f);
    ImGui::BeginChild("##homerecent", ImVec2(ImGui::GetContentRegionAvail().x - side - gutter, 0.0f));
    DrawHomeRecent();
    ImGui::EndChild();
    ImGui::SameLine(0.0f, gutter);
    ImGui::BeginGroup();
    Heading("FAF vault");
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::GetStyleColorVec4(ImGuiCol_TableBorderLight));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, Em(9.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(12.0f), Em(12.0f)));
    ImGui::BeginChild(
      "##homevault",
      ImVec2(0.0f, 0.0f),
      ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY
    );
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    DrawHomeVault(loggedIn);
    ImGui::EndChild();
    ImGui::EndGroup();
  }

  void EdShell::DrawHomeRecent()
  {
    const float gap = Em(12.0f);
    // Only maps are kept as recent work so far.
    const std::vector<std::string>& recent = mDocument.RecentMaps();
    std::vector<std::string> listed;
    for (const std::string& scenario : recent) {
      std::string title;
      std::string size;
      int players = 0;
      std::uint64_t picture = 0;
      if (mBrowser.MapCard(scenario, title, size, players, picture)) {
        listed.push_back(scenario);
      }
    }
    Heading("Recent");
    if (listed.empty()) {
      ImGui::TextDisabled("Maps you open show here.");
      return;
    }
    const EdCardGrid grid = CardGrid(ImGui::GetContentRegionAvail().x, Em(200.0f), gap, 5);
    const float pictureHeight = std::round(std::min(grid.cardWidth * 9.0f / 16.0f, Em(170.0f)));
    const float cardHeight = KindCardHeight(pictureHeight);
    // As many rows as fit without scrolling.
    const int rows = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().y + gap) / (cardHeight + gap)));
    const std::size_t shown = std::min(listed.size(), static_cast<std::size_t>(rows * grid.columns));
    for (std::size_t i = 0; i < shown; ++i) {
      if (i % static_cast<std::size_t>(grid.columns) != 0) {
        ImGui::SameLine(0.0f, gap);
      }
      std::string title;
      std::string size;
      int players = 0;
      std::uint64_t picture = 0;
      std::string disk;
      (void)mBrowser.MapCard(listed[i], title, size, players, picture, &disk);
      EdCardText text;
      text.title = title;
      text.meta = MapDisplayName(listed[i]);
      if (!size.empty()) {
        text.meta += " \xC2\xB7 " + size;
      }
      if (players > 0) {
        text.meta += " \xC2\xB7 " + std::to_string(players) + " players";
      }
      if (const double age = SecondsSinceChanged(disk); age >= 0.0) {
        text.third = WhenText(age);
      }
      ImGui::PushID(static_cast<int>(i));
      const EdCardResult card =
        KindCard("##recent", ImVec2(grid.cardWidth, cardHeight), pictureHeight, picture, "Map", 0x4EA1FFU, text);
      ImGui::PopID();
      if (card.hovered) {
        EdSetTooltip("%s", listed[i].c_str());
      }
      if (card.clicked) {
        gpg::Logf("editor: start screen: recent %s", listed[i].c_str());
        mBrowser.OpenListedMap(listed[i]);
      }
    }
  }

  void EdShell::DrawHomeVault(
    const bool loggedIn
  )
  {
    EdFafSession& faf = mBrowser.Faf();
    if (!mHomeVaultItems) {
      ImGui::TextDisabled("FAF vault items are hidden.");
      if (ImGui::Button("Show them")) {
        mHomeVaultItems = true;
      }
      return;
    }
    // Offline or signed out: each part one line with what to do.
    if (!loggedIn) {
      Subheading("Your uploads");
      if (faf.GetState() == EdFafSession::State::LoggedOut) {
        ImGui::TextDisabled("Sign in to FAF to see your maps in the vault.");
        if (ImGui::Button("Sign in")) {
          faf.StartLogin();
        }
      } else {
        ImGui::TextDisabled("Signing in to FAF... %s", faf.UserCode().c_str());
      }
      ImGui::Spacing();
      Subheading("Most played");
      ImGui::TextDisabled("Shown once you are signed in.");
      ImGui::Spacing();
      if (ImGui::Button("Hide vault items")) {
        mHomeVaultItems = false;
      }
      return;
    }
    if (!faf.UserName().empty() && !faf.NamedAsked(kUploads)) {
      faf.SearchNamed(kUploads, UploadsQuery(faf.UserName()));
    }
    if (!faf.NamedAsked(kPopular)) {
      faf.SearchNamed(kPopular, MostPlayedQuery());
    }
    const auto rowsOf = [this, &faf](const char* const name, const std::size_t max, const bool showPlays) {
      std::vector<VaultMap> maps;
      std::string error;
      if (!faf.NamedResults(name, maps, error)) {
        ImGui::TextDisabled("Loading...");
        return;
      }
      if (!error.empty()) {
        ImGui::TextDisabled("%s", error.c_str());
        ImGui::SameLine();
        if (ImGui::Button("Try again")) {
          faf.SearchNamed(name, std::string(name) == kUploads ? UploadsQuery(faf.UserName()) : MostPlayedQuery());
        }
        return;
      }
      if (maps.empty()) {
        ImGui::TextDisabled("None yet.");
        return;
      }
      const float thumb = Em(44.0f);
      for (std::size_t i = 0; i < maps.size() && i < max; ++i) {
        const VaultMap& map = maps[i];
        ImGui::PushID(name);
        ImGui::PushID(static_cast<int>(i));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const std::uint64_t picture = mBrowser.VaultThumbnail(map.thumbnail);
        ImDrawList* const dl = ImGui::GetWindowDrawList();
        if (picture != 0) {
          dl->AddImageRounded(
            static_cast<ImTextureID>(picture),
            at,
            ImVec2(at.x + thumb, at.y + thumb),
            ImVec2(0, 0),
            ImVec2(1, 1),
            IM_COL32_WHITE,
            Em(5.0f)
          );
        } else {
          dl->AddRectFilled(at, ImVec2(at.x + thumb, at.y + thumb), SurfaceU32(), Em(5.0f));
        }
        ImGui::SetCursorScreenPos(ImVec2(at.x + thumb + Em(10.0f), at.y));
        ImGui::BeginGroup();
        ImGui::TextUnformatted(map.name.c_str());
        const std::string here = mBrowser.ScenarioOfFolder(map.folder);
        if (showPlays) {
          ImGui::TextDisabled("%d players  %d games", map.players, map.gamesPlayed);
        } else {
          ImGui::TextDisabled(
            "%s  %d games%s", map.version.c_str(), map.gamesPlayed, here.empty() ? "" : "  on this computer"
          );
        }
        ImGui::EndGroup();
        // Open when it's here, else Download (which opens it once mounted).
        const char* const action = here.empty() ? "Download" : "Open";
        const float bw = ImGui::CalcTextSize(action).x + ImGui::GetStyle().FramePadding.x * 2.0f;
        ImGui::SetCursorScreenPos(ImVec2(at.x + ImGui::GetContentRegionAvail().x - bw, at.y + Em(8.0f)));
        if (ImGui::Button(action)) {
          gpg::Logf("editor: start screen: %s %s", action, map.folder.c_str());
          if (here.empty()) {
            mBrowser.Download(map.folder);
          } else {
            mBrowser.OpenListedMap(here);
          }
        }
        ImGui::SetCursorScreenPos(ImVec2(at.x, at.y + thumb + Em(8.0f)));
        ImGui::PopID();
        ImGui::PopID();
      }
    };
    Subheading("Your uploads");
    if (faf.UserName().empty()) {
      ImGui::TextDisabled("Loading...");
    } else {
      rowsOf(kUploads, 5, false);
    }
    ImGui::Spacing();
    Subheading("Most played");
    rowsOf(kPopular, 4, true);
    ImGui::Spacing();
    if (ImGui::Button("Hide vault items")) {
      mHomeVaultItems = false;
    }
  }

  void EdShell::DrawHomeSearch(
    const bool loggedIn
  )
  {
    const float gap = Em(14.0f);
    const float half = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;
    ImGui::BeginChild("##homelocal", ImVec2(half, -ImGui::GetFrameHeightWithSpacing()));
    Heading("On this computer");
    const std::vector<int> found = LocalMatches(mPlay.Titles(), mPlay.Maps(), mHomeSearch, 14);
    if (found.empty()) {
      ImGui::TextDisabled("No map here matches.");
    }
    for (const int index : found) {
      const std::string& scenario = mPlay.Maps()[static_cast<std::size_t>(index)];
      ImGui::PushID(index);
      if (ImGui::Selectable(mPlay.Titles()[static_cast<std::size_t>(index)].c_str(), false, 0, ImVec2(0.0f, 0.0f))) {
        gpg::Logf("editor: start screen: search opens %s", scenario.c_str());
        mBrowser.OpenListedMap(scenario);
      }
      ImGui::SameLine();
      ImGui::TextDisabled("%s", scenario.c_str());
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine(0.0f, gap);
    ImGui::BeginChild("##homevaultfound", ImVec2(0.0f, -ImGui::GetFrameHeightWithSpacing()));
    Heading("FAF vault");
    EdFafSession& faf = mBrowser.Faf();
    if (!mHomeVaultItems) {
      ImGui::TextDisabled("FAF vault items are hidden.");
    } else if (!loggedIn) {
      ImGui::TextDisabled("Sign in to search the vault here.");
      if (ImGui::Button("Sign in")) {
        faf.StartLogin();
      }
    } else {
      // The search runs once the typing stops for a moment.
      if (mHomeSearchAsked != mHomeSearch && ImGui::GetTime() - mHomeTypedAt > 0.4) {
        mHomeSearchAsked = mHomeSearch;
        faf.SearchNamed(kTyped, TypedQuery(mHomeSearchAsked));
      }
      std::vector<VaultMap> maps;
      std::string error;
      if (!faf.NamedResults(kTyped, maps, error)) {
        ImGui::TextDisabled("Searching...");
      } else if (!error.empty()) {
        ImGui::TextDisabled("%s", error.c_str());
      } else if (maps.empty()) {
        ImGui::TextDisabled("No vault map matches.");
      }
      for (std::size_t i = 0; i < maps.size() && i < 14; ++i) {
        ImGui::PushID(static_cast<int>(i));
        ImGui::TextUnformatted(maps[i].name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s  %d players", maps[i].author.c_str(), maps[i].players);
        ImGui::PopID();
      }
    }
    ImGui::EndChild();
    ImGui::TextDisabled("Enter: the FAF vault page with these words.");
  }
} // namespace faf::editor
