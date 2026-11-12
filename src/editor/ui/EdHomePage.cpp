// The start screen, "Home" (design §8 Files): EdShell's members that draw it.

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdFafApi.h"
#include "editor/EdPlay.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdHomeModel.h"
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

    /** A section's heading in the accent's colour. */
    void Heading(
      const char* const text
    )
    {
      ImGui::PushStyleColor(ImGuiCol_Text, AccentColor());
      ImGui::TextUnformatted(text);
      ImGui::PopStyleColor();
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
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(18.0f), Em(14.0f)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    // Opaque: the panels behind mustn't show through a theme's see-through window colour.
    ImVec4 ground = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
    ground.w = 1.0f;
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ground);
    const bool shown = ImGui::Begin("Start###Home", nullptr, kFlags);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);
    if (shown) {
      // Over the panels whatever gets the focus behind it.
      ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());

      // The left column: the pages, then Recover, Tour and Help, the open map's Continue, and the switch.
      ImGui::BeginChild("##homeleft", ImVec2(Em(220.0f), 0.0f));
      ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.3f);
      ImGui::TextUnformatted("FAF Map Editor");
      ImGui::PopFont();
      ImGui::Spacing();
      static constexpr const char* kPages[] = {"Home", "On this computer", "FAF vault"};
      for (int i = 0; i < 3; ++i) {
        if (ImGui::Selectable(kPages[i], mHomePage == i, ImGuiSelectableFlags_None, ImVec2(0.0f, Em(30.0f)))) {
          mHomePage = i;
        }
      }
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::Spacing();
      // What these run says why it can't yet (autosave, the tour and the help topics come later).
      for (const auto& [command, label] :
           {std::pair<const char*, const char*>{"file.recover", "Recover an autosaved map"},
            {"help.tour", "Tour"},
            {"help.open", "Help"}}) {
        const std::string why = mCommands != nullptr ? mCommands->WhyNot(command) : std::string("no commands");
        ImGui::BeginDisabled(!why.empty());
        if (ImGui::Selectable(label, false, ImGuiSelectableFlags_None, ImVec2(0.0f, Em(26.0f))) && mCommands) {
          (void)mCommands->Run(command);
        }
        ImGui::EndDisabled();
        if (!why.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          ImGui::SetTooltip(
            "Not yet: %s", why == "no such command" ? "it comes with a later part of the editor" : why.c_str()
          );
        }
      }
      // The open map: back to it.
      const float footer = ImGui::GetFrameHeightWithSpacing() * 1.2f;
      if (mDocument.GetState() == EdDocument::State::Open) {
        const float cardHeight = Em(64.0f);
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - footer - cardHeight - Em(10.0f));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const float width = ImGui::GetContentRegionAvail().x;
        if (ImGui::InvisibleButton("##continue", ImVec2(width, cardHeight))) {
          mShowHome = false;
        }
        ImDrawList* const dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(
          at, ImVec2(at.x + width, at.y + cardHeight), ImGui::IsItemHovered() ? SurfaceHotU32() : SurfaceU32(), Em(8.0f)
        );
        std::string title = mDocument.FolderName();
        std::string size;
        int players = 0;
        std::uint64_t picture = 0;
        (void)mBrowser.MapCard(mDocument.Path(), title, size, players, picture);
        const float pic = cardHeight - Em(12.0f);
        if (picture != 0) {
          dl->AddImageRounded(
            static_cast<ImTextureID>(picture),
            ImVec2(at.x + Em(6.0f), at.y + Em(6.0f)),
            ImVec2(at.x + Em(6.0f) + pic, at.y + Em(6.0f) + pic),
            ImVec2(0, 0),
            ImVec2(1, 1),
            IM_COL32_WHITE,
            Em(5.0f)
          );
        }
        const float tx = at.x + Em(14.0f) + pic;
        dl->AddText(ImVec2(tx, at.y + Em(10.0f)), InkDimU32(), "Continue");
        dl->PushClipRect(at, ImVec2(at.x + width - Em(6.0f), at.y + cardHeight), true);
        dl->AddText(ImVec2(tx, at.y + Em(10.0f) + ImGui::GetTextLineHeightWithSpacing()), InkU32(), title.c_str());
        dl->PopClipRect();
      }
      ImGui::SetCursorPosY(ImGui::GetWindowHeight() - footer);
      ImGui::Checkbox("Show this screen at start", &mHomeAtStart);
      ImGui::EndChild();

      ImGui::SameLine(0.0f, Em(18.0f));
      ImGui::BeginChild("##homepage", ImVec2(0.0f, 0.0f));
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
    const float gap = Em(14.0f);
    EdFafSession& faf = mBrowser.Faf();
    const bool loggedIn = faf.GetState() == EdFafSession::State::LoggedIn;

    // One search over your maps and the vault: typing shows both lists, Enter the vault page with the words.
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(12.0f), Em(9.0f)));
    // The keyboard goes to the search when the screen opens: typing searches at once.
    if (std::exchange(mHomeFocusSearch, false)) {
      ImGui::SetKeyboardFocusHere();
    }
    if (
      ImGui::InputTextWithHint("##homesearch", "Search your maps and the FAF vault", mHomeSearch, sizeof(mHomeSearch))
    ) {
      mHomeTypedAt = ImGui::GetTime();
    }
    const bool enter = ImGui::IsItemDeactivated() && ImGui::IsKeyPressed(ImGuiKey_Enter);
    ImGui::PopStyleVar();
    if (enter && mHomeSearch[0] != 0) {
      gpg::Logf("editor: start screen: the vault page for \"%s\"", mHomeSearch);
      mBrowser.AskSearch(mHomeSearch);
      mBrowser.Open() = false;
      (void)mBrowser.TakeSelectVault();
      mHomePage = 2;
      return;
    }
    ImGui::Spacing();
    if (mHomeSearch[0] != 0) {
      DrawHomeSearch(loggedIn);
      return;
    }

    // New: every kind the editor makes, as same-size cards.
    Heading("New");
    const std::vector<EdNewKind>& kinds = NewKinds();
    const EdCardGrid newGrid =
      CardGrid(ImGui::GetContentRegionAvail().x, Em(150.0f), gap, static_cast<int>(kinds.size()));
    const float newHeight = Em(70.0f);
    for (std::size_t i = 0; i < kinds.size(); ++i) {
      const EdNewKind& kind = kinds[i];
      if (i % static_cast<std::size_t>(newGrid.columns) != 0) {
        ImGui::SameLine(0.0f, gap);
      }
      const std::string why = mCommands != nullptr ? mCommands->WhyNot(kind.command) : std::string("no commands");
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImGui::PushID(kind.command);
      const bool clicked = ImGui::InvisibleButton("##new", ImVec2(newGrid.cardWidth, newHeight));
      const bool hovered = ImGui::IsItemHovered();
      ImGui::PopID();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 to(at.x + newGrid.cardWidth, at.y + newHeight);
      dl->AddRectFilled(at, to, hovered && why.empty() ? SurfaceHotU32() : SurfaceU32(), Em(8.0f));
      dl->AddRectFilled(
        at, ImVec2(at.x + Em(4.0f), to.y), why.empty() ? AccentU32() : LineU32(), Em(8.0f), ImDrawFlags_RoundCornersLeft
      );
      ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.15f);
      dl->AddText(ImVec2(at.x + Em(14.0f), at.y + Em(10.0f)), why.empty() ? InkU32() : InkDimU32(), kind.title);
      ImGui::PopFont();
      dl->PushClipRect(at, to, true);
      dl->AddText(
        nullptr,
        0.0f,
        ImVec2(at.x + Em(14.0f), at.y + Em(34.0f)),
        InkDimU32(),
        kind.about,
        nullptr,
        newGrid.cardWidth - Em(22.0f)
      );
      dl->PopClipRect();
      if (hovered && !why.empty()) {
        ImGui::SetTooltip("Not yet: %s", why.c_str());
      }
      if (clicked && why.empty() && mCommands != nullptr) {
        gpg::Logf("editor: start screen: New %s", kind.title);
        (void)mCommands->Run(kind.command);
      }
    }
    ImGui::Spacing();
    ImGui::Spacing();

    // Recent at the left; the vault's rows at the right.
    const float side = std::min(Em(380.0f), ImGui::GetContentRegionAvail().x * 0.38f);
    ImGui::BeginChild("##homerecent", ImVec2(ImGui::GetContentRegionAvail().x - side - gap, 0.0f));
    DrawHomeRecent();
    ImGui::EndChild();
    ImGui::SameLine(0.0f, gap);
    ImGui::BeginChild("##homevault", ImVec2(0.0f, 0.0f));
    DrawHomeVault(loggedIn);
    ImGui::EndChild();
  }

  void EdShell::DrawHomeRecent()
  {
    const float gap = Em(14.0f);
    Heading("Recent");
    // Only maps are kept as recent work so far: their chip, with the count.
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
    ImGui::SameLine(0.0f, Em(12.0f));
    char chip[32];
    (void)std::snprintf(chip, sizeof(chip), "Maps  %zu", listed.size());
    ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_Header));
    ImGui::SmallButton(chip);
    ImGui::PopStyleColor();
    if (listed.empty()) {
      ImGui::TextDisabled("Maps you open show here.");
      return;
    }
    const EdCardGrid grid = CardGrid(ImGui::GetContentRegionAvail().x, Em(190.0f), gap, 5);
    const float pictureHeight = std::min(grid.cardWidth * 0.56f, Em(150.0f));
    const float cardHeight = pictureHeight + ImGui::GetTextLineHeightWithSpacing() * 2.0f + Em(16.0f);
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
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImGui::PushID(static_cast<int>(i));
      const bool clicked = ImGui::InvisibleButton("##recent", ImVec2(grid.cardWidth, cardHeight));
      const bool hovered = ImGui::IsItemHovered();
      ImGui::PopID();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 to(at.x + grid.cardWidth, at.y + cardHeight);
      dl->AddRectFilled(at, to, hovered ? SurfaceHotU32() : SurfaceU32(), Em(8.0f));
      // The terrain's picture, its middle across the card's width.
      const ImVec2 p0(at.x + Em(6.0f), at.y + Em(6.0f));
      const ImVec2 p1(to.x - Em(6.0f), at.y + Em(6.0f) + pictureHeight - Em(6.0f));
      if (picture != 0) {
        const float aspect = (p1.y - p0.y) / std::max(1.0f, p1.x - p0.x);
        const float v0 = 0.5f - aspect * 0.5f;
        dl->AddImageRounded(
          static_cast<ImTextureID>(picture),
          p0,
          p1,
          ImVec2(0.0f, v0),
          ImVec2(1.0f, v0 + aspect),
          IM_COL32_WHITE,
          Em(6.0f)
        );
      } else {
        dl->AddRectFilled(p0, p1, ChipU32(), Em(6.0f));
      }
      dl->PushClipRect(at, ImVec2(to.x - Em(8.0f), to.y), true);
      const float line = ImGui::GetTextLineHeightWithSpacing();
      dl->AddText(ImVec2(at.x + Em(10.0f), p1.y + Em(6.0f)), InkU32(), title.c_str());
      const double age = SecondsSinceChanged(disk);
      const std::string detail = "Map  " + size + (players > 0 ? "  " + std::to_string(players) + " players" : "") +
        (age >= 0.0 ? "  changed " + WhenText(age) : "");
      dl->AddText(ImVec2(at.x + Em(10.0f), p1.y + Em(6.0f) + line), InkDimU32(), detail.c_str());
      dl->PopClipRect();
      if (hovered) {
        ImGui::SetTooltip("%s", listed[i].c_str());
      }
      if (clicked) {
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
      if (ImGui::SmallButton("Show them")) {
        mHomeVaultItems = true;
      }
      return;
    }
    // Offline or signed out: each part one line with what to do.
    if (!loggedIn) {
      Heading("Your uploads");
      if (faf.GetState() == EdFafSession::State::LoggedOut) {
        ImGui::TextDisabled("Sign in to FAF to see your maps in the vault.");
        if (ImGui::Button("Sign in")) {
          faf.StartLogin();
        }
      } else {
        ImGui::TextDisabled("Signing in to FAF... %s", faf.UserCode().c_str());
      }
      ImGui::Spacing();
      Heading("Most played");
      ImGui::TextDisabled("Shown once you are signed in.");
      ImGui::Spacing();
      if (ImGui::SmallButton("Hide vault items")) {
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
        if (ImGui::SmallButton("Try again")) {
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
        if (ImGui::SmallButton(action)) {
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
    Heading("Your uploads");
    if (faf.UserName().empty()) {
      ImGui::TextDisabled("Loading...");
    } else {
      rowsOf(kUploads, 5, false);
    }
    ImGui::Spacing();
    Heading("Most played");
    rowsOf(kPopular, 4, true);
    ImGui::Spacing();
    if (ImGui::SmallButton("Hide vault items")) {
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
