#include "editor/ui/EdTexturePicker.h"

#include "editor/tools/EdTextureLibrary.h"
#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <utility>

namespace faf::editor
{
  namespace
  {
    std::string Lower(std::string text)
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return text;
    }

    std::string FolderOf(const std::string& path)
    {
      const std::size_t slash = path.find_last_of("/\\");
      return slash == std::string::npos ? std::string() : path.substr(0, slash);
    }

    std::string NameOf(const std::string& path)
    {
      std::string name = path.substr(path.find_last_of("/\\") + 1);
      if (const std::size_t dot = name.rfind('.'); dot != std::string::npos) {
        name.erase(dot);
      }
      return name;
    }

    /** The picture, over a dark ground for one with alpha (a particle's shape shows as it would at night). */
    void Picture(EdTextureLibrary& library, const std::string& path, const bool withAlpha, const float size)
    {
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImDrawList* dl = ImGui::GetWindowDrawList();
      dl->AddRectFilled(at, ImVec2(at.x + size, at.y + size), withAlpha ? IM_COL32(12, 12, 16, 255) : IM_COL32(40, 40, 44, 255), 3.0f);
      if (const std::uint64_t image = path.empty() ? 0 : library.Thumbnail(path, withAlpha); image != 0) {
        dl->AddImage(ImTextureRef(static_cast<ImTextureID>(image)), at, ImVec2(at.x + size, at.y + size));
      } else if (path.empty()) {
        dl->AddText(ImVec2(at.x + 6.0f, at.y + size * 0.5f - 7.0f), IM_COL32(150, 150, 150, 255), "(none)");
      }
      ImGui::Dummy(ImVec2(size, size));
    }
  } // namespace

  bool EdTexturePicker::Field(const char* const id, std::string& path, const std::vector<std::string>& choices, EdTextureLibrary& library,
                              const bool withAlpha)
  {
    bool picked = false;
    ImGui::PushID(id);
    // The field: picture and name, one button.
    const float side = ImGui::GetFrameHeight() * 2.0f;
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const float width = std::max(ImGui::GetContentRegionAvail().x, 160.0f);
    if (ImGui::Button("##field", ImVec2(width, side + ImGui::GetStyle().FramePadding.y * 2.0f)) || std::exchange(mOpenAsk, false)) {
      ImGui::OpenPopup("Pick a texture");
    }
    ImGui::SetItemTooltip("%s\nClick to browse the textures", path.empty() ? "(none)" : path.c_str());
    {
      ImDrawList* dl = ImGui::GetWindowDrawList();
      const float pad = ImGui::GetStyle().FramePadding.y;
      const ImVec2 a(start.x + pad, start.y + pad);
      dl->AddRectFilled(a, ImVec2(a.x + side, a.y + side), withAlpha ? IM_COL32(12, 12, 16, 255) : IM_COL32(40, 40, 44, 255), 2.0f);
      if (const std::uint64_t image = path.empty() ? 0 : library.Thumbnail(path, withAlpha); image != 0) {
        dl->AddImage(ImTextureRef(static_cast<ImTextureID>(image)), a, ImVec2(a.x + side, a.y + side));
      }
      const std::string name = path.empty() ? std::string("(none)") : NameOf(path);
      const float textY = start.y + pad + side * 0.5f - ImGui::GetTextLineHeight();
      dl->AddText(ImVec2(a.x + side + 8.0f, textY), ImGui::GetColorU32(ImGuiCol_Text), name.c_str());
      dl->AddText(ImVec2(a.x + side + 8.0f, textY + ImGui::GetTextLineHeight()), ImGui::GetColorU32(ImGuiCol_TextDisabled), "Browse...");
    }

    // The browser: most of the screen, a grid of pictures.
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.6f, viewport->WorkSize.y * 0.7f), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    bool open = true;
    if (ImGui::BeginPopupModal("Pick a texture", &open)) {
      if (mFoldersFor != choices.size()) {
        mFoldersFor = choices.size();
        mFolders.clear();
        for (const std::string& choice : choices) {
          const std::string folder = FolderOf(choice);
          if (std::find(mFolders.begin(), mFolders.end(), folder) == mFolders.end()) {
            mFolders.push_back(folder);
          }
        }
        std::sort(mFolders.begin(), mFolders.end());
        mFolder = 0;
      }
      if (ImGui::IsWindowAppearing()) {
        ImGui::SetKeyboardFocusHere();
      }
      ImGui::SetNextItemWidth(260.0f);
      ImGui::InputTextWithHint("##search", "Search names", mSearch, sizeof(mSearch));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(260.0f);
      if (ImGui::BeginCombo("##folder", mFolder == 0 ? "All folders" : mFolders[static_cast<std::size_t>(mFolder - 1)].c_str(),
                            ImGuiComboFlags_HeightLarge)) {
        if (ImGui::Selectable("All folders", mFolder == 0)) {
          mFolder = 0;
        }
        for (std::size_t f = 0; f < mFolders.size(); ++f) {
          if (ImGui::Selectable(mFolders[f].c_str(), mFolder == static_cast<int>(f) + 1)) {
            mFolder = static_cast<int>(f) + 1;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SameLine();
      ImGui::SetNextItemWidth(140.0f);
      ImGui::SliderFloat("##tile", &mTile, 64.0f, 192.0f, "tiles %.0f px");
      ImGui::SameLine();
      if (ImGui::Button("None")) {
        picked = !path.empty();
        path.clear();
        ImGui::CloseCurrentPopup();
      }
      ImGui::SetItemTooltip("No texture");

      const std::string search = Lower(mSearch);
      const std::string folder = mFolder == 0 ? std::string() : mFolders[static_cast<std::size_t>(mFolder - 1)];
      std::vector<const std::string*> shown;
      for (const std::string& choice : choices) {
        if ((!folder.empty() && FolderOf(choice) != folder) || (!search.empty() && Lower(NameOf(choice)).find(search) == std::string::npos)) {
          continue;
        }
        shown.push_back(&choice);
      }
      ImGui::TextDisabled("%zu of %zu textures%s", shown.size(), choices.size(), path.empty() ? "" : (", picked: " + path).c_str());
      if (ImGui::BeginChild("##grid", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        const float pad = ImGui::GetStyle().ItemSpacing.x;
        const int columns = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + pad) / (mTile + pad)));
        const int rows = (static_cast<int>(shown.size()) + columns - 1) / columns;
        const float rowHeight = mTile + ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y + 4.0f;
        ImGuiListClipper clipper;
        clipper.Begin(rows, rowHeight);
        while (clipper.Step()) {
          for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            for (int column = 0; column < columns; ++column) {
              const int index = row * columns + column;
              if (index >= static_cast<int>(shown.size())) {
                break;
              }
              const std::string& choice = *shown[static_cast<std::size_t>(index)];
              if (column > 0) {
                ImGui::SameLine();
              }
              ImGui::PushID(index);
              ImGui::BeginGroup();
              const ImVec2 at = ImGui::GetCursorScreenPos();
              const bool clicked = ImGui::InvisibleButton("##tile", ImVec2(mTile, mTile));
              const bool hovered = ImGui::IsItemHovered();
              ImGui::SetCursorScreenPos(at);
              Picture(library, choice, withAlpha, mTile);
              const bool current = Lower(choice) == Lower(path);
              ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + mTile, at.y + mTile),
                                                  current ? IM_COL32(250, 200, 80, 255) : hovered ? IM_COL32(220, 220, 220, 255) : IM_COL32(50, 50, 56, 255),
                                                  3.0f, 0, current ? 2.5f : 1.0f);
              // The name, cut to the tile.
              std::string name = NameOf(choice);
              while (name.size() > 3 && ImGui::CalcTextSize(name.c_str()).x > mTile) {
                name.erase(name.size() - 4);
                name += "..";
              }
              ImGui::TextUnformatted(name.c_str());
              ImGui::EndGroup();
              if (hovered) {
                ImGui::BeginTooltip();
                Picture(library, choice, withAlpha, 256.0f);
                ImGui::TextUnformatted(choice.c_str());
                ImGui::EndTooltip();
              }
              if (clicked) {
                picked = Lower(choice) != Lower(path);
                path = choice;
                ImGui::CloseCurrentPopup();
              }
              ImGui::PopID();
            }
          }
        }
        library.Pump(12);
      }
      ImGui::EndChild();
      ImGui::EndPopup();
    }
    ImGui::PopID();
    return picked;
  }
} // namespace faf::editor
