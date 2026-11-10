#include "editor/ui/EdMapBrowser.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>

#include <Windows.h>
#include <shellapi.h>

#include "editor/EdPlay.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdLuaText.h"
#include "editor/doc/EdMapFile.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "legacy/containers/String.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"

namespace faf::editor
{
  namespace
  {
    constexpr int kPicture = 96;
    const char* const kWhereNames[] = {"Everywhere", "The game's folder", "FAF's ProgramData folder", "Your vault", "Other folders"};

    std::string Lower(std::string text)
    {
      for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      std::replace(text.begin(), text.end(), '\\', '/');
      return text;
    }

    std::string Unquote(const std::string& atom)
    {
      if (atom.size() >= 2 && (atom.front() == '\'' || atom.front() == '"') && atom.back() == atom.front()) {
        return atom.substr(1, atom.size() - 2);
      }
      return atom;
    }

    /** The preview image (a DDS) inside a `.scmap`'s preview record, or empty. */
    std::string PreviewImage(const std::vector<char>& record)
    {
      // 0xBEEFFEED, version, width, height; the name in UTF-16 up to a 0; tag count and tags; payload size; payload.
      std::size_t at = 16;
      while (at + 1 < record.size() && !(record[at] == 0 && record[at + 1] == 0)) {
        at += 2;
      }
      at += 2;
      if (at + 4 > record.size()) {
        return {};
      }
      std::uint32_t tags = 0;
      std::memcpy(&tags, record.data() + at, 4);
      at += 4 + static_cast<std::size_t>(tags) * 8;
      if (at + 4 > record.size()) {
        return {};
      }
      std::uint32_t payload = 0;
      std::memcpy(&payload, record.data() + at, 4);
      at += 4;
      if (at + payload > record.size()) {
        return {};
      }
      return std::string(record.data() + at, payload);
    }
  } // namespace

  EdMapBrowser::EdMapBrowser(EdPlay& play, EdDocument& document)
    : mPlay(play)
    , mDocument(document)
  {}

  EdMapBrowser::~EdMapBrowser()
  {
    for (auto& [scenario, details] : mDetails) {
      if (details.picture != 0) {
        EdImGuiRenderer::DestroyImage(details.picture);
      }
    }
  }

  EdMapBrowser::Details& EdMapBrowser::DetailsOf(const std::string& scenario)
  {
    Details& details = mDetails[scenario];
    if (!details.read && mReadsThisFrame < 12) {
      ++mReadsThisFrame;
      ReadDetails(scenario, details);
    }
    if (details.read && !details.pictureAsked && !details.scmap.empty() && mPicturesThisFrame < 2) {
      ++mPicturesThisFrame;
      MakePicture(details);
    }
    return details;
  }

  void EdMapBrowser::ReadDetails(const std::string& scenario, Details& details)
  {
    details.read = true;
    // Where it is on disk, which says whose it is.
    if (moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS(); vfs != nullptr) {
      fa::string disk;
      if (vfs->FindFile(&disk, scenario.c_str(), nullptr) != nullptr) {
        details.disk = disk.c_str();
      }
    }
    const std::string disk = Lower(details.disk);
    const std::string vault = Lower(mDocument.VaultFolder().generic_string());
    if (disk.find("/programdata/faforever/") != std::string::npos) {
      details.where = kWhereNames[2];
    } else if (!vault.empty() && disk.rfind(vault, 0) == 0) {
      details.where = kWhereNames[3];
    } else if (disk.find("/supreme commander forged alliance/maps/") != std::string::npos || disk.find(".scd") != std::string::npos) {
      details.where = kWhereNames[1];
    } else {
      details.where = kWhereNames[4];
    }
    std::string text;
    LuaText info;
    std::string error;
    if (!ReadGameFile(scenario, text) || !ReadLuaAssignment(text, "ScenarioInfo", info, error)) {
      return;
    }
    if (const LuaText* const name = info.Field("name")) {
      details.title = Unquote(name->atom);
    }
    if (const LuaText* const size = info.Field("size"); size != nullptr && size->items.size() >= 2) {
      char text2[48];
      (void)std::snprintf(text2, sizeof(text2), "%g x %g km", std::round(size->items[0].Number() / 51.2 * 10.0) / 10.0,
                          std::round(size->items[1].Number() / 51.2 * 10.0) / 10.0);
      details.size = text2;
    }
    if (const LuaText* const version = info.Field("map_version")) {
      details.version = version->atom;
    }
    if (const LuaText* const map = info.Field("map")) {
      details.scmap = Unquote(map->atom);
    }
    if (const LuaText* const configurations = info.Field("Configurations")) {
      if (const LuaText* const standard = configurations->Field("standard")) {
        if (const LuaText* const teams = standard->Field("teams"); teams != nullptr && !teams->items.empty()) {
          if (const LuaText* const armies = teams->items.front().Field("armies")) {
            details.players = static_cast<int>(armies->items.size());
          }
        }
      }
    }
  }

  void EdMapBrowser::MakePicture(Details& details)
  {
    details.pictureAsked = true;
    gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
    const std::string image = codec != nullptr ? PreviewImage(ReadPreviewRecord(details.scmap)) : std::string();
    if (image.empty()) {
      return;
    }
    gpg::gal::imaging::DecodeOptions options;
    options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    options.width = kPicture;
    options.height = kPicture;
    options.mipLevels = 1;
    gpg::gal::imaging::Image decoded;
    if (FAILED(codec->Decode(image.data(), image.size(), options, decoded)) || decoded.subresources.empty() ||
        decoded.format != DXGI_FORMAT_B8G8R8A8_UNORM) {
      return;
    }
    const auto& level = decoded.subresources.front();
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(level.width) * level.height);
    for (std::uint32_t y = 0; y < level.height; ++y) {
      for (std::uint32_t x = 0; x < level.width; ++x) {
        std::uint32_t pixel = 0;
        std::memcpy(&pixel, decoded.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch + x * 4U, 4U);
        pixels[static_cast<std::size_t>(y) * level.width + x] = pixel | 0xFF000000u;
      }
    }
    details.picture = EdImGuiRenderer::CreateImage(static_cast<int>(level.width), static_cast<int>(level.height), pixels.data());
  }

  std::string EdMapBrowser::ListedScenario(const std::string& folder) const
  {
    const std::string prefix = "/maps/" + Lower(folder) + "/";
    for (const std::string& scenario : mPlay.Maps()) {
      if (Lower(scenario).rfind(prefix, 0) == 0) {
        return scenario;
      }
    }
    return {};
  }

  void EdMapBrowser::OpenMap(const std::string& scenario)
  {
    const std::vector<std::string>& maps = mPlay.Maps();
    for (int i = 0; i < static_cast<int>(maps.size()); ++i) {
      if (Lower(maps[static_cast<std::size_t>(i)]) == Lower(scenario)) {
        mPlay.Select(i);
        break;
      }
    }
    if (mDocument.GetState() != EdDocument::State::Loading) {
      (void)mDocument.Open(scenario);
    }
  }

  void EdMapBrowser::SetFilter(const std::string& text)
  {
    (void)std::snprintf(mFilter, sizeof(mFilter), "%s", text.c_str());
  }

  void EdMapBrowser::Download(const std::string& name)
  {
    VaultMapName map;
    std::string error;
    if (!ParseVaultMapName(name, map, error)) {
      mStatus = error;
      gpg::Warnf("editor: vault: %s", error.c_str());
      return;
    }
    // Already listed: open it. On disk but not mounted (downloaded earlier, the game not restarted): mount it.
    if (const std::string listed = ListedScenario(map.folder); !listed.empty()) {
      mStatus = map.folder + " is already here; opened";
      gpg::Logf("editor: vault: %s is already in /maps; opening %s", map.folder.c_str(), listed.c_str());
      OpenMap(listed);
      return;
    }
    const std::filesystem::path maps = mDocument.VaultFolder() / "maps";
    if (mDownload.Start(map, maps)) {
      mStatus.clear();
      gpg::Logf("editor: vault: downloading %s into %s", map.url.c_str(), maps.string().c_str());
    }
  }

  void EdMapBrowser::Update()
  {
    mReadsThisFrame = 0;
    mPicturesThisFrame = 0;
    if (mDownload.GetState() == EdVaultDownload::State::Failed) {
      mStatus = mDownload.Message();
      gpg::Warnf("editor: vault: %s", mStatus.c_str());
      mDownload.Reset();
    } else if (mDownload.GetState() == EdVaultDownload::State::Done) {
      const VaultMapName map = mDownload.Map();
      mStatus = mDownload.Message();
      mDownload.Reset();
      gpg::Logf("editor: vault: %s", mStatus.c_str());
      // Mounted as init_faf.lua mounts a vault map, so the game (and Play) finds it now, not only after a restart.
      if (!moho::DISK_MountDirectoryNow(mDownload.Folder(), ("/maps/" + map.folder).c_str())) {
        mStatus += "; the game lists it from its next start";
        return;
      }
      mPlay.FindMaps();
      const std::string scenario = ListedScenario(map.folder);
      if (scenario.empty()) {
        mStatus += "; but the game doesn't list it (see the log)";
        gpg::Warnf("editor: vault: %s mounted, but no _scenario.lua in /maps/%s", map.folder.c_str(), map.folder.c_str());
        return;
      }
      gpg::Logf("editor: vault: %s mounted; opening %s", map.folder.c_str(), scenario.c_str());
      OpenMap(scenario);
    }
  }

  void EdMapBrowser::Draw()
  {
    if (!mOpen) {
      return;
    }
    // Half the window wide, two thirds high, in its middle (pixels: a fixed size is small on a 4K screen).
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x * 0.5f, viewport->Size.y * 0.66f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x + viewport->Size.x * 0.5f, viewport->Pos.y + viewport->Size.y * 0.5f), ImGuiCond_FirstUseEver,
                            ImVec2(0.5f, 0.5f));
    if (!ImGui::Begin(kWindowName, &mOpen, ImGuiWindowFlags_NoDocking)) {
      ImGui::End();
      return;
    }
    if (ImGui::BeginTabBar("##browsertabs")) {
      if (ImGui::BeginTabItem("On this computer")) {
        DrawLocal();
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("FAF vault")) {
        DrawVault();
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }
    ImGui::End();
  }

  void EdMapBrowser::DrawLocal()
  {
    const std::vector<std::string>& maps = mPlay.Maps();
    const std::vector<std::string>& titles = mPlay.Titles();
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.55f);
    ImGui::InputTextWithHint("##browserfilter", "Filter by name or folder", mFilter, sizeof(mFilter));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::Combo("##where", &mWhere, kWhereNames, 5);

    // The rows that pass the filter (where a map is shows once its details are read).
    std::vector<int> rows;
    for (int i = 0; i < static_cast<int>(maps.size()); ++i) {
      const std::size_t at = static_cast<std::size_t>(i);
      if (mFilter[0] != '\0' && ImStristr(titles[at].c_str(), nullptr, mFilter, nullptr) == nullptr &&
          ImStristr(maps[at].c_str(), nullptr, mFilter, nullptr) == nullptr) {
        continue;
      }
      if (mWhere != 0) {
        const auto found = mDetails.find(maps[at]);
        if (found == mDetails.end() || !found->second.read) {
          (void)DetailsOf(maps[at]);
          continue;
        }
        if (found->second.where != kWhereNames[mWhere]) {
          continue;
        }
      }
      rows.push_back(i);
    }
    ImGui::TextDisabled("%zu of %zu maps; double-click one to open it for editing", rows.size(), maps.size());

    const float picture = ImGui::GetTextLineHeight() * 3.6f;
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##maplist", 5, flags)) {
      ImGui::TableSetupScrollFreeze(0, 1);
      ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, picture);
      ImGui::TableSetupColumn("Map", ImGuiTableColumnFlags_WidthStretch, 3.0f);
      ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 1.0f);
      ImGui::TableSetupColumn("Players", ImGuiTableColumnFlags_WidthStretch, 0.7f);
      ImGui::TableSetupColumn("Where", ImGuiTableColumnFlags_WidthStretch, 1.6f);
      ImGui::TableHeadersRow();
      ImGuiListClipper clipper;
      clipper.Begin(static_cast<int>(rows.size()), picture + ImGui::GetStyle().CellPadding.y * 2.0f);
      while (clipper.Step()) {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
          const int index = rows[static_cast<std::size_t>(r)];
          const std::size_t at = static_cast<std::size_t>(index);
          const std::string& scenario = maps[at];
          Details& details = DetailsOf(scenario);
          ImGui::PushID(index);
          ImGui::TableNextRow(0, picture);
          ImGui::TableNextColumn();
          const bool current = mDocument.GetState() == EdDocument::State::Open && Lower(mDocument.Path()) == Lower(scenario);
          if (ImGui::Selectable("##row", current, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick,
                                ImVec2(0.0f, picture)) &&
              ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            OpenMap(scenario);
          }
          if (ImGui::IsItemHovered() && !details.disk.empty()) {
            ImGui::SetTooltip("%s\n%s\nDouble-click to open for editing", scenario.c_str(), details.disk.c_str());
          }
          if (ImGui::BeginPopupContextItem("##rowmenu")) {
            if (ImGui::MenuItem("Open for editing")) {
              OpenMap(scenario);
            }
            if (ImGui::MenuItem("Pick for Play")) {
              mPlay.Select(index);
            }
            ImGui::BeginDisabled(details.disk.empty());
            if (ImGui::MenuItem("Show its folder")) {
              const std::filesystem::path folder = std::filesystem::u8path(details.disk).parent_path();
              (void)::ShellExecuteW(nullptr, L"open", folder.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            ImGui::EndDisabled();
            ImGui::EndPopup();
          }
          ImGui::SameLine(0.0f, 0.0f);
          if (details.picture != 0) {
            ImGui::Image(static_cast<ImTextureID>(details.picture), ImVec2(picture, picture));
          } else {
            ImGui::Dummy(ImVec2(picture, picture));
          }
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(titles[at].c_str());
          ImGui::TextDisabled("%s", MapDisplayName(scenario).c_str());
          if (!details.version.empty()) {
            ImGui::TextDisabled("version %s", details.version.c_str());
          }
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(details.size.c_str());
          ImGui::TableNextColumn();
          if (details.players > 0) {
            ImGui::Text("%d", details.players);
          }
          ImGui::TableNextColumn();
          ImGui::TextWrapped("%s", details.where.c_str());
          ImGui::PopID();
        }
      }
      ImGui::EndTable();
    }
  }

  void EdMapBrowser::DrawVault()
  {
    const bool working = mDownload.GetState() == EdVaultDownload::State::Working;
    ImGui::TextWrapped("A map from the FAF vault: its folder name (dualgap_adaptive.v0012) or its download link. It goes into "
                       "your vault's maps folder, the game lists it at once, and it opens for editing.");
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.7f);
    const bool entered = ImGui::InputTextWithHint("##vaultname", "map folder name or download link", mVaultName, sizeof(mVaultName),
                                                  ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(working || mVaultName[0] == '\0');
    if (ImGui::Button("Download and open") || (entered && !working && mVaultName[0] != '\0')) {
      Download(mVaultName);
    }
    ImGui::EndDisabled();
    if (working) {
      ImGui::Text("%s: %.1f MB", mDownload.Message().c_str(), static_cast<double>(mDownload.Received()) / 1048576.0);
    } else if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }
    ImGui::TextDisabled("Downloads go to %s", (mDocument.VaultFolder() / "maps").string().c_str());
    ImGui::Separator();
    ImGui::TextWrapped("Searching the vault from here needs a FAF login, which the editor doesn't have yet. Meanwhile, find a "
                       "map on the FAF website and paste its name or download link above.");
    if (ImGui::Button("Open the FAF map vault in the browser")) {
      (void)::ShellExecuteW(nullptr, L"open", L"https://www.faforever.com/vault/maps", nullptr, nullptr, SW_SHOWNORMAL);
    }
  }
} // namespace faf::editor
