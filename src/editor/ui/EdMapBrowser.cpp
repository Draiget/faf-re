#include "editor/ui/EdMapBrowser.h"
#include "editor/ui/EdUiScale.h"
#include "editor/EdPath.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

#include <Windows.h>
#include <shellapi.h>

#include "editor/EdPlay.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdLuaText.h"
#include "editor/doc/EdMapFile.h"
#include "editor/ui/EdFonts.h"
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
    // The old test switch's choices (`/vaultquery sort,players,size,ranked`), as the new filters.
    const char* const kOldSorts[] = {"gamesPlayed", "latestVersion.updateTime", "latestVersion.createTime", "displayName"};
    const int kPlayersMin[] = {0, 2, 4, 6, 8, 10, 13};
    const int kPlayersMax[] = {0, 2, 4, 6, 8, 12, 0};

    const char* SortLabel(const std::string& property)
    {
      for (const VaultSortKey& key : kVaultSortKeys) {
        if (property == key.property) {
          return key.label;
        }
      }
      return "Times played";
    }

    /** The sizes chosen, "10 km, 20 km", or `none`. */
    std::string SizesText(const unsigned bits, const char* none)
    {
      std::string out;
      for (int k = 0; k < 7; ++k) {
        if ((bits & (1U << k)) != 0) {
          out += (out.empty() ? "" : ", ") + std::string(kVaultSizeNames[k]);
        }
      }
      return out.empty() ? std::string(none) : out;
    }

    std::filesystem::path SavedQueriesFile()
    {
      const char* const local = std::getenv("LOCALAPPDATA");
      return local != nullptr ? std::filesystem::path(local) / "FAForever" / "Editor" / "vault_queries.txt" : std::filesystem::path("vault_queries.txt");
    }
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

  namespace
  {
    const ImVec4 kAccent(0.89f, 0.58f, 0.26f, 1.0f);
    const ImVec4 kGood(0.45f, 0.80f, 0.45f, 1.0f);
    const ImVec4 kBad(0.95f, 0.45f, 0.40f, 1.0f);

    /** Text in the bold font at `scale` times the panel's size. */
    void Heading(const char* const text, const float scale)
    {
      ImGui::PushFont(gBoldFont, ImGui::GetStyle().FontSizeBase * scale);
      ImGui::TextUnformatted(text);
      ImGui::PopFont();
    }

    /** The editor's orange call-to-action button. */
    bool AccentButton(const char* const label, const ImVec2& size = ImVec2(0.0f, 0.0f))
    {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(kAccent.x * 0.85f, kAccent.y * 0.85f, kAccent.z * 0.85f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kAccent);
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(kAccent.x * 0.7f, kAccent.y * 0.7f, kAccent.z * 0.7f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.08f, 0.08f, 0.09f, 1.0f));
      ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, ImGui::GetFrameHeight() * 0.25f);
      const bool pressed = ImGui::Button(label, size);
      ImGui::PopStyleVar();
      ImGui::PopStyleColor(4);
      return pressed;
    }

    /** An ordinary button with the cards' rounded corners and the usual padding (SmallButton has none). */
    bool RoundButton(const char* const label, const ImVec2& size = ImVec2(0.0f, 0.0f))
    {
      ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, ImGui::GetFrameHeight() * 0.25f);
      const bool pressed = ImGui::Button(label, size);
      ImGui::PopStyleVar();
      return pressed;
    }

    /** A turning arc, `radius` pixels, in line with the text after it. */
    void Spinner(const float radius)
    {
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const float side = radius * 2.0f;
      ImGui::Dummy(ImVec2(side, side));
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const float start = static_cast<float>(ImGui::GetTime()) * 6.0f;
      draw->PathClear();
      for (int i = 0; i <= 24; ++i) {
        const float a = start + static_cast<float>(i) / 24.0f * 4.4f;
        draw->PathLineTo(ImVec2(at.x + radius + std::cos(a) * (radius - 2.0f), at.y + radius + std::sin(a) * (radius - 2.0f)));
      }
      draw->PathStroke(ImGui::GetColorU32(kAccent), 0, std::max(2.0f, radius * 0.22f));
    }

    /** A small rounded label (a map's size, players); `onPicture` gives it a dark backing to read over a picture. */
    void Chip(const char* const text, const ImVec4& color, const bool onPicture = false)
    {
      const ImVec2 size = ImGui::CalcTextSize(text);
      const ImVec2 pad(ImGui::GetStyle().FramePadding.x * 0.8f, ImGui::GetStyle().FramePadding.y * 0.4f);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      if (onPicture) {
        ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + size.x + pad.x * 2.0f, at.y + size.y + pad.y * 2.0f),
                                                  ImGui::GetColorU32(ImVec4(0.06f, 0.06f, 0.07f, 0.85f)), size.y);
      }
      ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + size.x + pad.x * 2.0f, at.y + size.y + pad.y * 2.0f),
                                                ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.18f)), size.y);
      ImGui::SetCursorScreenPos(ImVec2(at.x + pad.x, at.y + pad.y));
      ImGui::TextColored(color, "%s", text);
      ImGui::SetCursorScreenPos(at);
      ImGui::Dummy(ImVec2(size.x + pad.x * 2.0f, size.y + pad.y * 2.0f));
    }

    /** A card in the middle of the panel, `width` wide at most. */
    bool BeginCard(const char* const id, const float width)
    {
      const float avail = ImGui::GetContentRegionAvail().x;
      const float w = std::min(width, avail);
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail - w) * 0.5f);
      ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, ImGui::GetFrameHeight() * 0.4f);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ImGui::GetFrameHeight() * 1.1f, ImGui::GetFrameHeight() * 0.9f));
      ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.135f, 0.150f, 0.180f, 1.0f));
      const bool open = ImGui::BeginChild(id, ImVec2(w, 0.0f), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_AlwaysUseWindowPadding);
      return open;
    }

    void EndCard()
    {
      ImGui::EndChild();
      ImGui::PopStyleColor();
      ImGui::PopStyleVar(2);
    }

  } // namespace

  bool EdMapBrowser::OpenLink(const std::string& url)
  {
    const int wide = ::MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    std::wstring link(static_cast<std::size_t>(std::max(wide, 1)), L'\0');
    (void)::MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, link.data(), wide);
    const auto result = reinterpret_cast<std::intptr_t>(::ShellExecuteW(nullptr, L"open", link.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    if (result <= 32) {
      gpg::Warnf("editor: couldn't open %s in the browser (ShellExecute %lld, error %lu)", url.c_str(), static_cast<long long>(result),
                 ::GetLastError());
      mLinkFailed = true;
      return false;
    }
    gpg::Logf("editor: opened %s in the browser", url.c_str());
    return true;
  }

  EdMapBrowser::EdMapBrowser(EdPlay& play, EdDocument& document)
    : mPlay(play)
    , mDocument(document)
  {
    SetFafLog([](const char* const line) { gpg::Logf("%s", line); });
  }

  EdMapBrowser::~EdMapBrowser()
  {
    for (auto& [scenario, details] : mDetails) {
      if (details.picture != 0) {
        EdImGuiRenderer::DestroyImage(details.picture);
      }
    }
    for (auto& [url, picture] : mVaultPictures) {
      if (picture != 0) {
        EdImGuiRenderer::DestroyImage(picture);
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
      (void)vfs->FindFile(&disk, scenario.c_str(), nullptr); // empty when the file isn't there
      details.disk = disk.c_str();
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

  void EdMapBrowser::OpenFromDisk(const std::filesystem::path& scenarioFile)
  {
    const auto refuse = [&](const std::string& why) {
      mStatus = why;
      gpg::Warnf("editor: open from a folder: %s", why.c_str());
    };
    const std::filesystem::path folder = scenarioFile.parent_path();
    const std::string file = scenarioFile.filename().string();
    if (Lower(file).size() < 13 || Lower(file).compare(file.size() - 13, 13, "_scenario.lua") != 0) {
      refuse("pick a map's _scenario.lua");
      return;
    }
    // Where the scenario says its files are: its map's folder in /maps (a folder renamed on disk still works).
    std::string text;
    {
      std::ifstream in(scenarioFile, std::ios::binary);
      text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    LuaText info;
    std::string error;
    std::string mount;
    if (ReadLuaAssignment(text, "ScenarioInfo", info, error)) {
      if (const LuaText* const map = info.Field("map")) {
        const std::string path = Lower(Unquote(map->atom));
        if (path.rfind("/maps/", 0) == 0 && path.find('/', 6) != std::string::npos) {
          mount = path.substr(6, path.find('/', 6) - 6);
        }
      }
    }
    if (mount.empty()) {
      mount = Lower(folder.filename().string());
    }
    bool scmap = false;
    std::error_code code;
    for (const auto& entry : std::filesystem::directory_iterator(folder, code)) {
      scmap = scmap || Lower(entry.path().extension().string()) == ".scmap";
    }
    if (!scmap) {
      refuse("the folder has no .scmap");
      return;
    }
    const std::string scenario = "/maps/" + mount + "/" + Lower(file);
    if (const std::string listed = ListedScenario(mount); !listed.empty()) {
      // The same folder (mounted at startup): open it. Another folder of that name: the game would mix them.
      fa::string disk;
      moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS();
      if (vfs != nullptr) {
        (void)vfs->FindFile(&disk, listed.c_str(), nullptr); // empty when the file isn't there
      }
      const bool same = !disk.empty() &&
                        std::filesystem::equivalent(std::filesystem::path(disk.c_str()).parent_path(), folder, code);
      if (!same) {
        refuse("the game already has a map folder named " + mount + " (" + std::string(disk.c_str()) + "); rename one of them");
        return;
      }
      mStatus = "Opened " + listed;
      OpenMap(listed);
      return;
    }
    if (!moho::DISK_MountDirectoryNow(folder, ("/maps/" + mount).c_str())) {
      refuse("the game's file system isn't set up");
      return;
    }
    mPlay.FindMaps();
    const std::string listed = ListedScenario(mount);
    if (listed.empty()) {
      refuse("mounted " + folder.string() + " as /maps/" + mount + ", but the game doesn't list a map there");
      return;
    }
    gpg::Logf("editor: open from a folder: %s mounted as /maps/%s; opening %s", folder.string().c_str(), mount.c_str(), listed.c_str());
    mStatus = "Opened " + listed + " from " + folder.string();
    OpenMap(listed);
    (void)scenario;
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

  VaultQuery EdMapBrowser::Query() const
  {
    VaultQuery query = mFilters;
    query.text = mSearchedText;
    query.author = mAuthorText;
    query.uploadedFrom = mFromText;
    query.uploadedTo = mToText;
    return query;
  }

  void EdMapBrowser::SetFilters(const int sort, const int players, const int size, const bool ranked)
  {
    mFilters.sortProperty = kOldSorts[std::clamp(sort, 0, 3)];
    mFilters.descending = std::clamp(sort, 0, 3) != 3;
    mFilters.minPlayers = kPlayersMin[std::clamp(players, 0, 6)];
    mFilters.maxPlayers = kPlayersMax[std::clamp(players, 0, 6)];
    // Old sizes: any, 5, 10, 20, 40, 80 km (bits 2 to 6).
    mFilters.widths = size <= 0 ? 0U : (1U << std::clamp(size + 1, 2, 6));
    mFilters.rankedOnly = ranked;
  }

  void EdMapBrowser::ReadSavedQueries()
  {
    mSavedQueriesRead = true;
    mSavedQueries.clear();
    std::ifstream in(SavedQueriesFile());
    std::string line;
    while (std::getline(in, line)) {
      // name, a tab, then the query's text.
      const std::size_t tab = line.find('\t');
      if (tab != std::string::npos && tab > 0) {
        mSavedQueries.emplace_back(line.substr(0, tab), line.substr(tab + 1));
      }
    }
  }

  void EdMapBrowser::WriteSavedQueries() const
  {
    std::error_code ec;
    std::filesystem::create_directories(SavedQueriesFile().parent_path(), ec);
    std::ofstream out(SavedQueriesFile(), std::ios::trunc);
    for (const auto& [name, text] : mSavedQueries) {
      out << name << '\t' << text << '\n';
    }
  }

  bool EdMapBrowser::DrawVaultFilters()
  {
    // The FAF client's map vault filters (MapVaultController): three rows as its search bar has them.
    if (!mSavedQueriesRead) {
      ReadSavedQueries();
    }
    bool changed = false;
    const float field = std::max(ImGui::GetContentRegionAvail().x / 4.0f - ImGui::GetStyle().ItemSpacing.x, 120.0f);
    const auto sizes = [&](const char* id, const char* label, unsigned& bits) {
      ImGui::SetNextItemWidth(field);
      if (ImGui::BeginCombo(id, (std::string(label) + ": " + SizesText(bits, "any")).c_str())) {
        for (int k = 0; k < 7; ++k) {
          bool on = (bits & (1U << k)) != 0;
          if (ImGui::Checkbox(kVaultSizeNames[k], &on)) {
            bits = on ? (bits | (1U << k)) : (bits & ~(1U << k));
            changed = true;
          }
        }
        ImGui::EndCombo();
      }
    };
    // Row 1: author, uploaded from/to, width (the name is the search box above).
    ImGui::SetNextItemWidth(field);
    changed |= ImGui::InputTextWithHint("##author", "Author", mAuthorText, sizeof(mAuthorText), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(field);
    const std::string uploaded = std::string("Uploaded: ") + (mFromText[0] ? mFromText : "any") + " to " + (mToText[0] ? mToText : "any");
    if (ImGui::BeginCombo("##uploaded", uploaded.c_str())) {
      ImGui::TextDisabled("Updated after and before (YYYY-MM-DD)");
      ImGui::SetNextItemWidth(Em(130.0f));
      changed |= ImGui::InputTextWithHint("from", "2020-01-01", mFromText, sizeof(mFromText), ImGuiInputTextFlags_EnterReturnsTrue);
      ImGui::SetNextItemWidth(Em(130.0f));
      changed |= ImGui::InputTextWithHint("to", "2026-12-31", mToText, sizeof(mToText), ImGuiInputTextFlags_EnterReturnsTrue);
      if (ImGui::SmallButton("Any date")) {
        mFromText[0] = '\0';
        mToText[0] = '\0';
        changed = true;
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    sizes("##width", "Width", mFilters.widths);
    // Row 2: height, max players, review score, only ranked.
    sizes("##height", "Height", mFilters.heights);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(field);
    const std::string players = "Max. players: " + (mFilters.minPlayers > 0 ? std::to_string(mFilters.minPlayers) : std::string("")) + " to " +
                                (mFilters.maxPlayers > 0 && mFilters.maxPlayers < 16 ? std::to_string(mFilters.maxPlayers) : std::string(""));
    if (ImGui::BeginCombo("##players", players.c_str())) {
      changed |= ImGui::SliderInt("from##p", &mFilters.minPlayers, 0, 16, mFilters.minPlayers == 0 ? "any" : "%d");
      int to = mFilters.maxPlayers == 0 ? 16 : mFilters.maxPlayers;
      if (ImGui::SliderInt("to##p", &to, 0, 16, to >= 16 ? "any" : "%d")) {
        mFilters.maxPlayers = to >= 16 ? 0 : to;
        changed = true;
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(field);
    char score[64];
    (void)std::snprintf(score, sizeof(score), "Average reviews score: %s to %s", mFilters.minScore > 0.0f ? std::to_string(mFilters.minScore).substr(0, 3).c_str() : "",
                        mFilters.maxScore < 5.0f ? std::to_string(mFilters.maxScore).substr(0, 3).c_str() : "");
    if (ImGui::BeginCombo("##score", score)) {
      changed |= ImGui::SliderFloat("from##s", &mFilters.minScore, 0.0f, 5.0f, mFilters.minScore <= 0.0f ? "any" : "%.1f");
      changed |= ImGui::SliderFloat("to##s", &mFilters.maxScore, 0.0f, 5.0f, mFilters.maxScore >= 5.0f ? "any" : "%.1f");
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    changed |= ImGui::Checkbox("Only ranked", &mFilters.rankedOnly);
    // Row 3: reset, sort by and order, save query, favorites, display search query.
    if (RoundButton("Reset")) {
      const VaultQuery fresh;
      mFilters = fresh;
      mAuthorText[0] = mFromText[0] = mToText[0] = '\0';
      mSearchText[0] = '\0';
      changed = true;
    }
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Sort by");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(150.0f));
    if (ImGui::BeginCombo("##sortby", SortLabel(mFilters.sortProperty))) {
      for (const VaultSortKey& key : kVaultSortKeys) {
        if (ImGui::Selectable(key.label, mFilters.sortProperty == key.property)) {
          mFilters.sortProperty = key.property;
          changed = true;
        }
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(120.0f));
    int order = mFilters.descending ? 1 : 0;
    static const char* const kOrders[] = {"ascending", "descending"};
    if (ImGui::Combo("##order", &order, kOrders, 2)) {
      mFilters.descending = order == 1;
      changed = true;
    }
    ImGui::SameLine();
    if (RoundButton("Save query")) {
      ImGui::OpenPopup("##savequery");
      mSaveQueryName[0] = '\0';
    }
    if (ImGui::BeginPopup("##savequery")) {
      ImGui::SetNextItemWidth(Em(220.0f));
      const bool enter = ImGui::InputTextWithHint("##qname", "Name for this query", mSaveQueryName, sizeof(mSaveQueryName), ImGuiInputTextFlags_EnterReturnsTrue);
      ImGui::SameLine();
      if ((ImGui::Button("Save") || enter) && mSaveQueryName[0] != '\0') {
        VaultQuery query = Query();
        query.text = mSearchText;
        std::string name = mSaveQueryName;
        std::replace(name.begin(), name.end(), '\t', ' ');
        mSavedQueries.erase(std::remove_if(mSavedQueries.begin(), mSavedQueries.end(), [&](const auto& q) { return q.first == name; }), mSavedQueries.end());
        mSavedQueries.emplace_back(name, VaultQueryText(query));
        WriteSavedQueries();
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndPopup();
    }
    ImGui::SameLine();
    if (RoundButton("Favorites")) {
      ImGui::OpenPopup("##favorites");
    }
    if (ImGui::BeginPopup("##favorites")) {
      if (mSavedQueries.empty()) {
        ImGui::TextDisabled("No saved queries yet: Save query keeps the filters under a name.");
      }
      for (std::size_t i = 0; i < mSavedQueries.size(); ++i) {
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(mSavedQueries[i].first.c_str(), false, ImGuiSelectableFlags_None, ImVec2(Em(220.0f), 0.0f))) {
          VaultQuery query;
          if (VaultQueryFromText(mSavedQueries[i].second, query)) {
            mFilters = query;
            (void)std::snprintf(mSearchText, sizeof(mSearchText), "%s", query.text.c_str());
            (void)std::snprintf(mAuthorText, sizeof(mAuthorText), "%s", query.author.c_str());
            (void)std::snprintf(mFromText, sizeof(mFromText), "%s", query.uploadedFrom.c_str());
            (void)std::snprintf(mToText, sizeof(mToText), "%s", query.uploadedTo.c_str());
            changed = true;
          }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("x")) {
          mSavedQueries.erase(mSavedQueries.begin() + static_cast<std::ptrdiff_t>(i));
          WriteSavedQueries();
          ImGui::PopID();
          break;
        }
        ImGui::PopID();
      }
      ImGui::EndPopup();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Display search query", &mShowQuery);
    if (mShowQuery) {
      VaultQuery query = Query();
      query.text = mSearchText;
      std::string text = VaultQueryFilter(query) + "  (sort " + (query.descending ? "-" : "") + query.sortProperty + ")";
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputText("##query", text.data(), text.size() + 1, ImGuiInputTextFlags_ReadOnly);
    }
    return changed;
  }

  void EdMapBrowser::AskSearch(const std::string& text)
  {
    mAskedSearch = text.empty() ? std::string(" ") : text;
    (void)std::snprintf(mSearchText, sizeof(mSearchText), "%s", mAskedSearch == " " ? "" : mAskedSearch.c_str());
    ShowVault();
  }

  std::uint64_t EdMapBrowser::VaultPicture(const std::string& url)
  {
    if (url.empty()) {
      return 0;
    }
    if (const auto found = mVaultPictures.find(url); found != mVaultPictures.end()) {
      return found->second;
    }
    const std::string bytes = mFaf.Picture(url);
    if (bytes.empty() || mPicturesThisFrame >= 2) {
      return 0; // still coming, or this frame's decodes are done
    }
    ++mPicturesThisFrame;
    std::uint64_t picture = 0;
    if (bytes.size() <= 1) {
      mVaultNoPicture.insert(url);
    }
    gpg::gal::imaging::ImageCodec* const codec = gpg::gal::imaging::ImageCodec::Instance();
    if (codec != nullptr && bytes.size() > 1) {
      gpg::gal::imaging::DecodeOptions options;
      options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      options.width = kPicture * 2;
      options.height = kPicture * 2;
      options.mipLevels = 1;
      gpg::gal::imaging::Image decoded;
      if (SUCCEEDED(codec->Decode(bytes.data(), bytes.size(), options, decoded)) && !decoded.subresources.empty() &&
          decoded.format == DXGI_FORMAT_B8G8R8A8_UNORM) {
        const auto& level = decoded.subresources.front();
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(level.width) * level.height);
        for (std::uint32_t y = 0; y < level.height; ++y) {
          std::memcpy(pixels.data() + static_cast<std::size_t>(y) * level.width,
                      decoded.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch, level.width * 4U);
        }
        for (std::uint32_t& pixel : pixels) {
          pixel |= 0xFF000000u;
        }
        picture = EdImGuiRenderer::CreateImage(static_cast<int>(level.width), static_cast<int>(level.height), pixels.data());
      }
    }
    if (picture == 0) {
      mVaultNoPicture.insert(url);
    }
    mVaultPictures[url] = picture;
    return picture;
  }

  void EdMapBrowser::Update()
  {
    mReadsThisFrame = 0;
    mPicturesThisFrame = 0;
    if (mFaf.TakeOpenPage()) {
      mLinkFailed = false;
      (void)OpenLink(mFaf.VerifyUrl());
    }
    // A finished search; a search asked by a test run once logged in.
    if (int pages = 0; mFaf.TakeResults(mFound, pages)) {
      mSearchPages = pages;
      mSearchedOnce = true;
      gpg::Logf("editor: vault search %s (sort %s%s) page %d of %d: %zu maps%s%s", VaultQueryFilter(Query()).c_str(), mFilters.descending ? "-" : "",
                mFilters.sortProperty.c_str(), mSearchPage, pages, mFound.size(), mFaf.Message().empty() ? "" : "; ", mFaf.Message().c_str());
      for (std::size_t i = 0; i < mFound.size() && i < 5; ++i) {
        gpg::Logf("editor:   %s (%s), %d players, %d x %d, v%s, %d games%s", mFound[i].name.c_str(), mFound[i].folder.c_str(),
                  mFound[i].players, mFound[i].width, mFound[i].height, mFound[i].version.c_str(), mFound[i].gamesPlayed,
                  mFound[i].ranked ? ", ranked" : "");
      }
    }
    if (!mAskedSearch.empty() && mFaf.GetState() == EdFafSession::State::LoggedIn && !mFaf.Searching()) {
      mSearchedText = mAskedSearch == " " ? std::string() : mAskedSearch;
      mSearchPage = 1;
      mFaf.Search(Query(), mSearchPage);
      mAskedSearch.clear();
    }
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
      if (ImGui::BeginTabItem("FAF vault", nullptr, std::exchange(mSelectVault, false) ? ImGuiTabItemFlags_SetSelected : 0)) {
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
    ImGui::SameLine();
    if (RoundButton("Open from a folder...")) {
      mOpenFileAsk = true;
    }
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("A map folder anywhere on disk: pick its _scenario.lua. The editor adds it to the game's maps until it closes.");
    }
    if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }

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
              const std::filesystem::path folder = PathFromUtf8(details.disk).parent_path();
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
    if (!mFafResumed) {
      mFafResumed = true;
      mFaf.Resume(); // a sign-in kept from before, if there is one
    }
    const EdFafSession::State state = mFaf.GetState();

    // The header: what this is, and who is signed in.
    ImGui::Dummy(ImVec2(0.0f, ImGui::GetStyle().ItemSpacing.y));
    const float headerRight = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    Heading("FAF Vault", 1.6f);
    {
      const std::string name = mFaf.UserName();
      const bool in = state == EdFafSession::State::LoggedIn;
      const std::string who = in ? (name.empty() ? std::string("Signed in") : "Signed in as " + name) : std::string("Not signed in");
      const float outW = ImGui::CalcTextSize("Sign out").x + ImGui::GetStyle().FramePadding.x * 2.0f;
      const float chipW = ImGui::CalcTextSize(who.c_str()).x + ImGui::GetStyle().FramePadding.x * 1.6f;
      ImGui::SameLine(headerRight - chipW - (in ? outW + ImGui::GetStyle().ItemSpacing.x : 0.0f));
      Chip(who.c_str(), in ? kGood : ImVec4(0.6f, 0.62f, 0.66f, 1.0f));
      if (in) {
        ImGui::SameLine();
        if (RoundButton("Sign out")) {
          mFaf.Logout();
          mFound.clear();
          mSearchedOnce = false;
        }
      }
    }
    ImGui::TextDisabled("The community's maps: find one, and it downloads into your vault and opens for editing.");
    ImGui::Spacing();

    // A download under way, or how the last one went.
    if (mDownload.GetState() == EdVaultDownload::State::Working) {
      Spinner(ImGui::GetTextLineHeight() * 0.5f);
      ImGui::SameLine();
      ImGui::TextUnformatted(mDownload.Message().c_str());
      ImGui::SameLine();
      DrawDownloadProgress(-1.0f);
    } else if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }
    ImGui::Separator();
    ImGui::Spacing();

    const float cardWidth = ImGui::GetFontSize() * 30.0f;
    if (state == EdFafSession::State::LoggedOut || state == EdFafSession::State::Working) {
      ImGui::Dummy(ImVec2(0.0f, ImGui::GetFrameHeight() * 1.5f));
      if (BeginCard("##signin", cardWidth)) {
        Heading("Sign in to search the vault", 1.25f);
        ImGui::Spacing();
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled("You sign in on FAF's own website, so the editor never sees your password. It asks only for your name "
                            "and to keep you signed in.");
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        ImGui::Spacing();
        if (state == EdFafSession::State::Working) {
          Spinner(ImGui::GetTextLineHeight() * 0.6f);
          ImGui::SameLine();
          ImGui::AlignTextToFramePadding();
          ImGui::TextUnformatted("Connecting to FAF...");
        } else {
          ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ImGui::GetStyle().FramePadding.x, ImGui::GetStyle().FramePadding.y * 2.0f));
          if (AccentButton("Sign in with FAF", ImVec2(-FLT_MIN, 0.0f))) {
            mFaf.StartLogin();
          }
          ImGui::PopStyleVar();
          const std::string message = mFaf.Message();
          if (!message.empty() && message != "Logged out of FAF") {
            ImGui::Spacing();
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextColored(kBad, "%s", message.c_str());
            ImGui::PopTextWrapPos();
          }
        }
        EndCard();
      }
      // The search's filters, to set up before signing in (the search itself needs the sign-in).
      ImGui::Spacing();
      ImGui::SeparatorText("Search filters (searching needs the sign-in)");
      (void)DrawVaultFilters();
      DrawVaultByName();
      return;
    }

    if (state == EdFafSession::State::WaitingForApproval) {
      ImGui::Dummy(ImVec2(0.0f, ImGui::GetFrameHeight()));
      if (BeginCard("##approve", cardWidth)) {
        Heading("Approve the editor in your browser", 1.25f);
        ImGui::Spacing();
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled("FAF's page opened in your browser. Sign in there if it asks, check that it shows this code, and "
                            "approve. This window carries on by itself.");
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
        // The code, large, in a box: read it against the browser's.
        std::string code = mFaf.UserCode();
        std::string spaced;
        for (std::size_t i = 0; i < code.size(); ++i) {
          spaced += (i > 0 && i % 4 == 0) ? "  " : (i > 0 ? " " : "");
          spaced += code[i];
        }
        ImGui::PushFont(gMonoFont, ImGui::GetStyle().FontSizeBase * 2.4f);
        const ImVec2 codeSize = ImGui::CalcTextSize(spaced.c_str());
        const float boxW = ImGui::GetContentRegionAvail().x;
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const float boxH = codeSize.y + ImGui::GetStyle().FramePadding.y * 6.0f;
        ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + boxW, at.y + boxH), ImGui::GetColorU32(ImVec4(0.08f, 0.09f, 0.11f, 1.0f)),
                                                  ImGui::GetFrameHeight() * 0.3f);
        ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + boxW, at.y + boxH), ImGui::GetColorU32(ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.6f)),
                                            ImGui::GetFrameHeight() * 0.3f, 0, 1.5f);
        ImGui::GetWindowDrawList()->AddText(ImVec2(at.x + (boxW - codeSize.x) * 0.5f, at.y + (boxH - codeSize.y) * 0.5f),
                                            ImGui::GetColorU32(ImVec4(0.96f, 0.96f, 0.97f, 1.0f)), spaced.c_str());
        ImGui::Dummy(ImVec2(boxW, boxH));
        ImGui::PopFont();
        ImGui::Spacing();
        const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
        if (ImGui::Button("Copy code", ImVec2(half, 0.0f))) {
          ImGui::SetClipboardText(code.c_str());
        }
        ImGui::SameLine();
        if (AccentButton("Open FAF's page", ImVec2(half, 0.0f))) {
          (void)OpenLink(mFaf.VerifyUrl());
        }
        // The page's link, for a browser the editor couldn't open (or another device).
        if (mLinkFailed) {
          ImGui::Spacing();
          ImGui::TextColored(kAccent, "The browser didn't open. Open this link yourself:");
        } else {
          ImGui::TextDisabled("Or open this link in any browser:");
        }
        std::string link = mFaf.VerifyUrl();
        ImGui::PushFont(gMonoFont, 0.0f);
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Copy link").x - ImGui::GetStyle().FramePadding.x * 2.0f -
                                ImGui::GetStyle().ItemSpacing.x);
        ImGui::InputText("##link", link.data(), link.size() + 1, ImGuiInputTextFlags_ReadOnly);
        ImGui::PopFont();
        ImGui::SameLine();
        if (ImGui::Button("Copy link")) {
          ImGui::SetClipboardText(link.c_str());
        }
        ImGui::Spacing();
        const float cardRight = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
        Spinner(ImGui::GetTextLineHeight() * 0.5f);
        ImGui::SameLine();
        const int left = mFaf.SecondsLeft();
        ImGui::Text("Waiting for your approval  (%d:%02d left)", left / 60, left % 60);
        ImGui::SameLine(cardRight - ImGui::CalcTextSize("Cancel").x - ImGui::GetStyle().FramePadding.x * 2.0f);
        if (RoundButton("Cancel")) {
          mFaf.CancelLogin();
        }
        EndCard();
      }
      return;
    }

    DrawVaultSearch();
  }

  void EdMapBrowser::DrawDownloadProgress(const float width)
  {
    const double received = static_cast<double>(mDownload.Received()) / 1048576.0;
    const double total = static_cast<double>(mDownload.Total()) / 1048576.0;
    char text[64];
    if (total > 0.0) {
      (void)std::snprintf(text, sizeof(text), "%.1f of %.1f MB", received, total);
    } else {
      (void)std::snprintf(text, sizeof(text), "%.1f MB", received);
    }
    // Unpacking (all received): the bar full, its text saying so.
    const bool unpacking = total > 0.0 && received >= total;
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, kAccent);
    ImGui::ProgressBar(total > 0.0 ? static_cast<float>(received / total) : -1.0f * static_cast<float>(ImGui::GetTime()),
                       ImVec2(width < 0.0f && width > -1.5f ? ImGui::GetContentRegionAvail().x : width, 0.0f), unpacking ? "Unpacking..." : text);
    ImGui::PopStyleColor();
  }

  void EdMapBrowser::DrawVaultByName()
  {
    ImGui::Dummy(ImVec2(0.0f, ImGui::GetFrameHeight()));
    if (!ImGui::CollapsingHeader("Know a map's folder name or link?")) {
      return;
    }
    const bool working = mDownload.GetState() == EdVaultDownload::State::Working;
    ImGui::TextDisabled("Download any vault map without signing in: its folder name (dualgap_adaptive.v0012) or its link.");
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.7f);
    const bool entered = ImGui::InputTextWithHint("##vaultname", "folder name or download link", mVaultName, sizeof(mVaultName),
                                                  ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(working || mVaultName[0] == '\0');
    if (ImGui::Button("Download and open") || (entered && !working && mVaultName[0] != '\0')) {
      Download(mVaultName);
    }
    ImGui::EndDisabled();
    ImGui::TextDisabled("Maps go to %s", (mDocument.VaultFolder() / "maps").string().c_str());
    if (RoundButton("Browse the vault on faforever.com")) {
      (void)OpenLink("https://www.faforever.com/vault/maps");
    }
  }

  void EdMapBrowser::DrawVaultSearch()
  {
    // The search bar: large, the first thing to use.
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ImGui::GetStyle().FramePadding.x * 1.5f, ImGui::GetStyle().FramePadding.y * 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, ImGui::GetFrameHeight() * 0.3f);
    const float searchW = ImGui::CalcTextSize("Search").x + ImGui::GetStyle().FramePadding.x * 4.0f;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - searchW - ImGui::GetStyle().ItemSpacing.x);
    if (!mSearchedOnce && !mFaf.Searching() && mSearchText[0] == '\0') {
      ImGui::SetKeyboardFocusHere();
    }
    const bool entered = ImGui::InputTextWithHint("##vaultsearch", "Search maps by name", mSearchText, sizeof(mSearchText),
                                                  ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(mFaf.Searching());
    if (AccentButton("Search", ImVec2(searchW, 0.0f)) || (entered && !mFaf.Searching())) {
      mSearchedText = mSearchText;
      mSearchPage = 1;
      mFaf.Search(Query(), mSearchPage);
    }
    ImGui::EndDisabled();
    ImGui::PopStyleVar(2);

    // The filters and order (the FAF client's): a change searches again from the first page.
    {
      const bool changed = DrawVaultFilters();
      if (changed && !mFaf.Searching()) {
        mSearchedText = mSearchText;
        mSearchPage = 1;
        mFaf.Search(Query(), mSearchPage);
      }
    }

    // What the search found, or why it found nothing.
    if (mFaf.Searching()) {
      Spinner(ImGui::GetTextLineHeight() * 0.5f);
      ImGui::SameLine();
      ImGui::TextDisabled("Searching the vault...");
    } else if (!mFaf.Message().empty() && mFaf.Message() != "Logged in to FAF") {
      ImGui::TextColored(kBad, "%s", mFaf.Message().c_str());
    } else if (mSearchedOnce) {
      const float lineRight = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
      ImGui::AlignTextToFramePadding();
      ImGui::TextDisabled("%s", mFound.empty() ? "No maps match" : (std::string("By ") + SortLabel(mFilters.sortProperty) + (mFilters.descending ? ", most first" : ", least first")).c_str());
      if (mSearchPages > 1) {
        char page[32];
        (void)std::snprintf(page, sizeof(page), "Page %d of %d", mSearchPage, mSearchPages);
        const float pagerW = ImGui::CalcTextSize("< Previous").x + ImGui::CalcTextSize("Next >").x + ImGui::CalcTextSize(page).x +
                             ImGui::GetStyle().FramePadding.x * 4.0f + ImGui::GetStyle().ItemSpacing.x * 2.0f;
        ImGui::SameLine(lineRight - pagerW);
        ImGui::BeginDisabled(mSearchPage <= 1);
        if (RoundButton("< Previous")) {
          mFaf.Search(Query(), --mSearchPage);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(page);
        ImGui::SameLine();
        ImGui::BeginDisabled(mSearchPage >= mSearchPages);
        if (RoundButton("Next >")) {
          mFaf.Search(Query(), ++mSearchPage);
        }
        ImGui::EndDisabled();
      }
    } else {
      ImGui::TextDisabled("Type a name and press Enter; an empty search lists the most played maps.");
    }
    ImGui::Spacing();

    // The maps as cards: picture, name, size and players, one button.
    const float cardW = ImGui::GetFontSize() * 13.0f;
    const int columns = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + ImGui::GetStyle().ItemSpacing.x) /
                                                     (cardW + ImGui::GetStyle().ItemSpacing.x)));
    const bool working = mDownload.GetState() == EdVaultDownload::State::Working;
    if (!mFound.empty() && ImGui::BeginChild("##vaultcards", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar)) {
      if (ImGui::BeginTable("##vaultgrid", columns, ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_PadOuterX)) {
        for (std::size_t i = 0; i < mFound.size(); ++i) {
          const VaultMap& map = mFound[i];
          ImGui::TableNextColumn();
          ImGui::PushID(static_cast<int>(i));
          ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, ImGui::GetColorU32(ImVec4(0.135f, 0.150f, 0.180f, 1.0f)));
          const float w = ImGui::GetContentRegionAvail().x;
          const std::uint64_t image = VaultPicture(map.thumbnail);
          const ImVec2 at = ImGui::GetCursorScreenPos();
          if (image != 0) {
            ImGui::Image(static_cast<ImTextureID>(image), ImVec2(w, w));
          } else {
            ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + w, at.y + w), ImGui::GetColorU32(ImVec4(0.10f, 0.11f, 0.13f, 1.0f)));
            const bool none = map.thumbnail.empty() || mVaultNoPicture.count(map.thumbnail) != 0;
            if (none) {
              const ImVec2 text = ImGui::CalcTextSize("No picture");
              ImGui::GetWindowDrawList()->AddText(ImVec2(at.x + (w - text.x) * 0.5f, at.y + (w - text.y) * 0.5f),
                                                  ImGui::GetColorU32(ImGuiCol_TextDisabled), "No picture");
            } else {
              const float radius = w * 0.08f;
              ImGui::SetCursorScreenPos(ImVec2(at.x + w * 0.5f - radius, at.y + w * 0.5f - radius));
              Spinner(radius);
              ImGui::SetCursorScreenPos(at);
            }
            ImGui::Dummy(ImVec2(w, w));
          }
          if (map.ranked) {
            ImGui::SetCursorScreenPos(ImVec2(at.x + ImGui::GetStyle().FramePadding.x, at.y + ImGui::GetStyle().FramePadding.y));
            Chip("Ranked", kAccent, true);
            ImGui::SetCursorScreenPos(ImVec2(at.x, at.y + w + ImGui::GetStyle().ItemSpacing.y));
          }
          ImGui::PushFont(gBoldFont, 0.0f);
          ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + w);
          ImGui::TextUnformatted(map.name.c_str());
          ImGui::PopTextWrapPos();
          ImGui::PopFont();
          if (ImGui::IsItemHovered() && !map.description.empty()) {
            ImGui::SetTooltip("%s", map.description.c_str());
          }
          ImGui::TextDisabled("%s%s", map.author.empty() ? "" : "by ", map.author.c_str());
          char size[32] = "";
          if (map.width > 0) {
            (void)std::snprintf(size, sizeof(size), "%g km", std::round(map.width / 51.2 * 10.0) / 10.0);
            Chip(size, ImVec4(0.55f, 0.75f, 0.95f, 1.0f));
            ImGui::SameLine();
          }
          char players[32];
          (void)std::snprintf(players, sizeof(players), "%d players", map.players);
          Chip(players, ImVec4(0.75f, 0.75f, 0.80f, 1.0f));
          ImGui::TextDisabled("%d games played", map.gamesPlayed);
          const bool here = !ListedScenario(map.folder).empty();
          if (working && mDownload.Map().folder == map.folder) {
            DrawDownloadProgress(-FLT_MIN);
          } else {
            ImGui::BeginDisabled(working);
            if (here ? ImGui::Button("Open", ImVec2(-FLT_MIN, 0.0f)) : AccentButton("Download and open", ImVec2(-FLT_MIN, 0.0f))) {
              Download(map.folder);
            }
            ImGui::EndDisabled();
          }
          ImGui::Spacing();
          ImGui::PopID();
        }
        ImGui::EndTable();
      }
    }
    if (!mFound.empty()) {
      ImGui::EndChild();
    }
  }
} // namespace faf::editor
