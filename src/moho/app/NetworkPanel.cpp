#include "moho/app/NetworkPanel.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/app/NetworkTray.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/NetlinkPeers.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/font/MsdfFontRegistry.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "remote/client/ServerLaneMeter.h"

namespace moho
{
  bool net_ShowPanel = false;

  namespace
  {
    namespace nl = faf::netlink;
    using Clock = std::chrono::steady_clock;

    TConVar<bool> gTConVar_net_ShowPanel(
      "net_ShowPanel",
      "1: show the network panel (the game's peer links, reconnect and path choice per peer, the network log); "
      "0 (default) hides it. Ctrl+Shift+F11 flips it.",
      &net_ShowPanel
    );

    // Window messages the panel reads (winuser.h values; this file stays free of windows.h).
    constexpr unsigned kMouseMove = 0x0200;
    constexpr unsigned kLeftDown = 0x0201;
    constexpr unsigned kLeftUp = 0x0202;
    constexpr unsigned kLeftDouble = 0x0203;
    constexpr unsigned kRightDown = 0x0204;
    constexpr unsigned kRightUp = 0x0205;
    constexpr unsigned kRightDouble = 0x0206;
    constexpr unsigned kMiddleDown = 0x0207;
    constexpr unsigned kMiddleUp = 0x0208;
    constexpr unsigned kMiddleDouble = 0x0209;
    constexpr unsigned kWheel = 0x020A;

    constexpr int kMaxColumns = 120; // characters
    constexpr int kLogLines = 18;    // the log tab's page

    enum class Tab : int
    {
      Peers,
      Log,
      Servers,
    };

    struct Box
    {
      float left = 0, top = 0, right = 0, bottom = 0;
      [[nodiscard]] bool Has(const float x, const float y) const { return x >= left && x < right && y >= top && y < bottom; }
    };

    struct Click
    {
      enum class Kind
      {
        Tab,
        SelectPeer,
        Reconnect,   // one peer; with a choice, that path
        AllPeers,    // every peer, with the choice
        Close,
        CopyDiagnostics,
        LogFolder,
        CopyLog,
        LogOlder,
        LogNewer,
      };
      Kind kind = Kind::Close;
      Tab tab = Tab::Peers;
      std::int64_t peer = 0;
      std::string peerName;
      std::optional<nl::PathChoice> choice;
    };

    struct Hit
    {
      Box box;
      Click click;
    };

    // What the player did, shared by the window procedure (main thread) and the
    // draw (render thread).
    struct PanelState
    {
      std::mutex mutex;
      Tab tab = Tab::Peers;
      std::optional<std::int64_t> selected;
      int logScroll = 0; // lines back from the newest
      float mouseX = -1.0f;
      float mouseY = -1.0f;
      std::optional<Box> panel; // as last drawn
      float headWidth = 0.0f;   // the head size it was drawn at
      float headHeight = 0.0f;
      std::vector<Hit> hits;    // as last drawn
      std::optional<Hit> pressed;
      bool leftDown = false;  // a left press the panel took: it takes the release too
      bool otherDown = false; // likewise for the right and middle buttons
      std::string flash;      // what the last click did, shown for a few seconds
      Clock::time_point flashUntil{};
    };

    PanelState& State()
    {
      static PanelState state;
      return state;
    }

    // The profile's ui_scale option, as the other overlays read it; 1.0 when unset.
    [[nodiscard]] float UiScale()
    {
      IUserPrefs* const prefs = USER_GetPreferences();
      if (prefs == nullptr) {
        return 1.0f;
      }
      const std::lock_guard<std::recursive_mutex> lock(USER_PreferencesLock()); // #247
      const LuaPlus::LuaObject value = prefs->LookupCurrentOption("ui_scale");
      return value.IsNumber() ? std::clamp(static_cast<float>(value.GetNumber()), 0.5f, 4.0f) : 1.0f;
    }

    // A monospaced face that draws smooth: Consolas from Windows' fonts folder, given
    // to the MSDF registry like the game's own font files (issue #306), so the panel's
    // text comes from an atlas as the interface's does. GDI still gives the advances.
    // Without the file (older Windows, Wine): Courier New through GDI glyphs.
    [[nodiscard]] const char* PanelFace()
    {
      static const bool registered = [] {
        const char* const windows = std::getenv("WINDIR");
        if (windows == nullptr) {
          return false;
        }
        std::ifstream file(std::string(windows) + "/Fonts/consola.ttf", std::ios::binary);
        const std::vector<char> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
        if (bytes.empty()) {
          gpg::Logf("NETLINK: panel: no Consolas font file, the panel draws Courier New through GDI");
          return false;
        }
        MSDF_RegisterFontFile("consola.ttf", bytes.data(), bytes.size());
        return true;
      }();
      return registered ? "Consolas" : "Courier New";
    }

    [[nodiscard]] std::string Format(const char* format, const double value)
    {
      char buf[64];
      std::snprintf(buf, sizeof(buf), format, value);
      return buf;
    }

    [[nodiscard]] std::string PeerName(const SNetlinkPeerInfo& p)
    {
      return p.login + " (" + std::to_string(p.id) + ")";
    }

    [[nodiscard]] std::string Cut(const std::string& text, const int columns)
    {
      if (static_cast<int>(text.size()) <= columns) {
        return text;
      }
      return columns > 3 ? text.substr(0, static_cast<std::size_t>(columns - 3)) + "..." : text.substr(0, 0);
    }

    // The panel as lines of a character grid (Courier New is monospaced).
    struct Item
    {
      int column = 0;
      std::string text;
      std::uint32_t color = 0xFFFFFFFFu;
      std::optional<Click> click; // a button
      bool active = false;        // the button's current setting
      bool disabled = false;
    };

    struct Line
    {
      std::vector<Item> items;
      std::optional<Click> rowClick; // the whole line selects
      bool selected = false;
    };

    constexpr std::uint32_t kText = 0xFFFFFFFFu;
    constexpr std::uint32_t kHeading = 0xFFB0D0FFu;
    constexpr std::uint32_t kDim = 0xFFB0B0B0u;
    constexpr std::uint32_t kGood = 0xFF90E090u;
    constexpr std::uint32_t kBad = 0xFFFF9080u;

    class Builder
    {
    public:
      explicit Builder(const int columns) : mColumns(columns) {}

      Line& NewLine()
      {
        mLines.emplace_back();
        mColumn = 0;
        return mLines.back();
      }

      void Text(const std::string& text, const std::uint32_t color = kText)
      {
        Current().items.push_back({mColumn, Cut(text, mColumns - mColumn), color, std::nullopt, false, false});
        mColumn += static_cast<int>(text.size());
      }

      void TextAt(const int column, const std::string& text, const std::uint32_t color = kText)
      {
        mColumn = column;
        Text(text, color);
      }

      // "[ label ]"; wraps to a new line when it doesn't fit.
      void Button(const std::string& label, const Click& click, const bool active = false, const bool disabled = false)
      {
        const int width = static_cast<int>(label.size()) + 2;
        if (mColumn > 0 && mColumn + width > mColumns) {
          NewLine();
          mColumn = 2;
        }
        Current().items.push_back({mColumn, " " + label + " ", active ? kGood : kText, click, active, disabled});
        mColumn += width + 1;
      }

      // Buttons flush right on the current line.
      void RightButtons(const std::vector<std::pair<std::string, Click>>& buttons)
      {
        int width = 0;
        for (const auto& [label, click] : buttons) {
          width += static_cast<int>(label.size()) + 3;
        }
        mColumn = std::max(mColumn + 1, mColumns - width + 1);
        for (const auto& [label, click] : buttons) {
          Button(label, click);
        }
      }

      [[nodiscard]] std::vector<Line>& Lines() { return mLines; }
      [[nodiscard]] int Columns() const { return mColumns; }

    private:
      Line& Current() { return mLines.empty() ? NewLine() : mLines.back(); }

      int mColumns;
      int mColumn = 0;
      std::vector<Line> mLines;
    };

    /** Plan WP10.10: a server-mode game's bytes from the server by lane: the last seconds' rate and the total. */
    [[nodiscard]] bool BuildServerLanes(Builder& b)
    {
      using faf::remote::client::CServerLaneMeter;
      using faf::remote::client::EServerLane;
      const faf::remote::client::SServerLaneSnapshot lanes = CServerLaneMeter::Get().Snapshot();
      if (!lanes.active) {
        return false;
      }
      char text[160];
      double rate = 0.0;
      std::uint64_t total = 0;
      for (std::size_t lane = 0; lane < faf::remote::client::kServerLaneCount; ++lane) {
        rate += lanes.perSecond[lane];
        total += lanes.total[lane];
      }
      b.NewLine();
      std::snprintf(text, sizeof(text), "Server: %llu views, %.1f KB/s, %.1f MB in all", static_cast<unsigned long long>(lanes.views),
                    rate / 1024.0, static_cast<double>(total) / 1048576.0);
      b.Text(text, kHeading);
      b.NewLine();
      std::snprintf(text, sizeof(text), "  %-10s %10s %10s %7s", "lane", "KB/s", "MB", "share");
      b.Text(text, kDim);
      for (std::size_t lane = 0; lane < faf::remote::client::kServerLaneCount; ++lane) {
        b.NewLine();
        std::snprintf(text, sizeof(text), "  %-10s %10.1f %10.2f %6.1f%%", faf::remote::client::ServerLaneName(static_cast<EServerLane>(lane)),
                      lanes.perSecond[lane] / 1024.0, static_cast<double>(lanes.total[lane]) / 1048576.0,
                      total != 0u ? 100.0 * static_cast<double>(lanes.total[lane]) / static_cast<double>(total) : 0.0);
        b.Text(text);
      }
      b.NewLine();
      return true;
    }

    void BuildPeers(Builder& b, const SNetlinkSnapshot& view, const std::optional<std::int64_t> selected)
    {
      const bool serverGame = BuildServerLanes(b);
      if (view.mode.empty() && serverGame) {
        return; // a server game: its one link is the server's, above
      }
      if (view.mode.empty()) {
        b.NewLine();
        b.Text("The launcher's ICE adapter runs the links, not this game: nothing to act on here.", kDim);
        return;
      }
      if (view.peers.empty()) {
        b.NewLine();
        b.Text("No peers yet.", kDim);
        return;
      }
      // Columns sized to their longest cell.
      std::vector<std::vector<std::string>> rows;
      rows.push_back({"peer", "state", "path", "round trip", "loss", "resends", "lane", "picked"});
      for (const SNetlinkPeerInfo& p : view.peers) {
        rows.push_back({
          PeerName(p),
          p.state + (p.attempts > 1 ? " #" + std::to_string(p.attempts) : ""),
          NETPANEL_PathText(p),
          p.rttMs >= 0 ? Format("%.1f ms", p.rttMs) : "-",
          p.received > 0 ? Format("%.2f %%", p.lossPercent) : "-",
          std::to_string(p.resends),
          p.onLane ? (p.laneEncrypted ? "encrypted" : "plain") : "off",
          nl::PathChoiceText(p.choice),
        });
      }
      std::vector<int> widths(rows[0].size(), 0);
      for (const auto& row : rows) {
        for (std::size_t c = 0; c < row.size(); ++c) {
          widths[c] = std::max(widths[c], static_cast<int>(row[c].size()));
        }
      }
      for (std::size_t r = 0; r < rows.size(); ++r) {
        Line& line = b.NewLine();
        int column = 0;
        const SNetlinkPeerInfo* peer = r > 0 ? &view.peers[r - 1] : nullptr;
        if (peer != nullptr) {
          Click click;
          click.kind = Click::Kind::SelectPeer;
          click.peer = peer->id;
          line.rowClick = click;
          line.selected = selected && *selected == peer->id;
        }
        for (std::size_t c = 0; c < rows[r].size(); ++c) {
          std::uint32_t color = r == 0 ? kHeading : kText;
          if (peer != nullptr && c == 1) {
            color = peer->connected ? kGood : kBad;
          }
          b.TextAt(column, rows[r][c], color);
          column += widths[c] + 2;
        }
      }

      b.NewLine();
      const auto it = std::find_if(view.peers.begin(), view.peers.end(), [&](const SNetlinkPeerInfo& p) {
        return selected && p.id == *selected;
      });
      if (it == view.peers.end()) {
        b.NewLine();
        b.Text("Click a peer to reconnect it or to pick the path its link takes.", kDim);
        return;
      }
      const SNetlinkPeerInfo& p = *it;
      const auto reconnect = [&](const std::optional<nl::PathChoice>& choice) {
        Click click;
        click.kind = Click::Kind::Reconnect;
        click.peer = p.id;
        click.peerName = PeerName(p);
        click.choice = choice;
        return click;
      };
      b.NewLine();
      b.Text(PeerName(p) + ":", kHeading);
      b.NewLine();
      b.TextAt(2, "");
      b.Button("Reconnect", reconnect(std::nullopt));
      nl::PathChoice choice;
      choice.mode = nl::PathChoice::Mode::Auto;
      b.Button("Auto", reconnect(choice), p.choice == choice);
      choice.mode = nl::PathChoice::Mode::RelayOnly;
      b.Button("Relay only", reconnect(choice), p.choice == choice);
      choice.mode = nl::PathChoice::Mode::NoRelay;
      b.Button("No relay", reconnect(choice), p.choice == choice, view.forceRelay);
      if (!view.turnServers.empty()) {
        b.NewLine();
        b.TextAt(2, "Relay via ", kDim);
        for (const std::string& server : view.turnServers) {
          nl::PathChoice via;
          via.mode = nl::PathChoice::Mode::RelayOnly;
          via.turnServer = server;
          b.Button(server, reconnect(via), p.choice == via);
        }
      }
      b.NewLine();
      b.TextAt(2, view.forceRelay ? "This game takes relayed candidates only (/nativenetrelay)." :
                                    "Auto: every candidate type first, fewer after failed attempts, as FAF's adapter.",
               kDim);
    }

    void BuildLog(Builder& b, const SNetlinkSnapshot& view, int& scroll)
    {
      const std::string file = NETDIAG_LogFilePath();
      b.NewLine();
      b.Text("Log file: " + (file.empty() ? std::string("none (the game runs without /log)") : file), kHeading);
      const int total = static_cast<int>(view.log.size());
      scroll = std::clamp(scroll, 0, std::max(0, total - kLogLines));
      const int last = total - scroll; // exclusive
      const int first = std::max(0, last - kLogLines);
      for (int i = first; i < last; ++i) {
        b.NewLine();
        b.Text(view.log[static_cast<std::size_t>(i)], kDim);
      }
      for (int i = last - first; i < kLogLines; ++i) {
        b.NewLine(); // the page keeps its height
      }
      b.NewLine();
      b.NewLine();
      Click older;
      older.kind = Click::Kind::LogOlder;
      Click newer;
      newer.kind = Click::Kind::LogNewer;
      Click copy;
      copy.kind = Click::Kind::CopyLog;
      b.Button("Older", older, false, first == 0);
      b.Button("Newer", newer, false, scroll == 0);
      b.Button("Copy log", copy, false, total == 0);
      b.Text(total == 0 ? " no network log lines yet" :
                          " lines " + std::to_string(first + 1) + "-" + std::to_string(last) + " of " + std::to_string(total) +
                            " (mouse wheel scrolls)",
             kDim);
    }

    void BuildServers(Builder& b, const SNetlinkSnapshot& view)
    {
      if (view.mode.empty()) {
        b.NewLine();
        b.Text("The launcher's ICE adapter holds the ICE servers.", kDim);
        return;
      }
      const auto all = [](const nl::PathChoice& choice) {
        Click click;
        click.kind = Click::Kind::AllPeers;
        click.choice = choice;
        return click;
      };
      b.NewLine();
      b.Text("TURN servers (relays), for new links and reconnects:", kHeading);
      if (view.turnServers.empty()) {
        b.NewLine();
        b.TextAt(2, "none: links can't relay", kBad);
      }
      for (const std::string& server : view.turnServers) {
        b.NewLine();
        b.TextAt(2, server);
        nl::PathChoice via;
        via.mode = nl::PathChoice::Mode::RelayOnly;
        via.turnServer = server;
        b.TextAt(std::max(30, static_cast<int>(server.size()) + 4), "");
        b.Button("Every peer through this relay", all(via), false, view.peers.empty());
      }
      b.NewLine();
      b.Text("STUN servers:", kHeading);
      if (view.stunServers.empty()) {
        b.NewLine();
        b.TextAt(2, "none (TURN servers answer STUN too)", kDim);
      }
      for (const std::string& server : view.stunServers) {
        b.NewLine();
        b.TextAt(2, server);
      }
      b.NewLine();
      b.NewLine();
      b.Text("Every peer: ", kHeading);
      nl::PathChoice choice;
      b.Button("Auto", all(choice), false, view.peers.empty());
      choice.mode = nl::PathChoice::Mode::RelayOnly;
      b.Button("Relay only", all(choice), false, view.peers.empty());
      choice.mode = nl::PathChoice::Mode::NoRelay;
      b.Button("No relay", all(choice), false, view.peers.empty() || view.forceRelay);
    }

    void Flash(PanelState& state, std::string text)
    {
      state.flash = std::move(text);
      state.flashUntil = Clock::now() + std::chrono::seconds(4);
    }

    // A click on the panel. Main thread; no panel lock held.
    void Apply(const Click& click, void* const window)
    {
      PanelState& state = State();
      switch (click.kind) {
        case Click::Kind::Tab: {
          std::lock_guard lock(state.mutex);
          state.tab = click.tab;
          return;
        }
        case Click::Kind::SelectPeer: {
          std::lock_guard lock(state.mutex);
          state.selected = state.selected && *state.selected == click.peer ? std::nullopt
                                                                           : std::optional<std::int64_t>(click.peer);
          return;
        }
        case Click::Kind::Reconnect: {
          const nl::PathChoice* const choice = click.choice ? &*click.choice : nullptr;
          const bool ok = NETLINK_ReconnectPeer(click.peer, choice);
          std::lock_guard lock(state.mutex);
          Flash(state, ok ? "Reconnecting " + click.peerName + (choice ? ", " + nl::PathChoiceText(*choice) : "") :
                            click.peerName + " has no link any more");
          return;
        }
        case Click::Kind::AllPeers: {
          int n = 0;
          for (const SNetlinkPeerInfo& p : NETLINK_GetSnapshot().peers) {
            n += NETLINK_ReconnectPeer(p.id, click.choice ? &*click.choice : nullptr) ? 1 : 0;
          }
          std::lock_guard lock(state.mutex);
          Flash(state, "Reconnecting " + std::to_string(n) + " peers, " +
                         (click.choice ? nl::PathChoiceText(*click.choice) : std::string("as they were")));
          return;
        }
        case Click::Kind::Close:
          net_ShowPanel = false;
          return;
        case Click::Kind::CopyDiagnostics: {
          const bool ok = NETDIAG_CopyText(window, NETDIAG_Text());
          gpg::Logf("NETLINK: panel: diagnostics %s", ok ? "copied to the clipboard" : "not copied");
          std::lock_guard lock(state.mutex);
          Flash(state, ok ? "Diagnostics copied to the clipboard" : "The clipboard is busy, try again");
          return;
        }
        case Click::Kind::LogFolder: {
          const std::string result = NETDIAG_OpenLogFolder(window);
          std::lock_guard lock(state.mutex);
          Flash(state, result);
          return;
        }
        case Click::Kind::CopyLog: {
          std::string text;
          for (const std::string& line : NETLINK_GetSnapshot().log) {
            text += line + "\r\n";
          }
          const bool ok = NETDIAG_CopyText(window, text);
          std::lock_guard lock(state.mutex);
          Flash(state, ok ? "Network log copied to the clipboard" : "The clipboard is busy, try again");
          return;
        }
        case Click::Kind::LogOlder: {
          std::lock_guard lock(state.mutex);
          state.logScroll += kLogLines / 2;
          return;
        }
        case Click::Kind::LogNewer: {
          std::lock_guard lock(state.mutex);
          state.logScroll = std::max(0, state.logScroll - kLogLines / 2);
          return;
        }
      }
    }
  } // namespace

  std::string NETPANEL_PathText(const SNetlinkPeerInfo& p)
  {
    if (!p.connected || p.localType.empty()) {
      return "-";
    }
    const bool relayed = p.localType == "relay" || p.remoteType == "relay";
    return std::string(relayed ? "relayed" : "direct") + " (" + p.localType + "/" + p.remoteType + ")";
  }

  void NETPANEL_DrawServerLanes(CD3DPrimBatcher* const batcher, const float right, const float top)
  {
    using faf::remote::client::CServerLaneMeter;
    using faf::remote::client::EServerLane;
    const faf::remote::client::SServerLaneSnapshot lanes = CServerLaneMeter::Get().Snapshot();
    if (batcher == nullptr || !lanes.active) {
      return;
    }
    const int points = std::max(1, static_cast<int>(std::lround(10.0f * UiScale())));
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(points, PanelFace());
    CD3DFont* const font = rawFont.px;
    if (font == nullptr) {
      return;
    }
    double rate = 0.0;
    for (const double lane : lanes.perSecond) {
      rate += lane;
    }
    std::vector<std::string> lines;
    char text[96];
    std::snprintf(text, sizeof(text), "server %.1f KB/s", rate / 1024.0);
    lines.emplace_back(text);
    for (std::size_t lane = 0; lane < faf::remote::client::kServerLaneCount; ++lane) {
      std::snprintf(text, sizeof(text), "%s %.1f KB/s", faf::remote::client::ServerLaneName(static_cast<EServerLane>(lane)),
                    lanes.perSecond[lane] / 1024.0);
      lines.emplace_back(text);
    }
    const float rowStep = font->mHeight + font->mExternalLeading;
    float widest = 0.0f;
    for (const std::string& line : lines) {
      widest = std::max(widest, font->GetAdvance(line.c_str(), -1));
    }
    constexpr float kPad = 4.0f;
    const float left = right - widest - kPad;
    const float bottom = top + rowStep * static_cast<float>(lines.size()) + kPad;
    constexpr std::uint32_t kBackdrop = 0xC0000000u;
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
    batcher->DrawQuad(
      {left, top - kPad, 0.0f, kBackdrop, 0.0f, 0.0f}, {right + kPad, top - kPad, 0.0f, kBackdrop, 0.0f, 0.0f},
      {right + kPad, bottom, 0.0f, kBackdrop, 0.0f, 0.0f}, {left, bottom, 0.0f, kBackdrop, 0.0f, 0.0f}
    );
    const Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Vector3f yAxis{0.0f, -1.0f, 0.0f};
    for (std::size_t r = 0; r < lines.size(); ++r) {
      const float x = right - font->GetAdvance(lines[r].c_str(), -1);
      (void)font->Render(
        lines[r].c_str(), batcher, {x, top + rowStep * static_cast<float>(r) + font->mAscent, 0.0f}, xAxis, yAxis,
        r == 0 ? kHeading : kText, 0.0f, gpg::NaN
      );
    }
    rawFont.release();
  }

  void NETPANEL_Toggle()
  {
    net_ShowPanel = !net_ShowPanel;
  }

  void NETPANEL_Draw(CD3DPrimBatcher* const batcher, const float headWidth, const float headHeight)
  {
    PanelState& state = State();
    if (!net_ShowPanel || batcher == nullptr) {
      std::lock_guard lock(state.mutex);
      state.panel.reset();
      state.hits.clear();
      return;
    }
    NETLINK_KeepLogLines(); // from now on, also in a game that runs no links
    const SNetlinkSnapshot view = NETLINK_GetSnapshot();

    const int points = std::max(1, static_cast<int>(std::lround(10.0f * UiScale())));
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(points, PanelFace());
    CD3DFont* const font = rawFont.px;
    if (font == nullptr) {
      return;
    }
    constexpr float kPad = 6.0f;
    const float charWidth = std::max(1.0f, font->GetAdvance("M", -1));
    const float rowStep = font->mHeight + font->mExternalLeading + 4.0f; // room for button boxes
    const float left = 25.0f;
    const float top = 25.0f;
    const int columns =
      std::clamp(static_cast<int>((headWidth - 2.0f * left - 2.0f * kPad) / charWidth), 20, kMaxColumns);

    Tab tab;
    std::optional<std::int64_t> selected;
    int scroll;
    float mouseX;
    float mouseY;
    std::string flash;
    {
      std::lock_guard lock(state.mutex);
      tab = state.tab;
      selected = state.selected;
      scroll = state.logScroll;
      mouseX = state.mouseX;
      mouseY = state.mouseY;
      if (Clock::now() < state.flashUntil) {
        flash = state.flash;
      }
    }

    Builder b(columns);
    b.NewLine();
    const std::string title = view.mode.empty() ? "Network" :
                                                  "Network: " + view.mode + " links, " + std::to_string(view.peers.size()) +
                                                    " peer" + (view.peers.size() == 1 ? "" : "s");
    b.Text(title, kHeading);
    Click diag;
    diag.kind = Click::Kind::CopyDiagnostics;
    Click folder;
    folder.kind = Click::Kind::LogFolder;
    Click close;
    close.kind = Click::Kind::Close;
    b.RightButtons({{"Copy diagnostics", diag}, {"Log folder", folder}, {"X", close}});
    b.NewLine();
    const auto tabButton = [&](const std::string& label, const Tab which) {
      Click click;
      click.kind = Click::Kind::Tab;
      click.tab = which;
      b.Button(label, click, tab == which);
    };
    tabButton("Peers", Tab::Peers);
    tabButton("Log (" + std::to_string(view.log.size()) + ")", Tab::Log);
    tabButton("ICE servers (" + std::to_string(view.turnServers.size() + view.stunServers.size()) + ")", Tab::Servers);
    b.NewLine();
    if (tab == Tab::Peers) {
      BuildPeers(b, view, selected);
    } else if (tab == Tab::Log) {
      BuildLog(b, view, scroll);
    } else {
      BuildServers(b, view);
    }
    b.NewLine();
    b.NewLine();
    b.Text(flash.empty() ? "Ctrl+Shift+F11 closes this panel." : flash, flash.empty() ? kDim : kGood);

    std::vector<Line>& lines = b.Lines();
    const float width = static_cast<float>(columns) * charWidth + 2.0f * kPad;
    const float height = rowStep * static_cast<float>(lines.size()) + 2.0f * kPad;
    const float right = left + width;
    const float bottom = std::min(top + height, std::max(top + rowStep, headHeight - 5.0f));

    const boost::shared_ptr<CD3DBatchTexture> white = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
    const auto quad = [&](const Box& box, const std::uint32_t color) {
      batcher->SetTexture(white);
      batcher->DrawQuad(
        {box.left, box.top, 0.0f, color, 0.0f, 0.0f}, {box.right, box.top, 0.0f, color, 0.0f, 0.0f},
        {box.right, box.bottom, 0.0f, color, 0.0f, 0.0f}, {box.left, box.bottom, 0.0f, color, 0.0f, 0.0f}
      );
    };
    quad({left, top, right, bottom}, 0xD0000000u);

    std::vector<Hit> hits;
    const Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Vector3f yAxis{0.0f, -1.0f, 0.0f};
    for (std::size_t r = 0; r < lines.size(); ++r) {
      const float lineTop = top + kPad + rowStep * static_cast<float>(r);
      if (lineTop + rowStep > bottom) {
        break; // a window too short for the whole panel
      }
      const Line& line = lines[r];
      const Box row{left + 2.0f, lineTop, right - 2.0f, lineTop + rowStep};
      if (line.rowClick) {
        const bool hover = row.Has(mouseX, mouseY);
        if (line.selected || hover) {
          quad(row, line.selected ? 0x80305080u : 0x30FFFFFFu);
        }
      }
      for (const Item& item : line.items) {
        const float x = left + kPad + static_cast<float>(item.column) * charWidth;
        std::uint32_t color = item.disabled ? 0xFF707070u : item.color;
        if (item.click) {
          const Box box{x, lineTop + 1.0f, x + static_cast<float>(item.text.size()) * charWidth, lineTop + rowStep - 1.0f};
          const bool hover = !item.disabled && box.Has(mouseX, mouseY);
          quad(box, item.disabled ? 0xFF282828u : hover ? 0xFF4A6088u : item.active ? 0xFF2E5A36u : 0xFF33394Au);
          if (!item.disabled) {
            hits.push_back({box, *item.click});
          }
        }
        (void)font->Render(
          item.text.c_str(), batcher, {x, lineTop + 2.0f + font->mAscent, 0.0f}, xAxis, yAxis, color, 0.0f, gpg::NaN
        );
      }
      if (line.rowClick) {
        hits.push_back({row, *line.rowClick}); // after the buttons: they win
      }
    }

    batcher->SetTexture(white);
    constexpr std::uint32_t kBorder = 0xFF808080u;
    const CD3DPrimBatcher::Vertex tl{left, top, 0.0f, kBorder, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex tr{right, top, 0.0f, kBorder, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex br{right, bottom, 0.0f, kBorder, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bl{left, bottom, 0.0f, kBorder, 0.0f, 0.0f};
    batcher->DrawLine(tl, tr);
    batcher->DrawLine(tr, br);
    batcher->DrawLine(br, bl);
    batcher->DrawLine(bl, tl);
    rawFont.release();

    std::lock_guard lock(state.mutex);
    state.panel = Box{left, top, right, bottom};
    state.headWidth = headWidth;
    state.headHeight = headHeight;
    state.hits = std::move(hits);
    state.logScroll = scroll; // clamped to the log's length
  }

  bool NETPANEL_OnMouse(
    void* const window,
    const unsigned message,
    const int x,
    const int y,
    const int clientWidth,
    const int clientHeight,
    const int wheel
  )
  {
    PanelState& state = State();
    std::optional<Click> clicked;
    bool taken = false;
    {
      std::lock_guard lock(state.mutex);
      // Client pixels to the head's units, which match unless the back buffer is scaled.
      float px = static_cast<float>(x);
      float py = static_cast<float>(y);
      if (clientWidth > 0 && clientHeight > 0 && state.headWidth > 0.0f && state.headHeight > 0.0f) {
        px *= state.headWidth / static_cast<float>(clientWidth);
        py *= state.headHeight / static_cast<float>(clientHeight);
      }
      state.mouseX = px;
      state.mouseY = py;
      const bool open = net_ShowPanel && state.panel.has_value();
      const bool onPanel = open && state.panel->Has(px, py);
      const auto hitAt = [&]() -> std::optional<Hit> {
        for (const Hit& hit : state.hits) {
          if (hit.box.Has(px, py)) {
            return hit;
          }
        }
        return std::nullopt;
      };
      switch (message) {
        case kMouseMove:
          return false; // the game keeps its cursor
        case kLeftDown:
        case kLeftDouble:
          if (!onPanel) {
            return false;
          }
          state.leftDown = true;
          state.pressed = hitAt();
          return true;
        case kLeftUp: {
          if (!state.leftDown) {
            return false; // a press the game took
          }
          state.leftDown = false;
          const std::optional<Hit> hit = hitAt();
          if (hit && state.pressed && hit->box.left == state.pressed->box.left && hit->box.top == state.pressed->box.top) {
            clicked = hit->click;
          }
          state.pressed.reset();
          taken = true;
          break;
        }
        case kRightDown:
        case kRightDouble:
        case kMiddleDown:
        case kMiddleDouble:
          if (!onPanel) {
            return false;
          }
          state.otherDown = true;
          return true;
        case kRightUp:
        case kMiddleUp:
          if (!state.otherDown) {
            return false;
          }
          state.otherDown = false;
          return true;
        case kWheel:
          if (!onPanel) {
            return false;
          }
          if (state.tab == Tab::Log) {
            state.logScroll = std::max(0, state.logScroll + (wheel > 0 ? 3 : -3));
          }
          return true;
        default:
          return false;
      }
    }
    if (clicked) {
      Apply(*clicked, window);
    }
    return taken;
  }
} // namespace moho
