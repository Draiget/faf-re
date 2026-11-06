#include "moho/app/NetworkPanel.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/NetlinkPeers.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  bool net_ShowPanel = false;

  namespace
  {
    TConVar<bool> gTConVar_net_ShowPanel(
      "net_ShowPanel",
      "1: show the network panel (the game's peer links and the latest network log lines); 0 (default) hides it. "
      "Ctrl+Shift+F11 flips it.",
      &net_ShowPanel
    );

    constexpr std::size_t kLogLineChars = 110; // longer log lines are cut

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

    [[nodiscard]] std::string Format(const char* format, const double value)
    {
      char buf[64];
      std::snprintf(buf, sizeof(buf), format, value);
      return buf;
    }

    // The panel's text, as rows of cells; a row with one cell is a full-width line.
    [[nodiscard]] std::vector<std::vector<std::string>> BuildRows(const SNetlinkSnapshot& view)
    {
      std::vector<std::vector<std::string>> rows;
      if (view.mode.empty()) {
        rows.push_back({"Network: the links belong to the launcher's ICE adapter, not to this game."});
      } else {
        rows.push_back({"Network: " + view.mode + " links, " + std::to_string(view.peers.size()) + " peer" +
                        (view.peers.size() == 1 ? "" : "s")});
        rows.push_back({"peer", "state", "path", "round trip", "loss", "resends", "lane"});
        for (const SNetlinkPeerInfo& p : view.peers) {
          rows.push_back({
            p.login + " (" + std::to_string(p.id) + ")",
            p.state + (p.attempts > 1 ? " #" + std::to_string(p.attempts) : ""),
            NETPANEL_PathText(p),
            p.rttMs >= 0 ? Format("%.1f ms", p.rttMs) : "-",
            p.received > 0 ? Format("%.2f %%", p.lossPercent) : "-",
            std::to_string(p.resends),
            p.onLane ? (p.laneEncrypted ? "encrypted" : "plain") : "off",
          });
        }
      }
      if (!view.log.empty()) {
        rows.push_back({""});
        for (const std::string& line : view.log) {
          rows.push_back({line.size() > kLogLineChars ? line.substr(0, kLogLineChars - 3) + "..." : line});
        }
      }
      return rows;
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

  void NETPANEL_Toggle()
  {
    net_ShowPanel = !net_ShowPanel;
  }

  void NETPANEL_Draw(CD3DPrimBatcher* const batcher, const float headWidth, const float headHeight)
  {
    if (!net_ShowPanel || batcher == nullptr) {
      return;
    }
    NETLINK_KeepLogLines(); // from now on, also in a game that runs no links
    const std::vector<std::vector<std::string>> rows = BuildRows(NETLINK_GetSnapshot());

    const int points = std::max(1, static_cast<int>(std::lround(10.0f * UiScale())));
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(points, "Courier New");
    CD3DFont* const font = rawFont.px;
    if (font == nullptr) {
      return;
    }

    // Column widths over the table rows; full-width lines only widen the panel.
    constexpr float kPad = 6.0f;
    constexpr float kGap = 12.0f;
    std::vector<float> columns;
    float lineWidth = 0.0f;
    for (const std::vector<std::string>& row : rows) {
      if (row.size() == 1) {
        lineWidth = std::max(lineWidth, font->GetAdvance(row[0].c_str(), -1));
        continue;
      }
      columns.resize(std::max(columns.size(), row.size()), 0.0f);
      for (std::size_t c = 0; c < row.size(); ++c) {
        columns[c] = std::max(columns[c], font->GetAdvance(row[c].c_str(), -1));
      }
    }
    float tableWidth = 0.0f;
    for (const float w : columns) {
      tableWidth += w + kGap;
    }
    const float width = std::min(std::max(tableWidth, lineWidth) + 2.0f * kPad, headWidth - 50.0f);
    const float rowStep = font->mHeight + font->mExternalLeading;
    const float height = rowStep * static_cast<float>(rows.size()) + 2.0f * kPad;

    // Top left, below where the lobby and the game keep their own controls' margin.
    const float left = 25.0f;
    const float top = std::min(25.0f, std::max(0.0f, headHeight - height));
    const float right = left + width;
    const float bottom = top + height;

    const boost::shared_ptr<CD3DBatchTexture> white = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
    batcher->SetTexture(white);
    constexpr std::uint32_t kBackdrop = 0xC0000000u;
    batcher->DrawQuad(
      {left, top, 0.0f, kBackdrop, 0.0f, 0.0f}, {right, top, 0.0f, kBackdrop, 0.0f, 0.0f},
      {right, bottom, 0.0f, kBackdrop, 0.0f, 0.0f}, {left, bottom, 0.0f, kBackdrop, 0.0f, 0.0f}
    );

    const Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Vector3f yAxis{0.0f, -1.0f, 0.0f};
    constexpr std::uint32_t kText = 0xFFFFFFFFu;
    constexpr std::uint32_t kHeading = 0xFFB0D0FFu;
    constexpr std::uint32_t kLog = 0xFFB0B0B0u;
    float penY = top + kPad + font->mAscent;
    bool pastTable = false;
    for (std::size_t r = 0; r < rows.size(); ++r) {
      const std::vector<std::string>& row = rows[r];
      if (row.size() == 1) {
        pastTable = pastTable || (r > 0 && row[0].empty());
        const std::uint32_t color = r == 0 ? kHeading : pastTable ? kLog : kText;
        (void)font->Render(row[0].c_str(), batcher, {left + kPad, penY, 0.0f}, xAxis, yAxis, color, 0.0f, gpg::NaN);
      } else {
        float x = left + kPad;
        for (std::size_t c = 0; c < row.size(); ++c) {
          const std::uint32_t color = r == 1 ? kHeading : kText;
          (void)font->Render(row[c].c_str(), batcher, {x, penY, 0.0f}, xAxis, yAxis, color, 0.0f, gpg::NaN);
          x += columns[c] + kGap;
        }
      }
      penY += rowStep;
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
  }
} // namespace moho
