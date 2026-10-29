// Engine addition (dedicated-server plan WPL.4, WPR.11): the network-statistics HUD of
// CSimDriver::DrawNetworkStats (0x0073DFE0, ren_ShowNetworkStats), moved unchanged out of
// SimDriver.cpp as CSimDriver::DrawNetworkStatsPanel: it draws with the render device's font
// and primitive batcher. SimDriver.cpp's DrawNetworkStats reaches it through
// sSimDriverNetworkStatsDraw, which this file sets.
#include "SimDriver.h"
#include "moho/core/ThreadPlacement.h"
#include "legacy/math/X87Math.h"
#include "platform/X87Precision.h"

#include <algorithm>
#include <atomic>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <vector>

#include "boost/function.hpp"
#include <boost/bind.hpp>
#include <boost/ptr_container/exception.hpp>
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/app/WinApp.h"
#include "moho/net/CClientBase.h"
#include "moho/net/IClient.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/audio/SAudioRequest.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/TimeBar.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/render/CDecalTypes.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/unit/core/Unit.h"
#include "moho/misc/LaunchInfoBase.h"
#include "Sim.h"

using namespace moho;

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  /// The current profile's ui_scale option (what FAF's options menu writes),
  /// 1.0 when it is unset or not a number.
  [[nodiscard]] float CurrentUiScale()
  {
    IUserPrefs* const prefs = USER_GetPreferences();
    if (prefs == nullptr) {
      return 1.0f;
    }
    const LuaPlus::LuaObject value = prefs->LookupCurrentOption("ui_scale");
    if (!value.IsNumber()) {
      return 1.0f;
    }
    return std::clamp(static_cast<float>(value.GetNumber()), 0.5f, 4.0f);
  }
} // namespace


/**
 * Address: 0x0073DFE0 (FUN_0073DFE0), ISTIDriver slot 39
 *
 * IDA signature:
 * void __thiscall Moho::CSimDriver::DrawNetworkStats(
 *     CSimDriver *this, CD3DPrimBatcher *batcher, float anchorX, float anchorY,
 *     float scaleX, float scaleY);
 *
 * What it does:
 * The body of CSimDriver::DrawNetworkStats (see SimDriver.h).
 * Builds the network-diagnostics HUD (ren_ShowNetworkStats): a 4-line summary
 * block over a per-client table with 7 + N columns (index, nickname, ping,
 * maxsp, data, behind, avail, then one ack column per client), measures the
 * columns with a Courier New font, draws a translucent backdrop quad, renders
 * the cells (numbers right-justified) and strokes a white border. Runs
 * entirely under the driver lock.
 */
void CSimDriver::DrawNetworkStatsPanel(
  CD3DPrimBatcher* batcher, const float anchorX, const float anchorY, const float scaleX, const float scaleY
)
{
  boost::mutex::scoped_lock lock(mLock); // 0x0073E014 do_lock / 0x0073F40D unlock

  // Courier New font handle (0x0073E042). Held as a raw retained handle;
  // released explicitly at function exit (0x0073F3D3 releases the CountedPtr).
  // Retail asks for a fixed 10pt (0x0073E03F: lea ecx, [esi+0xA]).
  // [DELIBERATE-FIX] The point size follows the profile's ui_scale option so
  // the HUD is as large as the rest of the UI; every measurement below comes
  // from the font, so the whole panel scales with it. Pass 10 to go back to
  // retail's size.
  const int fontPoints = std::max(1, static_cast<int>(std::lround(10.0f * CurrentUiScale())));
  boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(fontPoints, "Courier New");
  CD3DFont* const font = rawFont.px;

  const std::size_t numClients = mClientManager->NumberOfClients(); // 0x0073E057 (mgr slot 6)

  // ---- Table columns: index, nickname, ping, maxsp, data, behind, avail, then
  // one ack column per client (0x0073E078: numClients + 7 inner vectors).
  constexpr std::size_t kFirstAckColumn = 7;
  msvc8::vector<msvc8::vector<msvc8::string>> columns(numClients + kFirstAckColumn);

  // Header row (0x0073E098..0x0073E28F).
  columns[0].push_back(msvc8::string(""));        // 0x0073E098 index header (empty)
  columns[1].push_back(msvc8::string(""));        // 0x0073E0FA nickname header (empty)
  columns[2].push_back(msvc8::string(" ping"));   // 0x0073E14B
  columns[3].push_back(msvc8::string(" maxsp"));  // 0x0073E19C
  columns[4].push_back(msvc8::string(" data"));   // 0x0073E1ED
  columns[5].push_back(msvc8::string(" behind")); // 0x0073E23E
  columns[6].push_back(msvc8::string(" avail"));  // 0x0073E28F

  // Each ack column is headed by the index of the client whose data it
  // counts (0x0073E2E8..0x0073E357: " %3d" into columns[7 + i]).
  for (std::size_t i = 0; i < numClients; ++i) {
    columns[kFirstAckColumn + i].push_back(gpg::STR_Printf(" %3d", static_cast<int>(i))); // 0x0073E310
  }

  // Beat cells are relative: data and behind to the beat we last dispatched
  // (mDispatchBeat - 1, loaded at 0x0073E091 into the slot 0x0073E499 and
  // 0x0073E4DC read), avail and the acks to the beat that client last
  // dispatched (GetLatestBeatDispatchedRemote at 0x0073E3F2).
  const std::int32_t lastDispatchedBeat = mDispatchBeat - 1;

  // Per-client body rows (0x0073E367..0x0073E681).
  for (std::size_t i = 0; i < numClients; ++i) {
    IClient* const client = mClientManager->GetClient(static_cast<int>(i)); // 0x0073E374 (mgr slot 7)

    columns[0].push_back(gpg::STR_Printf("%d: ", static_cast<int>(i))); // 0x0073E38B (row label)
    columns[1].push_back(client->GetNickname());                        // 0x0073E3D0 (nickname)

    if (!client->NoEjectionPending()) { // 0x0073E3DE (client slot 1)
      // Ejection pending: every remaining column, the ack columns included,
      // gets an empty cell so the rows stay aligned (0x0073E929..0x0073E9AB).
      for (std::size_t c = 2; c < columns.size(); ++c) {
        columns[c].push_back(msvc8::string("")); // 0x0073E96D
      }
      continue;
    }

    std::uint32_t remoteDispatchedBeat = 0;
    client->GetLatestBeatDispatchedRemote(remoteDispatchedBeat); // 0x0073E3F2 (client slot 5)
    const int remoteDispatched = static_cast<int>(remoteDispatchedBeat);

    const float ping = client->GetStatusMetricA();          // 0x0073E3FB (client slot 2)
    columns[2].push_back(gpg::STR_Printf(" %7.3fms", ping)); // 0x0073E40D

    columns[3].push_back(gpg::STR_Printf(" %+3d", client->GetSimRate())); // 0x0073E455 (client slot 12)

    // data: how far this client's queued commands run past our last dispatched beat.
    std::uint32_t queuedBeat = 0;
    client->GetQueuedBeat(queuedBeat); // 0x0073E495 (client slot 9)
    columns[4].push_back(gpg::STR_Printf(" %3d", static_cast<int>(queuedBeat) - lastDispatchedBeat)); // 0x0073E499

    // behind: how many beats this client's dispatch trails ours.
    columns[5].push_back(gpg::STR_Printf(" %3d", lastDispatchedBeat - remoteDispatched)); // 0x0073E4E0

    // avail: beats the client has available but not yet dispatched.
    std::uint32_t availableBeatRemote = 0;
    client->GetAvailableBeatRemote(availableBeatRemote); // 0x0073E531 (client slot 6)
    columns[6].push_back(gpg::STR_Printf(" %3d", static_cast<int>(availableBeatRemote) - remoteDispatched)); // 0x0073E535

    // One ack cell per client j: how far this client has acked j's data past
    // its own dispatch. A client being ejected gets a blank cell
    // (0x0073E5A1 GetClient(j), 0x0073E5AA NoEjectionPending, 0x0073E600).
    const msvc8::vector<int32_t>* const acks = client->GetLatestAcksVector(); // 0x0073E57F (client slot 4)
    for (std::size_t j = 0; j < numClients; ++j) {
      msvc8::vector<msvc8::string>& ackColumn = columns[kFirstAckColumn + j];
      if (mClientManager->GetClient(static_cast<int>(j))->NoEjectionPending()) {
        ackColumn.push_back(gpg::STR_Printf(" %3d", (*acks)[j] - remoteDispatched)); // 0x0073E5C0
      } else {
        ackColumn.push_back(msvc8::string("")); // 0x0073E620
      }
    }
  }

  // ---- Summary block: 4 lines (0x0073E687..0x0073E876).
  msvc8::vector<msvc8::string> summary;

  {
    int availableBeat = 0;
    mClientManager->GetAvailableBeat(availableBeat); // 0x0073E6BA (mgr slot 21)

    const int inflight = (mNextIssueBeat - 1) - availableBeat;   // 0x0073E6D1..0x0073E6D8
    const int available = availableBeat - (mDispatchBeat - 1);   // 0x0073E6BC..0x0073E6CF
    const int queued = static_cast<int>(mSyncDataQueue.Size());  // 0x0073E6C6 (mSyncDataQueue._Mysize @ CSimDriver+0xA0)
    summary.push_back(
      gpg::STR_Printf("inflight: %d, available: %d, queued: %d", inflight, available, queued)); // 0x0073E6EB
  }

  {
    const float medianDispatchMs = mSimSpeedSamples.Median(); // 0x0073E731 (NetSpeeds::Median, no args)
    summary.push_back(gpg::STR_Printf(
      "sim time: %.3f, max speed=%+d", static_cast<double>(medianDispatchMs), mCurrentSimRate)); // 0x0073E74E
  }

  {
    const int desiredSpeed = mClientManager->GetSimRateRequested(); // 0x0073E79E (mgr slot 15)
    const int actualSpeed = mClientManager->GetSimRate();           // 0x0073E792 (mgr slot 14)
    summary.push_back(
      gpg::STR_Printf("desired speed: %+d, actual speed: %+d", desiredSpeed, actualSpeed)); // 0x0073E7AB
  }

  {
    const SClientBottleneckInfo bottleneck = mClientManager->GetBottleneckInfo(); // 0x0073E7EB (mgr slot 24)
    msvc8::string bottleneckLabel;
    FormatBottleneckLabel(bottleneck, bottleneckLabel);                 // 0x0073E80F (FUN_0053B6B0)
    summary.push_back(msvc8::string("bottleneck: ") + bottleneckLabel); // 0x0073E859 operator+
  }

  // ---- Per-column max-advance measurement (0x0073E9BC..0x0073EB2F).
  // colWidths[c] = max advance across every cell in column c. GetAdvance's flags
  // argument is -1 (canonical "whole string" form; matches sibling HUDs).
  std::vector<float> colWidths(columns.size(), 0.0f); // 0x0073E9CD

  // Running total table width, seeded with 6.0 (flt_E4F71C @0x0073E90E).
  float totalWidth = 6.0f;
  for (std::size_t c = 0; c < columns.size(); ++c) { // trip = columns.size() (0x0073E9B0)
    for (const msvc8::string& cell : columns[c]) {
      const float advance = font->GetAdvance(cell.c_str(), -1); // 0x0073EA68
      colWidths[c] = std::max(colWidths[c], advance);           // 0x0073EA75..0x0073EA7F
    }
    totalWidth += colWidths[c]; // 0x0073EA9B
  }

  // Summary lines are measured (advance + 3.0) into a running max, but the retail
  // frame overwrites that stack slot with the panel-bottom coordinate before it is
  // ever consumed -- so the result is dead. Preserved 1:1 (0x0073EAB6..0x0073EB2F,
  // slot reused at 0x0073EC10). Latent 2007 debug-HUD quirk.
  float summaryMax = 0.0f;
  for (const msvc8::string& line : summary) {
    const float advance = font->GetAdvance(line.c_str(), -1) + 3.0f; // 0x0073EB06/0x0073EB0B (flt_E4F718 == 3.0)
    summaryMax = std::max(summaryMax, advance);                      // 0x0073EB13..0x0073EB1A
  }
  (void)summaryMax; // dead in retail (overwritten by rectBottom before use)

  // ---- Backdrop rectangle geometry (0x0073EB2F..0x0073EC10).
  const int rowCount = static_cast<int>(columns[0].size());       // 0x0073EB2F..0x0073EB57
  const int summaryLineCount = static_cast<int>(summary.size());  // 0x0073EB59..0x0073EB80
  const int totalTextRows = rowCount + summaryLineCount;          // 0x0073EB82

  // Panel pixel height = mHeight*rows + mExternalLeading*(rows-1) + 6.0
  // (0x0073EB84..0x0073EBC4; the unsigned->float fixups are ordinary casts).
  const float tableHeight = font->mHeight * static_cast<float>(totalTextRows)
                            + font->mExternalLeading * static_cast<float>(totalTextRows - 1) + 6.0f;

  // Panel corners (floor() on the scaled extents). 0x0073EBC8..0x0073EC10.
  const float rectLeft = anchorX - std::floor(totalWidth * scaleX);  // 0x0073EBCC..0x0073EBD7
  const float rectRight = rectLeft + totalWidth;                     // 0x0073EBDE..0x0073EBE2
  const float rectTop = anchorY - std::floor(tableHeight * scaleY);  // 0x0073EBED..0x0073EBF8
  const float rectBottom = rectTop + tableHeight;                    // 0x0073EC0C..0x0073EC10

  // ---- Backdrop quad (semi-transparent black over a white texture). 0x0073EC14..0x0073ED81.
  {
    const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu); // 0x0073EC14
    batcher->SetTexture(whiteTex);                                                                       // 0x0073EC29

    constexpr std::uint32_t kBackdropColor = 0x80000000u; // 0x0073EC85
    const CD3DPrimBatcher::Vertex topLeft{rectLeft, rectTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex topRight{rectRight, rectTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomRight{rectRight, rectBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bottomLeft{rectLeft, rectBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
    batcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft); // 0x0073ED81
  }

  // ---- Text rendering (0x0073EDAD..0x0073F0B2).
  // Glyph axes. Both Render calls build them the same way: flt_E4F6E8 (-1.0)
  // into lane y of the vector pushed as yAxis (0x0073EDF2 -> 0x0073EE0E, zeros
  // at 0x0073EE38/0x0073EE41), flt_DFEC20 (1.0) into lane x of the one passed
  // in ebx as xAxis (0x0073EE17 -> 0x0073EE1F, lea ebx at 0x0073EE77); again at
  // 0x0073EFB3/0x0073EFD4. The glyph y axis points up, as in every other
  // screen-space Render call (CD3DFont.cpp, Sim.cpp's screen text); +1 drew
  // each glyph upside down.
  const Vector3f xAxis{1.0f, 0.0f, 0.0f};
  const Vector3f yAxis{0.0f, -1.0f, 0.0f};
  constexpr std::uint32_t kTextColor = 0xFFFFFFFFu; // 0x0073EE04 (a5 == 0xFFFFFFFF)
  // Render's glyph-scale parameter is unused by CD3DFont::Render (see
  // CD3DFont.cpp); 0.0f matches the sibling debug-HUD Render sites.
  constexpr float kGlyphScale = 0.0f;
  // Render's maxAdvance sentinel is the "NaN_206" global (asm 0x0073EDEC /
  // 0x0073EF9F) -- a quiet NaN meaning "no advance limit", matching sibling
  // debug-HUD Render call sites.
  const float kNoMaxAdvance = gpg::NaN;

  // Shared pen Y: the summary block renders first (top), then the per-client
  // table continues BELOW it from the same running Y (retail preserves the pen
  // Y across both loops; 0x0073EED0 clears only the row/column counters).
  const float rowStep = font->mExternalLeading + font->mHeight; // 0x0073EEAC / 0x0073F088
  float penY = rectTop + font->mAscent + 3.0f; // 0x0073ED86..0x0073EDB6 (mAscent @ CD3DFont+0x14)

  // Summary lines, left-anchored at rectLeft+3 (loop over var_DC). 0x0073EDAD..0x0073EED0.
  for (const msvc8::string& line : summary) {
    const Vector3f origin{rectLeft + 3.0f, penY, 0.0f}; // 0x0073EE28..0x0073EE6E
    (void)font->Render(
      line.c_str(), batcher, origin, xAxis, yAxis, kTextColor, kGlyphScale, kNoMaxAdvance); // 0x0073EEA7
    penY += rowStep; // 0x0073EEAC..0x0073EEC5
  }

  // Per-client table, drawn row-major (outer = rows bounded by the index column,
  // inner = the 8 columns). Loop over var_C0. 0x0073EEE0..0x0073F0B2.
  //   - X starts at rectLeft+3 each row and accumulates each column's measured
  //     width; columns 0..1 are left-anchored, columns >=2 right-justified.
  //   - Y advances by one row height per outer iteration.
  const std::size_t tableRowCount = columns[0].size(); // outer trip = len(columns[0]) (0x0073EEF2..0x0073EF08)
  for (std::size_t row = 0; row < tableRowCount; ++row) {
    float cellX = rectLeft + 3.0f; // running X base, reset per row (0x0073EF22..0x0073EF44)
    for (std::size_t c = 0; c < columns.size(); ++c) {
      const msvc8::vector<msvc8::string>& column = columns[c];
      // The retail grid is rectangular (all data columns carry one row per
      // client); shorter columns simply contribute an empty cell for the tail
      // rows rather than reading past their storage.
      const msvc8::string cell = (row < column.size()) ? column[row] : msvc8::string();

      float originX;
      if (c < 2) {
        // Index/nickname columns are left-anchored (0x0073EF53 jb).
        originX = cellX;
      } else {
        // Numeric columns are right-justified within their slot (0x0073EF81..0x0073EF94).
        const float advance = font->GetAdvance(cell.c_str(), -1); // 0x0073EF7C
        originX = cellX + colWidths[c] - advance;
      }

      const Vector3f origin{originX, penY, 0.0f}; // 0x0073F009..0x0073F01B
      (void)font->Render(
        cell.c_str(), batcher, origin, xAxis, yAxis, kTextColor, kGlyphScale, kNoMaxAdvance); // 0x0073F056

      cellX += colWidths[c]; // running X += column width (0x0073F05F..0x0073F064)
    }
    penY += rowStep; // per-row Y advance (0x0073F088..0x0073F0A7)
  }

  // ---- Border rectangle: 4 white edges over a white texture. 0x0073F0B2..0x0073F365.
  {
    const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu); // 0x0073F0BE
    batcher->SetTexture(whiteTex);                                                                       // 0x0073F0D3

    constexpr std::uint32_t kBorderColor = 0xFFFFFFFFu; // esi == 0xFFFFFFFF (0x0073F0B2)
    const CD3DPrimBatcher::Vertex tl{rectLeft, rectTop, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex tr{rectRight, rectTop, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex br{rectRight, rectBottom, 0.0f, kBorderColor, 0.0f, 0.0f};
    const CD3DPrimBatcher::Vertex bl{rectLeft, rectBottom, 0.0f, kBorderColor, 0.0f, 0.0f};

    batcher->DrawLine(tl, tr); // 0x0073F1A6 (top edge)
    batcher->DrawLine(tr, br); // 0x0073F23C (right edge)
    batcher->DrawLine(br, bl); // 0x0073F2D2 (bottom edge)
    batcher->DrawLine(bl, tl); // 0x0073F365 (left edge)
  }

  // Release the retained font handle (0x0073F3D3..0x0073F3F9).
  rawFont.release();
}

namespace
{
  void DrawSimDriverNetworkStats(
    CSimDriver& driver, CD3DPrimBatcher* const batcher, const float anchorX, const float anchorY, const float scaleX,
    const float scaleY
  )
  {
    driver.DrawNetworkStatsPanel(batcher, anchorX, anchorY, scaleX, scaleY);
  }

  [[maybe_unused]] const bool gSimDriverNetworkStatsDrawSet =
    (moho::sSimDriverNetworkStatsDraw = &DrawSimDriverNetworkStats, true);
} // namespace
