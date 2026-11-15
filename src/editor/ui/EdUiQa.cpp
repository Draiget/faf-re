// The item status bits the test-engine hooks report (Checkable, Openable, Inputable) are declared only under this
// define; faf_imgui_core is built with it, and it changes no struct layout in imgui.h or imgui_internal.h.
#ifndef IMGUI_ENABLE_TEST_ENGINE
#define IMGUI_ENABLE_TEST_ENGINE
#endif
#include "editor/ui/EdUiQa.h"
#include "editor/ui/EdUiScale.h"

#include "faf_imgui_hooks.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>

namespace faf::editor
{
  namespace
  {
    // The items of the frame being built, collected by the hooks.
    std::vector<QaItem> gFrame;
    std::map<ImGuiID, std::size_t> gFrameAt;

    void OnItemAdd(
      ImGuiContext* ctx,
      const ImGuiID id,
      const ImRect& bb
    )
    {
      if (id == 0 || ctx == nullptr || ctx->CurrentWindow == nullptr) {
        return;
      }
      const ImGuiWindow* w = ctx->CurrentWindow;
      QaItem item;
      item.id = id;
      item.window = w->Name != nullptr ? w->Name : "";
      item.x0 = bb.Min.x;
      item.y0 = bb.Min.y;
      item.x1 = bb.Max.x;
      item.y1 = bb.Max.y;
      item.wx0 = w->Pos.x;
      item.wy0 = w->Pos.y;
      item.wx1 = w->Pos.x + w->Size.x;
      item.wy1 = w->Pos.y + w->Size.y;
      item.scrollX = w->ScrollbarX;
      item.title = id == w->MoveId || id == w->TabId || id == w->ID;
      // A dock tab is submitted in its dock host's window: it is the docked window's TabId.
      for (int i = 0; !item.title && i < ctx->Windows.Size; ++i) {
        item.title = ctx->Windows[i]->TabId == id || ctx->Windows[i]->MoveId == id;
      }
      const auto it = gFrameAt.find(id);
      if (it != gFrameAt.end()) {
        gFrame[it->second] = item;
        return;
      }
      gFrameAt[id] = gFrame.size();
      gFrame.push_back(std::move(item));
    }

    void OnItemInfo(
      ImGuiContext*,
      const ImGuiID id,
      const char* label,
      const ImGuiItemStatusFlags flags
    )
    {
      const auto it = gFrameAt.find(id);
      if (it == gFrameAt.end()) {
        return;
      }
      QaItem& item = gFrame[it->second];
      item.label = label != nullptr ? label : "";
      // The part after "##" is the id, not the label.
      if (const std::size_t at = item.label.find("##"); at != std::string::npos) {
        item.label.erase(at);
      }
      item.flags = flags;
    }

    void Hooks(
      const bool on
    )
    {
      faf::imgui_hooks::SetItemHooks(on ? &OnItemAdd : nullptr, on ? &OnItemInfo : nullptr);
      if (ImGuiContext* ctx = ImGui::GetCurrentContext(); ctx != nullptr) {
        ctx->TestEngineHookItems = on;
      }
    }

    std::string Lower(
      std::string s
    )
    {
      std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return s;
    }
  } // namespace

  bool QaSweepable(
    const QaItem& item
  )
  {
    if (item.label.empty() || item.title) {
      return false;
    }
    constexpr int kNotButton =
      ImGuiItemStatusFlags_Checkable | ImGuiItemStatusFlags_Openable | ImGuiItemStatusFlags_Inputable;
    if ((item.flags & kNotButton) != 0) {
      return false;
    }
    const std::string l = Lower(item.label);
    // "..." opens a dialog (a native file dialog blocks the editor's frame loop: the sweep would stall).
    if (l.size() >= 3 && l.ends_with("...")) {
      return false;
    }
    static const char* const kRisky[] = {
      "browse",  "open",    "load",       "pop out",  "pop-out", "put on",  "on the map", "folder",    "file",
      "choose",  "pick",    "delete",     "remove",   "close",   "quit",    "exit",       "save",      "upload",
      "release", "publish", "write over", "clear",    "reset",   "drop",    "erase",      "uninstall", "play",
      "flatten", "apply",   "run",        "generate", "build",   "convert", "package",    "import",    "export",
      "make",    "log in",  "log out",    "sign",     "restart",
    };
    for (const char* risky : kRisky) {
      if (l.contains(risky)) {
        return false;
      }
    }
    const std::string w = Lower(item.window);
    return !w.contains("log") && !w.contains("settings") && !w.contains("debug");
  }

  std::vector<QaLayoutProblem> QaLayoutProblems(
    const std::vector<QaItem>& items,
    const float slack
  )
  {
    std::vector<QaLayoutProblem> out;
    std::map<std::string, std::vector<const QaItem*>> byWindow;
    for (const QaItem& item : items) {
      if (!item.label.empty() && !item.title && item.x1 > item.x0 && item.y1 > item.y0) {
        byWindow[item.window].push_back(&item);
      }
    }
    for (const auto& [window, list] : byWindow) {
      // Across: inside the panel (a panel that scrolls sideways may hold wider rows).
      for (const QaItem* it : list) {
        if (!it->scrollX && (it->x0 < it->wx0 - slack || it->x1 > it->wx1 + slack)) {
          char text[200];
          (void)std::snprintf(
            text,
            sizeof(text),
            "'%s' runs past the panel's side (%.0f..%.0f of %.0f..%.0f)",
            it->label.c_str(),
            static_cast<double>(it->x0),
            static_cast<double>(it->x1),
            static_cast<double>(it->wx0),
            static_cast<double>(it->wx1)
          );
          out.push_back({window, text});
        }
      }
      // Covering: two controls over each other by more than a quarter of the smaller (one inside the other is a group).
      for (std::size_t a = 0; a < list.size(); ++a) {
        for (std::size_t b = a + 1; b < list.size(); ++b) {
          const QaItem& p = *list[a];
          const QaItem& q = *list[b];
          const float ix = std::min(p.x1, q.x1) - std::max(p.x0, q.x0);
          const float iy = std::min(p.y1, q.y1) - std::max(p.y0, q.y0);
          if (ix <= 2.0f || iy <= 2.0f) {
            continue;
          }
          const float areaP = (p.x1 - p.x0) * (p.y1 - p.y0);
          const float areaQ = (q.x1 - q.x0) * (q.y1 - q.y0);
          const float inter = ix * iy;
          const bool contained = inter >= std::min(areaP, areaQ) * 0.98f;
          if (!contained && inter > std::min(areaP, areaQ) * 0.25f) {
            out.push_back({window, "'" + p.label + "' and '" + q.label + "' cover each other"});
          }
        }
      }
    }
    return out;
  }

  void EdUiQa::Start(
    const Kind kind,
    const int wait
  )
  {
    mKind = kind;
    mState = State::Waiting;
    mWait = wait;
    mTargets.clear();
    mNext = 0;
    mPhase = 0;
    mPressed.clear();
    mSkipped = 0;
    mReport.clear();
    mProblems.clear();
    mScales = {1.0f, 1.25f, 1.5f, kMaxUiScale};
    mScaleAt = 0;
    mScaleBefore = getScale ? getScale() : 1.0f;
    mSettle = 0;
    // What is shown first (""), then every panel in turn.
    mPanels = panels ? panels() : std::vector<std::string>{};
    mPanels.insert(mPanels.begin(), std::string());
    mPanelAt = 0;
    mPanelOpen = false;
    mCollect = false;
    mSeen.clear();
    mGone = 0;
    gFrame.clear();
    gFrameAt.clear();
    Hooks(true);
    gpg::Logf(
      "editor: %s starts (%zu panels)", kind == Kind::ClickSweep ? "click sweep" : "layout check", mPanels.size() - 1
    );
  }

  bool EdUiQa::NextPanel()
  {
    if (mPanelOpen && showPanel && mPanelAt > 0) {
      (void)showPanel(mPanels[mPanelAt - 1], mPanelWas);
    }
    mPanelOpen = false;
    if (mPanelAt >= mPanels.size()) {
      return false;
    }
    const std::string& name = mPanels[mPanelAt++];
    if (!name.empty() && showPanel) {
      mPanelWas = showPanel(name, true);
      mPanelOpen = true;
    }
    mFocus = name;
    mSettle = 10;
    mCollect = mKind == Kind::ClickSweep;
    mTargets.clear();
    mNext = 0;
    mPhase = 0;
    return true;
  }

  bool EdUiQa::InPanel(
    const QaItem& item
  ) const
  {
    if (mPanelAt == 0) {
      return false;
    }
    const std::string& panel = mPanels[mPanelAt - 1];
    return panel.empty() || item.window == panel || item.window.starts_with(panel + "/");
  }

  void EdUiQa::CollectTargets()
  {
    for (const QaItem& item : gFrame) {
      if (!InPanel(item) || item.label.empty()) {
        continue;
      }
      const bool button = QaSweepable(item);
      const std::string key = (button ? "b:" : "s:") + item.window + " / " + item.label;
      if (std::find(mSeen.begin(), mSeen.end(), key) != mSeen.end()) {
        continue;
      }
      mSeen.push_back(key);
      if (button) {
        mTargets.push_back(item);
      } else {
        ++mSkipped;
      }
    }
  }

  void EdUiQa::BeforeNewFrame()
  {
    if (!Running()) {
      return;
    }
    gFrame.clear();
    gFrameAt.clear();
    if (ImGuiContext* ctx = ImGui::GetCurrentContext(); ctx != nullptr) {
      ctx->TestEngineHookItems = true;
    }
    if (mState != State::Running || mKind != Kind::ClickSweep || mSettle > 0 || mCollect || mNext >= mTargets.size()) {
      return;
    }
    ImGuiIO& io = ImGui::GetIO();
    const QaItem& t = mTargets[mNext];
    const float cx = (t.x0 + t.x1) * 0.5f;
    const float cy = (t.y0 + t.y1) * 0.5f;
    if (mPhase == 0) {
      io.AddMousePosEvent(cx, cy);
      io.AddMouseButtonEvent(0, true);
    } else if (mPhase == 1) {
      io.AddMousePosEvent(cx, cy);
      io.AddMouseButtonEvent(0, false);
    } else if (mPhase == 2 && ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel)) {
      io.AddKeyEvent(ImGuiKey_Escape, true);
    } else if (mPhase == 3) {
      io.AddKeyEvent(ImGuiKey_Escape, false);
    }
  }

  void EdUiQa::DuringFrame()
  {
    if (!Running() || mFocus.empty()) {
      return;
    }
    // The first frames after the show make the window; focusing it then brings its tab in front.
    if (mSettle > 0 && mSettle <= 7) {
      ImGui::SetWindowFocus(mFocus.c_str());
      // A floating panel opened without a size of its own is ImGui's smallest; it gets a usable size, as a user would
      // drag it to, so the check judges its layout rather than the default box.
      if (ImGuiWindow* const w = ImGui::FindWindowByName(mFocus.c_str()); w != nullptr && w->DockNode == nullptr) {
        const float em = ImGui::GetFontSize();
        if (w->Size.x < 22.0f * em || w->Size.y < 16.0f * em) {
          ImGui::SetWindowSize(
            mFocus.c_str(), ImVec2(std::max(w->Size.x, 30.0f * em), std::max(w->Size.y, 28.0f * em))
          );
        }
      }
    }
    if (mSettle <= 1) {
      mFocus.clear();
    }
  }

  void EdUiQa::AfterRender()
  {
    if (!Running()) {
      return;
    }
    if (mState == State::Waiting) {
      if (--mWait > 0) {
        return;
      }
      mState = State::Running;
      if (mKind == Kind::LayoutCheck && setScale) {
        setScale(mScales[0]);
      }
      if (!NextPanel()) {
        Finish();
      }
      return;
    }
    if (mSettle > 0) {
      --mSettle;
      return;
    }
    if (mKind == Kind::ClickSweep) {
      if (mCollect) {
        mCollect = false;
        CollectTargets();
        return;
      }
      if (mNext >= mTargets.size()) {
        if (!NextPanel()) {
          Finish();
        }
        return;
      }
      if (mPhase == 0) {
        // Still there, where it was? Panels move and change as buttons are pressed.
        const QaItem& t = mTargets[mNext];
        const auto it = gFrameAt.find(t.id);
        if (it == gFrameAt.end()) {
          ++mGone;
          ++mNext;
          return;
        }
        const std::string label = t.label;
        const int flags = t.flags;
        mTargets[mNext] = gFrame[it->second];
        mTargets[mNext].label = label;
        mTargets[mNext].flags = flags;
        // Before the press: a press that never comes back (a hang) is named by the last line.
        gpg::Logf("editor: click sweep: pressing %s / %s", mTargets[mNext].window.c_str(), label.c_str());
      }
      if (++mPhase > 3) {
        mPressed.push_back(mTargets[mNext].window + " / " + mTargets[mNext].label);
        mPhase = 0;
        ++mNext;
      }
      return;
    }
    // Layout check: at each scale, each panel settles for a few frames, then one frame is judged.
    std::vector<QaItem> mine;
    for (const QaItem& item : gFrame) {
      if (InPanel(item)) {
        mine.push_back(item);
      }
    }
    const float slack = ImGui::GetStyle().ItemSpacing.x * 0.5f + 1.0f;
    for (QaLayoutProblem& p : QaLayoutProblems(mine, slack)) {
      char head[32];
      (void)std::snprintf(head, sizeof(head), "[%.0f%%] ", static_cast<double>(mScales[mScaleAt] * 100.0f));
      p.text = head + p.text;
      const bool known = std::any_of(mProblems.begin(), mProblems.end(), [&p](const QaLayoutProblem& q) {
        return q.window == p.window && q.text == p.text;
      });
      if (!known) {
        mProblems.push_back(std::move(p));
      }
    }
    if (NextPanel()) {
      return;
    }
    if (++mScaleAt < mScales.size() && setScale) {
      setScale(mScales[mScaleAt]);
      mPanelAt = 0;
      (void)NextPanel();
      return;
    }
    if (setScale) {
      setScale(mScaleBefore);
    }
    Finish();
  }

  void EdUiQa::Finish()
  {
    if (mPanelOpen && showPanel && mPanelAt > 0) {
      (void)showPanel(mPanels[mPanelAt - 1], mPanelWas);
      mPanelOpen = false;
    }
    Hooks(false);
    mState = State::Done;
    const std::size_t panelCount = mPanels.empty() ? 0 : mPanels.size() - 1;
    if (mKind == Kind::ClickSweep) {
      char head[200];
      (void)std::snprintf(
        head,
        sizeof(head),
        "Click sweep over %zu panels: %zu buttons pressed, %d gone before their press, %d controls left alone "
        "(checkboxes, inputs, risky labels)",
        panelCount,
        mPressed.size(),
        mGone,
        mSkipped
      );
      mReport.push_back(head);
      for (const std::string& p : mPressed) {
        mReport.push_back("  pressed " + p);
      }
    } else {
      char head[160];
      (void)std::snprintf(
        head,
        sizeof(head),
        "Layout check over %zu panels at %zu UI scales: %zu problems",
        panelCount,
        mScales.size(),
        mProblems.size()
      );
      mReport.push_back(head);
      for (const QaLayoutProblem& p : mProblems) {
        mReport.push_back("  " + p.window + ": " + p.text);
      }
    }
    for (const std::string& line : mReport) {
      gpg::Logf("editor: %s", line.c_str());
    }
  }
} // namespace faf::editor
