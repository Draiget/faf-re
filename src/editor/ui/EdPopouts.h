#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ImGuiViewport;

namespace gpg::gal
{
  class DeviceContext;
}

namespace faf::editor
{
  class EdImGuiRenderer;

  /**
   * Panels in windows of their own (design §3 "Pop-out windows"; FAF Studio's pop-outs, rebuilt on ImGui's
   * multi-viewport): a panel dragged out of the editor's window gets a window of its own, closing it docks it back,
   * and ImGui's layout.ini keeps where it was. Each pop-out draws into a head of its own: the renderers make a swap
   * chain per head when the device is made and can only resize them later, so a pool of heads with hidden windows is
   * made with the device (AddHeads) and handed out as ImGui asks for windows. Menus, combos and tooltips stay inside
   * the window they open from (a "monitor" the size of the editor's window, listed first), so they never take one.
   */
  namespace popouts
  {
    /** How many panels can be out at once (the pool's size); 0 when off. */
    [[nodiscard]] int Capacity() noexcept;

    /**
     * Before the device exists: `count` hidden windows owned by `frame`, each a head of `context` (the heads after
     * the game's and the panels'). `firstHead` is the index the first one gets.
     */
    void AddHeads(gpg::gal::DeviceContext& context, void* frame, int count, std::uint32_t firstHead);

    /** After ImGui_ImplWin32_Init: multi-viewport on, the pool behind ImGui's platform windows. */
    void Install();

    /** Each frame after ImGui_ImplWin32_NewFrame, before ImGui::NewFrame: the editor's window as the first monitor. */
    void BeforeNewFrame(void* panelWindow);

    /** Each frame after ImGui::NewFrame: panels without a head of their own (the pool ran out) go back inside. */
    void AfterNewFrame();

    /**
     * The heads' sizes the pop-outs need now; true when one differs from `context` (and `context` was changed to them).
     * A size is taken once it stayed the same for a moment and no mouse button is down, so a drag re-makes the
     * heads once at its end.
     */
    [[nodiscard]] bool WantHeadSizes(gpg::gal::DeviceContext& context);

    /** After ImGui::Render: ImGui's platform windows updated and each pop-out drawn into its head. */
    void Render(EdImGuiRenderer& renderer, bool draw);

    /** True when the window of that name sits in a window of its own. */
    [[nodiscard]] bool IsOut(const char* windowName);

    /** The pop-outs now, by their panels' names (the log and test runs). */
    [[nodiscard]] std::vector<std::string> OutNames();

    /** Pure: the size a head takes for a window `width` x `height` (at least 8 x 8). */
    [[nodiscard]] std::uint32_t HeadExtent(int size) noexcept;
  } // namespace popouts
} // namespace faf::editor
