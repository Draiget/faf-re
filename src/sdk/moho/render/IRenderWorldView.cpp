#include "moho/render/IRenderWorldView.h"

namespace
{
  /**
   * Address: 0x007F7A60 (FUN_007F7A60)
   *
   * What it does:
   * Rebinds one world-view runtime lane to the base `IRenderWorldView`
   * vtable tag used by constructor/unwind helper paths.
   */
  [[maybe_unused]] moho::IRenderWorldView* ResetRenderWorldViewBaseVtable(
    moho::IRenderWorldView* const view
  ) noexcept
  {
    static std::uint8_t sRenderWorldViewBaseVtableTag = 0;
    if (view != nullptr) {
      *reinterpret_cast<void**>(view) = &sRenderWorldViewBaseVtableTag;
    }
    return view;
  }

  /**
   * Address: 0x007F6370 (FUN_007F6370)
   *
   * What it does:
   * Rebind lane that restores one runtime object to the base
   * `IRenderWorldView` vtable tag.
   */
  [[maybe_unused]] moho::IRenderWorldView* RebindRenderWorldViewInterfaceVtableLaneA(
    moho::IRenderWorldView* const view
  ) noexcept
  {
    return ResetRenderWorldViewBaseVtable(view);
  }
}

namespace moho
{
  /**
   * Address: 0x007F6280 (FUN_007F6280, ??0IRenderWorldView@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes one world-view render interface base object.
   */
  IRenderWorldView::IRenderWorldView() = default;

  /**
   * Address: 0x007F6250 (FUN_007F6250, Moho::SimpleRenderWorldView::Func1)
   */
  void IRenderWorldView::Func1()
  {}

  /**
   * Address: 0x007F6260 (FUN_007F6260, Moho::CRenderWorldView::Func2)
   */
  bool IRenderWorldView::Func2()
  {
    return false;
  }

  /**
   * Address: 0x007F6270 (FUN_007F6270, Moho::SimpleRenderWorldView::IsMiniMap)
   */
  bool IRenderWorldView::IsMiniMap()
  {
    return false;
  }
} // namespace moho
