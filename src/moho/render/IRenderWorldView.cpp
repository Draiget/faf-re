#include "moho/render/IRenderWorldView.h"

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
   * Address: 0x007F6260 (FUN_007F6260, Moho::IRenderWorldView::Func2)
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
