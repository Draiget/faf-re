#include "editor/ui/EdWindowChrome.h"

namespace faf::editor
{
  EdWindowChrome& WindowChrome()
  {
    static EdWindowChrome chrome;
    return chrome;
  }

  EdHit TitleHit(
    const EdWindowChrome& chrome,
    const float x,
    const float y,
    const float clientWidth,
    const float border
  )
  {
    if (!chrome.own || chrome.height <= 0.0f || y >= chrome.height || y < 0.0f) {
      return EdHit::Client;
    }
    // The caption buttons reach the window's top edge (Fitts), so they come before the resize band.
    if (chrome.close.Contains(x, y)) {
      return EdHit::Close;
    }
    if (chrome.maximize.Contains(x, y)) {
      return EdHit::Maximize;
    }
    if (chrome.minimize.Contains(x, y)) {
      return EdHit::Minimize;
    }
    if (!chrome.maximised && y < border) {
      if (x < border * 2.0f) {
        return EdHit::TopLeft;
      }
      if (x >= clientWidth - border * 2.0f) {
        return EdHit::TopRight;
      }
      return EdHit::Top;
    }
    for (const EdChromeRect& control : chrome.controls) {
      if (control.Contains(x, y)) {
        return EdHit::Client;
      }
    }
    return EdHit::Caption;
  }
} // namespace faf::editor
