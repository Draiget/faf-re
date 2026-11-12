#pragma once

// Engine addition (issues #255, #407): the shell's bitmap. The viewport kept a background image
// until the renderer presented; the renderer owns the whole window surface now, so the bitmap
// holds nothing. See defs.h.

#include "platform/shell/object.h"

class ShellBitmap : public ShellObject
{
public:
  ShellBitmap() = default;
  bool Ok() const
  {
    return false;
  }
};
