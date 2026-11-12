#pragma once

// Engine addition (issue #255): wx 2.4.2's bitmap (wx/bitmap.h), for the Linux client. See
// wx/defs.h in this folder. The shell keeps a background image for the viewport until the
// renderer presents; Linux shows no such image, so the bitmap holds nothing.

#include <wx/object.h>

class wxBitmap : public wxObject
{
public:
  wxBitmap() = default;
  bool Ok() const
  {
    return false;
  }
};
