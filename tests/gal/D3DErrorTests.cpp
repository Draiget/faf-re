// gpg::D3DErrorToString / D3DErrorToWideString (0x00B50FD8, 0x00B542F1): the DirectX error text
// tables. Codes come from the SDK headers' macros, so a wrong code value in the table shows as a
// wrong text. Expected texts come from the headers too: ddraw.h's comment above each DDERR_ code,
// winerror.h's MessageText, and for the Direct3D 9 and DXGI codes the words of the code's name,
// which is what DXErr's descriptions are. Unknown codes give "n/a"; the narrow and the wide table
// must agree on every code of every facility the tables cover.

#include <gtest/gtest.h>

#include <windows.h>

#include <d3d9.h>
#include <ddraw.h>
#include <dxgi.h>

#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

#include "gpg/gal/Error.hpp"

namespace
{
  struct Row
  {
    HRESULT code;
    const char* text;
  };

  // ddraw.h: the comment above each definition.
  const Row kDirectDraw[] = {
    {DDERR_ALREADYINITIALIZED, "This object is already initialized"},
    {DDERR_CANNOTATTACHSURFACE, "This surface can not be attached to the requested surface."},
    {DDERR_CURRENTLYNOTAVAIL, "Support is currently not available."},
    {DDERR_EXCEPTION, "An exception was encountered while performing the requested operation"},
    {DDERR_HEIGHTALIGN, "Height of rectangle provided is not a multiple of reqd alignment"},
    {DDERR_INVALIDCAPS, "One or more of the caps bits passed to the callback are incorrect."},
    {DDERR_INVALIDMODE, "DirectDraw does not support the requested mode"},
    {DDERR_INVALIDPIXELFORMAT, "pixel format was invalid as specified"},
    {DDERR_INVALIDRECT, "Rectangle provided was invalid."},
    {DDERR_NO3D, "There is no 3D present."},
    {DDERR_NOCLIPLIST, "no clip list available"},
    {DDERR_NOCOLORKEY, "Surface doesn't currently have a color key"},
    {DDERR_NOFLIPHW, "Flipping visible surfaces is not supported."},
    {DDERR_NOGDI, "There is no GDI present."},
    {DDERR_NOTFOUND, "Requested item was not found"},
    {DDERR_HWNDALREADYSET,
     "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces or palettes created."},
    {DDERR_NOPALETTEATTACHED, "No palette object attached to this surface."},
    {DDERR_NOBLTHW, "No blter."},
    {DDERR_EXCLUSIVEMODEALREADYSET, "An attempt was made to set the cooperative level when it was already set to exclusive."},
    {DDERR_NOTFLIPPABLE, "An attempt has been made to flip a surface that is not flippable."},
    {DDERR_CANTDUPLICATE, "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created."},
    {DDERR_NODC, "No DC was ever created for this surface."},
    {DDERR_WRONGMODE, "This surface can not be restored because it was created in a different mode."},
    {DDERR_NOTPALETTIZED, "The surface being used is not a palette-based surface"},
    {DDERR_UNSUPPORTEDMODE, "The display is currently in an unsupported mode"},
    {DDERR_DCALREADYCREATED, "A DC has already been returned for this surface. Only one DC can be retrieved per surface."},
    {DDERR_CANTPAGELOCK, "The attempt to page lock a surface failed."},
    {DDERR_MOREDATA, "There is more data available than the specified buffer size could hold"},
    {DDERR_EXPIRED, "The data has expired and is therefore no longer valid."},
    {DDERR_TESTFINISHED, "The mode test has finished executing."},
    {DDERR_NEWMODE, "The mode test has switched to a new mode."},
    {DDERR_D3DNOTINITIALIZED, "D3D has not yet been initialized."},
    {DDERR_VIDEONOTACTIVE, "The video port is not active"},
    {DDERR_NOMONITORINFORMATION, "The monitor does not have EDID data."},
    {DDERR_NODRIVERSUPPORT, "The driver does not enumerate display mode refresh rates."},
    {DDERR_DEVICEDOESNTOWNSURFACE, "Surfaces created by one direct draw device cannot be used directly by another direct draw device."},
  };

  // d3d9.h and winerror.h (DXGI): the words of each name.
  const Row kNamed[] = {
    {D3DERR_WRONGTEXTUREFORMAT, "Wrong texture format"},
    {D3DERR_UNSUPPORTEDCOLOROPERATION, "Unsupported color operation"},
    {D3DERR_UNSUPPORTEDCOLORARG, "Unsupported color arg"},
    {D3DERR_UNSUPPORTEDALPHAOPERATION, "Unsupported alpha operation"},
    {D3DERR_UNSUPPORTEDALPHAARG, "Unsupported alpha arg"},
    {D3DERR_TOOMANYOPERATIONS, "Too many operations"},
    {D3DERR_CONFLICTINGTEXTUREFILTER, "Conflicting texture filter"},
    {D3DERR_UNSUPPORTEDFACTORVALUE, "Unsupported factor value"},
    {D3DERR_CONFLICTINGRENDERSTATE, "Conflicting render state"},
    {D3DERR_UNSUPPORTEDTEXTUREFILTER, "Unsupported texture filter"},
    {D3DERR_CONFLICTINGTEXTUREPALETTE, "Conflicting texture palette"},
    {D3DERR_DRIVERINTERNALERROR, "Driver internal error"},
    {D3DERR_NOTFOUND, "Not found"},
    {D3DERR_MOREDATA, "More data"},
    {D3DERR_DEVICELOST, "Device lost"},
    {D3DERR_DEVICENOTRESET, "Device not reset"},
    {D3DERR_NOTAVAILABLE, "Not available"},
    {D3DERR_OUTOFVIDEOMEMORY, "Out of video memory"},
    {D3DERR_INVALIDDEVICE, "Invalid device"},
    {D3DERR_INVALIDCALL, "Invalid call"},
    {D3DERR_DRIVERINVALIDCALL, "Driver invalid call"},
    {D3DERR_WASSTILLDRAWING, "Was still drawing"},
    {DXGI_ERROR_UNSUPPORTED, "Unsupported."},
    {DXGI_ERROR_DEVICE_REMOVED, "Device removed."},
    {DXGI_ERROR_DEVICE_RESET, "Device reset."},
    {DXGI_ERROR_WAS_STILL_DRAWING, "Was still drawing."},
  };

  // winerror.h: MessageText.
  const Row kSystem[] = {
    {E_UNEXPECTED, "Catastrophic failure"},
    {REGDB_E_CLASSNOTREG, "Class not registered"},
    {CO_E_NOTINITIALIZED, "CoInitialize has not been called."},
    {CO_E_ALREADYINITIALIZED, "CoInitialize has already been called."},
    {E_PENDING, "The data necessary to complete this operation is not yet available."},
  };

  std::wstring Widen(const char* const text)
  {
    std::wstring wide;
    for (const char* c = text; *c != '\0'; ++c) {
      wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*c)));
    }
    return wide;
  }

  void ExpectRows(const Row* const rows, const std::size_t count)
  {
    for (std::size_t index = 0U; index < count; ++index) {
      const long code = static_cast<long>(rows[index].code);
      EXPECT_STREQ(gpg::D3DErrorToString(code), rows[index].text) << std::hex << static_cast<unsigned long>(code);
      EXPECT_EQ(std::wstring(gpg::D3DErrorToWideString(code)), Widen(rows[index].text)) << std::hex << static_cast<unsigned long>(code);
    }
  }
} // namespace

TEST(GalD3DErrors, DirectDrawCodesCarryTheirHeaderComment)
{
  ExpectRows(kDirectDraw, std::size(kDirectDraw));
}

TEST(GalD3DErrors, Direct3D9AndDxgiCodesSayTheirName)
{
  ExpectRows(kNamed, std::size(kNamed));
}

TEST(GalD3DErrors, ComCodesCarryTheSystemMessage)
{
  ExpectRows(kSystem, std::size(kSystem));
}

TEST(GalD3DErrors, UnknownCodesAreNotAvailable)
{
  for (const std::uint32_t code : {0x12340001U, 0x80FF0001U, 0xFFFFFFFFU, 0x7FFFFFFFU}) {
    EXPECT_STREQ(gpg::D3DErrorToString(static_cast<long>(code)), "n/a") << std::hex << code;
    EXPECT_STREQ(gpg::D3DErrorToWideString(static_cast<long>(code)), L"n/a") << std::hex << code;
  }
}

TEST(GalD3DErrors, NarrowAndWideTablesAgreeOnEveryCode)
{
  // Every facility (high 16 bits) the two tables have a code in, all 65536 codes of each.
  const std::uint32_t facilities[] = {0x0000U, 0x0004U, 0x0015U, 0x0876U, 0x0878U, 0x087AU, 0x8000U, 0x8004U, 0x8007U,
                                      0x8015U, 0x8876U, 0x8878U, 0x8879U, 0x887AU, 0x8896U, 0x8AC7U, 0xC00CU, 0xC877U};
  std::vector<std::uint32_t> mismatches;
  std::size_t known = 0U;
  for (const std::uint32_t facility : facilities) {
    for (std::uint32_t low = 0U; low <= 0xFFFFU; ++low) {
      const long code = static_cast<long>((facility << 16U) | low);
      const char* const narrow = gpg::D3DErrorToString(code);
      const wchar_t* const wide = gpg::D3DErrorToWideString(code);
      std::size_t index = 0U;
      while (narrow[index] != '\0' && static_cast<wchar_t>(static_cast<unsigned char>(narrow[index])) == wide[index]) {
        ++index;
      }
      if (narrow[index] != '\0' || wide[index] != L'\0') {
        mismatches.push_back(static_cast<std::uint32_t>(code));
      }
      if (std::strcmp(narrow, "n/a") != 0) {
        ++known;
      }
    }
  }
  EXPECT_TRUE(mismatches.empty()) << mismatches.size() << " codes differ, the first 0x" << std::hex
                                  << (mismatches.empty() ? 0U : mismatches.front());
  EXPECT_GE(known, std::size(kDirectDraw) + std::size(kNamed) + std::size(kSystem));
}
