#pragma once

// Engine addition (issue #255): the two Direct3D 9 structures the render interface keeps as
// parameter types on Linux, which has no Windows SDK and no D3D9 backend. gpg::gal::Device takes a
// D3DVIEWPORT9 (SetViewport/GetViewport, as the original's interface did) and the texture sheets
// hand out a D3DLOCKED_RECT. Fields have their Windows types and order (d3d9types.h).

#if FAFRE_PLATFORM_WINDOWS
#error "platform/posix/win32/d3d9types.h is for builds without the Windows SDK"
#endif

#include <Windows.h>

struct _D3DVIEWPORT9
{
  DWORD X;
  DWORD Y;
  DWORD Width;
  DWORD Height;
  float MinZ;
  float MaxZ;
};
using D3DVIEWPORT9 = _D3DVIEWPORT9;

struct _D3DLOCKED_RECT
{
  INT Pitch;
  void* pBits;
};
using D3DLOCKED_RECT = _D3DLOCKED_RECT;
