#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

  // Debug surface dump used by the committed [NORMALSDUMP] diagnostic in
  // AppWindows.cpp, which reaches it only when FAF_TOGGLE_DIR names a
  // directory holding dumpnormals.on. Defined here because this is where the
  // D3DX export is already resolved.
  long DebugSaveSurfaceToFileA(const char* filePath, unsigned int fileFormat, void* sourceSurface);
} // namespace gpg::gal

long gpg::gal::DebugSaveSurfaceToFileA(
  const char* const filePath,
  const unsigned int fileFormat,
  void* const sourceSurface
)
{
  return static_cast<long>(::D3DXSaveSurfaceToFileA(
    filePath,
    static_cast<D3DXIMAGE_FILEFORMAT>(fileFormat),
    static_cast<IDirect3DSurface9*>(sourceSurface),
    nullptr,
    nullptr
  ));
}
