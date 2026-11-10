# Engine addition (issue #255, milestone "Linux client"): the game client on Linux.
#
# Included by cmake/FafLinux.cmake when FAF_LINUX_CLIENT is ON (default OFF while the client
# doesn't build yet; the headless and server targets are unchanged either way):
#
#   cmake --preset linux-clang-x64-release-plain -DFAF_LINUX_CLIENT=ON
#   cmake --build --preset linux-clang-x64-release-plain --target faf_client_objs -- -k 0
#
# The client's translation units are faf_engine's sources that faf_sim leaves out
# (src/sim_sources.cmake: _faf_client_only_patterns and not _faf_sim_patterns), compiled with
# faf_sim's settings, minus the Windows-only render backends: Direct3D 9/10/11/12, DXGI and
# Effects 11. Vulkan is the only renderer on Linux.

set(_faf_client_windows_only
  "^gpg/gal/backends/(d3d9|d3d10|d3d11|d3d12|dxgi)/"
  "/FX11/"
  "^gpg/gal/(DxgiAdapterInfo|D3DErrorToString|D3DErrorToWideString)\\.cpp$"
  "^gpg/gal/backends/common/WindowsCursor\\.cpp$"
  "^moho/movie/sfd/DirectSoundMovieSink\\.cpp$"
  # The Win32 crash dialog; gpg/core/diagnostics/posix/DiagnosticsPosix.cpp has the POSIX one.
  "^gpg/core/diagnostics/CrashReportDialog\\.cpp$"
  # faf_sim compiles its own copy (cmake/FafLinux.cmake).
  "^gpg/gal/MatrixPortable\\.cpp$"
  # wxWindows 2.4.2 has no Linux port; the wx stand-in (src/platform/posix/wx) covers only what
  # the game code uses. Left out until their own issues land:
  #   the Windows entry point and process setup (WinMain, WinApp: crash handler, clipboard,
  #   splash, wx start) and the wx dialogs; the Linux entry point is issue #256 (SDL3). The main
  #   frame, the viewports and CScApp build over the wx stand-in.
  "^moho/app/(WinMain|WinApp|WxAppWindows)\\.cpp$"
  #   the wx script debugger (issue #260);
  "^moho/misc/(ScrDebugWindow|ScrFileCtrl|ScrSourceCtrl|ScrWatchCtrl|ScrGotoDialog|ScrPauseEvent|TreeData)\\.cpp$"
  #   the developer windows and Windows desktop features: emitter editor, log window,
  #   reference editor, snapshot folder dialog, network panel and tray icon, wxURL.
  "^moho/app/(WEmitterWx|WWinLogWindow|WRefEditDialog|SnapshotDirectoryDialog|NetworkPanel|NetworkTray|WxUrl)\\.cpp$")

# Portable files in the Windows backends' folders that the Vulkan backend shares: the DXGI format
# tables, the Direct3D 11 vertex layouts (D3D11_INPUT_ELEMENT_DESC from the POSIX <d3d11.h>) and
# the effect-source translator (FX to modern HLSL, plain text work).
set(_faf_client_shared_backend_files
  "^gpg/gal/backends/dxgi/DxgiFormats\\.cpp$"
  "^gpg/gal/backends/d3d11/(D3D11VertexLayouts|EffectSourceD3D11)\\.cpp$")
list(APPEND _faf_client_windows_only
  # The Direct3D 9 state manager's caches.
  "^gpg/gal/StateCache\\.cpp$"
  # Built in faf_client_imaging below, with DirectX-Headers' Win32 adapter.
  "^gpg/gal/backends/common/ImageCodecDirectXTex\\.cpp$")

set(_faf_client_files "")
foreach(_src IN LISTS FAF_ENGINE_SOURCES)
  set(_client FALSE)
  foreach(_pattern IN LISTS _faf_client_only_patterns)
    if(_src MATCHES "${_pattern}")
      set(_client TRUE)
      break()
    endif()
  endforeach()
  if(_client)
    foreach(_pattern IN LISTS _faf_sim_patterns _faf_client_windows_only)
      if(_src MATCHES "${_pattern}")
        set(_client FALSE)
        break()
      endif()
    endforeach()
    foreach(_pattern IN LISTS _faf_client_shared_backend_files)
      if(_src MATCHES "${_pattern}")
        set(_client TRUE)
        break()
      endif()
    endforeach()
  endif()
  if(_client)
    if(IS_ABSOLUTE "${_src}")
      list(APPEND _faf_client_files "${_src}")
    else()
      list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/${_src}")
    endif()
  endif()
endforeach()
list(LENGTH _faf_client_files _faf_client_count)
message(STATUS "faf_client: ${_faf_client_count} client translation units")

# The client's downloads (cmake/FafDependencies.cmake): DirectX-Headers for the DXGI format numbers
# the Vulkan backend and the texture code use (<dxgiformat.h>); SDL3 for the window, input and
# audio output; FAudio for XACT and X3DAudio (issue #258).
if(FAF_FETCH_DEPENDENCIES)
  set(FAF_DEPENDENCIES_ONLY DirectX-Headers SDL3 FAudio dxc-linux DirectXTex DirectXMath stb)
  include(FafDependencies)
endif()

# SDL3, static. Its X11, Wayland, audio and input backends load their system libraries at run time.
set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
set(SDL_TESTS OFF CACHE BOOL "" FORCE)
set(SDL_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SDL_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${FAF_DEPENDENCIES_DIR}/SDL3" "${CMAKE_BINARY_DIR}/deps/SDL3" EXCLUDE_FROM_ALL SYSTEM)

# FAudio, static, over that SDL3 (its CMakeLists takes SDL3_INCLUDE_DIRS and SDL3_LIBRARIES).
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SDL3_INCLUDE_DIRS "${FAF_DEPENDENCIES_DIR}/SDL3/include")
set(SDL3_LIBRARIES SDL3-static)
add_subdirectory("${FAF_DEPENDENCIES_DIR}/FAudio" "${CMAKE_BINARY_DIR}/deps/FAudio" EXCLUDE_FROM_ALL SYSTEM)

# Lowercase spellings of POSIX stand-in headers the client includes (the file system is
# case-sensitive here, and a Windows checkout can't hold both spellings), as FafLinux.cmake writes
# <windows.h>.
file(WRITE "${CMAKE_BINARY_DIR}/win32-alias/shlobj.h" "#pragma once\n#include <ShlObj.h>\n")

# The part of wxWindows 2.4.2 the game code uses (src/platform/posix/wx/wx/defs.h).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/wx/WxStandIn.cpp")
# The Win32 window, cursor and key-state calls the UI code makes (platform/posix/win32/Windows.h).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/Win32WindowPosix.cpp")
# The XACT engine on FAudio's FACT (issue #258).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/XactOverFact.cpp")

# DXC's Linux headers bring their own Win32 types, which clash with the POSIX <Windows.h> the
# client's files are compiled with (platform/PosixCompat.h), so the one file that includes them is
# built on its own, without faf_sim_settings. libdxcompiler.so is loaded at run time.
add_library(faf_client_dxc OBJECT "${PROJECT_SOURCE_DIR}/src/platform/posix/dxc/DxcGlue.cpp")
target_include_directories(faf_client_dxc PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${FAF_DEPENDENCIES_DIR}/dxc-linux/include")
target_compile_options(faf_client_dxc PRIVATE -pthread -Wall)

# Textures (issue #255): DirectXTex's CPU code, as Windows builds it (cmake/deps/directxtex) minus
# its WIC codec, on DirectXMath and DirectX-Headers, with empty SAL annotations
# (src/platform/posix/sal). DirectXTex brings DirectX-Headers' Win32 adapter, which can't meet the
# POSIX <Windows.h>, so ImageCodecDirectXTex.cpp (the engine's side of it) and stb, which reads and
# writes PNG, BMP and JPG there in WIC's place, are built apart too.
set(_faf_dxtex "${FAF_DEPENDENCIES_DIR}/DirectXTex/DirectXTex")
set(_faf_dx_headers "${FAF_DEPENDENCIES_DIR}/DirectX-Headers/include")
set(_faf_imaging_includes
  "${PROJECT_SOURCE_DIR}/src/platform/posix/sal"
  "${_faf_dxtex}"
  "${FAF_DEPENDENCIES_DIR}/DirectXMath/Inc"
  "${_faf_dx_headers}"
  "${_faf_dx_headers}/directx"
  "${_faf_dx_headers}/wsl/stubs")
add_library(faf_directxtex_linux STATIC
  "${_faf_dxtex}/BC.cpp"
  "${_faf_dxtex}/BC4BC5.cpp"
  "${_faf_dxtex}/BC6HBC7.cpp"
  "${_faf_dxtex}/DirectXTexCompress.cpp"
  "${_faf_dxtex}/DirectXTexConvert.cpp"
  "${_faf_dxtex}/DirectXTexDDS.cpp"
  # DirectXTexFlipRotate.cpp is WIC's, Windows only in DirectXTex's own build; the engine doesn't use it.
  "${_faf_dxtex}/DirectXTexHDR.cpp"
  "${_faf_dxtex}/DirectXTexImage.cpp"
  "${_faf_dxtex}/DirectXTexMipmaps.cpp"
  "${_faf_dxtex}/DirectXTexMisc.cpp"
  "${_faf_dxtex}/DirectXTexNormalMaps.cpp"
  "${_faf_dxtex}/DirectXTexPMAlpha.cpp"
  "${_faf_dxtex}/DirectXTexResize.cpp"
  "${_faf_dxtex}/DirectXTexTGA.cpp"
  "${_faf_dxtex}/DirectXTexUtil.cpp")
target_include_directories(faf_directxtex_linux SYSTEM PUBLIC ${_faf_imaging_includes})
target_compile_options(faf_directxtex_linux PRIVATE -w -pthread)

add_library(faf_client_imaging OBJECT
  "${PROJECT_SOURCE_DIR}/src/gpg/gal/backends/common/ImageCodecDirectXTex.cpp"
  "${PROJECT_SOURCE_DIR}/src/platform/posix/imaging/StbImage.cpp")
target_include_directories(faf_client_imaging PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/winadapter"
  "${PROJECT_SOURCE_DIR}/src"
  "${FAF_DEPENDENCIES_DIR}/stb")
target_link_libraries(faf_client_imaging PUBLIC faf_directxtex_linux)
target_compile_options(faf_client_imaging PRIVATE -pthread -Wall)

add_library(faf_client_objs OBJECT ${_faf_client_files})
add_dependencies(faf_client_objs faf_client_dxc faf_client_imaging)
# boost 1.34's string algorithms (the lobby) derive from std::unary_function, which libc++ keeps
# behind this opt-in since C++17, as boost.thread's std::auto_ptr (cmake/FafLinux.cmake).
target_compile_definitions(faf_client_objs PRIVATE _LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION=1)
target_link_libraries(faf_client_objs PUBLIC faf_sim_settings Wm3Headers zlib123 faf_monocypher faf_zstd
  FAudio-static SDL3::SDL3-static)  # FAudio names its static target FAudio-static, with no alias
target_include_directories(faf_client_objs PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/wx"
  "${FAF_DEPENDENCIES_DIR}/vulkan/include"
  "${FAF_DEPENDENCIES_DIR}/DirectX-Headers/include/directx")
