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
  set(FAF_DEPENDENCIES_ONLY DirectX-Headers SDL3 FAudio)
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

add_library(faf_client_objs OBJECT ${_faf_client_files})
target_link_libraries(faf_client_objs PUBLIC faf_sim_settings Wm3Headers zlib123 faf_monocypher faf_zstd
  FAudio-static SDL3::SDL3-static)  # FAudio names its static target FAudio-static, with no alias
target_include_directories(faf_client_objs PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/wx"
  "${FAF_DEPENDENCIES_DIR}/vulkan/include"
  "${FAF_DEPENDENCIES_DIR}/DirectX-Headers/include/directx")
