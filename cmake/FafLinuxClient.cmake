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
  # faf_sim compiles its own copy (cmake/FafLinux.cmake).
  "^gpg/gal/MatrixPortable\\.cpp$"
  # wxWindows 2.4.2 has no Linux port; the wx stand-in (src/platform/posix/wx) covers only what
  # the game code uses. Left out until their own issues land:
  #   the application shell - wx app and main loop, main frame, viewports, splash and
  #   resolution switching (issue #256, SDL3);
  "^moho/app/(WinMain|WinApp|CScApp|WxAppWindows|WSupComFrame|WD3DViewport|WRenViewport|ResolutionCommands)\\.cpp$"
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

# The part of wxWindows 2.4.2 the game code uses (src/platform/posix/wx/wx/defs.h).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/wx/WxStandIn.cpp")

add_library(faf_client_objs OBJECT ${_faf_client_files})
target_link_libraries(faf_client_objs PUBLIC faf_sim_settings Wm3Headers zlib123 faf_monocypher faf_zstd)
target_include_directories(faf_client_objs PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/wx"
  "${FAF_DEPENDENCIES_DIR}/vulkan/include")
