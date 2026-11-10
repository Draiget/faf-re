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
  "^gpg/gal/(DxgiAdapterInfo|D3DErrorToWideString)\\.cpp$"
  "^moho/movie/sfd/DirectSoundMovieSink\\.cpp$"
  # The Win32 crash dialog; gpg/core/diagnostics/posix/DiagnosticsPosix.cpp has the POSIX one.
  "^gpg/core/diagnostics/CrashReportDialog\\.cpp$"
  # faf_sim compiles its own copy (cmake/FafLinux.cmake).
  "^gpg/gal/MatrixPortable\\.cpp$"
  # wxWindows 2.4.2 has no Linux port; the wx stand-in (src/platform/posix/wx) covers only what
  # the game code uses. Left out until their own issues land:
  #   the Windows entry point (src/platform/posix/ClientMainPosix.cpp takes its place, issue
  #   #256). WinApp (the main loop), the app windows, the main frame, the viewports and CScApp
  #   build over the wx stand-in and the POSIX <Windows.h>.
  "^moho/app/WinMain\\.cpp$"
  #   the wx script debugger (issue #260);
  "^moho/misc/(ScrDebugWindow|ScrFileCtrl|ScrSourceCtrl|ScrWatchCtrl|ScrGotoDialog|ScrPauseEvent|TreeData)\\.cpp$"
  #   the developer windows: emitter editor, log window, reference editor, snapshot folder dialog.
  "^moho/app/(WEmitterWx|WWinLogWindow|WRefEditDialog|SnapshotDirectoryDialog)\\.cpp$")

# Portable files in the Windows backends' folders that the Vulkan backend shares: the DXGI format
# tables, the Direct3D 11 vertex layouts (D3D11_INPUT_ELEMENT_DESC from the POSIX <d3d11.h>) and
# the effect-source translator (FX to modern HLSL, plain text work), the abstract base classes'
# out-of-line members, and the vertex formatters Direct3D 10 to 12 and Vulkan share.
set(_faf_client_shared_backend_files
  "^gpg/gal/backends/dxgi/DxgiFormats\\.cpp$"
  "^gpg/gal/backends/d3d11/(D3D11VertexLayouts|EffectSourceD3D11)\\.cpp$"
  "^gpg/gal/backends/d3d9/D3D9BaseClasses\\.cpp$"
  "^gpg/gal/backends/d3d10/(Float16)?HardwareVertexFormatterD3D10\\.cpp$")
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
  set(FAF_DEPENDENCIES_ONLY DirectX-Headers SDL3 FAudio dxc-linux DirectXTex DirectXMath stb freetype msdfgen
    libjuice libdatachannel usrsctp plog mbedtls)
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
# The native windows and their input on SDL3 (platform/Window.h, issue #256).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/WindowSdl.cpp")
# Movie sound on an SDL3 audio stream (moho::sfd::AudioSink; DirectSoundMovieSink.cpp on Windows).
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/SdlMovieSink.cpp")
# CD3DFont's GDI text calls on FreeType.
list(APPEND _faf_client_files "${PROJECT_SOURCE_DIR}/src/platform/posix/GdiOverFreeType.cpp")

# DXC's Linux headers bring their own Win32 types, which clash with the POSIX <Windows.h> the
# client's files are compiled with (platform/PosixCompat.h), so the one file that includes them is
# built on its own, without faf_sim_settings. libdxcompiler.so is loaded at run time.
add_library(faf_client_dxc OBJECT "${PROJECT_SOURCE_DIR}/src/platform/posix/dxc/DxcGlue.cpp")
target_include_directories(faf_client_dxc PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${FAF_DEPENDENCIES_DIR}/dxc-linux/include")
target_compile_options(faf_client_dxc PRIVATE -pthread -Wall "SHELL:-include platform/PlatformDefines.h"
  -Wundef-prefix=FAFRE_PLATFORM_ -Werror=undef-prefix)

# MSDF text (moho/render/font, issue #306): FreeType and msdfgen, built as Windows builds them
# (their recipes take FAF_LINUX already).
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/freetype" "${CMAKE_BINARY_DIR}/deps/freetype")
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/msdfgen" "${CMAKE_BINARY_DIR}/deps/msdfgen")

# The in-engine peer links (src/netlink, issue #233) on libjuice and libdatachannel, built as
# Windows builds them (their recipes take FAF_LINUX).
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/libjuice" "${CMAKE_BINARY_DIR}/deps/libjuice")
add_subdirectory("${PROJECT_SOURCE_DIR}/cmake/deps/libdatachannel" "${CMAKE_BINARY_DIR}/deps/libdatachannel")
add_subdirectory("${PROJECT_SOURCE_DIR}/src/netlink" "${CMAKE_BINARY_DIR}/netlink")

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
# The platform macros for src/platform/posix/sal/sal.h, which DirectXTex reads.
target_compile_options(faf_directxtex_linux PRIVATE -w -pthread "SHELL:-include ${PROJECT_SOURCE_DIR}/src/platform/PlatformDefines.h")

add_library(faf_client_imaging OBJECT
  "${PROJECT_SOURCE_DIR}/src/gpg/gal/backends/common/ImageCodecDirectXTex.cpp"
  "${PROJECT_SOURCE_DIR}/src/platform/posix/imaging/StbImage.cpp")
target_include_directories(faf_client_imaging PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/winadapter"
  "${PROJECT_SOURCE_DIR}/src"
  "${FAF_DEPENDENCIES_DIR}/stb")
target_link_libraries(faf_client_imaging PUBLIC faf_directxtex_linux)
target_compile_options(faf_client_imaging PRIVATE -pthread -Wall "SHELL:-include platform/PlatformDefines.h"
  -Wundef-prefix=FAFRE_PLATFORM_ -Werror=undef-prefix)

# Movies (moho/movie/sfd): FFmpeg 7.1.3 from the dependencies/ffmpeg submodule Windows compiles.
# Its faf/ CMake build holds clang-cl configurations only, so here FFmpeg's own configure and make
# build the same components (FAF_CONFIGURE_OPTIONS in dependencies/ffmpeg/faf/generate.sh) as static
# libraries, with the pinned compiler, position-independent code for the executable, and no
# autodetection, so no library of the build machine is picked up.
include(ExternalProject)
include(ProcessorCount)
set(_faf_ffmpeg "${FAF_DEPENDENCIES_DIR}/ffmpeg")
if(NOT EXISTS "${_faf_ffmpeg}/configure")
  message(FATAL_ERROR "FFmpeg sources not found in ${_faf_ffmpeg} (git submodule update --init dependencies/ffmpeg)")
endif()
find_program(FAF_MAKE make REQUIRED)
ProcessorCount(_faf_ffmpeg_jobs)
if(_faf_ffmpeg_jobs EQUAL 0)
  set(_faf_ffmpeg_jobs 2)
endif()
set(_faf_ffmpeg_prefix "${CMAKE_BINARY_DIR}/deps/ffmpeg")
set(_faf_ffmpeg_libs avformat avcodec swscale swresample avutil)
set(_faf_ffmpeg_archives "")
foreach(_lib IN LISTS _faf_ffmpeg_libs)
  list(APPEND _faf_ffmpeg_archives "${_faf_ffmpeg_prefix}/lib/lib${_lib}.a")
endforeach()
ExternalProject_Add(faf_ffmpeg_build
  SOURCE_DIR "${_faf_ffmpeg}"
  BINARY_DIR "${_faf_ffmpeg_prefix}/build"
  INSTALL_DIR "${_faf_ffmpeg_prefix}"
  DOWNLOAD_COMMAND ""
  UPDATE_COMMAND ""
  CONFIGURE_COMMAND "${_faf_ffmpeg}/configure" --prefix=<INSTALL_DIR>
    "--cc=${CMAKE_C_COMPILER}" "--ar=${CMAKE_AR}" "--ranlib=${CMAKE_RANLIB}" "--nm=${CMAKE_NM}"
    --enable-pic --disable-autodetect --pkg-config=false
    --disable-x86asm --disable-everything --disable-programs --disable-doc --disable-network
    --enable-static --disable-shared
    --enable-avcodec --enable-avformat --enable-avutil --enable-swscale --enable-swresample
    --enable-decoder=mpeg1video,mpeg2video,adpcm_adx,mp1,mp2,mp3
    --enable-parser=mpegvideo,mpegaudio,adx
    --enable-demuxer=mpegps,mpegvideo,adx,mp3
    --enable-protocol=file
  BUILD_COMMAND "${FAF_MAKE}" -j${_faf_ffmpeg_jobs}
  INSTALL_COMMAND "${FAF_MAKE}" install-headers install-libs
  BUILD_BYPRODUCTS ${_faf_ffmpeg_archives})
file(MAKE_DIRECTORY "${_faf_ffmpeg_prefix}/include")
add_library(faf_ffmpeg INTERFACE)
foreach(_lib IN LISTS _faf_ffmpeg_libs)
  add_library(faf_ffmpeg_${_lib} STATIC IMPORTED)
  set_target_properties(faf_ffmpeg_${_lib} PROPERTIES IMPORTED_LOCATION "${_faf_ffmpeg_prefix}/lib/lib${_lib}.a")
  add_dependencies(faf_ffmpeg_${_lib} faf_ffmpeg_build)
  target_link_libraries(faf_ffmpeg INTERFACE faf_ffmpeg_${_lib})
endforeach()
target_include_directories(faf_ffmpeg SYSTEM INTERFACE "${_faf_ffmpeg_prefix}/include")
target_link_libraries(faf_ffmpeg INTERFACE m)

add_library(faf_client_objs OBJECT ${_faf_client_files})
add_dependencies(faf_client_objs faf_client_dxc faf_client_imaging faf_ffmpeg_build)
# boost 1.34's string algorithms (the lobby) derive from std::unary_function, which libc++ keeps
# behind this opt-in since C++17, as boost.thread's std::auto_ptr (cmake/FafLinux.cmake).
target_compile_definitions(faf_client_objs PRIVATE _LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION=1)
target_link_libraries(faf_client_objs PUBLIC faf_sim_settings Wm3Headers zlib123 faf_monocypher faf_zstd
  FAudio-static SDL3::SDL3-static  # FAudio names its static target FAudio-static, with no alias
  faf_freetype faf_msdfgen faf_ffmpeg faf_netlink)
target_include_directories(faf_client_objs PRIVATE
  "${PROJECT_SOURCE_DIR}/src/platform/posix/wx"
  "${FAF_DEPENDENCIES_DIR}/vulkan/include"
  "${FAF_DEPENDENCIES_DIR}/DirectX-Headers/include/directx")

# The Linux client executable (issue #256): its entry point (src/platform/posix/ClientMainPosix.cpp,
# WinMain's place), the client objects and the simulation. Not built by default until it links;
# `--target faf_client` lists what is still unresolved.
add_executable(faf_client EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/src/platform/posix/ClientMainPosix.cpp")
target_include_directories(faf_client PRIVATE "${PROJECT_SOURCE_DIR}/src/platform/posix/wx")
target_link_libraries(faf_client PRIVATE faf_client_objs faf_client_dxc faf_client_imaging faf_sim faf_directxtex_linux)
target_link_options(faf_client PRIVATE -Wl,--error-limit=0)
