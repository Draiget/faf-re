# The engine executable: main_x64.exe (x64) / main.exe (x86).
#
# The translation units and their order are in sources.cmake; per-file
# settings are below, each with its reason.

include(sources.cmake)

if(FAF_TARGET_ARCH STREQUAL "x64")
  set(_faf_default_name main_x64)
else()
  set(_faf_default_name main)
endif()
set(FAF_OUTPUT_NAME "${_faf_default_name}" CACHE STRING "Engine executable name, without .exe")

add_executable(faf_main WIN32 ${FAF_ENGINE_SOURCES})
set_target_properties(faf_main PROPERTIES OUTPUT_NAME "${FAF_OUTPUT_NAME}")

# --- Server mode ----------------------------------------------------------------------
# The client half of server-authoritative sessions (remote/sources.cmake). Its sources
# come after the engine's, so the static-init order stays the same. Without
# `/connectserver` on the command line the client is the lockstep client it is with the
# option off.
if(FAF_SERVER_MODE)
  include(remote/sources.cmake)
  target_sources(faf_main PRIVATE ${FAF_REMOTE_CLIENT_SOURCES})
  target_compile_definitions(faf_main PRIVATE FAF_SERVER_MODE=1)
endif()

# --- Resources ------------------------------------------------------------------------
# MohoResources.rc includes wx/msw/wx.rc (wx's cursors, bitmaps, menus).
# MohoManifest.rc embeds the application manifest (asInvoker, system DPI
# aware).
target_sources(faf_main PRIVATE moho/app/MohoResources.rc moho/app/MohoManifest.rc)
set_source_files_properties(moho/app/MohoResources.rc PROPERTIES
  INCLUDE_DIRECTORIES "${FAF_WX_INCLUDE_DIR}")

# The x64 half of legacy/math/X87Math.cpp: x64 has no inline assembly.
if(FAF_TARGET_ARCH STREQUAL "x64")
  target_sources(faf_main PRIVATE legacy/math/X87Math64.asm)
endif()

# --- FFmpeg ---------------------------------------------------------------------------
# FFmpeg 7.1.3 for the SFD movie player (moho/movie/sfd), compiled here from the
# dependencies/ffmpeg submodule (Draiget/ffmpeg-mirror: the unmodified release plus its
# faf/ CMake build) into static libraries and linked into the executable: no DLLs. Its
# objects get the same code generation rules as every other library (faf_codegen).
set(_faf_ffmpeg "${FAF_DEPENDENCIES_DIR}/ffmpeg")
if(NOT EXISTS "${_faf_ffmpeg}/faf/CMakeLists.txt")
  message(FATAL_ERROR "FFmpeg sources not found in ${_faf_ffmpeg} "
                      "(git submodule update --init dependencies/ffmpeg); see docs/FAF_SFD_COMPATIBILITY.md.")
endif()
add_subdirectory("${_faf_ffmpeg}/faf" "${CMAKE_BINARY_DIR}/dependencies/ffmpeg")
foreach(_lib IN LISTS FFMPEG_FAF_LIBRARIES)
  target_link_libraries(${_lib} PRIVATE faf_codegen)
endforeach()

# --- Compilation ----------------------------------------------------------------------
target_compile_definitions(faf_main PRIVATE
  WIN32 _WINDOWS WIN32_LEAN_AND_MEAN NOMINMAX
  LUAPLUS_LIB LUA_NUMBER=float
  BOOST_ALL_NO_LIB BOOST_NO_AUTO_PTR
  _CRT_SECURE_NO_WARNINGS
  UNICODE _UNICODE)

target_include_directories(faf_main PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${FAF_DEPENDENCIES_DIR}/boost_1_34_1"
  "${FAF_DEPENDENCIES_DIR}/zlib-1.2.3")
target_link_libraries(faf_main PRIVATE faf_codegen faf::wx Wm3Dx9Application)

set(_faf_main_options
  # C++ exceptions with extern "C" functions allowed to throw (/EHs, not
  # /EHsc): the Lua fork raises script errors as C++ lua::lua_Error throws out
  # of functions declared extern "C" (luaD_call and its callees). /EHsc lets the
  # optimizer drop the handlers around them, and luaB_pcall's try/catch then
  # vanishes.
  /EHs
  /permissive-
  /W3
  # The DirectX SDK (June 2010) goes after the Windows SDK: d3d9.h, dxgi.h and
  # d3d10.h must resolve to the Windows SDK copies, d3dx9*.h and xact3.h to
  # the DirectX SDK.
  "/clang:-idirafter${FAF_DXSDK_DIR}/Include")

if(FAF_TARGET_ARCH STREQUAL "x64")
  # Switches off the Win32 layout static_asserts (see the header).
  list(APPEND _faf_main_options /FIplatform/X64LayoutAsserts.h)
else()
  # Keeps sqrt a CRT call under the sim's _PC_24 x87 control word (see the
  # header and cmake/FafCodegen.cmake).
  list(APPEND _faf_main_options /FIplatform/X87SqrtCall.h)
endif()

# Diagnostics: the recovered tree is written against MSVC; keep clang's
# portability chatter out of the log so real problems stand out.
list(APPEND _faf_main_options
  -Wno-microsoft
  -Wno-unused-parameter -Wno-unused-variable -Wno-unused-private-field
  -Wno-unused-function -Wno-unused-local-typedef -Wno-unused-but-set-variable
  -Wno-unused-lambda-capture -Wno-unused-value -Wno-unused-command-line-argument
  -Wno-missing-field-initializers -Wno-sign-compare -Wno-switch
  -Wno-invalid-offsetof -Wno-keyword-macro -Wno-unknown-pragmas
  -Wno-ignored-pragma-intrinsic -Wno-pragma-pack -Wno-ignored-attributes
  -Wno-deprecated-declarations -Wno-deprecated-enum-enum-conversion
  -Wno-nonportable-include-path -Wno-reorder-ctor
  -Wno-delete-non-abstract-non-virtual-dtor -Wno-overloaded-virtual
  -Wno-inconsistent-missing-override -Wno-missing-braces -Wno-braced-scalar-init
  -Wno-char-subscripts -Wno-parentheses -Wno-dangling-else
  -Wno-tautological-constant-out-of-range-compare
  -Wno-tautological-undefined-compare -Wno-undefined-var-template
  -Wno-writable-strings -Wno-comment -Wno-extra-tokens -Wno-nontrivial-memcall
  -Wno-mismatched-tags -Wno-extra-qualification)

# C and C++ only (not the x64 MASM file).
target_compile_options(faf_main PRIVATE "$<$<COMPILE_LANGUAGE:C,CXX>:${_faf_main_options}>")

# --- Per-file settings ---------------------------------------------------------------
set(_fx11 "${FAF_DEPENDENCIES_DIR}/FX11")

set_property(SOURCE
    gpg/gal/backends/d3d11/D3D11Effects.cpp
    gpg/gal/backends/d3d11/D3D11Resources.cpp
    gpg/gal/backends/d3d11/D3D11VertexLayouts.cpp
    gpg/gal/backends/d3d11/DeviceD3D11.cpp
  APPEND PROPERTY INCLUDE_DIRECTORIES "${_fx11}/inc")

set_property(SOURCE gpg/gal/effects/ShaderCompiler.cpp
  APPEND PROPERTY INCLUDE_DIRECTORIES "${FAF_DEPENDENCIES_DIR}/dxc/inc")

set_property(SOURCE
    gpg/gal/Device.cpp
    gpg/gal/backends/vulkan/VulkanLoader.cpp
    gpg/gal/backends/vulkan/VulkanSurface.cpp
    gpg/gal/backends/vulkan/VulkanCore.cpp
    gpg/gal/backends/vulkan/ResourcesVulkan.cpp
    gpg/gal/backends/vulkan/DeviceVulkan.cpp
    gpg/gal/backends/vulkan/GpuDrivenVulkan.cpp
  APPEND PROPERTY INCLUDE_DIRECTORIES "${FAF_DEPENDENCIES_DIR}/vulkan/include")

# FX11 (Effects 11) compiles into the engine as its own project would build it:
# C++17, permissive, no two-phase lookup, warnings off.
set(_fx11_sources
  "${_fx11}/d3dxGlobal.cpp" "${_fx11}/EffectAPI.cpp" "${_fx11}/EffectLoad.cpp"
  "${_fx11}/EffectNonRuntime.cpp" "${_fx11}/EffectReflection.cpp" "${_fx11}/EffectRuntime.cpp")
set_property(SOURCE ${_fx11_sources}
  APPEND PROPERTY INCLUDE_DIRECTORIES "${_fx11}" "${_fx11}/inc" "${_fx11}/Binary")
set_property(SOURCE ${_fx11_sources}
  APPEND PROPERTY COMPILE_OPTIONS /std:c++17 /permissive /Zc:twoPhase- /W0)

# WxUrl.cpp: built ANSI (UNICODE/_UNICODE undefined), as the original's wxURL
# use was.
set_property(SOURCE moho/app/WxUrl.cpp APPEND PROPERTY COMPILE_DEFINITIONS NDEBUG)
set_property(SOURCE moho/app/WxUrl.cpp APPEND PROPERTY COMPILE_OPTIONS /UUNICODE /U_UNICODE)

# boost::algorithm::string (boost 1.34.1) needs std::unary_function and
# std::binary_function, which the MSVC STL keeps only behind this opt-in macro.
# CLobby.cpp is the one engine consumer (BuildLobbyIgnoreNameList's
# boost::algorithm::split).
set_property(SOURCE moho/net/CLobby.cpp APPEND PROPERTY COMPILE_DEFINITIONS _HAS_AUTO_PTR_ETC=1)

# boost.thread 1.34.1, compiled into the engine (no bjam build).
set(_boost_thread "${FAF_DEPENDENCIES_DIR}/boost_1_34_1/libs/thread/src")
set(_boost_thread_sources
  barrier.cpp condition.cpp exceptions.cpp mutex.cpp once.cpp recursive_mutex.cpp
  thread.cpp tss_hooks.cpp tss_dll.cpp tss_pe.cpp tss.cpp xtime.cpp)
list(TRANSFORM _boost_thread_sources PREPEND "${_boost_thread}/")
set_property(SOURCE ${_boost_thread_sources}
  APPEND PROPERTY COMPILE_DEFINITIONS _HAS_AUTO_PTR_ETC=1 BOOST_THREAD_BUILD_LIB=1)
set_property(SOURCE ${_boost_thread_sources} APPEND PROPERTY COMPILE_OPTIONS /W0)
# condition_impl::condition_impl() calls the UNICODE-sensitive
# CreateSemaphore/CreateMutex macros; the original (0x00AC2190) resolves them
# to the A entry points.
set_property(SOURCE "${_boost_thread}/condition.cpp" APPEND PROPERTY COMPILE_OPTIONS /UUNICODE /U_UNICODE)

set_property(SOURCE moho/movie/sfd/FfmpegSfdDecoder.cpp APPEND PROPERTY COMPILE_OPTIONS -Wno-everything)

# --- Link -----------------------------------------------------------------------------
if(FAF_TARGET_ARCH STREQUAL "x64")
  set(_faf_dxsdk_lib "${FAF_DXSDK_DIR}/Lib/x64")
  set(_faf_sdk_arch x64)
else()
  set(_faf_dxsdk_lib "${FAF_DXSDK_DIR}/Lib/x86")
  set(_faf_sdk_arch x86)
endif()
set(_faf_sdk_um_lib "${FAF_WINSDK_DIR}/Lib/${FAF_WINSDK_VERSION}/um/${_faf_sdk_arch}")

if(FAF_TARGET_ARCH STREQUAL "x64")
  set(_faf_zlib zlib123)
else()
  set(_faf_zlib wx_zlib)
endif()

# The DirectX SDK libraries are searched before the Windows SDK's;
# d3dcompiler.lib and dxguid.lib are taken from the Windows SDK by full path.
target_link_directories(faf_main PRIVATE "${_faf_dxsdk_lib}")
target_link_libraries(faf_main PRIVATE
  FFmpeg::FFmpeg
  ws2_32 d3d9 d3dx9 d3d10 d3d11 "${_faf_sdk_um_lib}/d3dcompiler.lib" dxgi
  "${_faf_sdk_um_lib}/dxguid.lib" dsound x3daudio
  legacy_stdio_definitions legacy_stdio_wide_specifiers
  dbghelp winmm version comctl32 shlwapi faultrep
  ${_faf_zlib}
  # Visual Studio's default AdditionalDependencies beyond CMake's defaults.
  odbc32 odbccp32)

target_link_options(faf_main PRIVATE
  # Nothing may pull in the DLL runtime beside the static one.
  /NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:msvcprt.lib /NODEFAULTLIB:msvcrtd.lib /NODEFAULTLIB:msvcprtd.lib
  /NODEFAULTLIB:ucrt.lib /NODEFAULTLIB:vcruntime.lib
  # The manifest comes from MohoManifest.rc.
  /MANIFEST:NO)

# The static UCRT is the C runtime's math library, so its release decides
# results the simulation depends on. UCRT 10.0.26100's x64 asin, acos, atan,
# atan2 and pow (float and double) differ in the last bit, for 0.1-1% of
# inputs, from every earlier release - and from ucrtbase.dll 10.0.22000, which
# the MSVC build's replay parity was established against. Linked with 26100,
# replay 26935800 desyncs at beat 2800. The library is therefore pinned to
# FAF_UCRT_LIB_VERSION (default 10.0.22000.0, whose math is bit-identical to
# 19041's and 20348's); the headers stay those of FAF_WINSDK_VERSION.
set(_faf_ucrt_default "10.0.22000.0")
if(NOT EXISTS "${FAF_WINSDK_DIR}/Lib/${_faf_ucrt_default}/ucrt/${_faf_sdk_arch}/libucrt.lib")
  set(_faf_ucrt_default "${FAF_WINSDK_VERSION}")
endif()
set(FAF_UCRT_LIB_VERSION "${_faf_ucrt_default}" CACHE STRING
    "Windows SDK version whose static UCRT (libucrt.lib) the engine links")
set(_faf_libucrt "${FAF_WINSDK_DIR}/Lib/${FAF_UCRT_LIB_VERSION}/ucrt/${_faf_sdk_arch}/libucrt.lib")
if(NOT EXISTS "${_faf_libucrt}")
  message(FATAL_ERROR "libucrt.lib not found: ${_faf_libucrt} (FAF_UCRT_LIB_VERSION)")
endif()
if(NOT FAF_UCRT_LIB_VERSION STREQUAL "10.0.22000.0")
  message(WARNING "Linking the UCRT of SDK ${FAF_UCRT_LIB_VERSION}: install the Windows 10.0.22000 SDK "
                  "for the C runtime math the simulation's replay parity was established with.")
endif()
# Debug links the debug flavour (libucrtd.lib) from the same SDK.
set(_faf_ucrt_dir "${FAF_WINSDK_DIR}/Lib/${FAF_UCRT_LIB_VERSION}/ucrt/${_faf_sdk_arch}")
target_link_options(faf_main PRIVATE "/NODEFAULTLIB:libucrt$<$<CONFIG:Debug>:d>.lib")
target_link_libraries(faf_main PRIVATE "${_faf_ucrt_dir}/libucrt$<$<CONFIG:Debug>:d>.lib")

if(FAF_TARGET_ARCH STREQUAL "x86")
  # Both from the shipped binary's PE header (characteristics 0x123, stack
  # reserve 0x1E8480 = /STACK:2000000).
  target_link_options(faf_main PRIVATE /LARGEADDRESSAWARE /STACK:2000000)
else()
  # x64 address-space mode:
  #   full - large-address-aware with high-entropy ASLR (the default when the
  #          wx tree is pointer-safe),
  #   heap - large-address-aware, image pinned low (/BASE:0x10000000),
  #   none - the 2 GB image (/LARGEADDRESSAWARE:NO), the fallback when wx still
  #          truncates window-message pointers.
  if(FAF_WX_X64_POINTERS)
    set(_faf_x64_address_default full)
  else()
    set(_faf_x64_address_default none)
  endif()
  set(FAF_X64_LARGE_ADDRESS "${_faf_x64_address_default}" CACHE STRING "x64 address-space mode: none, heap or full")
  set_property(CACHE FAF_X64_LARGE_ADDRESS PROPERTY STRINGS none heap full)
  if(FAF_X64_LARGE_ADDRESS STREQUAL "full")
    if(NOT FAF_WX_X64_POINTERS)
      message(WARNING "FAF_X64_LARGE_ADDRESS=full with a wxWindows tree that lacks "
                      "wxwindows_2_4_2_faf_x64_pointers.patch: wx truncates window-message pointers above 2 GB.")
    endif()
    target_link_options(faf_main PRIVATE /LARGEADDRESSAWARE)
  elseif(FAF_X64_LARGE_ADDRESS STREQUAL "heap")
    target_link_options(faf_main PRIVATE /LARGEADDRESSAWARE /HIGHENTROPYVA:NO /BASE:0x10000000)
  else()
    target_link_options(faf_main PRIVATE /LARGEADDRESSAWARE:NO /HIGHENTROPYVA:NO)
  endif()
  # 4 MB of stack instead of the binary's 2 MB: every frame that holds pointers
  # is bigger.
  target_link_options(faf_main PRIVATE /STACK:4000000)
endif()

# --- Staging next to the executable ---------------------------------------------------
# The engine's own Lua hooks: the engine mounts the `fafengine` folder next to
# the executable at /fafengine (DISK_SetupDataAndSearchPaths; see
# docs/RENDERER_BACKENDS.md). And the DXC runtime (dxcompiler.dll, dxil.dll),
# which Direct3D 12 and Vulkan load to compile their shaders.
set(_faf_dxc_bin "${FAF_DEPENDENCIES_DIR}/dxc/bin/${_faf_sdk_arch}")
add_custom_command(TARGET faf_main POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_directory "${PROJECT_SOURCE_DIR}/data/fafengine"
          "$<TARGET_FILE_DIR:faf_main>/fafengine"
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_faf_dxc_bin}/dxcompiler.dll"
          "${_faf_dxc_bin}/dxil.dll" "$<TARGET_FILE_DIR:faf_main>"
  VERBATIM)
