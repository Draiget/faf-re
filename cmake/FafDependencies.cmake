# FafDependencies.cmake - puts dependencies/ into the state the build needs.
#
# Runs at configure time (the top-level CMakeLists.txt includes it) and on its own:
#   cmake -P cmake/FafDependencies.cmake
#
#   * Git submodules (WildMagic3p8, zlib-1.2.3, FX11, vulkan, ffmpeg): initialised when
#     missing and moved when their pin changes, always with core.autocrlf=false.
#     Git for Windows turns autocrlf on system-wide, and converted line endings
#     break the CR-exact patches.
#   * Downloads (boost 1.34.1, wxWindows 2.4.2, DXC): pinned by SHA256, cached in
#     dependencies/.downloads and extracted into dependencies/<name>.
#   * Patches (dependencies/patches): applied in order onto a fresh baseline. A
#     stamp file in each tree records the patches (and their hashes) it carries,
#     so a re-run does nothing and a changed patch re-creates the tree from its
#     baseline. A tree without a stamp (one made before this script) is adopted
#     as it is when its last patch is already applied (line endings aside),
#     patched when it is the baseline, and re-created from the baseline otherwise.
#   * wxWindows' generated files, which its nmake build used to create.
#
#   * The DirectX SDK (June 2010): an installed one, else its headers and libraries
#     extracted from Microsoft's installer (see faf_dependency_dxsdk).
#
# FAF_DEPENDENCIES_ONLY, a list of names (dxsdk for the DirectX SDK), limits a run to those;
# the Linux build (cmake/FafLinux.cmake) needs three:
#   cmake -DFAF_DEPENDENCIES_ONLY="WildMagic3p8;zlib-1.2.3;boost_1_34_1" -P cmake/FafDependencies.cmake
#
# FFmpeg (dependencies/ffmpeg, Draiget/ffmpeg-mirror) is the unmodified 7.1.3 source
# with a faf/ CMake build; src/CMakeLists.txt compiles it into static libraries
# (see docs/FAF_SFD_COMPATIBILITY.md).

if(CMAKE_SCRIPT_MODE_FILE)
  cmake_minimum_required(VERSION 3.25)  # standalone (cmake -P): no project policies yet
endif()

get_filename_component(_faf_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
if(NOT FAF_DEPENDENCIES_DIR)
  set(FAF_DEPENDENCIES_DIR "${_faf_root}/dependencies")
endif()
set(_faf_patches "${FAF_DEPENDENCIES_DIR}/patches")
set(_faf_downloads "${FAF_DEPENDENCIES_DIR}/.downloads")
find_program(FAF_GIT git REQUIRED)

function(_faf_git dir out_rc)
  get_filename_component(_parent "${dir}" DIRECTORY)
  # GIT_CEILING_DIRECTORIES keeps git from treating a downloaded tree as part
  # of this repository, so patch paths resolve against the tree itself.
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${_parent}"
            "${FAF_GIT}" -c core.autocrlf=false ${ARGN}
    WORKING_DIRECTORY "${dir}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  set(${out_rc} "${_rc}" PARENT_SCOPE)
  set(_faf_git_output "${_out}${_err}" PARENT_SCOPE)
endfunction()

function(_faf_apply_patch dir patch out_rc)
  _faf_git("${dir}" _rc apply ${ARGN} --unsafe-paths --whitespace=nowarn "${_faf_patches}/${patch}")
  set(${out_rc} "${_rc}" PARENT_SCOPE)
  set(_faf_git_output "${_faf_git_output}" PARENT_SCOPE)
endfunction()

# The stamp: one "<patch> <sha256>" line per patch, in order.
function(_faf_patch_stamp_text out)
  set(_text "")
  foreach(_patch IN LISTS ARGN)
    file(SHA256 "${_faf_patches}/${_patch}" _hash)
    string(APPEND _text "${_patch} ${_hash}\n")
  endforeach()
  set(${out} "${_text}" PARENT_SCOPE)
endfunction()

# Re-creates a tree from its baseline: a fresh extraction for a download, a
# hard reset and clean for a submodule.
function(_faf_rebaseline name kind)
  set(_dir "${FAF_DEPENDENCIES_DIR}/${name}")
  if(kind STREQUAL "submodule")
    _faf_git("${_dir}" _rc reset --hard -q)
    _faf_git("${_dir}" _rc2 clean -fdxq)
    if(_rc OR _rc2)
      message(FATAL_ERROR "Dependencies: could not reset dependencies/${name}: ${_faf_git_output}")
    endif()
  else()
    file(REMOVE_RECURSE "${_dir}")
    _faf_download_tree(${name})
  endif()
endfunction()

# Applies the patches of one tree, see the header.
function(faf_dependency_patches name kind)
  if(FAF_DEPENDENCIES_ONLY AND NOT name IN_LIST FAF_DEPENDENCIES_ONLY)
    return()
  endif()
  set(_dir "${FAF_DEPENDENCIES_DIR}/${name}")
  set(_stamp "${_dir}/.faf-patches")
  if(NOT CMAKE_SCRIPT_MODE_FILE)
    # A changed patch re-runs configure on the next build, which re-applies it.
    foreach(_patch IN LISTS ARGN)
      set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_faf_patches}/${_patch}")
    endforeach()
  endif()
  _faf_patch_stamp_text(_want ${ARGN})
  if(EXISTS "${_stamp}")
    file(READ "${_stamp}" _have)
    if(_have STREQUAL _want)
      return()
    endif()
    message(STATUS "Dependencies: patches for dependencies/${name} changed, re-creating it from its baseline")
    _faf_rebaseline(${name} ${kind})
  else()
    # Already patched, whatever its line endings (an older copy may have been
    # converted to CRLF): the patches are not applied a second time.
    list(GET ARGN -1 _last)
    _faf_apply_patch("${_dir}" "${_last}" _rc --reverse --check --ignore-whitespace)
    if(_rc EQUAL 0)
      message(STATUS "Dependencies: dependencies/${name} already carries its patches")
      file(WRITE "${_stamp}" "${_want}")
      return()
    endif()
    # Neither patched nor the baseline (an older copy, other line endings, local
    # edits): start over from the baseline.
    list(GET ARGN 0 _first)
    _faf_apply_patch("${_dir}" "${_first}" _rc --check)
    if(NOT _rc EQUAL 0)
      message(STATUS "Dependencies: dependencies/${name} is not its baseline, re-creating it")
      _faf_rebaseline(${name} ${kind})
    endif()
  endif()
  foreach(_patch IN LISTS ARGN)
    _faf_apply_patch("${_dir}" "${_patch}" _rc)
    if(NOT _rc EQUAL 0)
      message(FATAL_ERROR "Dependencies: ${_patch} does not apply to dependencies/${name}:\n${_faf_git_output}\n"
                          "Delete dependencies/${name} (or reset the submodule) and configure again.")
    endif()
    message(STATUS "Dependencies: applied ${_patch}")
  endforeach()
  file(WRITE "${_stamp}" "${_want}")
endfunction()

# --- Submodules -----------------------------------------------------------------------
function(faf_dependency_submodule name)
  if(FAF_DEPENDENCIES_ONLY AND NOT name IN_LIST FAF_DEPENDENCIES_ONLY)
    return()
  endif()
  set(_dir "${FAF_DEPENDENCIES_DIR}/${name}")
  if(EXISTS "${_dir}/.git")
    # Follow a pin change (a pull that moved the gitlink): back to the baseline,
    # check out the new commit, and let faf_dependency_patches re-apply.
    _faf_git("${_faf_root}" _rc ls-files -s -- "dependencies/${name}")
    string(REGEX MATCH "^160000 ([0-9a-f]+)" _m "${_faf_git_output}")
    set(_want "${CMAKE_MATCH_1}")
    _faf_git("${_dir}" _rc rev-parse HEAD)
    string(STRIP "${_faf_git_output}" _have)
    if(NOT _want OR _have STREQUAL _want)
      return()
    endif()
    message(STATUS "Dependencies: moving dependencies/${name} to ${_want}")
    _faf_rebaseline(${name} submodule)
  else()
    message(STATUS "Dependencies: fetching submodule dependencies/${name}")
  endif()
  execute_process(
    COMMAND "${FAF_GIT}" -c core.autocrlf=false submodule update --init -- "dependencies/${name}"
    WORKING_DIRECTORY "${_faf_root}" RESULT_VARIABLE _rc ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "Dependencies: git submodule update failed for dependencies/${name}:\n${_err}")
  endif()
  # Keep the setting for later checkouts, and rewrite anything a global
  # autocrlf converted during the clone.
  _faf_git("${_dir}" _rc config core.autocrlf false)
  _faf_git("${_dir}" _rc rm -r -q --cached .)
  _faf_git("${_dir}" _rc reset --hard -q)
endfunction()

# --- Downloads ------------------------------------------------------------------------
set(_faf_download_boost_1_34_1
    "https://downloads.sourceforge.net/project/boost/boost/1.34.1/boost_1_34_1.tar.bz2"
    "0f866c75b025a4f1340117a106595cc0675f48ba1e5a9b5c221ec7f19e96ec4c"
    "boost_1_34_1")
set(_faf_download_wxWindows-2.4.2
    "https://github.com/wxWidgets/wxWidgets/releases/download/v2.4.2/wxMSW-2.4.2.zip"
    "081cb30347ed9092a50c39311b46586f4264fb125942652db168851be96ebf33"
    "wxWindows-2.4.2")
set(_faf_download_dxc
    "https://github.com/microsoft/DirectXShaderCompiler/releases/download/v1.9.2609/dxc_2026_09_29.zip"
    "ad31b1fc8443175d204f77a611fdb3ef2ec42759bdc2f1167368de24a4a7e7f1"
    "")

function(_faf_download_tree name)
  list(GET _faf_download_${name} 0 _url)
  list(GET _faf_download_${name} 1 _sha256)
  list(LENGTH _faf_download_${name} _n)
  set(_root "")
  if(_n GREATER 2)
    list(GET _faf_download_${name} 2 _root)
  endif()
  get_filename_component(_file "${_url}" NAME)
  set(_archive "${_faf_downloads}/${_file}")
  if(EXISTS "${_archive}")
    file(SHA256 "${_archive}" _have)
  endif()
  if(NOT EXISTS "${_archive}" OR NOT _have STREQUAL _sha256)
    message(STATUS "Dependencies: downloading ${_url}")
    file(DOWNLOAD "${_url}" "${_archive}" EXPECTED_HASH SHA256=${_sha256} STATUS _status TLS_VERIFY ON)
    list(GET _status 0 _code)
    if(NOT _code EQUAL 0)
      message(FATAL_ERROR "Dependencies: download failed: ${_url}: ${_status}")
    endif()
  endif()
  string(REPLACE "/" "-" _scratch_name "${name}")
  set(_scratch "${_faf_downloads}/extract-${_scratch_name}")
  file(REMOVE_RECURSE "${_scratch}")
  get_filename_component(_parent "${FAF_DEPENDENCIES_DIR}/${name}" DIRECTORY)
  file(MAKE_DIRECTORY "${_parent}")
  file(ARCHIVE_EXTRACT INPUT "${_archive}" DESTINATION "${_scratch}")
  if(_root)
    file(RENAME "${_scratch}/${_root}" "${FAF_DEPENDENCIES_DIR}/${name}")
    file(REMOVE_RECURSE "${_scratch}")
  else()
    file(RENAME "${_scratch}" "${FAF_DEPENDENCIES_DIR}/${name}")
  endif()
  file(WRITE "${FAF_DEPENDENCIES_DIR}/${name}/.faf-download" "${_sha256}\n")
endfunction()

function(faf_dependency_download name)
  if(FAF_DEPENDENCIES_ONLY AND NOT name IN_LIST FAF_DEPENDENCIES_ONLY)
    return()
  endif()
  if(EXISTS "${FAF_DEPENDENCIES_DIR}/${name}")
    return()  # downloaded earlier, or a tree made before this script
  endif()
  _faf_download_tree(${name})
endfunction()

# --- wxWindows' generated files ---------------------------------------------------------
# What wx's makefile.vc and FAF's former Build-Deps step produced: the per-configuration
# setup.h copies (Unicode for mswu) and the parser sources it copies from their DOS names.
function(_faf_wx_generated)
  if(FAF_DEPENDENCIES_ONLY AND NOT "wxWindows-2.4.2" IN_LIST FAF_DEPENDENCIES_ONLY)
    return()
  endif()
  set(_wx "${FAF_DEPENDENCIES_DIR}/wxWindows-2.4.2")
  file(READ "${_wx}/include/wx/msw/setup.h" _setup)
  if(NOT EXISTS "${_wx}/lib/msw/wx/setup.h")
    file(WRITE "${_wx}/lib/msw/wx/setup.h" "${_setup}")
  endif()
  if(NOT EXISTS "${_wx}/lib/mswu/wx/setup.h")
    string(REPLACE "#define wxUSE_UNICODE 0" "#define wxUSE_UNICODE 1" _unicode "${_setup}")
    file(WRITE "${_wx}/lib/mswu/wx/setup.h" "${_unicode}")
  endif()
  foreach(_pair "y_tab.c=dosyacc.c" "lex_yy.c=doslex.c")
    string(REPLACE "=" ";" _pair "${_pair}")
    list(GET _pair 0 _to)
    list(GET _pair 1 _from)
    if(NOT EXISTS "${_wx}/src/common/${_to}")
      file(COPY_FILE "${_wx}/src/common/${_from}" "${_wx}/src/common/${_to}")
    endif()
  endforeach()
endfunction()

# --- DirectX SDK (June 2010) -----------------------------------------------------------
# An installed SDK is used as it is. Only when none is found, or the one found is not
# June 2010 (D3DX_SDK_VERSION 43), are its Include and Lib folders extracted from
# Microsoft's installer into dependencies/dxsdk; nothing is installed. Its licence
# does not allow redistributing them, so they come from Microsoft, not from here.
set(_faf_dxsdk_url
    "https://download.microsoft.com/download/A/E/7/AE743F1F-632B-4809-87A9-AA1BB3458E31/DXSDK_Jun10.exe")
set(_faf_dxsdk_sha256 "705271dc83bfee54d9b94e028426e288d5f070784b7446d164f48ecfbb2a02cb")

function(_faf_dxsdk_is_june2010 dir out)
  set(${out} FALSE PARENT_SCOPE)
  if(EXISTS "${dir}/Include/d3dx9core.h" AND EXISTS "${dir}/Lib/x86/d3dx9.lib" AND EXISTS "${dir}/Lib/x64/d3dx9.lib")
    file(STRINGS "${dir}/Include/d3dx9core.h" _version REGEX "^#define D3DX_SDK_VERSION 43")
    if(_version)
      set(${out} TRUE PARENT_SCOPE)
    endif()
  endif()
endfunction()

function(faf_dependency_dxsdk)
  if(FAF_DEPENDENCIES_ONLY AND NOT "dxsdk" IN_LIST FAF_DEPENDENCIES_ONLY)
    return()
  endif()
  set(_candidates "")
  if(NOT FAF_DXSDK_FORCE_DOWNLOAD)  # FAF_DXSDK_FORCE_DOWNLOAD=ON tests the fallback
    if(FAF_DXSDK_DIR)
      list(APPEND _candidates "${FAF_DXSDK_DIR}")
    endif()
    if(DEFINED ENV{DXSDK_DIR})
      file(TO_CMAKE_PATH "$ENV{DXSDK_DIR}" _env)
      list(APPEND _candidates "${_env}")
    endif()
    list(APPEND _candidates "C:/Program Files (x86)/Microsoft DirectX SDK (June 2010)")
  endif()
  list(APPEND _candidates "${FAF_DEPENDENCIES_DIR}/dxsdk")
  foreach(_dir IN LISTS _candidates)
    string(REGEX REPLACE "/$" "" _dir "${_dir}")
    _faf_dxsdk_is_june2010("${_dir}" _ok)
    if(_ok)
      set(_found "${_dir}")
      break()
    endif()
  endforeach()
  if(NOT _found)
    message(STATUS "Dependencies: no DirectX SDK (June 2010) found, extracting its headers and libraries from ${_faf_dxsdk_url}")
    set(_archive "${_faf_downloads}/DXSDK_Jun10.exe")
    if(EXISTS "${_archive}")
      file(SHA256 "${_archive}" _have)
    endif()
    if(NOT EXISTS "${_archive}" OR NOT _have STREQUAL _faf_dxsdk_sha256)
      file(DOWNLOAD "${_faf_dxsdk_url}" "${_archive}" EXPECTED_HASH SHA256=${_faf_dxsdk_sha256} STATUS _status TLS_VERIFY ON)
      list(GET _status 0 _code)
      if(NOT _code EQUAL 0)
        message(FATAL_ERROR "Dependencies: download failed: ${_faf_dxsdk_url}: ${_status}")
      endif()
    endif()
    set(_scratch "${_faf_downloads}/extract-dxsdk")
    file(REMOVE_RECURSE "${_scratch}" "${FAF_DEPENDENCIES_DIR}/dxsdk")
    file(ARCHIVE_EXTRACT INPUT "${_archive}" DESTINATION "${_scratch}" PATTERNS "DXSDK/Include/*" "DXSDK/Lib/*")
    file(RENAME "${_scratch}/DXSDK" "${FAF_DEPENDENCIES_DIR}/dxsdk")
    file(REMOVE_RECURSE "${_scratch}")
    set(_found "${FAF_DEPENDENCIES_DIR}/dxsdk")
    _faf_dxsdk_is_june2010("${_found}" _ok)
    if(NOT _ok)
      message(FATAL_ERROR "Dependencies: the extracted DirectX SDK is incomplete: ${_found}")
    endif()
  endif()
  message(STATUS "Dependencies: DirectX SDK (June 2010): ${_found}")
  if(NOT CMAKE_SCRIPT_MODE_FILE)
    set(FAF_DXSDK_DIR "${_found}" CACHE PATH "DirectX SDK (June 2010): D3DX9, XACT3, X3DAudio" FORCE)
  endif()
endfunction()

# --- The dependencies -------------------------------------------------------------------
faf_dependency_dxsdk()
faf_dependency_submodule(WildMagic3p8)
faf_dependency_submodule(zlib-1.2.3)
faf_dependency_submodule(FX11)
faf_dependency_submodule(vulkan)
faf_dependency_submodule(ffmpeg)
faf_dependency_download(boost_1_34_1)
faf_dependency_download(wxWindows-2.4.2)
faf_dependency_download(dxc)

faf_dependency_patches(WildMagic3p8 submodule
  wildmagic3p8_faf_required.patch)
faf_dependency_patches(zlib-1.2.3 submodule
  zlib_1_2_3_faf_required.patch)
faf_dependency_patches(boost_1_34_1 download
  boost_1_34_1_faf_required.patch)
faf_dependency_patches(wxWindows-2.4.2 download
  wxwindows_2_4_2_faf_required.patch wxwindows_2_4_2_faf_x64.patch wxwindows_2_4_2_faf_x64_pointers.patch)
_faf_wx_generated()
