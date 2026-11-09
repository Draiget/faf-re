# The map editor (.plans/map-editor): FafEditor_x64.exe (x64) / FafEditor.exe (x86).
#
# A program of its own on the engine's objects. It links faf_engine as the engine tests do,
# so every engine object is linked in the same order as faf_main's; the game's WinMain is
# among them, so the editor starts at its own main() (mainCRTStartup) instead.
#
# The editor runs the game's own app (CScApp) inside its own (editor/EdApp.cpp), limited to
# Direct3D 12 and Vulkan (moho::gAppRenderers); the other backends are linked but never created.

if(NOT TARGET faf_imgui)
  message(STATUS "faf_editor: Dear ImGui not found; the map editor is not built")
  return()
endif()

include(sources.cmake)

add_executable(faf_editor WIN32 ${FAF_EDITOR_SOURCES})
if(FAF_TARGET_ARCH STREQUAL "x64")
  set_target_properties(faf_editor PROPERTIES OUTPUT_NAME FafEditor_x64)
else()
  set_target_properties(faf_editor PROPERTIES OUTPUT_NAME FafEditor)
endif()
target_link_libraries(faf_editor PRIVATE faf_engine faf_imgui)
# /memtrace names the call sites of what a play leaves behind (EdMemTrace.cpp).
target_link_libraries(faf_editor PRIVATE dbghelp)
# Height images (tools/EdHeightFile.cpp) through the Windows imaging component; the file dialogs.
target_link_libraries(faf_editor PRIVATE ole32 windowscodecs comdlg32)
target_link_options(faf_editor PRIVATE "/ENTRY:mainCRTStartup")

# The game's window resources (wx's cursors and bitmaps, the icon) and manifest, as faf_main has
# them (src/CMakeLists.txt): the game's frame and viewport are the editor's window.
set(_faf_editor_app_dir "${CMAKE_CURRENT_SOURCE_DIR}/../moho/app")
target_sources(faf_editor PRIVATE "${_faf_editor_app_dir}/MohoResources.rc" "${_faf_editor_app_dir}/MohoManifest.rc")
set_source_files_properties("${_faf_editor_app_dir}/MohoResources.rc" PROPERTIES INCLUDE_DIRECTORIES "${FAF_WX_INCLUDE_DIR}")
target_link_options(faf_editor PRIVATE /MANIFEST:NO)

# The older renderers' DLLs load only if something calls into them, which the editor never
# does: it starts on a machine without the June 2010 DirectX runtime (d3dx9_43.dll, as
# faf_main's issue #317 delay-load), and Direct3D 9 is never loaded at all. Direct3D 11 stays
# usable on demand: Direct3D 12 and Vulkan decode textures on a private WARP device
# (gpg/gal/backends/common/ImageCodec).
target_link_options(faf_editor PRIVATE
  /DELAYLOAD:d3d9.dll /DELAYLOAD:d3dx9_43.dll /DELAYLOAD:d3d10.dll /DELAYLOAD:d3d11.dll)
target_link_libraries(faf_editor PRIVATE delayimp)

# With FAF_SERVER_MODE faf_engine's objects include the client's channel to the server
# (src/remote/client), which needs these, as faf_main links them.
if(FAF_SERVER_MODE)
  target_link_libraries(faf_editor PRIVATE faf_netchannel faf_monocypher)
endif()

# DXC's DLLs, carried as faf_main carries them (src/CMakeLists.txt, issue #315): Direct3D 12
# and Vulkan compile their shaders with it. The packed archive is made in src/ (faf_dxc_pack),
# so the resource waits for that target and is rebuilt when the archive changes.
target_sources(faf_editor PRIVATE "${_faf_embed_dir}/EmbeddedFiles.rc")
set_source_files_properties("${_faf_embed_dir}/EmbeddedFiles.rc" PROPERTIES
  OBJECT_DEPENDS "${_faf_embed_dir}/dxc.tar.zst")
add_dependencies(faf_editor faf_dxc_pack)
