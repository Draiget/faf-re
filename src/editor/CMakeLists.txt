# The map editor (.plans/map-editor): FafEditor_x64.exe (x64) / FafEditor.exe (x86).
#
# A program of its own on the engine's objects. It links faf_engine as the engine tests do,
# so every engine object is linked in the same order as faf_main's; the game's WinMain is
# among them, so the editor starts at its own main() (mainCRTStartup) instead.
#
# It draws through Direct3D 12 or Vulkan only (editor/EdDevice.cpp); the other backends are
# linked but never created.

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
target_link_options(faf_editor PRIVATE "/ENTRY:mainCRTStartup")

# DXC's DLLs, carried as faf_main carries them (src/CMakeLists.txt, issue #315): Direct3D 12
# and Vulkan compile their shaders with it.
target_sources(faf_editor PRIVATE "${_faf_embed_dir}/EmbeddedFiles.rc")
