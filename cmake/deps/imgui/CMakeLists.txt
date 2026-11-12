# Dear ImGui 1.92.4, docking branch (MIT, LICENSE.txt in the tree). dependencies/imgui is the tag's
# source archive, pinned by SHA256 in cmake/FafDependencies.cmake.
#
#   faf_imgui_core  the core, shared by both users below
#   faf_imgui       + the Win32 platform backend: the map editor's panels (src/editor), which it
#                   draws through its own gal renderer (src/editor/ui/EdImGuiRenderer.cpp). Windows.
#   faf_imgui_sdl   + the SDL3 platform backend and SDL's renderer: the developer windows
#                   (src/platform/sdl/ToolWindow.cpp, issue #412), on every platform.
#
# The SDL3 targets (cmake/deps/sdl3, cmake/FafLinuxClient.cmake) are named, not required here.

set(_imgui "${FAF_DEPENDENCIES_DIR}/imgui")
if(NOT EXISTS "${_imgui}/imgui.cpp")
  message(STATUS "Dependencies: Dear ImGui not found in ${_imgui}; the map editor and the developer windows are not built")
  return()
endif()

add_library(faf_imgui_core STATIC
  "${_imgui}/imgui.cpp"
  "${_imgui}/imgui_demo.cpp"
  "${_imgui}/imgui_draw.cpp"
  "${_imgui}/imgui_tables.cpp"
  "${_imgui}/imgui_widgets.cpp")
target_include_directories(faf_imgui_core SYSTEM PUBLIC "${_imgui}" "${_imgui}/backends")
# 32-bit indices: the editor's renderer reads them from a structured buffer of uint; SDL's renderer
# takes either size.
target_compile_definitions(faf_imgui_core PUBLIC "ImDrawIdx=unsigned int" IMGUI_DISABLE_OBSOLETE_FUNCTIONS)
if(FAF_LINUX)
  target_compile_options(faf_imgui_core PRIVATE -w)
  set_target_properties(faf_imgui_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
  target_compile_options(faf_imgui_core PRIVATE /W0)
  target_link_libraries(faf_imgui_core PRIVATE faf_codegen)
endif()
set_target_properties(faf_imgui_core PROPERTIES FOLDER "dependencies")

if(NOT FAF_LINUX)
  add_library(faf_imgui STATIC "${_imgui}/backends/imgui_impl_win32.cpp")
  target_compile_options(faf_imgui PRIVATE /W0)
  target_link_libraries(faf_imgui PRIVATE faf_codegen)
  target_link_libraries(faf_imgui PUBLIC faf_imgui_core dwmapi)
  set_target_properties(faf_imgui PROPERTIES FOLDER "dependencies")
endif()

add_library(faf_imgui_sdl STATIC
  "${_imgui}/backends/imgui_impl_sdl3.cpp"
  "${_imgui}/backends/imgui_impl_sdlrenderer3.cpp")
target_link_libraries(faf_imgui_sdl PUBLIC faf_imgui_core SDL3::SDL3-static)
if(FAF_LINUX)
  target_compile_options(faf_imgui_sdl PRIVATE -w)
  set_target_properties(faf_imgui_sdl PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
  target_compile_options(faf_imgui_sdl PRIVATE /W0)
  target_link_libraries(faf_imgui_sdl PRIVATE faf_codegen)
endif()
set_target_properties(faf_imgui_sdl PROPERTIES FOLDER "dependencies")
