# Dear ImGui 1.92.4, docking branch (MIT, LICENSE.txt in the tree): the map editor's panels
# (src/editor). dependencies/imgui is the tag's source archive, pinned by SHA256 in
# cmake/FafDependencies.cmake. The core and the Win32 platform backend; the editor draws
# through its own gal renderer (src/editor/ui/EdImGuiRenderer.cpp), not one of ImGui's.

set(_imgui "${FAF_DEPENDENCIES_DIR}/imgui")
if(NOT EXISTS "${_imgui}/imgui.cpp")
  message(STATUS "Dependencies: Dear ImGui not found in ${_imgui}; the map editor (src/editor) is not built")
  return()
endif()

add_library(faf_imgui STATIC
  "${_imgui}/imgui.cpp"
  "${_imgui}/imgui_demo.cpp"
  "${_imgui}/imgui_draw.cpp"
  "${_imgui}/imgui_tables.cpp"
  "${_imgui}/imgui_widgets.cpp"
  "${_imgui}/backends/imgui_impl_win32.cpp")
target_include_directories(faf_imgui SYSTEM PUBLIC "${_imgui}" "${_imgui}/backends")
# 32-bit indices: the renderer reads them from a structured buffer of uint.
target_compile_definitions(faf_imgui PUBLIC "ImDrawIdx=unsigned int" IMGUI_DISABLE_OBSOLETE_FUNCTIONS)
target_compile_options(faf_imgui PRIVATE /W0)
target_link_libraries(faf_imgui PRIVATE faf_codegen)
target_link_libraries(faf_imgui PUBLIC dwmapi)
set_target_properties(faf_imgui PROPERTIES FOLDER "dependencies")
