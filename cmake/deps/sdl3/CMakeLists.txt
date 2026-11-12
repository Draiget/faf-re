# SDL 3.4.18 (zlib), static, for the Windows client (issue #407): the windows, input, clipboard,
# message boxes, file and folder pickers (platform/Window.h, src/platform/sdl) and the renderer
# the developer windows draw Dear ImGui with (src/platform/sdl/ToolWindow.cpp). dependencies/SDL3
# is the release archive, pinned by SHA256 in cmake/FafDependencies.cmake. The Linux client
# builds the same tree with its audio, for FAudio (cmake/FafLinuxClient.cmake).

set(_sdl "${FAF_DEPENDENCIES_DIR}/SDL3")
if(NOT EXISTS "${_sdl}/CMakeLists.txt")
  message(FATAL_ERROR "SDL3 sources not found in ${_sdl} (configure with FAF_FETCH_DEPENDENCIES=ON)")
endif()

set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
set(SDL_TESTS OFF CACHE BOOL "" FORCE)
set(SDL_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SDL_INSTALL OFF CACHE BOOL "" FORCE)
# The game's sound is XACT and DirectSound on Windows; controllers, cameras and sensors aren't used.
set(SDL_AUDIO OFF CACHE BOOL "" FORCE)
set(SDL_CAMERA OFF CACHE BOOL "" FORCE)
set(SDL_JOYSTICK OFF CACHE BOOL "" FORCE)
set(SDL_HAPTIC OFF CACHE BOOL "" FORCE)
set(SDL_SENSOR OFF CACHE BOOL "" FORCE)
set(SDL_HIDAPI OFF CACHE BOOL "" FORCE)
set(SDL_POWER OFF CACHE BOOL "" FORCE)
add_subdirectory("${_sdl}" "${CMAKE_BINARY_DIR}/deps/SDL3" EXCLUDE_FROM_ALL SYSTEM)
set_target_properties(SDL3-static PROPERTIES FOLDER "dependencies")
