cmake_minimum_required(VERSION 3.25)
project(ParticleBatchReclaimHostTests LANGUAGES CXX)

# Deliberately separate from faf_engine: this is a source-bound host recorder,
# not a graphics backend, ABI check, or native engine integration target.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(FAF_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." CACHE PATH "Engine source tree to bind")
set(GTEST_SOURCE_DIR "" CACHE PATH "Existing official GoogleTest source; no downloads")
option(SANITIZE "AddressSanitizer and fail-fast UndefinedBehaviorSanitizer" OFF)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(NOT TARGET gtest_main)
  if(NOT GTEST_SOURCE_DIR)
    message(FATAL_ERROR "Supply -DGTEST_SOURCE_DIR=<existing GoogleTest 1.15.2 directory>")
  endif()
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  add_subdirectory("${GTEST_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)
endif()
set(_bound "${CMAKE_CURRENT_BINARY_DIR}/ParticleBatchProduction.inc")
add_custom_command(OUTPUT "${_bound}" "${CMAKE_CURRENT_BINARY_DIR}/ParticleBatchProduction.json"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/bind_production.py"
    --source-root "${FAF_SOURCE_ROOT}" --output "${_bound}"
  DEPENDS bind_production.py
    "${FAF_SOURCE_ROOT}/src/moho/particles/CWorldParticles.cpp"
    "${FAF_SOURCE_ROOT}/src/moho/particles/ParticleRenderBuckets.cpp"
    "${FAF_SOURCE_ROOT}/src/moho/particles/ParticleRenderWorkItem.cpp"
    "${FAF_SOURCE_ROOT}/src/moho/render/GpuPathSettings.cpp"
    "${FAF_SOURCE_ROOT}/src/moho/particles/ParticlePoolReclaim.h"
    "${FAF_SOURCE_ROOT}/src/legacy/containers/Vector.h"
    "${FAF_SOURCE_ROOT}/src/legacy/containers/Layout.h"
    "${FAF_SOURCE_ROOT}/src/gpg/gal/GpuDriven.h"
    "${FAF_SOURCE_ROOT}/src/platform/LayoutAsserts.h"
  VERBATIM)
add_executable(faf_particle_batch_reclaim_host_tests ParticleBatchReclaimTests.cpp "${_bound}")
target_include_directories(faf_particle_batch_reclaim_host_tests PRIVATE
  "${FAF_SOURCE_ROOT}/src" "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(faf_particle_batch_reclaim_host_tests PRIVATE FAF_RETAIL_LAYOUT=0)
target_link_libraries(faf_particle_batch_reclaim_host_tests PRIVATE gtest_main)
add_executable(faf_particle_pool_reclaim_tests "${FAF_SOURCE_ROOT}/tests/particles/ParticlePoolReclaimTests.cpp")
target_include_directories(faf_particle_pool_reclaim_tests PRIVATE "${FAF_SOURCE_ROOT}/src")
target_link_libraries(faf_particle_pool_reclaim_tests PRIVATE gtest_main)
set_target_properties(faf_particle_batch_reclaim_host_tests faf_particle_pool_reclaim_tests
  PROPERTIES FOLDER "Tests/Particles")
foreach(t faf_particle_batch_reclaim_host_tests faf_particle_pool_reclaim_tests)
  if(MSVC)
    target_compile_options(${t} PRIVATE /W4)
  else()
    target_compile_options(${t} PRIVATE -Wall -Wextra -Werror -pedantic)
  endif()
endforeach()
if(SANITIZE)
  if(MSVC)
    message(FATAL_ERROR "SANITIZE in this host harness requires a GCC/Clang-style driver")
  endif()
  foreach(t faf_particle_batch_reclaim_host_tests faf_particle_pool_reclaim_tests gtest gtest_main)
    target_compile_options(${t} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_link_options(${t} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
  endforeach()
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 14)
  # Existing fa::list repeats outer typedef names; DestroyParticleRenderWorkItem
  # returns a freed pointer (callers discard it). Keep those GCC diagnostics visible,
  # without editing production or making them fatal to this host recorder.
  target_compile_options(faf_particle_batch_reclaim_host_tests PRIVATE -Wno-error=changes-meaning -Wno-error=use-after-free)
endif()
enable_testing()
add_test(NAME particle_batch_reclaim_host COMMAND faf_particle_batch_reclaim_host_tests)
add_test(NAME particle_pool_reclaim COMMAND faf_particle_pool_reclaim_tests)
set_tests_properties(particle_batch_reclaim_host PROPERTIES LABELS "Particles;ParticlesHost")
set_tests_properties(particle_pool_reclaim PROPERTIES LABELS "Particles")
