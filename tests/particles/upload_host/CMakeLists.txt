cmake_minimum_required(VERSION 3.25)
project(ParticleUploadHostTests LANGUAGES CXX)

# Standalone on purpose: configure the host fixture without the engine/graphics SDKs.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
get_filename_component(FAF_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(FAF_GTEST_DIR "${FAF_SOURCE_ROOT}/dependencies/googletest" CACHE PATH "Official GoogleTest source")
set(FAF_GTEST_LIBRARY_DIR "" CACHE PATH "Optional prebuilt matching libgtest and libgtest_main directory")
option(FAF_PARTICLE_SANITIZE "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(FAF_GTEST_LIBRARY_DIR)
  foreach(name gtest gtest_main)
    add_library(${name} STATIC IMPORTED)
    set_target_properties(${name} PROPERTIES
      IMPORTED_LOCATION "${FAF_GTEST_LIBRARY_DIR}/lib${name}.a"
      INTERFACE_INCLUDE_DIRECTORIES "${FAF_GTEST_DIR}/googletest/include")
  endforeach()
else()
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  add_subdirectory("${FAF_GTEST_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/googletest" EXCLUDE_FROM_ALL)
endif()

set(wm_root "${FAF_SOURCE_ROOT}/dependencies/WildMagic3p8/Foundation")
if(NOT EXISTS "${wm_root}/Math/Wm3Vector3.inl")
  message(FATAL_ERROR "Initialize the repository's WildMagic dependency and apply its documented patch first")
endif()
file(GLOB wm_subdirs LIST_DIRECTORIES true "${wm_root}/*")
set(wm_includes "${wm_root}")
foreach(path IN LISTS wm_subdirs)
  if(IS_DIRECTORY "${path}")
    list(APPEND wm_includes "${path}")
  endif()
endforeach()
file(GLOB_RECURSE source_inputs CONFIGURE_DEPENDS
  "${FAF_SOURCE_ROOT}/src/moho/particles/*.h"
  "${FAF_SOURCE_ROOT}/src/moho/particles/*.cpp"
  "${FAF_SOURCE_ROOT}/src/legacy/containers/*.h"
  "${FAF_SOURCE_ROOT}/src/legacy/containers/*.cpp"
  "${FAF_SOURCE_ROOT}/src/platform/*.h"
  "${wm_root}/*.h" "${wm_root}/*.inl" "${wm_root}/*.mcr")
set(generated "${CMAKE_CURRENT_BINARY_DIR}/generated")
add_custom_command(OUTPUT "${generated}/ParticleBatchProduction.inc" "${generated}/ParticlePayload.inc"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/bind_production.py"
    --source-root "${FAF_SOURCE_ROOT}" --output "${generated}/ParticleBatchProduction.inc" --inject-append
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/bind_payload.py"
    --source-root "${FAF_SOURCE_ROOT}" --output "${generated}/ParticlePayload.inc"
  DEPENDS bind_production.py bind_payload.py ${source_inputs}
    "${FAF_SOURCE_ROOT}/src/moho/render/GpuPathSettings.cpp"
    "${FAF_SOURCE_ROOT}/src/moho/misc/CountedObject.h"
  VERBATIM)
add_custom_target(particle_upload_bindings
  DEPENDS "${generated}/ParticleBatchProduction.inc" "${generated}/ParticlePayload.inc")
set_target_properties(particle_upload_bindings PROPERTIES FOLDER "Tests/Particles")

# Keep allocation interception out of ordinary correctness and timing runs.
foreach(target particle_upload_host particle_upload_allocation)
  add_executable(${target} ParticleUploadTests.cpp)
  add_dependencies(${target} particle_upload_bindings)
  target_compile_definitions(${target} PRIVATE FAF_RETAIL_LAYOUT=0 APPEND_HOOK)
  target_include_directories(${target} PRIVATE "${FAF_SOURCE_ROOT}/src" "${generated}" ${wm_includes})
  target_link_libraries(${target} PRIVATE gtest_main gtest Threads::Threads)
  set_target_properties(${target} PROPERTIES FOLDER "Tests/Particles")
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -O2 -g)
    if(FAF_PARTICLE_SANITIZE)
      target_compile_options(${target} PRIVATE
        -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -fno-pie)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all -no-pie)
    endif()
  elseif(FAF_PARTICLE_SANITIZE)
    message(FATAL_ERROR "This standalone sanitizer configuration requires GCC or Clang")
  endif()
endforeach()
target_compile_definitions(particle_upload_allocation PRIVATE PARTICLE_ALLOCATION_TEST)

enable_testing()
foreach(linear 0 1)
  foreach(batch 0 1)
    set(name "ParticleUpload_${linear}_Batch_${batch}")
    add_test(NAME ${name} COMMAND particle_upload_host --gtest_filter=-*EveryEnsureAllocation*)
    set_tests_properties(${name} PROPERTIES LABELS "Particles;ParticlesHost"
      ENVIRONMENT "PARTICLE_LINEAR_UPLOAD=${linear};PARTICLE_BATCH=${batch};ASAN_OPTIONS=detect_leaks=0")
  endforeach()
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/states-${linear}")
  add_test(NAME ParticleUpload_Allocation_${linear} COMMAND particle_upload_allocation --gtest_filter=*EveryEnsureAllocation*)
  set_tests_properties(ParticleUpload_Allocation_${linear} PROPERTIES LABELS "Particles;ParticlesHost;ParticlesAllocation"
    ENVIRONMENT "PARTICLE_LINEAR_UPLOAD=${linear};PARTICLE_STATE_DIR=${CMAKE_CURRENT_BINARY_DIR}/states-${linear};ASAN_OPTIONS=detect_leaks=0")
endforeach()
add_test(NAME ParticleUpload_AllocationComparison COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/compare_states.py" "${CMAKE_CURRENT_BINARY_DIR}")
set_tests_properties(ParticleUpload_AllocationComparison PROPERTIES LABELS "Particles;ParticlesHost;ParticlesAllocation"
  DEPENDS "ParticleUpload_Allocation_0;ParticleUpload_Allocation_1")
