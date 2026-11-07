# Compile the actual allocator in isolation, not faf_engine; these are host tests.
# Each filter runs in a fresh process because the allocator owns global state.
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  # The engine build has gtest_main; the standalone lua_arena/ project fetches the release
  # cmake/FafDependencies.cmake pins (same archive, same SHA256).
  if(NOT TARGET gtest_main)
    include(FetchContent)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(googletest
      URL https://codeload.github.com/google/googletest/tar.gz/refs/tags/v1.15.2
      URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926)
    FetchContent_MakeAvailable(googletest)
    if(MSVC)
      target_compile_options(gtest PRIVATE /EHsc)
      target_compile_options(gtest_main PRIVATE /EHsc)
    endif()
  endif()
  find_package(Threads REQUIRED)

  # faf_lua_arena_host_test(<target> <source> <suite> <case>...): one executable, one CTest per case.
  function(faf_lua_arena_host_test target source suite)
    add_executable(${target} EXCLUDE_FROM_ALL ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/${source})
    target_compile_features(${target} PRIVATE cxx_std_20)
    if(WIN32)
      # LuaArena.cpp defines WIN32_LEAN_AND_MEAN before Windows.h itself.
      target_compile_definitions(${target} PRIVATE NOMINMAX)
    endif()
    if(MSVC)
      target_compile_options(${target} PRIVATE /EHsc)
    endif()
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../src)
    target_link_libraries(${target} PRIVATE gtest_main Threads::Threads)
    set_target_properties(${target} PROPERTIES FOLDER "Tests/Memory")
    foreach(_case IN LISTS ARGN)
      add_test(NAME ${suite}_${_case} COMMAND ${target} --gtest_filter=${suite}.${_case})
      set_tests_properties(${suite}_${_case} PROPERTIES LABELS "LuaArenaHost" TIMEOUT 120)
    endforeach()
  endfunction()

  faf_lua_arena_host_test(faf_lua_arena_large_run_tests LuaArenaLargeRunTests.cpp LuaArenaLargeRun
    FullCapacity FailedRequestOrder HostHeapFailure Oversize CrossThreadFree)
  faf_lua_arena_host_test(faf_lua_arena_pressure_tests LuaArenaPressureTests.cpp LuaArenaPressure
    RandomizedOccupancyOracle)
  faf_lua_arena_host_test(faf_lua_arena_reuse_tests LuaArenaReuseTests.cpp LuaArenaReuse
    FullCapacity MixedSizes OversizedRejected ConcurrentReuse)
endif()
