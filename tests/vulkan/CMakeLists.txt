# The allocator is compiled directly, without the engine or a Vulkan driver.
add_executable(faf_vulkan_allocator_tests EXCLUDE_FROM_ALL
  MemoryAllocatorTests.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../../src/gpg/gal/backends/vulkan/VulkanMemoryAllocator.cpp)
target_include_directories(faf_vulkan_allocator_tests PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../src
  ${FAF_DEPENDENCIES_DIR}/vulkan/include)
target_link_libraries(faf_vulkan_allocator_tests PRIVATE gtest_main)
if(WIN32)
  target_compile_definitions(faf_vulkan_allocator_tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
if(MSVC)
  target_compile_options(faf_vulkan_allocator_tests PRIVATE /EHsc)
endif()
set_target_properties(faf_vulkan_allocator_tests PROPERTIES FOLDER "Tests/Vulkan")
add_test(NAME vulkan_allocator COMMAND faf_vulkan_allocator_tests)
set_tests_properties(vulkan_allocator PROPERTIES LABELS "Vulkan" TIMEOUT 120)
