# faf_tests: one target that builds every GoogleTest executable below a directory.
#
#   faf_add_tests_target(<directory>)
#
# A target counts as a test when it links gtest or gtest_main, so a new test needs no list
# entry here. Run them all with `ctest --test-dir <build> --output-on-failure`.

function(_faf_collect_gtest_targets directory out)
  set(found "")
  get_property(targets DIRECTORY "${directory}" PROPERTY BUILDSYSTEM_TARGETS)
  foreach(target IN LISTS targets)
    get_target_property(type ${target} TYPE)
    if(NOT type STREQUAL "EXECUTABLE")
      continue()
    endif()
    get_target_property(libraries ${target} LINK_LIBRARIES)
    if(libraries AND ("gtest" IN_LIST libraries OR "gtest_main" IN_LIST libraries))
      list(APPEND found ${target})
    endif()
  endforeach()
  get_property(children DIRECTORY "${directory}" PROPERTY SUBDIRECTORIES)
  foreach(child IN LISTS children)
    _faf_collect_gtest_targets("${child}" child_found)
    list(APPEND found ${child_found})
  endforeach()
  set(${out} "${found}" PARENT_SCOPE)
endfunction()

function(faf_add_tests_target directory)
  _faf_collect_gtest_targets("${directory}" targets)
  # Tests ctest runs that aren't GoogleTest programs: the difffuzz golden check (tools/difffuzz/dump.cmake).
  foreach(extra faf_math_dump)
    if(TARGET ${extra})
      list(APPEND targets ${extra})
    endif()
  endforeach()
  list(REMOVE_DUPLICATES targets)
  add_custom_target(faf_tests DEPENDS ${targets})
  set_target_properties(faf_tests PROPERTIES FOLDER "Tests")
  list(LENGTH targets count)
  message(STATUS "faf_tests: ${count} test executables")
endfunction()
