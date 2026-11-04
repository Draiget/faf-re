# The warnings the engine's own sources build with, on Windows and Linux.
#
# Warnings are on, none is an error, and each one silenced here says why. Add to
# this list only for something the code does on purpose or something third-party
# headers do on every include.
#
# Fixing a warning in a sim file is a sim change: read CONTRIBUTING.md's sim
# parity rules first. A cast that quiets sign-compare can change a result, and a
# virtual destructor that quiets delete-non-abstract-non-virtual-dtor changes a
# vtable the binary's layout fixes.
#
# Not -Wall here: clang-cl reads it as -Weverything. /W3 turns on the same set on
# Windows, and cmake/FafLinux.cmake adds -Wall for the GNU driver.

set(FAF_WARNING_OPTIONS
  -Wextra
  # The layout static_asserts use offsetof on recovered types that aren't
  # standard layout, on purpose: the binary fixes those offsets.
  -Wno-invalid-offsetof
  # Third-party headers, on every include: boost 1.34's unqualified friend
  # declarations, wx 2.4's flag enums, which it also needs at every sizer call.
  -Wno-microsoft-unqualified-friend
  -Wno-deprecated-enum-enum-conversion)

# Third-party headers read as system headers, so their warnings stay out of the
# log: on x86, boost 1.34's member-function-pointer tester alone gave 50,544. By
# include name, because /external:I would change the include search order, and
# src/boost/ wraps boost's own headers. Generated code doesn't change.
foreach(_faf_third_party_prefix boost/ wx/)
  if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    list(APPEND FAF_WARNING_OPTIONS "/clang:--system-header-prefix=${_faf_third_party_prefix}")
  else()
    list(APPEND FAF_WARNING_OPTIONS "--system-header-prefix=${_faf_third_party_prefix}")
  endif()
endforeach()
