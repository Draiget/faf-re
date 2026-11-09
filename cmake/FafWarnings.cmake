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
# Wild Magic is named without a folder ("Wm3Vector3.h"); its .inl files follow their
# header. An engine header under moho/math with a Wm3 name is included by path, so
# it isn't caught.
foreach(_faf_third_party_prefix boost/ wx/ Wm3)
  if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    list(APPEND FAF_WARNING_OPTIONS "/clang:--system-header-prefix=${_faf_third_party_prefix}")
  else()
    list(APPEND FAF_WARNING_OPTIONS "--system-header-prefix=${_faf_third_party_prefix}")
  endif()
endforeach()

# Sources with wx 2.4 event tables, relative to src/. EVT_MENU and its family, and
# the Connect calls written the way they expand, cast each handler to
# wxObjectEventFunction, the one member-function type wx's tables hold. The cast is
# wx's API and its headers are pinned. Per source, so everything else keeps the
# warning.
set(FAF_WX_EVENT_TABLE_SOURCES
  moho/app/WD3DViewport.cpp
  moho/app/WEmitterWx.cpp
  moho/app/WRefEditDialog.cpp
  moho/app/WRenViewport.cpp
  moho/app/WSupComFrame.cpp
  moho/app/WWinLogWindow.cpp
  moho/app/WxAppWindows.cpp
  moho/misc/ScrDebugWindow.cpp
  moho/misc/ScrFileCtrl.cpp
  moho/misc/ScrGotoDialog.cpp
  moho/misc/ScrWatchCtrl.cpp
  moho/ui/CMauiLuaDragger.cpp
  moho/ui/UiMisc.cpp)
set(FAF_WX_EVENT_TABLE_OPTIONS -Wno-cast-function-type-mismatch)

# FFmpeg 7.1.3 is a pinned submodule, compiled as released. These are what its own
# sources do: raw demuxers it builds but we don't use (unused-function), INT64_MAX
# as a double in its option tables (implicit-const-int-float-conversion), its own
# deprecated codec fields (deprecated-declarations), a late declaration in demux.c
# (declaration-after-statement) and an enum forward reference in hwcontext_stub.c
# (microsoft-enum-forward-reference).
set(FAF_FFMPEG_WARNING_OPTIONS
  -Wno-unused-function
  -Wno-implicit-const-int-float-conversion
  -Wno-deprecated-declarations
  -Wno-declaration-after-statement
  -Wno-microsoft-enum-forward-reference)
