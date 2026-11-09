# Engine addition (dedicated-server plan WPR.12): headless's imports, checked after every
# link. headless links only the simulation, which must not reach for UI, graphics or audio
# code; a DLL outside the list below (USER32, GDI32, D3D*, DSOUND, XAudio, wx's comctl32,
# ...) or a COM call beyond starting COM (XACT is created through COM, which the linker
# cannot show) fails the build and names what was imported.
#
# Debug builds keep every function of every object they link, so they show what a release
# build's dead-code elimination hides.
#
#   cmake -DREADOBJ=<llvm-readobj> -DEXE=<headless> [-DTRACY=ON] -P HeadlessImports.cmake
#
# TRACY=ON (the Profile presets) also allows what the Tracy client itself imports:
# user32.dll (MessageBoxA when the profiler fails to start, TracyProfiler.cpp) and
# secur32.dll (Tracy's CMake links TracyClient to it).

cmake_minimum_required(VERSION 3.20)

#
# api-ms-win-core-synch-l1-2-0.dll is kernel32's WaitOnAddress/WakeByAddress* API set, not UI.
# From MSVC Build Tools 14.50 (Visual Studio 2026) the STL links synchronization.lib for
# its wait/notify functions, so a headless built with it imports this DLL; 14.44 and older
# reached WaitOnAddress through the STL's own __std_atomic_wait_* functions instead.
set(_allowed_dlls kernel32.dll advapi32.dll ole32.dll shell32.dll shlwapi.dll ws2_32.dll dbghelp.dll
  api-ms-win-core-synch-l1-2-0.dll)
if(TRACY)
  list(APPEND _allowed_dlls user32.dll secur32.dll)
endif()
set(_allowed_ole32 CoInitialize CoInitializeEx CoUninitialize)

execute_process(
  COMMAND "${READOBJ}" --coff-imports "${EXE}"
  OUTPUT_VARIABLE _out
  ERROR_VARIABLE _err
  RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "headless imports: ${READOBJ} failed on ${EXE}: ${_err}")
endif()

string(REPLACE ";" "," _out "${_out}")
string(REPLACE "\n" ";" _lines "${_out}")
set(_dll "")
set(_bad "")
foreach(_line IN LISTS _lines)
  if(_line MATCHES "^ *Name: (.+)$")
    string(TOLOWER "${CMAKE_MATCH_1}" _dll)
    if(NOT _dll IN_LIST _allowed_dlls)
      list(APPEND _bad "${_dll}")
    endif()
  elseif(_dll STREQUAL "ole32.dll" AND _line MATCHES "^ *Symbol: ([A-Za-z0-9_]+)")
    if(NOT CMAKE_MATCH_1 IN_LIST _allowed_ole32)
      list(APPEND _bad "ole32.dll!${CMAKE_MATCH_1}")
    endif()
  endif()
endforeach()

if(_bad)
  list(REMOVE_DUPLICATES _bad)
  list(JOIN _bad " " _bad_text)
  message(FATAL_ERROR
    "headless imports ${_bad_text}: simulation code reaches UI, graphics or audio code. "
    "Find the object with the reference (debug build: dumpbin /imports, or grep the objects) "
    "and split it as src/sim_sources.cmake describes; do not widen cmake/HeadlessImports.cmake.")
endif()
