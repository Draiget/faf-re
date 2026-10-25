# Code generation every object linked into the engine is built with: the
# engine itself and each static library under cmake/deps (Wild Magic's math is
# used by the simulation; wx and the image codecs get the same rules so no
# object differs by accident).
#
# The simulation must compute bit for bit what the 2007 engine computed (replays
# carry every player's per-beat checksum; any difference is a desync). The MSVC
# build gets there with /fp:precise, /arch:SSE2 on x86 and the x87 helpers in
# src/legacy/math. clang has to be held to the same code:
#
#  - /fp:precise without contraction. clang's precise model contracts a*b+c
#    into FMA where the target has it; MSVC's /fp:precise never does. No
#    -march/-mavx/-mfma anywhere: the baseline x86-64 / SSE2 ISA only.
#
#  - Math library calls stay calls. With the functions recognised as builtins,
#    LLVM folds them on constant arguments with the compiler's own libm,
#    rewrites pow(x, 2.0) to x*x and pow(2.0, x) to exp2, and - because it then
#    treats them as not reading memory - may move them across the
#    _controlfp/_set_SSE2_enable calls that pick the CRT's x87 bodies at PC24.
#    The game's results come from those bodies (pow(21.4163856f, 2) is not
#    x*x there), so the transcendental functions are not builtins. Exact
#    functions (fabs, floor, ceil, trunc, fmod, ldexp, ...) are unaffected and
#    keep their builtins.
#
#  - x86: sqrt is a CRT call as well, the clang counterpart of
#    platform/X87SqrtCall.h's `#pragma function(sqrt)` (which clang-cl also
#    honours; the flags make it hold for every library too). Under the sim's
#    _PC_24 control word the CRT's fsqrt rounds to 24 bits where an inlined
#    sqrtsd would not. x64 keeps sqrt inline: MSVC x64 inlines sqrtsd too.
#
#  - Undefined behaviour MSVC does not exploit stays unexploited: no
#    type-based alias analysis, wrapping signed overflow, null checks kept,
#    float-to-int conversions that behave like cvttss2si on out-of-range
#    values (MSVC's 0x80000000), no forward-progress assumption for loops, and
#    no "unreachable" after a missing return.

add_library(faf_codegen INTERFACE)
add_library(faf::codegen ALIAS faf_codegen)

set(_faf_libm_calls
  acos asin atan atan2 cos cosh sin sinh tan tanh
  exp exp2 expm1 log log10 log1p log2 logb pow cbrt hypot erf erfc tgamma lgamma)

# Engine addition (dedicated-server plan WPL.2): the same rules for the Linux
# build (clang with the GNU driver, cmake/toolchains/linux-clang-x64.cmake),
# spelled for that driver, plus what the GNU driver defaults differently from
# clang-cl:
#
#  - -fno-math-errno: clang-cl's default. With errno semantics clang keeps
#    sqrt as a call guarded for negative inputs where clang-cl inlines sqrtsd.
#  - -fsigned-char: plain char signed, as with MSVC (the x86-64 Linux default
#    too; spelled out so no target can differ).
#  - Function and data sections, collected at link time: /Gy and /OPT:REF.
#
# Never -ffast-math or -Ofast: checked below.
if(FAF_LINUX)
  set(_faf_no_builtin "")
  foreach(_fn IN LISTS _faf_libm_calls)
    list(APPEND _faf_no_builtin "-fno-builtin-${_fn}" "-fno-builtin-${_fn}f" "-fno-builtin-${_fn}l")
  endforeach()
  foreach(_flags IN ITEMS CMAKE_C_FLAGS CMAKE_CXX_FLAGS CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
    if("${${_flags}}" MATCHES "-ffast-math|-Ofast|-ffp-contract=(on|fast)|-march=|-mfma|-mavx")
      message(FATAL_ERROR "${_flags} contains a flag that changes floating-point results: ${${_flags}}")
    endif()
  endforeach()
  target_compile_options(faf_codegen INTERFACE
    "$<$<COMPILE_LANGUAGE:C,CXX>:-ffp-model=precise;-ffp-contract=off;-fno-math-errno;${_faf_no_builtin};-fno-strict-aliasing;-fwrapv;-fno-delete-null-pointer-checks;-fno-strict-float-cast-overflow;-fno-finite-loops;-fsigned-char;-ffunction-sections;-fdata-sections;-Wno-overriding-option>"
    $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-return>)
  target_link_options(faf_codegen INTERFACE -Wl,--gc-sections)
  return()
endif()

set(_faf_no_builtin "")
foreach(_fn IN LISTS _faf_libm_calls)
  list(APPEND _faf_no_builtin "/clang:-fno-builtin-${_fn}" "/clang:-fno-builtin-${_fn}f" "/clang:-fno-builtin-${_fn}l")
endforeach()
if(FAF_TARGET_ARCH STREQUAL "x86")
  list(APPEND _faf_no_builtin /clang:-fno-builtin-sqrt /clang:-fno-builtin-sqrtf /clang:-fno-builtin-sqrtl)
endif()

set(_faf_codegen_options
  /fp:precise
  /clang:-ffp-contract=off
  ${_faf_no_builtin}
  /clang:-fno-strict-aliasing
  /clang:-fwrapv
  /clang:-fno-delete-null-pointer-checks
  /clang:-fno-strict-float-cast-overflow
  /clang:-fno-finite-loops
  # Function-level linking, as /Gy in the MSVC Release configurations.
  /Gy
  # "overriding -ffp-model=precise with -ffp-contract=off": intended, see above.
  -Wno-overriding-option)
if(FAF_TARGET_ARCH STREQUAL "x86")
  # MSVC's x86 default; spelled out so clang cannot pick another baseline.
  list(APPEND _faf_codegen_options /arch:SSE2)
endif()

# C and C++ only: the x64 MASM file goes through llvm-ml, which takes none of
# these.
target_compile_options(faf_codegen INTERFACE
  "$<$<COMPILE_LANGUAGE:C,CXX>:${_faf_codegen_options}>"
  $<$<COMPILE_LANGUAGE:CXX>:/clang:-fno-strict-return>)

# Checked iterators off in Debug as well, for every library: the setting changes
# the size of every std container, and a mismatch between the engine and a
# library changes object layout (LNK2038).
target_compile_definitions(faf_codegen INTERFACE $<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=0>)
