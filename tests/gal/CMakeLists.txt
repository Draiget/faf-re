# Unit tests for the graphics layer's code that runs without a device: the effect layer of the
# Direct3D 12 and Vulkan backends (gpg/gal/effects: text helpers, effect parser, HLSL rewrite,
# parameter store, SPIR-V reading, the effect runtime's objects), the Direct3D 11 override layer
# the effects pass through first, the D3D error tables, gal::Math and the small backend helpers.
# The effect sources are written in the tests; no game data is read. Tests named DISABLED_ show
# a suspected bug; their comments name it.
#
# DXC's two DLLs are copied next to the executable, as next to the game's, for the suites that
# compile the generated HLSL (GalShaderCompiler); they skip when DXC cannot be loaded.
#
#   cmake --build --preset clang-x64-release --target faf_gal_tests
#   ctest --test-dir build/clang-x64-release -L Gal --output-on-failure
add_executable(faf_gal_tests EXCLUDE_FROM_ALL
  GalTestSupport.cpp
  EffectTextTests.cpp
  EffectDescriptionTests.cpp
  ModernHlslTests.cpp
  EffectParametersTests.cpp
  EffectRuntimeTests.cpp
  EffectSourceD3D11Tests.cpp
  SpirvReflectTests.cpp
  ShaderCompilerTests.cpp
  D3DErrorTests.cpp
  GalMathTests.cpp
  BackendHelperTests.cpp
)
target_link_libraries(faf_gal_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_gal_tests PROPERTIES FOLDER "Tests/Gal")
add_custom_command(TARGET faf_gal_tests POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
          "${FAF_DEPENDENCIES_DIR}/dxc/bin/${FAF_TARGET_ARCH}/dxcompiler.dll"
          "${FAF_DEPENDENCIES_DIR}/dxc/bin/${FAF_TARGET_ARCH}/dxil.dll"
          "$<TARGET_FILE_DIR:faf_gal_tests>"
  VERBATIM)
add_test(NAME gal COMMAND faf_gal_tests)
set_tests_properties(gal PROPERTIES LABELS "Gal")
