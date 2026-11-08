# Client maths without a device, a window or game data: moho/math, the camera (GeomCamera3, CameraImpl),
# the spatial database, the tesselator, cartographic decal batches, decal bookkeeping, the terrain
# resource's own state and the range renderer's profile table. Windows only: the camera, tesselator and
# render classes are not in Linux's faf_sim.
#
#   cmake --build --preset clang-x64-release --target faf_render_math_tests
#   ctest --test-dir build/clang-x64-release -L Render --output-on-failure
add_executable(faf_render_math_tests EXCLUDE_FROM_ALL
  MathTests.cpp
  GeomCameraTests.cpp
  SpatialDbTests.cpp
  CartographicTests.cpp
  TesselatorTests.cpp
)
target_link_libraries(faf_render_math_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_render_math_tests PROPERTIES FOLDER "Tests/Render")
add_test(NAME render_math COMMAND faf_render_math_tests)
set_tests_properties(render_math PROPERTIES LABELS "Render")
