# Engine addition (Android port): Android x86_64, the emulator's ABI. Its
# simulation runs the x87 helpers of the Linux x64 build, so it is checked
# against the same results before arm64 is.
# See android-common.cmake for the NDK discovery and android-pins.cmake for the pin.

set(FAF_ANDROID_ABI x86_64)

include("${CMAKE_CURRENT_LIST_DIR}/android-common.cmake")
