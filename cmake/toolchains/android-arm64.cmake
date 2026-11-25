# Engine addition (Android port): Android arm64-v8a, the phones' ABI.
# See android-common.cmake for the NDK discovery and android-pins.cmake for the pin.

set(FAF_ANDROID_ABI arm64-v8a)

include("${CMAKE_CURRENT_LIST_DIR}/android-common.cmake")
