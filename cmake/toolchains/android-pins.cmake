# Engine addition (Android port): the NDK the Android builds are made with.
#
# The Android toolchains (android-arm64.cmake, android-x64.cmake, the
# android-*-release presets) compile the simulation with the NDK's clang
# against bionic. The NDK release is pinned here, as linux-clang-pins.cmake pins
# the Linux toolchain, so every build of a commit is the same binary;
# android-common.cmake refuses another release unless
# FAF_ANDROID_ALLOW_UNPINNED_NDK is ON.
#
#   NDK r29 (29.0.14206865): Android clang 21.0.0 (r563880c), libc++ (linked
#   statically, ANDROID_STL=c++_static), lld. Installed with
#   `sdkmanager "ndk;29.0.14206865"`.
#
# API level 26 (Android 8.0): the programs call no bionic function newer than
# that. A higher level would let the code call the ones it goes without now
# (platform/posix/Backtrace.h, SystemPosix.cpp's thread affinity,
# remote/net/Handshake.cpp's random bytes).

set(FAF_ANDROID_PINNED_NDK_REVISION "29.0.14206865")
set(FAF_ANDROID_API_LEVEL 26)
