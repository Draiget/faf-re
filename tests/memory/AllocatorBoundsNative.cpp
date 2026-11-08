// x86 allocator bounds on real reservations. The cases live in Global.cpp's own object
// (AllocatorBoundsNative.inl). Each case reserves address space for the whole process, so ctest
// runs one per process with --gtest_filter (tests/memory/CMakeLists.txt). A case that can't get
// its fixture exits 77, which fails the run on purpose.

#include <gtest/gtest.h>

extern "C" int FafRunAllocatorBoundsCase(const char* mode);

TEST(AllocatorBounds, Normal) { EXPECT_EQ(FafRunAllocatorBoundsCase("normal"), 0); }
TEST(AllocatorBounds, Low) { EXPECT_EQ(FafRunAllocatorBoundsCase("low"), 0); }
TEST(AllocatorBounds, High) { EXPECT_EQ(FafRunAllocatorBoundsCase("high"), 0); }
TEST(AllocatorBounds, Map) { EXPECT_EQ(FafRunAllocatorBoundsCase("map"), 0); }
TEST(AllocatorBounds, Separate) { EXPECT_EQ(FafRunAllocatorBoundsCase("separate"), 0); }
