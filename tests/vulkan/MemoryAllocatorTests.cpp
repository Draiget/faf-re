// Host regression: actual allocator compilation unit and Vulkan function signatures.
// No driver, GPU, logging, or gal::Error transport is exercised.
#include <gtest/gtest.h>
#include <cstring>
#include <type_traits>
#include "gpg/gal/backends/vulkan/VulkanMemoryAllocator.h"
#include "gpg/gal/backends/vulkan/VulkanLoader.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <map>
#include <memory>
#include <new>
#include <vector>

namespace HeapFault {
  inline bool enabled = false;
  inline std::size_t calls = 0;
  inline std::size_t failAt = 0;
  inline void Arm(std::size_t at = 0) noexcept { calls = 0; failAt = at; enabled = true; }
  inline void Disarm() noexcept { enabled = false; }
}

// Fail persistently from the requested allocation onward. Cleanup must work
// while all later host allocations remain unavailable, not just one failure.
void* operator new(std::size_t size) {
  if (HeapFault::enabled) {
    ++HeapFault::calls;
    if (HeapFault::failAt != 0 && HeapFault::calls >= HeapFault::failAt) throw std::bad_alloc();
  }
  if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }
// GoogleTest's stable_sort uses nothrow new; keep the replacement family paired.
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  try { return ::operator new(size); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
  return ::operator new(size, std::nothrow);
}
void operator delete(void* p, const std::nothrow_t&) noexcept { ::operator delete(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { ::operator delete[](p); }

struct VkFailure { VkResult code; };
struct BackendFailure {};
namespace gpg::gal::backend {
  [[noreturn]] void ThrowError(const char*, int, const char*) { throw BackendFailure{}; }
}

template<class T> T Handle(std::uintptr_t value) {
  if constexpr (std::is_pointer_v<T>) return reinterpret_cast<T>(value);
  else return static_cast<T>(value);
}
template<class T> std::uintptr_t HandleIndex(T value) {
  if constexpr (std::is_pointer_v<T>) return reinterpret_cast<std::uintptr_t>(value);
  else return static_cast<std::uintptr_t>(value);
}
namespace Native {
  inline constexpr std::uint64_t MiB = 1ULL << 20;
  struct Record {
    VkDevice device = VK_NULL_HANDLE;
    VkDeviceSize bytes = 0;
    bool live = false;
    bool mapped = false;
  };
  inline std::array<Record, 4096> records{};
  inline std::size_t next = 1;
  inline std::size_t heapCallsAtAllocate = 0;
  inline std::size_t allocateCalls = 0, mapCalls = 0, unmapCalls = 0, freeCalls = 0, invalidCalls = 0;
  inline std::uint64_t liveBytes = 0;
  inline std::uint64_t budgetBytes = ~0ULL;
  inline VkResult allocateFailure = VK_SUCCESS, mapFailure = VK_SUCCESS;
  inline bool errorTranslationBadAlloc = false;
  inline std::array<unsigned char, 64 * MiB> mappedToken{};
  inline void Reset() noexcept {
    records = {}; next = 1; allocateCalls = mapCalls = unmapCalls = freeCalls = invalidCalls = 0;
    liveBytes = 0; budgetBytes = ~0ULL; allocateFailure = mapFailure = VK_SUCCESS; errorTranslationBadAlloc = false;
    HeapFault::Disarm();
  }
  inline void VKAPI_CALL GetProperties(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties* out) noexcept {
    *out = {}; out->memoryTypeCount = 2;
    out->memoryTypes[0].propertyFlags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    out->memoryTypes[1].propertyFlags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
  }
  inline VkResult VKAPI_CALL Allocate(VkDevice device, const VkMemoryAllocateInfo* info, const VkAllocationCallbacks*, VkDeviceMemory* out) noexcept {
    ++allocateCalls;
    heapCallsAtAllocate = HeapFault::calls;
    if (allocateFailure < 0) return allocateFailure;
    if (info->allocationSize > budgetBytes-liveBytes) return VK_ERROR_OUT_OF_DEVICE_MEMORY;
    if (next >= records.size()) std::abort();
    *out = Handle<VkDeviceMemory>(next); records[next++] = {device, info->allocationSize, true, false};
    liveBytes += info->allocationSize; return VK_SUCCESS;
  }
  inline VkResult VKAPI_CALL Map(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size,
                      std::uint32_t, void** out) noexcept {
    ++mapCalls;
    if (memory == 0 || HandleIndex(memory) >= next || !records[HandleIndex(memory)].live || records[HandleIndex(memory)].device != device ||
        records[HandleIndex(memory)].mapped || offset != 0 || size != VK_WHOLE_SIZE) {
      ++invalidCalls; return VK_ERROR_MEMORY_MAP_FAILED;
    }
    if (mapFailure < 0) return mapFailure;
    records[HandleIndex(memory)].mapped = true; *out = mappedToken.data(); return VK_SUCCESS;
  }
  inline void VKAPI_CALL Unmap(VkDevice device, VkDeviceMemory memory) noexcept {
    ++unmapCalls;
    if (memory == 0 || HandleIndex(memory) >= next || !records[HandleIndex(memory)].live || records[HandleIndex(memory)].device != device ||
        !records[HandleIndex(memory)].mapped) { ++invalidCalls; return; }
    records[HandleIndex(memory)].mapped = false;
  }
  inline void VKAPI_CALL Free(VkDevice device, VkDeviceMemory memory, const VkAllocationCallbacks*) noexcept {
    ++freeCalls;
    if (memory == 0 || HandleIndex(memory) >= next || !records[HandleIndex(memory)].live || records[HandleIndex(memory)].device != device ||
        records[HandleIndex(memory)].mapped) { ++invalidCalls; return; }
    records[HandleIndex(memory)].live = false; liveBytes -= records[HandleIndex(memory)].bytes;
  }
}
namespace gpg::gal::vulkan {
  Functions& Vk() {
    static Functions functions;
    functions.vkGetPhysicalDeviceMemoryProperties = Native::GetProperties;
    functions.vkAllocateMemory = Native::Allocate;
    functions.vkMapMemory = Native::Map;
    functions.vkUnmapMemory = Native::Unmap;
    functions.vkFreeMemory = Native::Free;
    return functions;
  }
  // Only exception transport is adapted; production callsites and control flow
  // are the separately compiled production source. Error translation can itself run out of memory.
  void CheckVk(const char*, int, VkResult result) {
    if (result >= 0) return;
    if (Native::errorTranslationBadAlloc) throw std::bad_alloc();
    throw VkFailure{result};
  }
}


namespace gpg::gal::vulkan {
struct MemoryAllocatorTestAccess {
  static auto& Blocks(MemoryAllocator& allocator) { return allocator.mBlocks; }
  static const auto& Blocks(const MemoryAllocator& allocator) { return allocator.mBlocks; }
};
}
using namespace gpg::gal::vulkan;
namespace {
struct TestAllocator : MemoryAllocator {
  ~TestAllocator() { HeapFault::Disarm(); Release(); }
};
constexpr VkDeviceSize B = 64 * Native::MiB;
Allocation Take(MemoryAllocator& a, VkDeviceSize size, VkDeviceSize alignment = 1, bool host = false) {
  return a.Allocate({size, alignment, host ? 2U : 1U},
                   host ? VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT : VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, false);
}
struct State {
  std::array<std::pair<VkDeviceSize, VkDeviceSize>, 1024> ranges{};
  std::size_t count = 0;
  VkDeviceSize bytes = 0;
};
State Snapshot(const MemoryAllocator& a) {
  State s;
  for (const auto& block : MemoryAllocatorTestAccess::Blocks(a)) if (block) for (const auto& range : block->free) {
    if (s.count >= s.ranges.size()) { ADD_FAILURE() << "Too many ranges"; return s; }
    s.ranges[s.count++] = range; s.bytes += range.second;
  }
  return s;
}
bool Equal(const State& a, const State& b) {
  if (a.count != b.count || a.bytes != b.bytes) return false;
  for (std::size_t i = 0; i < a.count; ++i) if (a.ranges[i] != b.ranges[i]) return false;
  return true;
}
void Finish(MemoryAllocator& a) {
  a.Release(); a.Release();
  EXPECT_TRUE(Native::liveBytes == 0 && Native::invalidCalls == 0);
}
void Split(const char* kind, std::size_t fault) {
  Native::Reset(); Native::budgetBytes = B;
  TestAllocator a; a.Initialize(Handle<VkPhysicalDevice>(7), Handle<VkDevice>(19));
  const bool exact = std::strcmp(kind, "exact") == 0;
  const bool suffix = std::strcmp(kind, "suffix") == 0;
  const bool prefix = std::strcmp(kind, "prefix") == 0;
  const VkDeviceSize seed = (exact || suffix) ? Native::MiB : 1;
  (void)Take(a, seed);
  const VkDeviceSize size = exact ? B - seed : prefix ? B - 16 : Native::MiB;
  const VkDeviceSize alignment = (exact || suffix) ? 1 : 16;
  const auto before = Snapshot(a);
  Allocation result; bool failed = false;
  HeapFault::Arm(fault);
  try { result = Take(a, size, alignment); } catch (const std::bad_alloc&) { failed = true; }
  const auto calls = HeapFault::calls; HeapFault::Disarm();
  const std::size_t needed = (exact || suffix || prefix) ? 0 : 1;
  EXPECT_TRUE(failed == (fault != 0 && fault <= needed));
  EXPECT_TRUE(calls == (failed ? fault : needed));
  EXPECT_TRUE(Native::liveBytes == B && Native::allocateCalls == 1);
  if (failed) {
    EXPECT_TRUE(Equal(before, Snapshot(a)));
    result = Take(a, size, alignment); // Same request must still fit under the one-block budget.
    EXPECT_TRUE(Native::allocateCalls == 1);
  }
  EXPECT_TRUE(result.offset == ((seed + alignment - 1) / alignment) * alignment);
  EXPECT_TRUE(result.memory != 0 && result.size == size && result.mapped == nullptr && !result.linear);
  EXPECT_TRUE(Snapshot(a).bytes + size == before.bytes);
  for (const auto& range : MemoryAllocatorTestAccess::Blocks(a)[result.block]->free)
    EXPECT_TRUE(range.first + range.second <= result.offset || range.first >= result.offset + result.size);
  Finish(a);
}
void Repeated() {
  Native::Reset(); Native::budgetBytes = B;
  TestAllocator a; a.Initialize(Handle<VkPhysicalDevice>(7), Handle<VkDevice>(19)); (void)Take(a, 1);
  for (int i = 0; i < 8; ++i) {
    const auto before = Snapshot(a); bool failed = false;
    HeapFault::Arm(1);
    try { (void)Take(a, Native::MiB, 32); } catch (const std::bad_alloc&) { failed = true; }
    HeapFault::Disarm(); EXPECT_TRUE(failed && Equal(before, Snapshot(a)));
    (void)Take(a, 1); // Successful work between repeated host failures.
  }
  EXPECT_TRUE(Native::allocateCalls == 1 && Snapshot(a).bytes == B - 9);
  Finish(a);
}
enum class Fault { Block, AllocateHost, AllocateDevice, AllocateTranslate, Map, MapHost,
                   MapTranslate, FreeMap, Vector };
struct Case { const char* name; Fault fault; bool host; VkDeviceSize size; };
constexpr Case cases[] = {
  {"block_new", Fault::Block, true, 8 * Native::MiB},
  {"allocate_host", Fault::AllocateHost, true, 8 * Native::MiB},
  {"allocate_device", Fault::AllocateDevice, false, 8 * Native::MiB},
  {"allocate_translation", Fault::AllocateTranslate, true, 8 * Native::MiB},
  {"map", Fault::Map, true, 8 * Native::MiB},
  {"map_host", Fault::MapHost, true, 8 * Native::MiB},
  {"map_translation", Fault::MapTranslate, true, 8 * Native::MiB},
  {"host_free_map", Fault::FreeMap, true, 8 * Native::MiB},
  {"device_free_map", Fault::FreeMap, false, 8 * Native::MiB},
  {"host_vector", Fault::Vector, true, 8 * Native::MiB},
  {"device_vector", Fault::Vector, false, 8 * Native::MiB},
  {"exact_vector", Fault::Vector, true, B},
  {"oversized_host_vector", Fault::Vector, true, 96 * Native::MiB},
  {"oversized_device_vector", Fault::Vector, false, 96 * Native::MiB},
};
// Calibrate on this standard library, including any map sentinel/proxy allocation.
// Reserving the vector outside the measured interval removes only publication
// growth; the actual Block construction and initial free-map insertion still run.
struct AllocationCounts { std::size_t beforeNative, total; };
AllocationCounts MeasureNewBlock(const Case& c, bool existing, bool reservePublication) {
  Native::Reset(); TestAllocator allocator;
  allocator.Initialize(Handle<VkPhysicalDevice>(1), Handle<VkDevice>(53));
  if (existing) {
    do { (void)Take(allocator, B, 1, c.host); }
    while (MemoryAllocatorTestAccess::Blocks(allocator).size() < 8 ||
           MemoryAllocatorTestAccess::Blocks(allocator).size() != MemoryAllocatorTestAccess::Blocks(allocator).capacity());
  }
  auto& blocks = MemoryAllocatorTestAccess::Blocks(allocator);
  if (reservePublication) blocks.reserve(blocks.size() + 1);
  HeapFault::Arm();
  (void)Take(allocator, c.size, 1, c.host);
  const AllocationCounts counts{Native::heapCallsAtAllocate, HeapFault::calls};
  HeapFault::Disarm();
  Finish(allocator);
  return counts;
}
void Failure(const Case& c, bool existing) {
  const auto withoutGrowth = MeasureNewBlock(c, existing, true);
  const auto withGrowth = MeasureNewBlock(c, existing, false);
  ASSERT_EQ(withGrowth.beforeNative, withoutGrowth.beforeNative);
  ASSERT_GT(withGrowth.total, withoutGrowth.total);
  // A non-full block must create free-map storage after native allocation.
  if (c.size < B) ASSERT_GT(withoutGrowth.total, withoutGrowth.beforeNative);
  else ASSERT_EQ(withoutGrowth.total, withoutGrowth.beforeNative);

  Native::Reset(); TestAllocator a; a.Initialize(Handle<VkPhysicalDevice>(1), Handle<VkDevice>(53));
  std::array<Allocation, 64> live{}; std::size_t n = 0;
  if (existing) {
    // Force genuine vector growth without assuming the implementation's growth factor.
    do { ASSERT_LT(n, live.size()); live[n++] = Take(a, B, 1, c.host); }
    while (n < 8 || MemoryAllocatorTestAccess::Blocks(a).size() != MemoryAllocatorTestAccess::Blocks(a).capacity());
  }
  const auto before = Native::liveBytes;
  for (int round = 0; round < 4; ++round) {
    std::size_t heapAt = 0;
    VkResult expectedError = VK_SUCCESS;
    bool owns = true, mapped = c.host;
    switch (c.fault) {
      case Fault::Block: heapAt = 1; owns = mapped = false; break;
      case Fault::AllocateHost: expectedError = Native::allocateFailure = VK_ERROR_OUT_OF_HOST_MEMORY; owns = mapped = false; break;
      case Fault::AllocateDevice: expectedError = Native::allocateFailure = VK_ERROR_OUT_OF_DEVICE_MEMORY; owns = mapped = false; break;
      case Fault::AllocateTranslate: Native::allocateFailure = VK_ERROR_OUT_OF_HOST_MEMORY; Native::errorTranslationBadAlloc = true; owns = mapped = false; break;
      case Fault::Map: expectedError = Native::mapFailure = VK_ERROR_MEMORY_MAP_FAILED; mapped = false; break;
      case Fault::MapHost: expectedError = Native::mapFailure = VK_ERROR_OUT_OF_HOST_MEMORY; mapped = false; break;
      case Fault::MapTranslate: Native::mapFailure = VK_ERROR_MEMORY_MAP_FAILED; Native::errorTranslationBadAlloc = true; mapped = false; break;
      case Fault::FreeMap: heapAt = withoutGrowth.beforeNative + 1; break;
      case Fault::Vector: heapAt = withoutGrowth.total + 1; break;
    }
    const auto frees = Native::freeCalls, unmaps = Native::unmapCalls;
    bool caught = false, correctError = false; HeapFault::Arm(heapAt);
    try { (void)Take(a, c.size, 1, c.host); }
    catch (const std::bad_alloc&) { caught = true; correctError = expectedError == VK_SUCCESS; }
    catch (const VkFailure& e) { caught = true; correctError = expectedError != VK_SUCCESS && e.code == expectedError; }
    const auto calls = HeapFault::calls; HeapFault::Disarm();
    Native::allocateFailure = Native::mapFailure = VK_SUCCESS; Native::errorTranslationBadAlloc = false;
    EXPECT_TRUE(correctError);
    EXPECT_TRUE(caught && (heapAt == 0 || calls == heapAt));
    EXPECT_TRUE(MemoryAllocatorTestAccess::Blocks(a).size() == n && a.BlockBytes() == before && Native::liveBytes == before);
    EXPECT_TRUE(Native::freeCalls == frees + (owns ? 1U : 0U));
    EXPECT_TRUE(Native::unmapCalls == unmaps + (mapped ? 1U : 0U));
    EXPECT_TRUE(Native::invalidCalls == 0);
    for (std::size_t i = 0; i < n; ++i)
      EXPECT_TRUE(Native::records[HandleIndex(live[i].memory)].live && MemoryAllocatorTestAccess::Blocks(a)[i]->memory == live[i].memory);
  }
  const auto success = Take(a, c.size, 1, c.host);
  EXPECT_TRUE(success.block == static_cast<std::int32_t>(n) && success.offset == 0);
  EXPECT_TRUE(Native::liveBytes == before + std::max(B, c.size));
  Finish(a);
}
void Normal() {
  Native::Reset(); TestAllocator a; a.Initialize(Handle<VkPhysicalDevice>(1), Handle<VkDevice>(73));
  const auto first = Take(a, Native::MiB, 1, true);
  EXPECT_TRUE(Native::freeCalls == 0 && Native::unmapCalls == 0);
  a.Free(first); EXPECT_TRUE(Native::liveBytes == B); // Keep one empty normal block.
  const auto full = Take(a, B, 1, true);
  EXPECT_TRUE(full.memory == first.memory);
  const auto second = Take(a, B, 1, true);
  a.Free(full); a.Free(second);
  EXPECT_TRUE(Native::liveBytes == B && Native::freeCalls == 1);
  const auto large = Take(a, 96 * Native::MiB, 1, true);
  a.Free(large); EXPECT_TRUE(Native::liveBytes == B); // Oversized blocks are not retained.
  const auto filled = Take(a, B, 1, true);
  const auto hole = Take(a, Native::MiB, 1, true);
  EXPECT_TRUE(filled.block == 0 && hole.block == 1); // Publish into an empty slot.
  EXPECT_TRUE(Native::freeCalls == 2 && Native::unmapCalls == 2);
  Finish(a);
  Native::Reset(); a.Initialize(Handle<VkPhysicalDevice>(1), Handle<VkDevice>(74));
  const auto x = Take(a, Native::MiB), y = Take(a, Native::MiB);
  EXPECT_TRUE(x.memory == y.memory && x.offset == 0 && y.offset == Native::MiB);
  a.Free(x); a.Free(y); EXPECT_TRUE(Snapshot(a).bytes == B);
  Finish(a);
}

class VulkanAllocatorSplit : public testing::TestWithParam<std::tuple<const char*, std::size_t>> {};
TEST_P(VulkanAllocatorSplit, PreservesCapacityAndAllowsRetry) {
  Split(std::get<0>(GetParam()), std::get<1>(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(ShapesAndHeapFailures, VulkanAllocatorSplit,
  testing::Combine(testing::Values("exact", "suffix", "prefix", "both"),
                   testing::Values(std::size_t{0}, std::size_t{1}, std::size_t{2})));
class VulkanAllocatorFailure : public testing::TestWithParam<std::tuple<Case, bool>> {};
TEST_P(VulkanAllocatorFailure, ReleasesOnlyUnpublishedMemory) {
  Failure(std::get<0>(GetParam()), std::get<1>(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(NewAndExistingBlocks, VulkanAllocatorFailure,
  testing::Combine(testing::ValuesIn(cases), testing::Bool()));
TEST(VulkanAllocator, RepeatedFailureThenSuccessfulWork) { Repeated(); }
TEST(VulkanAllocator, SuccessfulReleaseRetentionAndSlotReuse) { Normal(); }
} // namespace
