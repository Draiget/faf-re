#!/usr/bin/env python3
"""Host regression for the checkout's actual Vulkan MemoryAllocator source.

Run: python3 tests/vulkan/allocator_source_test.py [--sanitize] [--cxx clang++]
Use --source /path/to/checkout to test another tree (including an unpatched
negative control). Assertions are identical for every tree; old code fails.
Requires Python 3 and a C++17 compiler, but no Vulkan SDK, network or GPU.
Only Vulkan types/API calls and error transport are adapted. The allocator,
its declarations, map, vector and unique_ptr are production/standard-library
code. Private members are exposed only to inspect invariants. API memory sizes
are accounting values, not real driver allocations or GPU validation.

--sanitize enables ASan and fail-fast UBSan, explicitly NOT LeakSanitizer.
Native handle leaks are checked by the adapter's accounting. Heap failures
replace ordinary global new, persist until disarmed, and exercise real
std::map/vector allocations. Free() is not called with injection armed.
Temporary builds are removed on exit; source files are never modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ADAPTER = r'''
// Explicit host-only Vulkan API adapter. No Vulkan driver, GPU, windows.h or SDK.
// Native bytes below are accounting values, not real GPU/host allocations.
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
[[gnu::noinline]] void* operator new(std::size_t size) {
  if (HeapFault::enabled) {
    ++HeapFault::calls;
    if (HeapFault::failAt != 0 && HeapFault::calls >= HeapFault::failAt) throw std::bad_alloc();
  }
  if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void operator delete(void* p) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

using VkDevice = std::uint64_t;
using VkPhysicalDevice = std::uint64_t;
using VkDeviceMemory = std::uint64_t;
using VkDeviceSize = std::uint64_t;
using VkMemoryPropertyFlags = std::uint32_t;
using VkResult = std::int32_t;
inline constexpr VkDeviceMemory VK_NULL_HANDLE = 0;
inline constexpr VkDeviceSize VK_WHOLE_SIZE = ~0ULL;
inline constexpr VkResult VK_SUCCESS = 0;
inline constexpr VkResult VK_ERROR_OUT_OF_HOST_MEMORY = -1;
inline constexpr VkResult VK_ERROR_OUT_OF_DEVICE_MEMORY = -2;
inline constexpr VkResult VK_ERROR_MEMORY_MAP_FAILED = -5;
inline constexpr int VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5;
inline constexpr VkMemoryPropertyFlags VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT = 1;
inline constexpr VkMemoryPropertyFlags VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT = 2;
inline constexpr VkMemoryPropertyFlags VK_MEMORY_PROPERTY_HOST_COHERENT_BIT = 4;
struct VkMemoryType { VkMemoryPropertyFlags propertyFlags = 0; std::uint32_t heapIndex = 0; };
struct VkPhysicalDeviceMemoryProperties {
  std::uint32_t memoryTypeCount = 0;
  VkMemoryType memoryTypes[32]{};
};
struct VkMemoryRequirements { VkDeviceSize size = 0; VkDeviceSize alignment = 1; std::uint32_t memoryTypeBits = 0; };
struct VkMemoryAllocateInfo {
  int sType = 0;
  const void* pNext = nullptr;
  VkDeviceSize allocationSize = 0;
  std::uint32_t memoryTypeIndex = 0;
};
struct VkFailure { VkResult code; };
struct BackendFailure {};
namespace gpg::gal::backend {
  [[noreturn]] inline void ThrowError(const char*, int, const char*) { throw BackendFailure{}; }
}

namespace Native {
  inline constexpr std::uint64_t MiB = 1ULL << 20;
  struct Record {
    VkDevice device = 0;
    VkDeviceSize bytes = 0;
    bool live = false;
    bool mapped = false;
  };
  inline std::array<Record, 4096> records{};
  inline std::size_t next = 1;
  inline std::size_t allocateCalls = 0, mapCalls = 0, unmapCalls = 0, freeCalls = 0, invalidCalls = 0;
  inline std::uint64_t liveBytes = 0;
  inline std::uint64_t budgetBytes = ~0ULL;
  inline VkResult allocateFailure = VK_SUCCESS, mapFailure = VK_SUCCESS;
  inline bool errorTranslationBadAlloc = false;
  inline unsigned char mappedToken = 0;
  inline void Reset() noexcept {
    records = {}; next = 1; allocateCalls = mapCalls = unmapCalls = freeCalls = invalidCalls = 0;
    liveBytes = 0; budgetBytes = ~0ULL; allocateFailure = mapFailure = VK_SUCCESS; errorTranslationBadAlloc = false;
    HeapFault::Disarm();
  }
  inline void GetProperties(VkPhysicalDevice, VkPhysicalDeviceMemoryProperties* out) noexcept {
    *out = {}; out->memoryTypeCount = 2;
    out->memoryTypes[0].propertyFlags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    out->memoryTypes[1].propertyFlags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
  }
  inline VkResult Allocate(VkDevice device, const VkMemoryAllocateInfo* info, const void*, VkDeviceMemory* out) noexcept {
    ++allocateCalls;
    if (allocateFailure < 0) return allocateFailure;
    if (info->allocationSize > budgetBytes-liveBytes) return VK_ERROR_OUT_OF_DEVICE_MEMORY;
    if (next >= records.size()) std::abort();
    *out = next; records[next++] = {device, info->allocationSize, true, false};
    liveBytes += info->allocationSize; return VK_SUCCESS;
  }
  inline VkResult Map(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size,
                      std::uint32_t, void** out) noexcept {
    ++mapCalls;
    if (memory == 0 || memory >= next || !records[memory].live || records[memory].device != device ||
        records[memory].mapped || offset != 0 || size != VK_WHOLE_SIZE) ++invalidCalls;
    if (mapFailure < 0) return mapFailure;
    records[memory].mapped = true; *out = &mappedToken; return VK_SUCCESS;
  }
  inline void Unmap(VkDevice device, VkDeviceMemory memory) noexcept {
    ++unmapCalls;
    if (memory == 0 || memory >= next || !records[memory].live || records[memory].device != device ||
        !records[memory].mapped) { ++invalidCalls; return; }
    records[memory].mapped = false;
  }
  inline void Free(VkDevice device, VkDeviceMemory memory, const void*) noexcept {
    ++freeCalls;
    if (memory == 0 || memory >= next || !records[memory].live || records[memory].device != device ||
        records[memory].mapped) { ++invalidCalls; return; }
    records[memory].live = false; liveBytes -= records[memory].bytes;
  }
}
namespace gpg::gal::vulkan {
  struct Functions {
    decltype(&Native::GetProperties) vkGetPhysicalDeviceMemoryProperties = &Native::GetProperties;
    decltype(&Native::Allocate) vkAllocateMemory = &Native::Allocate;
    decltype(&Native::Map) vkMapMemory = &Native::Map;
    decltype(&Native::Unmap) vkUnmapMemory = &Native::Unmap;
    decltype(&Native::Free) vkFreeMemory = &Native::Free;
  };
  inline Functions& Vk() noexcept { static Functions functions; return functions; }
  // Only exception transport is adapted; production callsites and control flow
  // are the extracted source. Error translation can itself run out of memory.
  inline void CheckVk(const char*, int, VkResult result) {
    if (result >= 0) return;
    if (Native::errorTranslationBadAlloc) throw std::bad_alloc();
    throw VkFailure{result};
  }
}

'''

HARNESS = r'''
#include <cstring>
#include "extracted.inc"
using namespace gpg::gal::vulkan;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #x); std::exit(1); } } while (0)
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
  for (const auto& block : a.mBlocks) if (block) for (const auto& range : block->free) {
    CHECK(s.count < s.ranges.size()); s.ranges[s.count++] = range; s.bytes += range.second;
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
  CHECK(Native::liveBytes == 0 && Native::invalidCalls == 0);
}
void Split(const char* kind, std::size_t fault) {
  Native::Reset(); Native::budgetBytes = B;
  MemoryAllocator a; a.Initialize(7, 19);
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
  CHECK(failed == (fault != 0 && fault <= needed));
  CHECK(calls == (failed ? fault : needed));
  CHECK(Native::liveBytes == B && Native::allocateCalls == 1);
  if (failed) {
    CHECK(Equal(before, Snapshot(a)));
    result = Take(a, size, alignment); // Same request must still fit under the one-block budget.
    CHECK(Native::allocateCalls == 1);
  }
  CHECK(result.offset == ((seed + alignment - 1) / alignment) * alignment);
  CHECK(result.memory != 0 && result.size == size && result.mapped == nullptr && !result.linear);
  CHECK(Snapshot(a).bytes + size == before.bytes);
  for (const auto& range : a.mBlocks[result.block]->free)
    CHECK(range.first + range.second <= result.offset || range.first >= result.offset + result.size);
  Finish(a);
}
void Repeated() {
  Native::Reset(); Native::budgetBytes = B;
  MemoryAllocator a; a.Initialize(7, 19); (void)Take(a, 1);
  for (int i = 0; i < 8; ++i) {
    const auto before = Snapshot(a); bool failed = false;
    HeapFault::Arm(1);
    try { (void)Take(a, Native::MiB, 32); } catch (const std::bad_alloc&) { failed = true; }
    HeapFault::Disarm(); CHECK(failed && Equal(before, Snapshot(a)));
    (void)Take(a, 1); // Successful work between repeated host failures.
  }
  CHECK(Native::allocateCalls == 1 && Snapshot(a).bytes == B - 9);
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
void Failure(const Case& c, bool existing) {
  Native::Reset(); MemoryAllocator a; a.Initialize(1, 53);
  std::array<Allocation, 64> live{}; std::size_t n = 0;
  if (existing) {
    // Force genuine vector growth without assuming the implementation's growth factor.
    do { CHECK(n < live.size()); live[n++] = Take(a, B, 1, c.host); }
    while (n < 8 || a.mBlocks.size() != a.mBlocks.capacity());
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
      case Fault::FreeMap: heapAt = 2; break;
      case Fault::Vector: heapAt = c.size < B ? 3 : 2; break;
    }
    const auto frees = Native::freeCalls, unmaps = Native::unmapCalls;
    bool caught = false; HeapFault::Arm(heapAt);
    try { (void)Take(a, c.size, 1, c.host); }
    catch (const std::bad_alloc&) { caught = true; CHECK(expectedError == VK_SUCCESS); }
    catch (const VkFailure& e) { caught = true; CHECK(expectedError != VK_SUCCESS && e.code == expectedError); }
    const auto calls = HeapFault::calls; HeapFault::Disarm();
    Native::allocateFailure = Native::mapFailure = VK_SUCCESS; Native::errorTranslationBadAlloc = false;
    CHECK(caught && (heapAt == 0 || calls == heapAt));
    CHECK(a.mBlocks.size() == n && a.BlockBytes() == before && Native::liveBytes == before);
    CHECK(Native::freeCalls == frees + (owns ? 1U : 0U));
    CHECK(Native::unmapCalls == unmaps + (mapped ? 1U : 0U));
    CHECK(Native::invalidCalls == 0);
    for (std::size_t i = 0; i < n; ++i)
      CHECK(Native::records[live[i].memory].live && a.mBlocks[i]->memory == live[i].memory);
  }
  const auto success = Take(a, c.size, 1, c.host);
  CHECK(success.block == static_cast<std::int32_t>(n) && success.offset == 0);
  CHECK(Native::liveBytes == before + std::max(B, c.size));
  Finish(a);
}
void Normal() {
  Native::Reset(); MemoryAllocator a; a.Initialize(1, 73);
  const auto first = Take(a, Native::MiB, 1, true);
  CHECK(Native::freeCalls == 0 && Native::unmapCalls == 0);
  a.Free(first); CHECK(Native::liveBytes == B); // Keep one empty normal block.
  const auto full = Take(a, B, 1, true);
  CHECK(full.memory == first.memory);
  const auto second = Take(a, B, 1, true);
  a.Free(full); a.Free(second);
  CHECK(Native::liveBytes == B && Native::freeCalls == 1);
  const auto large = Take(a, 96 * Native::MiB, 1, true);
  a.Free(large); CHECK(Native::liveBytes == B); // Oversized blocks are not retained.
  const auto filled = Take(a, B, 1, true);
  const auto hole = Take(a, Native::MiB, 1, true);
  CHECK(filled.block == 0 && hole.block == 1); // Publish into an empty slot.
  CHECK(Native::freeCalls == 2 && Native::unmapCalls == 2);
  Finish(a);
  Native::Reset(); a.Initialize(1, 74);
  const auto x = Take(a, Native::MiB), y = Take(a, Native::MiB);
  CHECK(x.memory == y.memory && x.offset == 0 && y.offset == Native::MiB);
  a.Free(x); a.Free(y); CHECK(Snapshot(a).bytes == B);
  Finish(a);
}
int main(int argc, char** argv) {
  CHECK(argc >= 2);
  if (std::strcmp(argv[1], "split") == 0) { CHECK(argc == 4); Split(argv[2], std::strtoul(argv[3], nullptr, 10)); }
  else if (std::strcmp(argv[1], "repeated") == 0) Repeated();
  else if (std::strcmp(argv[1], "normal") == 0) Normal();
  else {
    CHECK(argc == 4 && std::strcmp(argv[1], "failure") == 0);
    const auto index = std::strtoul(argv[2], nullptr, 10); CHECK(index < std::size(cases));
    Failure(cases[index], std::strcmp(argv[3], "existing") == 0);
  }
  std::puts("PASS");
}
'''


def section(text, start, end):
    """Fail closed if source boundaries disappear or become ambiguous."""
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"Expected exactly one source boundary: {start!r} / {end!r}")
    begin, finish = text.index(start), text.index(end)
    if finish <= begin:
        raise ValueError("Source boundaries are out of order")
    return text[begin:finish], text[:begin].count('\n') + 1


def extract(root, destination):
    base = root / 'src/gpg/gal/backends/vulkan'
    header, source = base / 'VulkanCore.h', base / 'VulkanCore.cpp'
    h, s = header.read_text(), source.read_text()
    declarations, hl = section(h, '  /** One sub-allocation of device memory. */',
                              '  /** One upload-memory allocation:')
    allocator, sl = section(s, '  namespace\n  {\n    constexpr VkDeviceSize kBlockSize',
                           '  // ---------------------------------------------------------------------------\n  // UploadAllocator')
    stats, bl = section(s, '  std::uint64_t MemoryAllocator::BlockBytes() const noexcept',
                       '  std::uint64_t UploadAllocator::TakeAllocatedBytes() noexcept')
    # #line preserves diagnostics; source slices themselves are verbatim.
    text = 'namespace gpg::gal::vulkan {\n#define private public\n'
    text += f'#line {hl} {json.dumps(str(header))}\n' + declarations + '\n#undef private\n'
    text += f'#line {sl} {json.dumps(str(source))}\n' + allocator
    text += f'#line {bl} {json.dumps(str(source))}\n' + stats + '\n}\n'
    destination.write_text(text)
    for path in (header, source):
        print(f'SOURCE sha256={hashlib.sha256(path.read_bytes()).hexdigest()} {path}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2],
                        help='Repository root containing src/gpg/gal/backends/vulkan')
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'c++'), help='C++17 compiler executable')
    parser.add_argument('--sanitize', action='store_true', help='ASan + fail-fast UBSan; no LSan')
    args = parser.parse_args()
    print('Host source-bound regression; no native Vulkan/GPU validation.', flush=True)
    with tempfile.TemporaryDirectory(prefix='vulkan-allocator-test-') as directory:
        work = Path(directory)
        extract(args.source.resolve(), work / 'extracted.inc')
        (work / 'test.cpp').write_text(ADAPTER + HARNESS)
        exe = work / 'test'
        command = [args.cxx, '-std=c++17', '-O0', '-g', '-Wall', '-Wextra', '-Werror', '-pedantic']
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
            print('Sanitizers: ASan + fail-fast UBSan; LeakSanitizer disabled.', flush=True)
        command += [str(work / 'test.cpp'), '-o', str(exe)]
        subprocess.run(command, check=True)
        env = os.environ.copy()
        if args.sanitize:
            env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1:abort_on_error=1'
            env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        tests = [('split', kind, str(fault)) for kind in ('exact', 'suffix', 'prefix', 'both') for fault in (0, 1, 2)]
        tests += [('repeated',), ('normal',)]
        tests += [('failure', str(i), state) for i in range(14) for state in ('empty', 'existing')]
        failures = 0
        for test in tests:
            result = subprocess.run([str(exe), *test], env=env, text=True, capture_output=True)
            passed = result.returncode == 0
            print(f'{"PASS" if passed else "FAIL"} {" ".join(test)}', flush=True)
            if not passed:
                failures += 1
                print(result.stdout + result.stderr, end='', flush=True)
        print(f'SUMMARY: {len(tests) - failures}/{len(tests)} passed; {failures} failed.', flush=True)
        return int(failures != 0)


if __name__ == '__main__':
    raise SystemExit(main())
