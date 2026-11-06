#!/usr/bin/env python3
"""Host regression for the checkout's actual D3D12 placed-heap Take/Give code.

Run from the repository root:
  python3 tests/d3d12/placed_heap_source_test.py
  python3 tests/d3d12/placed_heap_source_test.py --sanitize
  python3 tests/d3d12/placed_heap_source_test.py --debug
  python3 tests/d3d12/placed_heap_source_test.py --thread-sanitize
  python3 tests/d3d12/placed_heap_source_test.py --negative

Requires Python 3 and GCC-compatible C++17 or newer, without an SDK or GPU.
--source selects another checkout; the same assertions reject the old source.
--negative compiles four deliberate regressions and requires assertion failure.
Only D3D12/COM interfaces are adapted. Actual State/Take/Give, map, vector,
unique_ptr and allocation failure are exercised. The adapter records native
heap lifetimes and byte counts; it does not allocate GPU memory. Private access
is exposed solely to check invariants. No production source is modified.

Faults persist until explicitly disarmed. Give is exercised with host allocation
available: its existing fallible cleanup is not fixed here. RangeOwner, resource
creation, GPU retirement, Windows ABI and the game are outside this fixture.
ASan/UBSan disable LeakSanitizer explicitly; heap handles have separate accounting.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ADAPTER = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace Fault {
  inline thread_local bool armed = false;
  inline thread_local std::size_t calls = 0, failAt = 0;
  void Arm(std::size_t at = 0) { calls = 0; failAt = at; armed = true; }
  void Disarm() { armed = false; }
}
[[gnu::noinline]] void* operator new(std::size_t n) {
  if (Fault::armed && ++Fault::calls >= Fault::failAt && Fault::failAt) throw std::bad_alloc();
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc();
}
[[gnu::noinline]] void operator delete(void* p) noexcept { std::free(p); }
[[gnu::noinline]] void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

using HRESULT = std::int32_t;
constexpr HRESULT S_OK = 0, E_FAIL = -1;
#define FAILED(x) ((x) < 0)
#define IID_PPV_ARGS(x) x
using D3D12_HEAP_FLAGS = unsigned;
using D3D12_RESOURCE_STATES = unsigned;
constexpr unsigned D3D12_HEAP_FLAG_NONE = 0, D3D12_HEAP_FLAG_CREATE_NOT_ZEROED = 1;
constexpr unsigned D3D12_HEAP_TYPE_DEFAULT = 1;
struct D3D12_RESOURCE_DESC {};
struct ID3D12Resource {};
struct GUID { std::uint32_t a; std::uint16_t b, c; std::uint8_t d[8]; };
struct D3D12_HEAP_DESC {
  std::uint64_t SizeInBytes = 0;
  struct { unsigned Type = 0; } Properties;
  unsigned Flags = 0;
};

namespace Microsoft::WRL {
  template<class T> class ComPtr {
    T* value = nullptr;
  public:
    ComPtr() = default;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ~ComPtr() { if (value) value->Release(); }
    ComPtr& operator=(T* p) {
      if (p) p->AddRef();
      if (value) value->Release();
      value = p;
      return *this;
    }
    T** operator&() { return &value; }
    T* operator->() const { return value; }
    T* Get() const { return value; }
  };
}
namespace Native {
  inline std::mutex mutex;
  inline std::size_t live = 0, calls = 0;
  inline std::uint64_t bytes = 0, budget = ~0ULL;
  inline bool fail = false, rejectNotZeroed = false;
}
struct ID3D12Heap {
  bool active = false;
  std::uint64_t bytes = 0;
  void Release() {
    const std::lock_guard<std::mutex> lock(Native::mutex);
    if (!active) std::abort();
    active = false;
    --Native::live;
    Native::bytes -= bytes;
  }
  HRESULT SetName(const wchar_t*) { return S_OK; }
};
namespace Native { inline std::array<ID3D12Heap, 1024> heaps; }
struct ID3D12Device {
  unsigned refs = 1;
  void AddRef() { ++refs; }
  void Release() { --refs; }
  HRESULT CreateHeap(const D3D12_HEAP_DESC* desc, ID3D12Heap** out) {
    const std::lock_guard<std::mutex> lock(Native::mutex);
    ++Native::calls;
    if (Native::fail || (Native::rejectNotZeroed && (desc->Flags & 1)) ||
        desc->SizeInBytes > Native::budget - Native::bytes) return E_FAIL;
    for (auto& h : Native::heaps) {
      if (h.active) continue;
      h.active = true;
      h.bytes = desc->SizeInBytes;
      Native::bytes += h.bytes;
      ++Native::live;
      *out = &h;
      return S_OK;
    }
    std::abort();
  }
};
namespace Native {
  void Reset() {
    if (live || bytes) std::abort();
    calls = 0; budget = ~0ULL; fail = rejectNotZeroed = false;
    Fault::Disarm();
  }
}
'''

TESTS = r'''
using State = gpg::gal::d3d12::PlacedHeapAllocator::State;
constexpr std::uint64_t MiB = 1ULL << 20, H = 64 * MiB;
std::size_t checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { \
  std::fprintf(stderr, "CHECK FAILED line %d: %s\n", __LINE__, #x); std::exit(99); \
} } while (false)

struct Snapshot {
  std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> ranges;
  std::vector<std::uint64_t> used;
  std::uint64_t heapBytes, usedBytes, nativeBytes;
  std::size_t nativeHeaps;
  bool operator==(const Snapshot& r) const {
    return ranges == r.ranges && used == r.used && heapBytes == r.heapBytes &&
      usedBytes == r.usedBytes && nativeBytes == r.nativeBytes && nativeHeaps == r.nativeHeaps;
  }
};
Snapshot Capture(const State& s) {
  Snapshot out{{}, {}, s.heapBytes.load(), s.usedBytes.load(), Native::bytes, Native::live};
  for (const auto& h : s.heaps) {
    out.ranges.emplace_back(h->free.begin(), h->free.end());
    out.used.push_back(h->used);
  }
  return out;
}
void Invariant(const State& s) {
  CHECK(s.heapBytes == s.heaps.size() * H);
  CHECK(Native::live == s.heaps.size());
  CHECK(Native::bytes == s.heapBytes);
  for (const auto& h : s.heaps) {
    std::uint64_t total = h->used, end = 0;
    for (auto [off, len] : h->free) {
      CHECK(len > 0 && off >= end && off + len <= H);
      total += len; end = off + len;
    }
    CHECK(total == H);
  }
}
void Shapes() {
  struct Shape { std::uint64_t start, length, size, alignment; std::size_t allocations; };
  const Shape shapes[] = {{0,128,128,1,0}, {17,111,64,64,0}, {0,128,64,64,0}, {17,239,64,64,1}};
  for (const auto c : shapes) for (std::size_t fail = 0; fail <= 2; ++fail) {
    Native::Reset(); ID3D12Device d;
    {
      State s; s.device = &d;
      auto h = std::make_unique<State::Heap>();
      D3D12_HEAP_DESC desc; desc.SizeInBytes = H;
      CHECK(d.CreateHeap(&desc, &h->heap) == S_OK);
      h->free.emplace(c.start, c.length); h->used = H - c.length;
      s.heaps.push_back(std::move(h)); s.heapBytes = H;
      const auto before = Capture(s);
      std::uint64_t off = 987654;
      bool threw = false;
      Fault::Arm(fail);
      try { CHECK(s.Take(c.size, c.alignment, off) == s.heaps[0].get()); }
      catch (const std::bad_alloc&) { threw = true; }
      const auto allocations = Fault::calls;
      Fault::Disarm();
      CHECK(threw == (fail != 0 && fail <= c.allocations));
      if (threw) {
        CHECK(off == 987654); CHECK(Capture(s) == before);
        CHECK(s.Take(c.size, c.alignment, off) != nullptr);
      } else CHECK(allocations == c.allocations);
      CHECK(off == ((c.start + c.alignment - 1) / c.alignment * c.alignment));
      Invariant(s);
    }
    CHECK(d.refs == 1 && Native::live == 0);
  }
}
void Growth() {
  for (unsigned prefill = 0; prefill < 3; ++prefill) for (std::size_t fail = 0; fail <= 4; ++fail) {
    Native::Reset(); ID3D12Device d;
    {
      State s; s.device = &d; std::uint64_t off = 0;
      if (prefill) {
        CHECK(s.Take(32 * MiB, 65536, off)); CHECK(s.Take(32 * MiB, 65536, off));
        if (prefill == 2) s.heaps.reserve(8);
      }
      const auto before = Capture(s); off = 999;
      bool threw = false;
      Fault::Arm(fail);
      try { CHECK(s.Take(MiB, 65536, off)); }
      catch (const std::bad_alloc&) { threw = true; }
      Fault::Disarm();
      if (threw) {
        CHECK(Capture(s) == before); CHECK(off == 999);
        CHECK(s.Take(MiB, 65536, off));
      }
      CHECK(off == 0); CHECK(s.heaps.size() == before.ranges.size() + 1);
      Invariant(s);
    }
    CHECK(d.refs == 1 && Native::live == 0);
  }
}
void NativeFailures() {
  for (unsigned mode = 0; mode < 3; ++mode) {
    Native::Reset(); ID3D12Device d;
    {
      State s; s.device = &d;
      Native::fail = mode == 0;
      Native::rejectNotZeroed = mode == 1;
      if (mode == 2) { Native::fail = true; s.notZeroed = false; }
      std::uint64_t off = 999;
      const auto result = s.Take(MiB, 65536, off);
      CHECK((result != nullptr) == (mode == 1));
      CHECK(Native::calls == (mode == 2 ? 1U : 2U));
      CHECK(off == (mode == 1 ? 0U : 999U));
      CHECK(!s.notZeroed); Invariant(s);
    }
    CHECK(Native::live == 0);
  }
}
void Pressure() {
  Native::Reset(); Native::budget = H; ID3D12Device d;
  {
    State s; s.device = &d; std::uint64_t off = 0;
    CHECK(s.Take(4096, 4096, off)); const auto before = Capture(s);
    bool threw = false; Fault::Arm(1);
    try { static_cast<void>(s.Take(8 * MiB, 65536, off)); }
    catch (const std::bad_alloc&) { threw = true; }
    Fault::Disarm(); CHECK(threw && Capture(s) == before);
    for (unsigned i = 0; i < 7; ++i) CHECK(s.Take(8 * MiB, 65536, off));
    CHECK(Native::calls == 1); Invariant(s);
  }
  CHECK(Native::live == 0);
}
void Trace() {
  Native::Reset(); ID3D12Device d;
  {
    State s; s.device = &d;
    struct Reservation { State::Heap* heap = nullptr; std::uint64_t off = 0, size = 0; };
    std::array<Reservation, 128> live;
    std::uint64_t rng = 1, hash = 0;
    for (unsigned step = 0; step < 24000; ++step) {
      rng = rng * 6364136223846793005ULL + 1;
      auto& r = live[(rng >> 32) % live.size()];
      if (r.heap) { s.Give(r.heap, r.off, r.size); r.heap = nullptr; }
      else {
        r.size = (((rng >> 16) % 128) + 1) * 65536;
        r.heap = s.Take(r.size, 65536, r.off); CHECK(r.heap);
        hash = (hash * 131) ^ r.off; hash = (hash * 131) ^ r.size;
      }
      Invariant(s);
      std::uint64_t total = 0;
      for (std::size_t i = 0; i < live.size(); ++i) if (live[i].heap) {
        const auto& a = live[i]; total += a.size;
        for (const auto [off, len] : a.heap->free) CHECK(a.off + a.size <= off || off + len <= a.off);
        for (std::size_t j = i + 1; j < live.size(); ++j) {
          const auto& b = live[j];
          if (a.heap == b.heap) CHECK(a.off + a.size <= b.off || b.off + b.size <= a.off);
        }
      }
      std::uint64_t used = 0;
      for (const auto& h : s.heaps) used += h->used;
      CHECK(used == total);
    }
    for (auto r : live) if (r.heap) s.Give(r.heap, r.off, r.size);
    Invariant(s); CHECK(s.heaps.size() == 1 && s.heaps.front()->used == 0);
    std::printf("TRACE operations=24000 hash=%llu native_heap_calls=%zu\n",
                static_cast<unsigned long long>(hash), Native::calls);
  }
  CHECK(Native::live == 0);
}
void Threads() {
  Native::Reset(); ID3D12Device d;
  {
    State s; s.device = &d;
    std::array<std::thread, 4> threads;
    for (auto& t : threads) t = std::thread([&] {
      for (unsigned i = 0; i < 1000; ++i) {
        std::uint64_t off = 0, size = ((i % 17) + 1) * 65536;
        State::Heap* h;
        { const std::lock_guard<std::mutex> lock(s.mutex); h = s.Take(size, 65536, off); }
        if (!h) std::abort();
        { const std::lock_guard<std::mutex> lock(s.mutex); s.Give(h, off, size); }
      }
    });
    for (auto& t : threads) t.join();
    Invariant(s); CHECK(s.heaps.size() == 1 && s.heaps.front()->used == 0);
  }
  CHECK(Native::live == 0);
}
int main(int argc, char**) {
  if (argc > 1) { Trace(); return 0; }
  Pressure(); Shapes(); Growth(); NativeFailures(); Threads();
  std::printf("PASS placed-heap range/counter checks=%zu\n", checks);
}
'''


def section(text, start, end):
    if text.count(start) != 1:
        raise RuntimeError(f"Source marker changed: {start!r}")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def extract(root):
    cpp = root / "src/gpg/gal/backends/d3d12/D3D12Core.cpp"
    header = root / "src/gpg/gal/backends/d3d12/D3D12Core.h"
    source, declarations = cpp.read_text(), header.read_text()
    parts = [
        section(declarations, "  class PlacedHeapAllocator\n", "  /** A resource and the state"),
        section(source, "    [[nodiscard]] std::uint64_t AlignUp(", "  } // namespace"),
        section(source, "  namespace\n  {\n    constexpr std::uint64_t kPlacedHeapSize", "  /** Gives a placed resource's range back"),
    ]
    print(json.dumps({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (cpp, header)}, sort_keys=True))
    return ADAPTER + '\nnamespace gpg::gal::d3d12 {\nusing Microsoft::WRL::ComPtr;\n#define private public\n' + parts[0] + '\n#undef private\nnamespace {\n' + parts[1] + '\n}\n' + parts[2] + '\n}\n' + TESTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--std", choices=["c++17", "c++20"], default="c++20")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sanitize", action="store_true")
    mode.add_argument("--debug", action="store_true")
    mode.add_argument("--thread-sanitize", action="store_true")
    parser.add_argument("--negative", action="store_true")
    args = parser.parse_args()
    source = extract(args.source.resolve())
    flags = ["-O2", "-DNDEBUG"]
    if args.sanitize:
        flags = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    elif args.debug:
        flags = ["-O1", "-g", "-D_GLIBCXX_DEBUG", "-fsanitize=undefined", "-fno-sanitize-recover=all"]
    elif args.thread_sanitize:
        flags = ["-O1", "-g", "-fsanitize=thread", "-fno-omit-frame-pointer"]
    variants = {"current": source}
    if args.negative:
        fixed = section(source, "        // Keep the original range", "        heap->used += size;")
        old = '''        heap->free.erase(range);
        if (offset > start) heap->free.emplace(start, offset - start);
        if (offset + size < start + length) heap->free.emplace(offset + size, start + length - offset - size);
'''
        variants.update({
            "destructive_split": source.replace(fixed, old, 1),
            "wrong_suffix_size": source.replace("remainder.mapped() = start + length - offset - size;", "remainder.mapped() = start + length - offset;", 1),
            "early_heap_counter": source.replace("    heaps.push_back(std::move(heap));\n    heapBytes += kPlacedHeapSize;", "    heapBytes += kPlacedHeapSize;\n    heaps.push_back(std::move(heap));", 1),
            "early_output": source.replace("    heaps.push_back(std::move(heap));\n    heapBytes += kPlacedHeapSize;\n    outOffset = 0U;", "    outOffset = 0U;\n    heaps.push_back(std::move(heap));\n    heapBytes += kPlacedHeapSize;", 1),
        })
        if any(s == source for name, s in variants.items() if name != "current"):
            raise RuntimeError("Negative-control source marker changed")
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1", TSAN_OPTIONS="halt_on_error=1")
    with tempfile.TemporaryDirectory(prefix="d3d12-placed-test-") as temp:
        directory = Path(temp)
        for name, content in variants.items():
            cpp, exe = directory / f"{name}.cpp", directory / name
            cpp.write_text(content)
            subprocess.run([args.cxx, f"-std={args.std}", "-pthread", "-Wall", "-Wextra", "-Werror",
                            "-Wno-mismatched-new-delete", *flags, str(cpp), "-o", str(exe)], check=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True, env=env, timeout=120)
            print(name + ": " + result.stdout + result.stderr, end="", flush=True)
            expected = 0 if name == "current" else 99
            if result.returncode != expected:
                raise RuntimeError(f"{name}: exit {result.returncode}, expected {expected}")
            if name == "current":
                subprocess.run([str(exe), "trace"], env=env, check=True, timeout=120)


if __name__ == "__main__":
    main()
