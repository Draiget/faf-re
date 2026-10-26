// FAF addition, not in the shipped binary: see D3D12Core.h.

#include "D3D12Core.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <string>

#include "gpg/gal/PlacedResources.h"
#include "gpg/gal/backends/common/BackendErrors.h"

namespace gpg::gal::d3d12
{
  using Microsoft::WRL::ComPtr;

  bool Library::Load()
  {
    if (module != nullptr) {
      return true;
    }
    module = ::LoadLibraryA("d3d12.dll");
    if (module == nullptr) {
      return false;
    }
    createDevice = reinterpret_cast<PFN_D3D12_CREATE_DEVICE>(::GetProcAddress(module, "D3D12CreateDevice"));
    getDebugInterface = reinterpret_cast<PFN_D3D12_GET_DEBUG_INTERFACE>(::GetProcAddress(module, "D3D12GetDebugInterface"));
    serializeRootSignature =
      reinterpret_cast<PFN_D3D12_SERIALIZE_ROOT_SIGNATURE>(::GetProcAddress(module, "D3D12SerializeRootSignature"));
    if (createDevice == nullptr || serializeRootSignature == nullptr) {
      Unload();
      return false;
    }
    return true;
  }

  void Library::Unload() noexcept
  {
    if (module != nullptr) {
      ::FreeLibrary(module);
    }
    module = nullptr;
    createDevice = nullptr;
    getDebugInterface = nullptr;
    serializeRootSignature = nullptr;
  }

  // ---------------------------------------------------------------------------
  // UploadAllocator

  namespace
  {
    constexpr std::uint64_t kPageSize = 8ULL << 20U;
#if defined(_M_IX86)
    constexpr std::uint64_t kIdlePageReserve = 32ULL << 20U;   // idle pages kept for reuse
#else
    constexpr std::uint64_t kIdlePageReserve = 128ULL << 20U;
#endif

    [[nodiscard]] std::uint64_t AlignUp(const std::uint64_t value, const std::uint64_t alignment) noexcept
    {
      return (value + alignment - 1U) / alignment * alignment;
    }
  } // namespace

  void UploadAllocator::Initialize(ID3D12Device* const device)
  {
    mDevice = device;
  }

  void UploadAllocator::Release() noexcept
  {
    mCurrent = nullptr;
    mPages.clear();
    mDevice.Reset();
  }

  UploadAllocator::Page* UploadAllocator::NewPage(const std::uint64_t size)
  {
    auto page = std::make_unique<Page>();
    page->size = size;

    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_UPLOAD;
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = size;
    desc.Height = 1U;
    desc.DepthOrArraySize = 1U;
    desc.MipLevels = 1U;
    desc.SampleDesc.Count = 1U;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    backend::CheckHresult(
      "D3D12Core.cpp", __LINE__,
      mDevice->CreateCommittedResource(
        &heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_GENERIC_READ, nullptr, IID_PPV_ARGS(&page->resource)
      )
    );
    static_cast<void>(page->resource->SetName(L"upload page"));
    const D3D12_RANGE noRead{0U, 0U};
    void* mapped = nullptr;
    backend::CheckHresult("D3D12Core.cpp", __LINE__, page->resource->Map(0U, &noRead, &mapped));
    page->cpu = static_cast<std::uint8_t*>(mapped);
    page->gpu = page->resource->GetGPUVirtualAddress();
    mPages.push_back(std::move(page));
    return mPages.back().get();
  }

  UploadAllocation UploadAllocator::Allocate(const std::uint64_t bytes, const std::uint64_t alignment, const std::uint64_t serial)
  {
    const std::uint64_t size = std::max<std::uint64_t>(bytes, 1U);
    if (mCurrent != nullptr) {
      const std::uint64_t offset = AlignUp(mCurrent->used, alignment);
      if (offset + size <= mCurrent->size) {
        mCurrent->used = offset + size;
        mCurrent->lastSerial = serial;
        mCurrent->busy = true;
        mAllocatedBytes += size;
        return UploadAllocation{mCurrent->resource.Get(), offset, mCurrent->cpu + offset, mCurrent->gpu + offset};
      }
    }

    // A free page large enough, else a new one.
    Page* chosen = nullptr;
    for (const std::unique_ptr<Page>& page : mPages) {
      if (!page->busy && page->size >= size && (chosen == nullptr || page->size < chosen->size)) {
        chosen = page.get();
      }
    }
    if (chosen == nullptr) {
      chosen = NewPage(std::max(kPageSize, AlignUp(size, 64ULL * 1024U)));
    }
    chosen->used = size;
    chosen->lastSerial = serial;
    chosen->busy = true;
    // Oversized one-off pages are not kept as the current page.
    if (chosen->size <= kPageSize) {
      mCurrent = chosen;
    }
    mAllocatedBytes += size;
    return UploadAllocation{chosen->resource.Get(), 0U, chosen->cpu, chosen->gpu};
  }

  void UploadAllocator::Retire(const std::uint64_t completedSerial) noexcept
  {
    for (const std::unique_ptr<Page>& page : mPages) {
      if (page->busy && page->lastSerial <= completedSerial && page.get() != mCurrent) {
        page->busy = false;
        page->used = 0U;
      }
    }
    if (mCurrent != nullptr && mCurrent->lastSerial <= completedSerial) {
      mCurrent->busy = false;
      mCurrent->used = 0U;
    }
    // Oversized pages that sit idle are given back, and so are the idle
    // ordinary pages past a reserve: a burst (a loading screen, a terrain
    // normal-map rebuild) would otherwise leave its peak mapped for the rest
    // of the session, which a 32-bit process cannot afford.
    std::uint64_t idleKept = 0U;
    mPages.erase(
      std::remove_if(
        mPages.begin(), mPages.end(),
        [&](const std::unique_ptr<Page>& page) {
          if (page->busy || page.get() == mCurrent) {
            return false;
          }
          if (page->size > kPageSize || idleKept + page->size > kIdlePageReserve) {
            return true;
          }
          idleKept += page->size;
          return false;
        }
      ),
      mPages.end()
    );
  }

  std::uint64_t UploadAllocator::TakeAllocatedBytes() noexcept
  {
    const std::uint64_t bytes = mAllocatedBytes;
    mAllocatedBytes = 0U;
    return bytes;
  }

  std::uint64_t UploadAllocator::PageBytes() const noexcept
  {
    std::uint64_t bytes = 0U;
    for (const std::unique_ptr<Page>& page : mPages) {
      bytes += page->size;
    }
    return bytes;
  }

  std::uint64_t UploadAllocator::BusyBytes() const noexcept
  {
    std::uint64_t bytes = 0U;
    for (const std::unique_ptr<Page>& page : mPages) {
      if (page->busy) {
        bytes += page->size;
      }
    }
    return bytes;
  }

  // ---------------------------------------------------------------------------
  // DescriptorPool

  void DescriptorPool::Initialize(ID3D12Device* const device, const D3D12_DESCRIPTOR_HEAP_TYPE type, const std::uint32_t perHeap)
  {
    mDevice = device;
    mType = type;
    mPerHeap = perHeap;
    mIncrement = device->GetDescriptorHandleIncrementSize(type);
    mNextInHeap = perHeap; // the first Allocate creates a heap
  }

  void DescriptorPool::Release() noexcept
  {
    mFree.clear();
    mHeaps.clear();
    mDevice.Reset();
  }

  D3D12_CPU_DESCRIPTOR_HANDLE DescriptorPool::Allocate()
  {
    if (!mFree.empty()) {
      const D3D12_CPU_DESCRIPTOR_HANDLE handle = mFree.back();
      mFree.pop_back();
      return handle;
    }
    if (mNextInHeap >= mPerHeap) {
      D3D12_DESCRIPTOR_HEAP_DESC desc{};
      desc.Type = mType;
      desc.NumDescriptors = mPerHeap;
      desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
      ComPtr<ID3D12DescriptorHeap> heap;
      backend::CheckHresult("D3D12Core.cpp", __LINE__, mDevice->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&heap)));
      mHeaps.push_back(heap);
      mNextInHeap = 0U;
    }
    D3D12_CPU_DESCRIPTOR_HANDLE handle = mHeaps.back()->GetCPUDescriptorHandleForHeapStart();
    handle.ptr += static_cast<SIZE_T>(mNextInHeap++) * mIncrement;
    return handle;
  }

  void DescriptorPool::Free(const D3D12_CPU_DESCRIPTOR_HANDLE handle)
  {
    if (handle.ptr != 0U) {
      mFree.push_back(handle);
    }
  }

  // ---------------------------------------------------------------------------
  // DescriptorArena

  void DescriptorArena::Initialize(ID3D12Device* const device, const D3D12_DESCRIPTOR_HEAP_TYPE type, const std::uint32_t capacity)
  {
    D3D12_DESCRIPTOR_HEAP_DESC desc{};
    desc.Type = type;
    desc.NumDescriptors = capacity;
    desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
    backend::CheckHresult("D3D12Core.cpp", __LINE__, device->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&mHeap)));
    mCapacity = capacity;
    mUsed = 0U;
    mIncrement = device->GetDescriptorHandleIncrementSize(type);
  }

  void DescriptorArena::Release() noexcept
  {
    mHeap.Reset();
    mCapacity = 0U;
    mUsed = 0U;
  }

  bool DescriptorArena::Allocate(const std::uint32_t count, D3D12_CPU_DESCRIPTOR_HANDLE& cpu, D3D12_GPU_DESCRIPTOR_HANDLE& gpu)
  {
    if (mUsed + count > mCapacity) {
      return false;
    }
    cpu = mHeap->GetCPUDescriptorHandleForHeapStart();
    cpu.ptr += static_cast<SIZE_T>(mUsed) * mIncrement;
    gpu = mHeap->GetGPUDescriptorHandleForHeapStart();
    gpu.ptr += static_cast<UINT64>(mUsed) * mIncrement;
    mUsed += count;
    return true;
  }

  // ---------------------------------------------------------------------------
  // PlacedHeapAllocator

  namespace
  {
    constexpr std::uint64_t kPlacedHeapSize = 64ULL << 20U;
    constexpr std::uint64_t kLargestPlaced = kPlacedHeapSize / 2U; // larger ones stay committed

    // {5B0D4F62-8C4E-4C41-9F0B-6A2E1D7C3A90}: the private data slot holding a placed
    // resource's RangeOwner.
    constexpr GUID kRangeOwnerSlot = {0x5b0d4f62, 0x8c4e, 0x4c41, {0x9f, 0x0b, 0x6a, 0x2e, 0x1d, 0x7c, 0x3a, 0x90}};
  } // namespace

  struct PlacedHeapAllocator::State
  {
    struct Heap
    {
      ComPtr<ID3D12Heap> heap;
      std::map<std::uint64_t, std::uint64_t> free; // offset -> size, adjacent ranges merged
      std::uint64_t used = 0;
    };

    std::mutex mutex;
    ComPtr<ID3D12Device> device;
    D3D12_HEAP_FLAGS flags = D3D12_HEAP_FLAG_NONE;
    std::wstring name;
    bool notZeroed = true; // D3D12_HEAP_FLAG_CREATE_NOT_ZEROED until the runtime refuses it
    std::vector<std::unique_ptr<Heap>> heaps;
    std::atomic<std::uint64_t> heapBytes{0};
    std::atomic<std::uint64_t> usedBytes{0};

    /** Takes `size` bytes at `alignment` from a heap, making one when none has room. */
    [[nodiscard]] Heap* Take(std::uint64_t size, std::uint64_t alignment, std::uint64_t& outOffset);
    void Give(Heap* heap, std::uint64_t offset, std::uint64_t size);
  };

  PlacedHeapAllocator::State::Heap* PlacedHeapAllocator::State::Take(
    const std::uint64_t size, const std::uint64_t alignment, std::uint64_t& outOffset
  )
  {
    for (const std::unique_ptr<Heap>& heap : heaps) {
      for (auto range = heap->free.begin(); range != heap->free.end(); ++range) {
        const auto [start, length] = *range;
        const std::uint64_t offset = AlignUp(start, alignment);
        if (offset + size > start + length) {
          continue;
        }
        heap->free.erase(range);
        if (offset > start) {
          heap->free.emplace(start, offset - start);
        }
        if (offset + size < start + length) {
          heap->free.emplace(offset + size, start + length - offset - size);
        }
        heap->used += size;
        outOffset = offset;
        return heap.get();
      }
    }

    D3D12_HEAP_DESC desc{};
    desc.SizeInBytes = kPlacedHeapSize;
    desc.Properties.Type = D3D12_HEAP_TYPE_DEFAULT;
    desc.Flags = flags | (notZeroed ? D3D12_HEAP_FLAG_CREATE_NOT_ZEROED : D3D12_HEAP_FLAG_NONE);
    auto heap = std::make_unique<Heap>();
    if (FAILED(device->CreateHeap(&desc, IID_PPV_ARGS(&heap->heap)))) {
      if (!notZeroed) {
        return nullptr;
      }
      // Windows before 10 2004 does not know the flag.
      notZeroed = false;
      desc.Flags = flags;
      if (FAILED(device->CreateHeap(&desc, IID_PPV_ARGS(&heap->heap)))) {
        return nullptr;
      }
    }
    static_cast<void>(heap->heap->SetName(name.c_str()));
    heap->free.emplace(size, kPlacedHeapSize - size);
    heap->used = size;
    heapBytes += kPlacedHeapSize;
    outOffset = 0U;
    heaps.push_back(std::move(heap));
    return heaps.back().get();
  }

  void PlacedHeapAllocator::State::Give(Heap* const heap, const std::uint64_t offset, const std::uint64_t size)
  {
    std::uint64_t start = offset;
    std::uint64_t length = size;
    auto next = heap->free.lower_bound(offset);
    if (next != heap->free.begin()) {
      const auto previous = std::prev(next);
      if (previous->first + previous->second == start) {
        start = previous->first;
        length += previous->second;
        heap->free.erase(previous);
      }
    }
    if (next != heap->free.end() && next->first == offset + size) {
      length += next->second;
      heap->free.erase(next);
    }
    heap->free.emplace(start, length);
    heap->used -= size;

    // An empty heap goes when another empty one is kept for the next allocations.
    if (heap->used == 0U) {
      const auto empty = std::count_if(heaps.begin(), heaps.end(), [](const std::unique_ptr<Heap>& h) { return h->used == 0U; });
      if (empty > 1) {
        heaps.erase(std::find_if(heaps.begin(), heaps.end(), [heap](const std::unique_ptr<Heap>& h) { return h.get() == heap; }));
        heapBytes -= kPlacedHeapSize;
      }
    }
  }

  /** Gives a placed resource's range back when the resource, which holds it as private data, goes. */
  class PlacedHeapAllocator::RangeOwner final : public IUnknown
  {
  public:
    RangeOwner(std::shared_ptr<State> state, State::Heap* const heap, const std::uint64_t offset, const std::uint64_t size)
      : mState(std::move(state))
      , mHeap(heap)
      , mOffset(offset)
      , mSize(size)
    {
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** const object) override
    {
      if (object == nullptr) {
        return E_POINTER;
      }
      if (riid == __uuidof(IUnknown)) {
        AddRef();
        *object = static_cast<IUnknown*>(this);
        return S_OK;
      }
      *object = nullptr;
      return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++mReferences; }

    ULONG STDMETHODCALLTYPE Release() override
    {
      const ULONG left = --mReferences;
      if (left == 0U) {
        {
          const std::lock_guard<std::mutex> lock(mState->mutex);
          mState->Give(mHeap, mOffset, mSize);
        }
        mState->usedBytes -= mSize;
        delete this;
      }
      return left;
    }

  private:
    std::shared_ptr<State> mState;
    State::Heap* mHeap;
    std::uint64_t mOffset;
    std::uint64_t mSize;
    std::atomic<ULONG> mReferences{1U};
  };

  PlacedHeapAllocator::PlacedHeapAllocator() = default;
  PlacedHeapAllocator::~PlacedHeapAllocator() = default;

  void PlacedHeapAllocator::Initialize(ID3D12Device* const device, const D3D12_HEAP_FLAGS flags, const wchar_t* const name)
  {
    mState = std::make_shared<State>();
    mState->device = device;
    mState->flags = flags;
    mState->name = name;
  }

  void PlacedHeapAllocator::Release() noexcept
  {
    mState.reset();
  }

  bool PlacedHeapAllocator::Create(
    const D3D12_RESOURCE_DESC& desc, const D3D12_RESOURCE_STATES state, ComPtr<ID3D12Resource>& outResource
  )
  {
    if (mState == nullptr) {
      return false;
    }
    // Small textures may take 4 KB alignment instead of 64 KB when the driver allows it.
    D3D12_RESOURCE_DESC placed = desc;
    D3D12_RESOURCE_ALLOCATION_INFO info{};
    if (desc.Dimension != D3D12_RESOURCE_DIMENSION_BUFFER) {
      placed.Alignment = D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT;
      info = mState->device->GetResourceAllocationInfo(0U, 1U, &placed);
      if (info.Alignment != D3D12_SMALL_RESOURCE_PLACEMENT_ALIGNMENT) {
        placed.Alignment = 0U;
        info = mState->device->GetResourceAllocationInfo(0U, 1U, &placed);
      }
    } else {
      placed.Alignment = 0U;
      info = mState->device->GetResourceAllocationInfo(0U, 1U, &placed);
    }
    if (info.SizeInBytes == UINT64_MAX || info.SizeInBytes == 0U || info.SizeInBytes > kLargestPlaced) {
      return false;
    }

    std::uint64_t offset = 0U;
    State::Heap* heap = nullptr;
    {
      const std::lock_guard<std::mutex> lock(mState->mutex);
      heap = mState->Take(info.SizeInBytes, info.Alignment, offset);
    }
    if (heap == nullptr) {
      return false;
    }
    ComPtr<ID3D12Resource> resource;
    if (FAILED(mState->device->CreatePlacedResource(heap->heap.Get(), offset, &placed, state, nullptr, IID_PPV_ARGS(&resource)))) {
      const std::lock_guard<std::mutex> lock(mState->mutex);
      mState->Give(heap, offset, info.SizeInBytes);
      return false;
    }
    auto* const owner = new RangeOwner(mState, heap, offset, info.SizeInBytes);
    mState->usedBytes += info.SizeInBytes;
    const HRESULT attached = resource->SetPrivateDataInterface(kRangeOwnerSlot, owner);
    owner->Release(); // the resource holds it now, or nothing does and the range is free again
    if (FAILED(attached)) {
      return false;
    }
    outResource = std::move(resource);
    return true;
  }

  std::uint64_t PlacedHeapAllocator::HeapBytes() const noexcept
  {
    return mState != nullptr ? mState->heapBytes.load() : 0U;
  }

  std::uint64_t PlacedHeapAllocator::UsedBytes() const noexcept
  {
    return mState != nullptr ? mState->usedBytes.load() : 0U;
  }
} // namespace gpg::gal::d3d12

namespace gpg::gal
{
  bool gPlacedResources = true;
} // namespace gpg::gal
