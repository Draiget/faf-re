// FAF addition, not in the shipped binary: see D3D12Core.h.

#include "D3D12Core.h"

#include <algorithm>

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
    // Oversized pages that sit idle are given back.
    mPages.erase(
      std::remove_if(mPages.begin(), mPages.end(), [&](const std::unique_ptr<Page>& page) {
        return !page->busy && page->size > kPageSize && page.get() != mCurrent;
      }),
      mPages.end()
    );
  }

  std::uint64_t UploadAllocator::TakeAllocatedBytes() noexcept
  {
    const std::uint64_t bytes = mAllocatedBytes;
    mAllocatedBytes = 0U;
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
} // namespace gpg::gal::d3d12
