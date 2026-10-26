#pragma once

// FAF addition, not in the shipped binary.
//
// Building blocks of the Direct3D 12 gal backend: the run-time link to
// d3d12.dll (so the executable still starts where there is none), the upload
// allocator every CPU-to-GPU copy goes through, the descriptor heaps, and a
// resource that remembers its state for barriers.

#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

#include <d3d12.h>
#include <wrl/client.h>

namespace gpg::gal::d3d12
{
  /** Frames the CPU may record ahead of the GPU. */
  inline constexpr std::uint32_t kFramesInFlight = 3;

  /** d3d12.dll's exports, linked at run time. */
  struct Library
  {
    HMODULE module = nullptr;
    PFN_D3D12_CREATE_DEVICE createDevice = nullptr;
    PFN_D3D12_GET_DEBUG_INTERFACE getDebugInterface = nullptr;
    PFN_D3D12_SERIALIZE_ROOT_SIGNATURE serializeRootSignature = nullptr;

    /** Loads d3d12.dll; false when Direct3D 12 is not installed. */
    [[nodiscard]] bool Load();
    void Unload() noexcept;
  };

  /** One upload-heap allocation: written by the CPU, read by the GPU once. */
  struct UploadAllocation
  {
    ID3D12Resource* resource = nullptr;
    std::uint64_t offset = 0;
    std::uint8_t* cpu = nullptr;
    D3D12_GPU_VIRTUAL_ADDRESS gpu = 0;
  };

  /**
   * Upload memory in pages. Each allocation is tagged with the submission
   * that reads it; a page is reused once the GPU has finished that submission.
   */
  class UploadAllocator
  {
  public:
    void Initialize(ID3D12Device* device);
    void Release() noexcept;

    /** Throws a gal Error when the heap cannot grow. */
    [[nodiscard]] UploadAllocation Allocate(std::uint64_t bytes, std::uint64_t alignment, std::uint64_t serial);

    /** Pages whose last submission has completed become reusable. */
    void Retire(std::uint64_t completedSerial) noexcept;

    /** Bytes handed out since the last call (the device flushes when this grows large). */
    [[nodiscard]] std::uint64_t TakeAllocatedBytes() noexcept;
    /** Bytes in pages still waiting for the GPU. */
    [[nodiscard]] std::uint64_t BusyBytes() const noexcept;
    /** Bytes in all pages, and their count (memory diagnostics). */
    [[nodiscard]] std::uint64_t PageBytes() const noexcept;
    [[nodiscard]] std::size_t PageCount() const noexcept { return mPages.size(); }

  private:
    struct Page
    {
      Microsoft::WRL::ComPtr<ID3D12Resource> resource;
      std::uint8_t* cpu = nullptr;
      D3D12_GPU_VIRTUAL_ADDRESS gpu = 0;
      std::uint64_t size = 0;
      std::uint64_t used = 0;
      std::uint64_t lastSerial = 0;
      bool busy = false;
    };

    [[nodiscard]] Page* NewPage(std::uint64_t size);

    Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
    std::vector<std::unique_ptr<Page>> mPages;
    Page* mCurrent = nullptr;
    std::uint64_t mAllocatedBytes = 0;
  };

  /** A CPU-only descriptor heap handing out single descriptors. */
  class DescriptorPool
  {
  public:
    void Initialize(ID3D12Device* device, D3D12_DESCRIPTOR_HEAP_TYPE type, std::uint32_t perHeap);
    void Release() noexcept;

    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE Allocate();
    void Free(D3D12_CPU_DESCRIPTOR_HANDLE handle);

  private:
    Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
    D3D12_DESCRIPTOR_HEAP_TYPE mType = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    std::uint32_t mPerHeap = 0;
    std::uint32_t mIncrement = 0;
    std::vector<Microsoft::WRL::ComPtr<ID3D12DescriptorHeap>> mHeaps;
    std::vector<D3D12_CPU_DESCRIPTOR_HANDLE> mFree;
    std::uint32_t mNextInHeap = 0;
  };

  /** A shader-visible heap filled front to back and emptied whole. */
  class DescriptorArena
  {
  public:
    void Initialize(ID3D12Device* device, D3D12_DESCRIPTOR_HEAP_TYPE type, std::uint32_t capacity);
    void Release() noexcept;

    /** False when `count` more do not fit. */
    [[nodiscard]] bool Allocate(std::uint32_t count, D3D12_CPU_DESCRIPTOR_HANDLE& cpu, D3D12_GPU_DESCRIPTOR_HANDLE& gpu);
    void Reset() noexcept { mUsed = 0U; }

    [[nodiscard]] ID3D12DescriptorHeap* Heap() const noexcept { return mHeap.Get(); }
    [[nodiscard]] std::uint32_t Increment() const noexcept { return mIncrement; }

  private:
    Microsoft::WRL::ComPtr<ID3D12DescriptorHeap> mHeap;
    std::uint32_t mCapacity = 0;
    std::uint32_t mUsed = 0;
    std::uint32_t mIncrement = 0;
  };

  /**
   * Engine addition (gal::gPlacedResources): resources placed in 64 MB default heaps of one
   * kind (textures that are not render targets, or buffers). A heap range is free again when
   * its resource is destroyed, which the device delays until the GPU is done with it, so the
   * memory is never reused while a submission still reads it. Thread-safe.
   */
  class PlacedHeapAllocator
  {
  public:
    PlacedHeapAllocator();
    ~PlacedHeapAllocator();
    PlacedHeapAllocator(const PlacedHeapAllocator&) = delete;
    PlacedHeapAllocator& operator=(const PlacedHeapAllocator&) = delete;

    /** `flags`: D3D12_HEAP_FLAG_ALLOW_ONLY_NON_RT_DS_TEXTURES or D3D12_HEAP_FLAG_ALLOW_ONLY_BUFFERS. */
    void Initialize(ID3D12Device* device, D3D12_HEAP_FLAGS flags, const wchar_t* name);
    /** The heaps go once the last resource placed in them is destroyed. */
    void Release() noexcept;

    /**
     * Creates `desc` in a heap; false when it should be a committed resource instead (too large
     * for a heap, or the driver refused), and `outResource` is left empty.
     */
    [[nodiscard]] bool Create(const D3D12_RESOURCE_DESC& desc, D3D12_RESOURCE_STATES state,
                              Microsoft::WRL::ComPtr<ID3D12Resource>& outResource);

    /** Bytes in heaps, and bytes placed resources take in them (memory diagnostics). */
    [[nodiscard]] std::uint64_t HeapBytes() const noexcept;
    [[nodiscard]] std::uint64_t UsedBytes() const noexcept;

  private:
    struct State;
    class RangeOwner;
    std::shared_ptr<State> mState;
  };

  /** A resource and the state its last barrier left it in. */
  struct TrackedResource
  {
    Microsoft::WRL::ComPtr<ID3D12Resource> resource;
    D3D12_RESOURCE_STATES state = D3D12_RESOURCE_STATE_COMMON;
  };
} // namespace gpg::gal::d3d12
