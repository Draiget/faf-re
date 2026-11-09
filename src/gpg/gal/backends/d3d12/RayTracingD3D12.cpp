// FAF addition, not in the shipped binary.
//
// Engine addition (ren_RayTracedShadows, RayTracing.h): the Direct3D 12 side of the ray-traced scene. Needs
// DXR tier 1.1 (inline ray queries) and shader model 6.5. Each piece of geometry gets a bottom-level
// structure inside a few large buffers (a committed resource each would take 64 KB at least, and a map has
// thousands of pieces); `SetRayInstances` rebuilds the top-level structure on the command list being
// recorded, and every effect draw binds it at root parameter 3 (t0, space1).

#include "DeviceD3D12.h"

#include <algorithm>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/effects/RayTracedShadows.h"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;

  namespace
  {
    constexpr std::uint64_t kRayChunkBytes = 32ULL << 20U;

    [[nodiscard]] std::uint64_t AlignUp(const std::uint64_t value, const std::uint64_t alignment) noexcept
    {
      return (value + alignment - 1U) & ~(alignment - 1U);
    }

    [[nodiscard]] ComPtr<ID3D12Resource> CreateRayBuffer(
      ID3D12Device* const device, const std::uint64_t bytes, const D3D12_RESOURCE_STATES state, const wchar_t* const name
    )
    {
      D3D12_HEAP_PROPERTIES heap{};
      heap.Type = D3D12_HEAP_TYPE_DEFAULT;
      D3D12_RESOURCE_DESC desc{};
      desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
      desc.Width = bytes;
      desc.Height = 1U;
      desc.DepthOrArraySize = 1U;
      desc.MipLevels = 1U;
      desc.SampleDesc.Count = 1U;
      desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
      desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;
      ComPtr<ID3D12Resource> resource;
      if (FAILED(device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, state, nullptr, IID_PPV_ARGS(&resource)))) {
        return nullptr;
      }
      resource->SetName(name);
      return resource;
    }
  } // namespace

  bool DeviceD3D12::RayArena::Allocate(ID3D12Device* const device, const std::uint64_t bytes, RayRange& out)
  {
    const std::uint64_t size = AlignUp(bytes, D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BYTE_ALIGNMENT);
    for (std::uint32_t chunk = 0U; chunk < chunks.size(); ++chunk) {
      std::map<std::uint64_t, std::uint64_t>& holes = chunks[chunk].holes;
      for (auto hole = holes.begin(); hole != holes.end(); ++hole) {
        if (hole->second < size) {
          continue;
        }
        out.chunk = chunk;
        out.offset = hole->first;
        out.bytes = size;
        const std::uint64_t left = hole->second - size;
        const std::uint64_t next = hole->first + size;
        holes.erase(hole);
        if (left != 0U) {
          holes.emplace(next, left);
        }
        out.address = chunks[chunk].buffer->GetGPUVirtualAddress() + out.offset;
        return true;
      }
    }
    Chunk chunk;
    chunk.bytes = std::max(kRayChunkBytes, size);
    chunk.buffer = CreateRayBuffer(device, chunk.bytes, D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE, L"ray geometry");
    if (chunk.buffer == nullptr) {
      return false;
    }
    chunk.holes.emplace(0U, chunk.bytes);
    chunks.push_back(std::move(chunk));
    return Allocate(device, bytes, out);
  }

  void DeviceD3D12::RayArena::Free(const RayRange& range)
  {
    std::map<std::uint64_t, std::uint64_t>& holes = chunks[range.chunk].holes;
    auto inserted = holes.emplace(range.offset, range.bytes).first;
    // Join the hole after it, then the one before.
    const auto next = std::next(inserted);
    if (next != holes.end() && inserted->first + inserted->second == next->first) {
      inserted->second += next->second;
      holes.erase(next);
    }
    if (inserted != holes.begin()) {
      const auto previous = std::prev(inserted);
      if (previous->first + previous->second == inserted->first) {
        previous->second += inserted->second;
        holes.erase(inserted);
      }
    }
  }

  void DeviceD3D12::CreateRayTracing()
  {
    ++gRaySceneEpoch;
    mRayQuery = false;
    effects::gRayQueryShaders = false;
    if (!effects::RayTracedShadowsWanted()) {
      gpg::Logf("D3D12: ray tracing off (ren_RayTracedShadows -1 at device creation)");
      return;
    }
    D3D12_FEATURE_DATA_D3D12_OPTIONS5 options5{};
    D3D12_FEATURE_DATA_SHADER_MODEL shaderModel{D3D_SHADER_MODEL_6_5};
    const bool tier = SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS5, &options5, sizeof(options5))) &&
      options5.RaytracingTier >= D3D12_RAYTRACING_TIER_1_1;
    const bool model = SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_SHADER_MODEL, &shaderModel, sizeof(shaderModel))) &&
      shaderModel.HighestShaderModel >= D3D_SHADER_MODEL_6_5;
    if (!tier || !model || FAILED(mDevice.As(&mDevice5)) || FAILED(mList.As(&mList4))) {
      gpg::Logf(
        "D3D12: no inline ray queries (raytracing tier %d, shader model 0x%X); ray-traced shadows off", static_cast<int>(options5.RaytracingTier),
        static_cast<unsigned>(shaderModel.HighestShaderModel)
      );
      mDevice5.Reset();
      mList4.Reset();
      return;
    }
    mRayQuery = true;
    effects::gRayQueryShaders = true;
    gpg::Logf("D3D12: inline ray queries available (raytracing tier %d)", static_cast<int>(options5.RaytracingTier));
  }

  void DeviceD3D12::ReleaseRayTracing() noexcept
  {
    ++gRaySceneEpoch;
    mRayGeometries.clear();
    mRayFrees.clear();
    mRayArena.chunks.clear();
    mRayScratch = d3d12::TrackedResource{};
    mRayScratchBytes = 0U;
    mTlas = d3d12::TrackedResource{};
    mTlasBytes = 0U;
    mTlasAddress = 0U;
    mRayInstanceDescs.clear();
    mList4.Reset();
    mDevice5.Reset();
    mRayQuery = false;
    effects::gRayQueryShaders = false;
  }

  bool DeviceD3D12::EnsureRayScratch(const std::uint64_t bytes)
  {
    if (mRayScratch.resource != nullptr && mRayScratchBytes >= bytes) {
      return true;
    }
    if (mRayScratch.resource != nullptr) {
      Retire(mRayScratch.resource);
    }
    mRayScratchBytes = AlignUp(std::max<std::uint64_t>(bytes, 4ULL << 20U), 65536U);
    mRayScratch.resource = CreateRayBuffer(mDevice.Get(), mRayScratchBytes, D3D12_RESOURCE_STATE_UNORDERED_ACCESS, L"ray build scratch");
    mRayScratch.state = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
    if (mRayScratch.resource == nullptr) {
      mRayScratchBytes = 0U;
      return false;
    }
    return true;
  }

  void DeviceD3D12::RayBuildBarrier(ID3D12Resource* const resource)
  {
    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_UAV;
    barrier.UAV.pResource = resource;
    mPendingBarriers.push_back(barrier);
  }

  void DeviceD3D12::CollectRayFrees()
  {
    const std::uint64_t completed = mFence->GetCompletedValue();
    auto keep = mRayFrees.begin();
    for (auto it = mRayFrees.begin(); it != mRayFrees.end(); ++it) {
      if (it->serial <= completed) {
        mRayArena.Free(it->range);
      } else {
        *keep++ = *it;
      }
    }
    mRayFrees.erase(keep, mRayFrees.end());
  }

  RayGeometryId DeviceD3D12::CreateRayGeometry(const RayGeometryDesc& desc)
  {
    if (!mRayQuery || desc.positions == nullptr || desc.indices == nullptr || desc.vertexCount == 0U || desc.indexCount < 3U ||
        desc.positionStride < 12U) {
      return 0U;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    CollectRayFrees();
    const std::uint32_t triangles = desc.indexCount / 3U;
    // Inputs from upload memory, which the build reads (GENERIC_READ holds NON_PIXEL_SHADER_RESOURCE).
    // Both allocations come first: an allocation can hand the recorded commands to the GPU.
    const std::uint64_t vertexBytes = static_cast<std::uint64_t>(desc.vertexCount) * 12U;
    const std::uint64_t indexBytes = static_cast<std::uint64_t>(triangles) * 12U;
    const d3d12::UploadAllocation vertices = AllocateUpload(vertexBytes, 16U);
    const d3d12::UploadAllocation indices = AllocateUpload(indexBytes, 16U);
    const auto* source = reinterpret_cast<const std::uint8_t*>(desc.positions);
    for (std::uint32_t vertex = 0U; vertex < desc.vertexCount; ++vertex) {
      std::memcpy(vertices.cpu + (static_cast<std::size_t>(vertex) * 12U), source + (static_cast<std::size_t>(vertex) * desc.positionStride), 12U);
    }
    std::memcpy(indices.cpu, desc.indices, static_cast<std::size_t>(indexBytes));

    D3D12_RAYTRACING_GEOMETRY_DESC geometry{};
    geometry.Type = D3D12_RAYTRACING_GEOMETRY_TYPE_TRIANGLES;
    geometry.Flags = D3D12_RAYTRACING_GEOMETRY_FLAG_OPAQUE;
    geometry.Triangles.VertexBuffer.StartAddress = vertices.gpu;
    geometry.Triangles.VertexBuffer.StrideInBytes = 12U;
    geometry.Triangles.VertexFormat = DXGI_FORMAT_R32G32B32_FLOAT;
    geometry.Triangles.VertexCount = desc.vertexCount;
    geometry.Triangles.IndexFormat = DXGI_FORMAT_R32_UINT;
    geometry.Triangles.IndexCount = triangles * 3U;
    geometry.Triangles.IndexBuffer = indices.gpu;

    D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC build{};
    build.Inputs.Type = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_BOTTOM_LEVEL;
    build.Inputs.Flags = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_PREFER_FAST_TRACE;
    build.Inputs.NumDescs = 1U;
    build.Inputs.DescsLayout = D3D12_ELEMENTS_LAYOUT_ARRAY;
    build.Inputs.pGeometryDescs = &geometry;
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO prebuild{};
    mDevice5->GetRaytracingAccelerationStructurePrebuildInfo(&build.Inputs, &prebuild);
    if (prebuild.ResultDataMaxSizeInBytes == 0U) {
      return 0U;
    }
    RayGeometryD3D12 piece;
    if (!mRayArena.Allocate(mDevice.Get(), prebuild.ResultDataMaxSizeInBytes, piece.range) || !EnsureRayScratch(prebuild.ScratchDataSizeInBytes)) {
      gpg::Logf("D3D12: out of memory for ray geometry '%s'", desc.name);
      return 0U;
    }
    build.DestAccelerationStructureData = piece.range.address;
    build.ScratchAccelerationStructureData = mRayScratch.resource->GetGPUVirtualAddress();
    // The scratch buffer is shared: the build before this one must be done with it.
    RayBuildBarrier(mRayScratch.resource.Get());
    FlushBarriers();
    MarkDraw("ray geometry build");
    mList4->BuildRaytracingAccelerationStructure(&build, 0U, nullptr);
    FinishDraw();
    RayBuildBarrier(mRayArena.chunks[piece.range.chunk].buffer.Get());
    FlushBarriers();
    piece.triangles = triangles;
    const RayGeometryId id = mNextRayGeometry++;
    mRayGeometries.emplace(id, piece);
    mRayGeometryBytes += piece.range.bytes;
    return id;
  }

  void DeviceD3D12::DestroyRayGeometry(const RayGeometryId geometry)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const auto found = mRayGeometries.find(geometry);
    if (found == mRayGeometries.end()) {
      return;
    }
    // The commands recorded so far (and the scene built from them) may still read it.
    mRayFrees.push_back(RayFree{RecordingSerial(), found->second.range});
    mRayGeometryBytes -= found->second.range.bytes;
    mRayGeometries.erase(found);
  }

  bool DeviceD3D12::SetRayInstances(const RayInstance* const instances, const std::uint32_t count)
  {
    if (!mRayQuery) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    mRayInstanceDescs.clear();
    mRayInstanceDescs.reserve(count);
    for (std::uint32_t index = 0U; index < count; ++index) {
      const RayInstance& instance = instances[index];
      const auto found = mRayGeometries.find(instance.geometry);
      if (found == mRayGeometries.end()) {
        continue;
      }
      D3D12_RAYTRACING_INSTANCE_DESC desc{};
      std::memcpy(desc.Transform, instance.transform, sizeof(desc.Transform));
      desc.InstanceID = 0U;
      desc.InstanceMask = instance.mask;
      desc.Flags = D3D12_RAYTRACING_INSTANCE_FLAG_TRIANGLE_CULL_DISABLE | D3D12_RAYTRACING_INSTANCE_FLAG_FORCE_OPAQUE;
      desc.AccelerationStructure = found->second.range.address;
      mRayInstanceDescs.push_back(desc);
    }
    return BuildRayScene();
  }

  bool DeviceD3D12::BuildRayScene()
  {
    const auto count = static_cast<std::uint32_t>(mRayInstanceDescs.size());
    const std::uint64_t descBytes = std::max<std::uint64_t>(1U, count) * sizeof(D3D12_RAYTRACING_INSTANCE_DESC);
    const d3d12::UploadAllocation upload = AllocateUpload(descBytes, D3D12_RAYTRACING_INSTANCE_DESCS_BYTE_ALIGNMENT);
    if (count != 0U) {
      std::memcpy(upload.cpu, mRayInstanceDescs.data(), static_cast<std::size_t>(count) * sizeof(D3D12_RAYTRACING_INSTANCE_DESC));
    }
    D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC build{};
    build.Inputs.Type = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_TYPE_TOP_LEVEL;
    build.Inputs.Flags = D3D12_RAYTRACING_ACCELERATION_STRUCTURE_BUILD_FLAG_PREFER_FAST_BUILD;
    build.Inputs.NumDescs = count;
    build.Inputs.DescsLayout = D3D12_ELEMENTS_LAYOUT_ARRAY;
    build.Inputs.InstanceDescs = upload.gpu;
    D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO prebuild{};
    mDevice5->GetRaytracingAccelerationStructurePrebuildInfo(&build.Inputs, &prebuild);
    const std::uint64_t needed = AlignUp(std::max<std::uint64_t>(prebuild.ResultDataMaxSizeInBytes, 256U), 256U);
    // Scratch first: a failure after the old scene was retired would leave a freed address bound.
    if (!EnsureRayScratch(prebuild.ScratchDataSizeInBytes)) {
      return false;
    }
    if (mTlas.resource == nullptr || mTlasBytes < needed) {
      // The new buffer first: when it can't be made, the old scene stays bound (the lookups don't trace it).
      const std::uint64_t bytes = AlignUp(needed + (needed / 2U), 65536U);
      ComPtr<ID3D12Resource> grown = CreateRayBuffer(mDevice.Get(), bytes, D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE, L"ray scene");
      if (grown == nullptr) {
        return false;
      }
      if (mTlas.resource != nullptr) {
        Retire(mTlas.resource);
      }
      mTlas.resource = std::move(grown);
      mTlas.state = D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE;
      mTlasBytes = bytes;
    }
    build.DestAccelerationStructureData = mTlas.resource->GetGPUVirtualAddress();
    build.ScratchAccelerationStructureData = mRayScratch.resource->GetGPUVirtualAddress();
    // Earlier draws in this list read the scene being replaced, and the scratch buffer may still be in use.
    RayBuildBarrier(mTlas.resource.Get());
    RayBuildBarrier(mRayScratch.resource.Get());
    FlushBarriers();
    MarkDraw("ray scene build");
    mList4->BuildRaytracingAccelerationStructure(&build, 0U, nullptr);
    FinishDraw();
    RayBuildBarrier(mTlas.resource.Get());
    FlushBarriers();
    mTlasAddress = mTlas.resource->GetGPUVirtualAddress();
    mRayInstanceCount = count;
    return true;
  }
} // namespace gpg::gal
