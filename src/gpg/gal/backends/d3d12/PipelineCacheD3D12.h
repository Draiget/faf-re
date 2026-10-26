#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <d3d12.h>
#include <wrl/client.h>

namespace gpg::gal::d3d12
{
  /**
   * Engine addition (see gpg/gal/PipelineDiskCache.h): an ID3D12PipelineLibrary backed by
   * one file in the shader cache directory. `Load` returns a pipeline stored by an earlier
   * session (the library checks that the description matches), `Store` adds one created in
   * this session. New pipelines are written out once `kQuietSeconds` pass without another
   * (`OnFrame`, once a frame), every `kSaveEvery` stores, and on `Close`, so a session that
   * ends without a clean shutdown keeps what it compiled; the library is serialised on the
   * calling thread and the file written on a background thread. A file from another driver
   * or adapter is dropped and the library starts empty.
   */
  class PipelineCache
  {
  public:
    void Open(ID3D12Device* device, const std::string& directory);
    void Close() noexcept;

    [[nodiscard]] bool IsOpen() const noexcept { return mLibrary != nullptr; }

    /** A stored pipeline for `key` whose description is `desc`, or null. */
    [[nodiscard]] Microsoft::WRL::ComPtr<ID3D12PipelineState>
    Load(std::uint64_t key, const D3D12_GRAPHICS_PIPELINE_STATE_DESC& desc);

    void Store(std::uint64_t key, ID3D12PipelineState* pipeline);

    /** Once a frame: writes the unsaved pipelines once none was added for `kQuietSeconds`. */
    void OnFrame();

  private:
    static constexpr std::uint32_t kSaveEvery = 64;
    static constexpr std::uint64_t kQuietSeconds = 5;

    void Save(bool inBackground);

    Microsoft::WRL::ComPtr<ID3D12PipelineLibrary> mLibrary;
    std::vector<std::uint8_t> mBlob; // the loaded library's backing store; must outlive mLibrary
    std::string mPath;
    std::uint32_t mLoaded = 0;
    std::uint32_t mStored = 0;
    std::uint32_t mUnsaved = 0;
    std::uint64_t mLastStoreTick = 0; // GetTickCount64 of the last Store
  };
} // namespace gpg::gal::d3d12
