// Engine addition, not in the shipped binary (see PipelineCacheD3D12.h).

#include "gpg/gal/backends/d3d12/PipelineCacheD3D12.h"

#include <Windows.h>

#include <cstdio>
#include <cwchar>
#include <iterator>
#include <memory>
#include <thread>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/PipelineDiskCache.h"

namespace gpg::gal
{
  bool gPipelineDiskCache = true;
} // namespace gpg::gal

namespace gpg::gal::d3d12
{
  namespace
  {
    constexpr const char* kFileName = "pipelines-d3d12.bin";

    [[nodiscard]] bool StartupFlagDisables()
    {
      const wchar_t* const commandLine = ::GetCommandLineW();
      return commandLine != nullptr && std::wcsstr(commandLine, L"/nopipelinecache") != nullptr;
    }

    [[nodiscard]] std::vector<std::uint8_t> ReadFileBytes(const std::string& path)
    {
      std::vector<std::uint8_t> bytes;
      HANDLE const file = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return bytes;
      }
      LARGE_INTEGER size{};
      if (::GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (512LL << 20)) {
        bytes.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0U;
        if (!::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()) {
          bytes.clear();
        }
      }
      ::CloseHandle(file);
      return bytes;
    }

    /** Writes through a temporary file, so a crash mid-write leaves the old file. */
    void WriteFileBytes(const std::string& path, const std::vector<std::uint8_t>& bytes)
    {
      char suffix[32]{};
      std::snprintf(suffix, sizeof(suffix), ".%lu.tmp", static_cast<unsigned long>(::GetCurrentThreadId()));
      const std::string temporary = path + suffix;
      HANDLE const file = ::CreateFileA(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      DWORD written = 0U;
      const bool ok = ::WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
      ::CloseHandle(file);
      if (!ok || !::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ::DeleteFileA(temporary.c_str());
      }
    }

    void PipelineName(const std::uint64_t key, wchar_t (&name)[20])
    {
      std::swprintf(name, std::size(name), L"%016llx", static_cast<unsigned long long>(key));
    }
  } // namespace

  void PipelineCache::Open(ID3D12Device* const device, const std::string& directory)
  {
    Close();
    if (!gPipelineDiskCache || StartupFlagDisables()) {
      gPipelineDiskCache = false;
      gpg::Logf("D3D12: pipeline cache off");
      return;
    }
    if (device == nullptr || directory.empty()) {
      return;
    }
    Microsoft::WRL::ComPtr<ID3D12Device1> device1;
    if (FAILED(device->QueryInterface(IID_PPV_ARGS(&device1)))) {
      gpg::Logf("D3D12: pipeline cache unavailable (no ID3D12Device1)");
      return;
    }

    mPath = directory + kFileName;
    mBlob = ReadFileBytes(mPath);
    HRESULT result = E_FAIL;
    if (!mBlob.empty()) {
      result = device1->CreatePipelineLibrary(mBlob.data(), mBlob.size(), IID_PPV_ARGS(&mLibrary));
      if (FAILED(result)) {
        // Another driver or adapter (D3D12_ERROR_DRIVER_VERSION_MISMATCH, ..._ADAPTER_NOT_FOUND)
        // or a damaged file: start over.
        gpg::Logf("D3D12: pipeline cache %s not usable (HRESULT 0x%08lX); starting empty", mPath.c_str(),
          static_cast<unsigned long>(result));
        mBlob.clear();
      }
    }
    if (mLibrary == nullptr) {
      result = device1->CreatePipelineLibrary(nullptr, 0U, IID_PPV_ARGS(&mLibrary));
      if (FAILED(result)) {
        gpg::Logf("D3D12: pipeline cache unavailable (HRESULT 0x%08lX)", static_cast<unsigned long>(result));
        mLibrary.Reset();
        return;
      }
    }
    gpg::Logf("D3D12: pipeline cache %s (%zu KB)", mPath.c_str(), mBlob.size() / 1024U);
  }

  void PipelineCache::Close() noexcept
  {
    if (mLibrary != nullptr) {
      try {
        if (mUnsaved != 0U) {
          Save(false); // the process may exit right after; write before returning
        }
        gpg::Logf("D3D12: pipeline cache: %u loaded, %u new", mLoaded, mStored);
      } catch (...) {
      }
    }
    mLibrary.Reset();
    mBlob.clear();
    mLoaded = 0U;
    mStored = 0U;
    mUnsaved = 0U;
  }

  Microsoft::WRL::ComPtr<ID3D12PipelineState>
  PipelineCache::Load(const std::uint64_t key, const D3D12_GRAPHICS_PIPELINE_STATE_DESC& desc)
  {
    Microsoft::WRL::ComPtr<ID3D12PipelineState> pipeline;
    if (mLibrary == nullptr || !gPipelineDiskCache) {
      return pipeline;
    }
    wchar_t name[20]{};
    PipelineName(key, name);
    // E_INVALIDARG: not stored, or stored with a different description.
    if (SUCCEEDED(mLibrary->LoadGraphicsPipeline(name, &desc, IID_PPV_ARGS(&pipeline)))) {
      ++mLoaded;
    } else {
      pipeline.Reset();
    }
    return pipeline;
  }

  void PipelineCache::Store(const std::uint64_t key, ID3D12PipelineState* const pipeline)
  {
    if (mLibrary == nullptr || !gPipelineDiskCache || pipeline == nullptr) {
      return;
    }
    wchar_t name[20]{};
    PipelineName(key, name);
    // Fails for a name already taken (a key hash collision); that pipeline is just not kept.
    if (SUCCEEDED(mLibrary->StorePipeline(name, pipeline))) {
      ++mStored;
      mLastStoreTick = ::GetTickCount64();
      if (++mUnsaved >= kSaveEvery) {
        Save(true);
      }
    }
  }

  void PipelineCache::OnFrame()
  {
    if (mUnsaved != 0U && mLibrary != nullptr && ::GetTickCount64() - mLastStoreTick >= kQuietSeconds * 1000U) {
      Save(true);
    }
  }

  void PipelineCache::Save(const bool inBackground)
  {
    mUnsaved = 0U;
    const SIZE_T size = mLibrary->GetSerializedSize();
    if (size == 0U || mPath.empty()) {
      return;
    }
    auto bytes = std::make_shared<std::vector<std::uint8_t>>(size);
    if (FAILED(mLibrary->Serialize(bytes->data(), size))) {
      return;
    }
    if (inBackground) {
      std::thread([path = mPath, bytes] { WriteFileBytes(path, *bytes); }).detach();
    } else {
      WriteFileBytes(mPath, *bytes);
    }
  }
} // namespace gpg::gal::d3d12
