// Engine addition, not in the shipped binary (see PipelineCacheD3D12.h).

#include "gpg/gal/backends/d3d12/PipelineCacheD3D12.h"

#include <Windows.h>

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <iterator>
#include <memory>
#include <mutex>
#include <thread>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/PipelineDiskCache.h"

namespace gpg::gal::d3d12
{
  namespace
  {
    constexpr const char* kFileName = "pipelines-d3d12.bin";

    /**
     * The file writes run on detached threads (and the last one on the thread that closes the cache): each save
     * numbers its snapshot, and a write whose snapshot is older than the one already on disk is dropped, so a slow
     * writer can't put an older library over a newer one.
     */
    std::mutex gWriteMutex;
    std::uint64_t gWrittenSnapshot = 0U; // under gWriteMutex
    std::atomic<std::uint64_t> gNextSnapshot{0U};

    [[nodiscard]] bool StartupFlagDisables()
    {
      const wchar_t* const commandLine = ::GetCommandLineW();
      return commandLine != nullptr && std::wcsstr(commandLine, L"/nopipelinecache") != nullptr;
    }

    [[nodiscard]] std::vector<std::uint8_t> ReadFileBytes(
      const std::string& path
    )
    {
      std::vector<std::uint8_t> bytes;
      // FILE_SHARE_DELETE: another game process can replace the file (its MoveFileEx) while this one reads it.
      HANDLE const file = ::CreateFileA(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0U, nullptr
      );
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
    void WriteFileBytes(
      const std::string& path,
      const std::vector<std::uint8_t>& bytes,
      const std::uint64_t snapshot
    ) noexcept
    {
      const std::lock_guard<std::mutex> lock(gWriteMutex);
      if (snapshot <= gWrittenSnapshot) {
        return; // a newer library is on disk already
      }
      gWrittenSnapshot = snapshot;
      // No allocation here: this runs on a detached thread, where an exception would end the process.
      char temporary[MAX_PATH + 32]{};
      const int length = std::snprintf(
        temporary, sizeof(temporary), "%s.%lu.tmp", path.c_str(), static_cast<unsigned long>(::GetCurrentThreadId())
      );
      if (length <= 0 || static_cast<std::size_t>(length) >= sizeof(temporary)) {
        return;
      }
      HANDLE const file = ::CreateFileA(temporary, GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      DWORD written = 0U;
      const bool ok =
        ::WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
      ::CloseHandle(file);
      if (!ok || !::MoveFileExA(temporary, path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ::DeleteFileA(temporary);
      }
    }

    /**
     * Temporary files a process left when it ended mid-write (`<file>.<thread id>.tmp`). Only ones untouched for ten
     * minutes: another game process may be writing its own right now.
     */
    void RemoveStaleTemporaries(
      const std::string& path
    )
    {
      const std::string folder = path.substr(0U, path.find_last_of("\\/") + 1U);
      WIN32_FIND_DATAA found{};
      HANDLE const search = ::FindFirstFileA((path + ".*.tmp").c_str(), &found);
      if (search == INVALID_HANDLE_VALUE) {
        return;
      }
      FILETIME now{};
      ::GetSystemTimeAsFileTime(&now);
      const auto ticks = [](const FILETIME& time) {
        return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32U) | time.dwLowDateTime;
      };
      constexpr std::uint64_t kTenMinutes = 10ULL * 60ULL * 10000000ULL; // in 100 ns units
      do {
        if (ticks(now) - ticks(found.ftLastWriteTime) > kTenMinutes) {
          (void)::DeleteFileA((folder + found.cFileName).c_str());
        }
      } while (::FindNextFileA(search, &found));
      ::FindClose(search);
    }

    void PipelineName(
      const std::uint64_t key,
      wchar_t (&name)[20]
    )
    {
      std::swprintf(name, std::size(name), L"%016llx", static_cast<unsigned long long>(key));
    }
  } // namespace

  void PipelineCache::Open(
    ID3D12Device* const device,
    const std::string& directory
  )
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
    RemoveStaleTemporaries(mPath);
    mBlob = ReadFileBytes(mPath);
    HRESULT result = E_FAIL;
    if (!mBlob.empty()) {
      result = device1->CreatePipelineLibrary(mBlob.data(), mBlob.size(), IID_PPV_ARGS(&mLibrary));
      if (FAILED(result)) {
        // Another driver or adapter (D3D12_ERROR_DRIVER_VERSION_MISMATCH, ..._ADAPTER_NOT_FOUND)
        // or a damaged file: start over.
        gpg::Logf(
          "D3D12: pipeline cache %s not usable (HRESULT 0x%08lX); starting empty",
          mPath.c_str(),
          static_cast<unsigned long>(result)
        );
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
    const std::lock_guard<std::mutex> lock(mMutex);
    if (mLibrary != nullptr) {
      try {
        if (mUnsaved != 0U) {
          mUnsaved = 0U;
          Save(false); // the process may exit right after; write before returning
        }
        gpg::Logf("D3D12: pipeline cache: %u loaded, %u new", mLoaded, mStored);
      } catch (...) {}
    }
    mLibrary.Reset();
    mBlob.clear();
    mLoaded = 0U;
    mStored = 0U;
    mUnsaved = 0U;
  }

  Microsoft::WRL::ComPtr<ID3D12PipelineState> PipelineCache::Load(
    const std::uint64_t key,
    const D3D12_GRAPHICS_PIPELINE_STATE_DESC& desc
  )
  {
    Microsoft::WRL::ComPtr<ID3D12PipelineState> pipeline;
    // The library synchronizes itself (except two threads loading the same pipeline, which the device's pending
    // list rules out): the driver's load runs unlocked, so a slow one on a worker never holds the render thread.
    if (mLibrary == nullptr || !gPipelineDiskCache) {
      return pipeline;
    }
    wchar_t name[20]{};
    PipelineName(key, name);
    // E_INVALIDARG: not stored, or stored with a different description.
    if (SUCCEEDED(mLibrary->LoadGraphicsPipeline(name, &desc, IID_PPV_ARGS(&pipeline)))) {
      const std::lock_guard<std::mutex> lock(mMutex);
      ++mLoaded;
    } else {
      pipeline.Reset();
    }
    return pipeline;
  }

  void PipelineCache::Store(
    const std::uint64_t key,
    ID3D12PipelineState* const pipeline
  )
  {
    if (mLibrary == nullptr || !gPipelineDiskCache || pipeline == nullptr) {
      return;
    }
    wchar_t name[20]{};
    PipelineName(key, name);
    // Fails for a name already taken (a key hash collision); that pipeline is just not kept.
    if (SUCCEEDED(mLibrary->StorePipeline(name, pipeline))) {
      bool save = false;
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        ++mStored;
        mLastStoreTick = ::GetTickCount64();
        if (++mUnsaved >= kSaveEvery && !mSaving) {
          mSaving = true;
          mUnsaved = 0U;
          save = true;
        }
      }
      // Serialized outside the lock: a render-thread Load or Store never waits for a save.
      if (save) {
        Save(true);
        mSaving = false;
      }
    }
  }

  void PipelineCache::OnFrame()
  {
    // A worker saving holds the lock: this frame doesn't wait for it.
    std::unique_lock<std::mutex> lock(mMutex, std::try_to_lock);
    if (!lock.owns_lock()) {
      return;
    }
    if (
      mUnsaved == 0U || mLibrary == nullptr || mSaving || ::GetTickCount64() - mLastStoreTick < kQuietSeconds * 1000U
    ) {
      return;
    }
    mSaving = true;
    mUnsaved = 0U;
    lock.unlock();
    Save(true);
    mSaving = false;
  }

  void PipelineCache::Save(
    const bool inBackground
  ) noexcept
  {
    // Runs on pipeline workers too (Store): out of memory or no thread for the write skips this save, and the next
    // store or quiet frame saves again, rather than the exception reaching the draw that takes the worker's pipeline.
    try {
      // The library is free-threaded: a worker can store a pipeline between the size and the copy, and Serialize
      // then refuses the smaller buffer. Measure again.
      for (int attempt = 0; attempt < 3; ++attempt) {
        const SIZE_T size = mLibrary->GetSerializedSize();
        if (size == 0U || mPath.empty()) {
          return;
        }
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(size);
        if (FAILED(mLibrary->Serialize(bytes->data(), size))) {
          continue;
        }
        const std::uint64_t snapshot = ++gNextSnapshot;
        if (inBackground) {
          std::thread([path = mPath, bytes, snapshot] {
            WriteFileBytes(path, *bytes, snapshot);
          }).detach();
        } else {
          WriteFileBytes(mPath, *bytes, snapshot);
        }
        return;
      }
    } catch (...) {}
  }
} // namespace gpg::gal::d3d12
