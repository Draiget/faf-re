// Engine addition, not in the shipped binary (see RenderInfo.h).

#include "moho/render/RenderInfo.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <fstream>

#include <Windows.h>
#include <psapi.h>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/RenderProfiler.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/StartupHelpers.h"

#pragma comment(lib, "psapi.lib")

namespace moho
{
  namespace
  {
    void AppendLine(std::string& text, const char* const format, ...)
    {
      char line[512] = {};
      va_list args;
      va_start(args, format);
      std::vsnprintf(line, sizeof(line), format, args);
      va_end(args);
      text += line;
      text += '\n';
    }

    [[nodiscard]] double Megabytes(const std::uint64_t bytes) noexcept
    {
      return static_cast<double>(bytes) / (1024.0 * 1024.0);
    }

    [[nodiscard]] std::string GpuDrivenFeatureNames(const std::uint32_t features)
    {
      std::string names;
      const auto add = [&](const std::uint32_t bit, const char* const name) {
        if ((features & bit) != 0U) {
          names += names.empty() ? "" : ", ";
          names += name;
        }
      };
      add(gpg::gal::kGpuFeatureVertexPulling, "vertex pulling");
      add(gpg::gal::kGpuFeatureCompute, "compute");
      add(gpg::gal::kGpuFeatureIndirectDraw, "indirect draws");
      add(gpg::gal::kGpuFeatureTimestamps, "GPU timestamps");
      return names.empty() ? std::string("none") : names;
    }

    /** Files and bytes directly in `directory`. */
    void MeasureDirectory(const std::string& directory, std::uint32_t& files, std::uint64_t& bytes)
    {
      files = 0U;
      bytes = 0U;
      WIN32_FIND_DATAA entry{};
      const HANDLE search = ::FindFirstFileA((directory + "\\*").c_str(), &entry);
      if (search == INVALID_HANDLE_VALUE) {
        return;
      }
      do {
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) {
          ++files;
          bytes += (static_cast<std::uint64_t>(entry.nFileSizeHigh) << 32U) | entry.nFileSizeLow;
        }
      } while (::FindNextFileA(search, &entry) != FALSE);
      ::FindClose(search);
    }

    /** Prints `text` to the console and the log, one line at a time. */
    void PrintRuntimeInfo(const std::string& text)
    {
      std::size_t begin = 0U;
      while (begin < text.size()) {
        std::size_t end = text.find('\n', begin);
        if (end == std::string::npos) {
          end = text.size();
        }
        const std::string line = text.substr(begin, end - begin);
        CON_Printf("%s", line.c_str());
        gpg::Logf("%s", line.c_str());
        begin = end + 1U;
      }
    }

    void RenInfo(const msvc8::vector<msvc8::string>&)
    {
      PrintRuntimeInfo(REN_FormatRuntimeInfo());
    }

    void RenInfoDump(const msvc8::vector<msvc8::string>& args)
    {
      if (args.size() < 2U) {
        CON_Printf("syntax: ren_InfoDump <file>");
        return;
      }
      const std::string path = args[1].c_str();
      std::ofstream file(path, std::ios::out | std::ios::trunc);
      if (!file) {
        CON_Printf("ren_InfoDump: cannot write %s", path.c_str());
        return;
      }
      file << REN_FormatRuntimeInfo();
      CON_Printf("ren_InfoDump: wrote %s", path.c_str());
    }

    CConFunc gCConFunc_ren_Info(
      "ren_Info",
      "Print the render backend, GPU, video memory, swap chain, last-frame statistics and memory use.",
      &RenInfo
    );
    CConFunc gCConFunc_ren_InfoDump("ren_InfoDump", "Write the ren_Info block to a file: ren_InfoDump <file>.", &RenInfoDump);
  } // namespace

  std::string REN_FormatRuntimeInfo()
  {
    std::string text;
    AppendLine(text, "ren_Info:");

    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    gpg::gal::DeviceRuntimeInfo info{};
    if (device == nullptr || !device->GetRuntimeInfo(info)) {
      AppendLine(text, "  backend: %s", device == nullptr ? "none" : "(no runtime information)");
    } else {
      AppendLine(text, "  backend: %s, feature level %s", info.api.c_str(), info.featureLevel.c_str());
      AppendLine(
        text, "  adapter: %s (vendor 0x%04X, device 0x%04X), driver %s", info.adapter.c_str(), info.vendorId, info.deviceId,
        info.driverVersion.empty() ? "unknown" : info.driverVersion.c_str()
      );
      AppendLine(
        text, "  video memory: %.0f MB dedicated, %.0f MB shared", Megabytes(info.dedicatedVideoMemory),
        Megabytes(info.sharedSystemMemory)
      );
      if (info.localBudget != 0U || info.nonLocalBudget != 0U) {
        AppendLine(
          text, "  budget: local %.0f / %.0f MB used, non-local %.0f / %.0f MB used", Megabytes(info.localUsage),
          Megabytes(info.localBudget), Megabytes(info.nonLocalUsage), Megabytes(info.nonLocalBudget)
        );
      }
      if (info.availableTextureMemory != 0U) {
        AppendLine(text, "  available texture memory: %.0f MB", Megabytes(info.availableTextureMemory));
      }
      AppendLine(text, "  swap chain: %s", info.swapChain.empty() ? "unknown" : info.swapChain.c_str());
      AppendLine(text, "  vsync: %s", info.vsync ? "on" : "off");
      AppendLine(text, "  GPU-driven features: %s", GpuDrivenFeatureNames(info.gpuDrivenFeatures).c_str());
    }

    const gpg::gal::RenderProfiler::Summary& summary = gpg::gal::RenderProfiler::Get().GetSummary();
    if (summary.frames != 0U) {
      AppendLine(
        text, "  last frame: %.2f ms, %u draws, %u state changes, %.1f KB uploaded", summary.lastFrameWallMilliseconds,
        summary.lastFrame.drawCalls, summary.lastFrame.stateChanges,
        static_cast<double>(summary.lastFrame.uploadBytes) / 1024.0
      );
    }
    if (summary.intervalFrames != 0U) {
      AppendLine(
        text, "  render profile (last %u frames): CPU %.2f ms, GPU %.2f ms per frame", summary.intervalFrames,
        summary.intervalCpuMilliseconds, summary.intervalGpuMilliseconds
      );
    } else {
      AppendLine(text, "  render profile: off (set FAF_GPU_PROFILE=<frames> for render CPU and GPU times)");
    }

    PROCESS_MEMORY_COUNTERS_EX process{};
    process.cb = sizeof(process);
    if (::GetProcessMemoryInfo(::GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&process), sizeof(process))) {
      AppendLine(
        text, "  process: %.0f MB private, %.0f MB working set (peak %.0f MB)", Megabytes(process.PrivateUsage),
        Megabytes(process.WorkingSetSize), Megabytes(process.PeakWorkingSetSize)
      );
    }
    gpg::HeapStats heap{};
    gpg::GetHeapInfo(&heap);
    AppendLine(
      text, "  engine heap: %.0f MB in use, %.0f MB committed, %.0f MB reserved", Megabytes(heap.inUse),
      Megabytes(heap.committed), Megabytes(heap.reserved)
    );

    const msvc8::string cacheDirectory = USER_GetAppCacheDir();
    std::uint32_t cacheFiles = 0U;
    std::uint64_t cacheBytes = 0U;
    MeasureDirectory(cacheDirectory.c_str(), cacheFiles, cacheBytes);
    AppendLine(
      text, "  shader cache: %s (%u files, %.1f MB)", cacheDirectory.c_str(), cacheFiles, Megabytes(cacheBytes)
    );
    return text;
  }

  void REN_LogRuntimeInfoOnce()
  {
    static bool sLogged = false;
    if (sLogged) {
      return;
    }
    sLogged = true;
    const std::string text = REN_FormatRuntimeInfo();
    std::size_t begin = 0U;
    while (begin < text.size()) {
      std::size_t end = text.find('\n', begin);
      if (end == std::string::npos) {
        end = text.size();
      }
      gpg::Logf("%s", text.substr(begin, end - begin).c_str());
      begin = end + 1U;
    }
  }
} // namespace moho
