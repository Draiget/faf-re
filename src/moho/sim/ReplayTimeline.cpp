#include "moho/sim/ReplayTimeline.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>

#include <Windows.h>
#include <zstd.h>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/ISaveRequest.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/WldSessionInfo.h"

namespace moho
{
  namespace
  {
    int replay_KeyframeEvery = 300;
    TConVar<int> gTConVar_replay_KeyframeEvery(
      "replay_KeyframeEvery",
      "Ticks of a replay between the keyframes the viewer keeps to move back to (300: 30 seconds of game time), more when saves get slow. 0: none, "
      "and moving back starts from the replay's beginning.",
      &replay_KeyframeEvery
    );

    int replay_KeyframeMaxMB = 2048;
    TConVar<int> gTConVar_replay_KeyframeMaxMB(
      "replay_KeyframeMaxMB",
      "Disk space a replay's keyframes may take, compressed, in replay_keyframes next to the exe. Past it, every second "
      "one of the older half goes, oldest first.",
      &replay_KeyframeMaxMB
    );

    bool replay_PrepareKeyframes = true;
    TConVar<bool> gTConVar_replay_PrepareKeyframes(
      "replay_PrepareKeyframes",
      "A hidden copy of this exe, below normal priority, writes a replay's keyframes ahead of the viewer. Read when a "
      "replay opens; turning it off also stops one that is running.",
      &replay_PrepareKeyframes
    );

    bool replay_KeyframeQuietDisk = true;
    TConVar<bool> gTConVar_replay_KeyframeQuietDisk(
      "replay_KeyframeQuietDisk",
      "The hidden process stays below normal priority and compresses keyframes as it saves them; the viewer's are marked temporary, so they stay in the "
      "system's file cache until compressed; their file work runs on a background thread; and the viewer's sim doesn't "
      "stop to save while the hidden process runs. Read for the hidden process when a replay opens.",
      &replay_KeyframeQuietDisk
    );

    // Moves shorter than this say too little about the speed.
    constexpr std::int32_t kMinTicksToMeasure = 50;
    // A longer way than this from a keyframe plays forward in view: holding it would take too much memory.
    constexpr std::size_t kMaxHeldBeats = 3000;
    // Beats that can't come for this long mean the replay has ended before its target.
    constexpr double kFastForwardStallSeconds = 10.0;
    // A save stops the sim, so the next keyframe waits this many ticks per second the last save took:
    // at normal speed, saving takes at most 5% of the time however big the game gets.
    constexpr double kKeyframeTicksPerSaveSecond = 200.0;
    // The first keyframe comes this early: loading it is quicker than starting the replay over, and thinning keeps it.
    constexpr std::int32_t kFirstKeyframeTick = 20;
    // Keyframes this close are the same place as far as a move is concerned.
    constexpr std::int32_t kKeyframeSameSpotTicks = 60;
    // However small the budget, these stay.
    constexpr std::size_t kMinKeyframes = 4;

    using Clock = std::chrono::steady_clock;

    std::string sReplayPath;
    std::int32_t sTotalBeats = 0;

    struct SKeyframeFile
    {
      std::string path;
      std::uint64_t bytes = 0;
    };
    std::map<std::int32_t, SKeyframeFile> sKeyframes;
    std::uint64_t sKeyframeBytes = 0;
    std::int32_t sLastKeyframeTick = 0;
    bool sKeyframePending = false;
    double sLastSaveSeconds = 0.0;

    std::int32_t sTargetTick = -1;
    std::int32_t sStartTick = 0;
    std::int32_t sHeldTick = -1; // of the new sim's last beat being held

    // What a move costs on this machine: first guesses, then what the last moves took.
    double sLoadSeconds = 5.0;
    double sTicksPerSecond = 100.0;
    Clock::time_point sRestartAsked{};
    Clock::time_point sRunStart{};
    std::int32_t sRunStartTick = 0;

    void NoteRunEnd(const std::int32_t tick)
    {
      const double seconds = std::chrono::duration<double>(Clock::now() - sRunStart).count();
      if (tick - sRunStartTick >= kMinTicksToMeasure && seconds > 0.0) {
        sTicksPerSecond = static_cast<double>(tick - sRunStartTick) / seconds;
      }
    }
    bool sFastForwarding = false;
    Clock::time_point sLastProgress{};
    std::int32_t sLastProgressTick = 0;

    bool sLaunchPending = false;
    bool sRestartWanted = false;
    bool sRestarting = false;
    boost::shared_ptr<std::FILE> sRestoreFile;
    SSimKeyframeHeader sRestoreHeader{};
    // Keyframes hold the flattened rects only, so each new sim starts from the map as it loaded.
    std::unique_ptr<STIMap> sStartMap;

    std::int32_t sDeferredTarget = -1;

    Clock::time_point sSeekAsked{};
    bool sSeekTimed = false;
    std::int32_t sSeekFrom = 0;

    void StartSeekClock(const std::int32_t from)
    {
      sSeekAsked = Clock::now();
      sSeekTimed = true;
      sSeekFrom = from;
    }

    void LogSeekArrival(const std::int32_t tick)
    {
      if (sSeekTimed) {
        sSeekTimed = false;
        gpg::Logf(
          "Replay timeline: from tick %d to %d in %.1f s", sSeekFrom, tick,
          std::chrono::duration<double>(Clock::now() - sSeekAsked).count()
        );
      }
    }

    /** `replay_keyframes` next to the exe, or in the temporary folder when the exe's folder can't be written. */
    [[nodiscard]] const std::filesystem::path& KeyframeRoot()
    {
      static const std::filesystem::path root = [] {
        wchar_t exePath[MAX_PATH] = {};
        std::error_code ignored;
        if (::GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
          std::filesystem::path beside = std::filesystem::path(exePath).parent_path() / "replay_keyframes";
          std::filesystem::create_directories(beside, ignored);
          const std::filesystem::path probe = beside / "probe.tmp";
          std::FILE* file = nullptr;
          if (fopen_s(&file, probe.string().c_str(), "wb") == 0 && file != nullptr) {
            std::fclose(file);
            std::filesystem::remove(probe, ignored);
            return beside;
          }
        }
        return std::filesystem::temp_directory_path(ignored) / "faf_replay_keyframes";
      }();
      return root;
    }

    /** Each running game has its own folder, by process id. */
    [[nodiscard]] std::filesystem::path KeyframeDirectory()
    {
      std::error_code ignored;
      std::filesystem::path directory = KeyframeRoot() / std::to_string(static_cast<unsigned long>(::GetCurrentProcessId()));
      std::filesystem::create_directories(directory, ignored);
      return directory;
    }

    /** What earlier games left: this one's last replay, and any game that didn't get to clean up. */
    void RemoveLeftoverKeyframes()
    {
      const unsigned long self = ::GetCurrentProcessId();
      std::error_code ignored;
      std::vector<std::filesystem::path> leftovers;
      for (const auto& entry : std::filesystem::directory_iterator(KeyframeRoot(), ignored)) {
        const unsigned long owner = std::strtoul(entry.path().filename().string().c_str(), nullptr, 10);
        bool running = false;
        if (owner != 0u && owner != self) {
          if (HANDLE process = ::OpenProcess(SYNCHRONIZE, FALSE, owner); process != nullptr) {
            running = ::WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
            ::CloseHandle(process);
          }
        }
        if (!running) {
          leftovers.push_back(entry.path());
        }
      }
      for (const std::filesystem::path& leftover : leftovers) {
        std::filesystem::remove_all(leftover, ignored);
      }
    }

    void RemoveFile(const std::string& path)
    {
      std::error_code ignored;
      std::filesystem::remove(path, ignored);
    }

    /** Copies `input` through zstd into `output`. False on any failure, or when `stop` is set. */
    [[nodiscard]] bool CompressStream(std::FILE* const input, std::FILE* const output, const std::atomic<bool>& stop)
    {
      std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx*)> context(ZSTD_createCCtx(), &ZSTD_freeCCtx);
      if (!context) {
        return false;
      }
      (void)ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, kSimKeyframeZstdLevel);
      std::vector<char> inBuffer(ZSTD_CStreamInSize());
      std::vector<char> outBuffer(ZSTD_CStreamOutSize());
      bool ended = false;
      while (!ended) {
        if (stop.load()) {
          return false;
        }
        const std::size_t readBytes = std::fread(inBuffer.data(), 1u, inBuffer.size(), input);
        const ZSTD_EndDirective mode = readBytes < inBuffer.size() ? ZSTD_e_end : ZSTD_e_continue;
        ZSTD_inBuffer in{inBuffer.data(), readBytes, 0u};
        bool finished = false;
        while (!finished) {
          ZSTD_outBuffer out{outBuffer.data(), outBuffer.size(), 0u};
          const std::size_t remaining = ZSTD_compressStream2(context.get(), &out, &in, mode);
          if (ZSTD_isError(remaining) || std::fwrite(outBuffer.data(), 1u, out.pos, output) != out.pos) {
            return false;
          }
          finished = mode == ZSTD_e_end ? remaining == 0u : in.pos == in.size;
        }
        ended = mode == ZSTD_e_end;
      }
      return std::ferror(input) == 0;
    }

    [[nodiscard]] bool DecompressStream(std::FILE* const input, std::FILE* const output)
    {
      std::unique_ptr<ZSTD_DCtx, size_t (*)(ZSTD_DCtx*)> context(ZSTD_createDCtx(), &ZSTD_freeDCtx);
      if (!context) {
        return false;
      }
      std::vector<char> inBuffer(ZSTD_DStreamInSize());
      std::vector<char> outBuffer(ZSTD_DStreamOutSize());
      std::size_t readBytes = 0u;
      while ((readBytes = std::fread(inBuffer.data(), 1u, inBuffer.size(), input)) != 0u) {
        ZSTD_inBuffer in{inBuffer.data(), readBytes, 0u};
        while (in.pos < in.size) {
          ZSTD_outBuffer out{outBuffer.data(), outBuffer.size(), 0u};
          const std::size_t result = ZSTD_decompressStream(context.get(), &out, &in);
          if (ZSTD_isError(result) || std::fwrite(outBuffer.data(), 1u, out.pos, output) != out.pos) {
            return false;
          }
        }
      }
      return std::ferror(input) == 0;
    }

    /**
     * One background thread compresses finished keyframes, so nothing waits for it. Until its result
     * is taken, on the main thread, a keyframe stays the plain file it was saved as.
     */
    struct SCompressedKeyframe
    {
      std::int32_t tick = 0;
      std::string plainPath;
      std::string path;
      std::uint64_t bytes = 0;
      bool ok = false;
    };
    std::mutex sCompressLock;
    std::condition_variable sCompressWake;
    std::deque<std::pair<std::int32_t, std::string>> sCompressQueue;
    std::vector<SCompressedKeyframe> sCompressDone;
    std::atomic<bool> sCompressStop{false};
    std::thread* sCompressThread = nullptr;

    /** A keyframe the hidden process finished, moved up by the background thread. An empty path: one here already. */
    struct SPreparedKeyframe
    {
      std::int32_t tick = 0;
      std::string path;
      std::uint64_t bytes = 0;
      bool compressed = false;
    };
    std::deque<std::string> sRemoveQueue;
    std::vector<SPreparedKeyframe> sPreparedFound;
    bool sPrepareScanning = false;
    std::filesystem::path sPrepareScanFrom;
    std::filesystem::path sPrepareScanTo;

    void CompressOneKeyframe(const std::int32_t tick, const std::string& plainPath)
    {
      SCompressedKeyframe done;
      done.tick = tick;
      done.plainPath = plainPath;
      done.path = plainPath + ".zst";
      const std::string partPath = done.path + ".part";
      std::FILE* input = nullptr;
      std::FILE* output = nullptr;
      if (fopen_s(&input, plainPath.c_str(), "rb") == 0 && input != nullptr) {
        if (fopen_s(&output, partPath.c_str(), "wb") == 0 && output != nullptr) {
          done.ok = CompressStream(input, output, sCompressStop);
          done.ok = std::fclose(output) == 0 && done.ok;
        }
        std::fclose(input);
      }
      std::error_code failed;
      if (done.ok) {
        done.bytes = std::filesystem::file_size(partPath, failed);
        std::filesystem::rename(partPath, done.path, failed);
        done.ok = !failed;
      }
      if (done.ok) {
        RemoveFile(plainPath);
      } else {
        RemoveFile(partPath);
      }
      const std::lock_guard<std::mutex> lock(sCompressLock);
      sCompressDone.push_back(std::move(done));
    }

    /** On the background thread, once a second: what the hidden process has finished moves up to the keyframes. */
    void ScanPreparedKeyframes(const std::filesystem::path& from, const std::filesystem::path& to)
    {
      std::error_code ignored;
      std::vector<std::filesystem::path> finished;
      for (const auto& entry : std::filesystem::directory_iterator(from, ignored)) {
        if (entry.path().extension() == ".bin") {
          finished.push_back(entry.path());
        } else if (entry.path().extension() == ".zst") {
          // Compressed by the hidden process: keyframe_<tick>.bin.zst, its tick in its name.
          SPreparedKeyframe found;
          found.tick = std::atoi(entry.path().filename().string().c_str() + std::strlen("keyframe_"));
          const std::filesystem::path target = to / entry.path().filename();
          found.bytes = static_cast<std::uint64_t>(std::filesystem::file_size(entry.path(), ignored));
          std::error_code renameFailed;
          std::filesystem::rename(entry.path(), target, renameFailed);
          if (renameFailed) {
            continue; // tried again next time
          }
          found.path = target.string();
          found.compressed = true;
          const std::lock_guard<std::mutex> lock(sCompressLock);
          sPreparedFound.push_back(std::move(found));
        }
      }
      for (const std::filesystem::path& file : finished) {
        SSimKeyframeHeader header{};
        bool readable = false;
        std::FILE* input = nullptr;
        if (fopen_s(&input, file.string().c_str(), "rb") == 0 && input != nullptr) {
          readable = SIM_ReadKeyframeHeader(input, header);
          std::fclose(input);
        }
        if (!readable) {
          std::filesystem::remove(file, ignored);
          continue;
        }
        SPreparedKeyframe found;
        found.tick = static_cast<std::int32_t>(header.tick);
        const std::filesystem::path target = to / ("keyframe_" + std::to_string(found.tick) + ".bin");
        if (std::filesystem::exists(target, ignored)) {
          std::filesystem::remove(file, ignored);
        } else {
          const std::uintmax_t size = std::filesystem::file_size(file, ignored);
          std::error_code renameFailed;
          std::filesystem::rename(file, target, renameFailed);
          if (renameFailed) {
            continue; // tried again next time
          }
          found.path = target.string();
          found.bytes = static_cast<std::uint64_t>(size);
        }
        const std::lock_guard<std::mutex> lock(sCompressLock);
        sPreparedFound.push_back(std::move(found));
      }
    }

    void CompressThreadMain()
    {
      ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
      Clock::time_point nextScan = Clock::now();
      std::unique_lock<std::mutex> lock(sCompressLock);
      while (!sCompressStop.load()) {
        if (!sRemoveQueue.empty()) {
          const std::string path = std::move(sRemoveQueue.front());
          sRemoveQueue.pop_front();
          lock.unlock();
          RemoveFile(path);
          lock.lock();
          continue;
        }
        if (sPrepareScanning && Clock::now() >= nextScan) {
          nextScan = Clock::now() + std::chrono::seconds(1);
          const std::filesystem::path from = sPrepareScanFrom;
          const std::filesystem::path to = sPrepareScanTo;
          lock.unlock();
          ScanPreparedKeyframes(from, to);
          lock.lock();
          continue;
        }
        if (!sCompressQueue.empty()) {
          const auto [tick, plainPath] = sCompressQueue.front();
          sCompressQueue.pop_front();
          lock.unlock();
          CompressOneKeyframe(tick, plainPath);
          lock.lock();
          continue;
        }
        if (sPrepareScanning) {
          sCompressWake.wait_until(lock, nextScan);
        } else {
          sCompressWake.wait(lock);
        }
      }
    }

    /** With `sCompressLock` held. */
    void StartFileThread()
    {
      if (sCompressThread == nullptr) {
        sCompressStop.store(false);
        sCompressThread = new std::thread(&CompressThreadMain);
      }
    }

    void QueueKeyframeCompression(const std::int32_t tick, const std::string& plainPath)
    {
      const std::lock_guard<std::mutex> lock(sCompressLock);
      sCompressQueue.emplace_back(tick, plainPath);
      StartFileThread();
      sCompressWake.notify_one();
    }

    /** A delete can wait for the disk, and the main thread must not. */
    void RemoveFileLater(const std::string& path)
    {
      const std::lock_guard<std::mutex> lock(sCompressLock);
      sRemoveQueue.push_back(path);
      StartFileThread();
      sCompressWake.notify_one();
    }

    void StopKeyframeCompression()
    {
      {
        const std::lock_guard<std::mutex> lock(sCompressLock);
        sCompressStop.store(true);
        sCompressQueue.clear();
        sRemoveQueue.clear();
        sPreparedFound.clear();
        sCompressWake.notify_one();
      }
      if (sCompressThread != nullptr) {
        sCompressThread->join();
        delete sCompressThread;
        sCompressThread = nullptr;
      }
      sCompressDone.clear();
    }

    /**
     * The hidden process that writes keyframes ahead of the viewer. The job ends it with the game, however the
     * game ends. It plays the same recorded beats from the same start, so what it saves is what the viewer's sim
     * would have saved at that beat. It has to be this exe: a save holds factory numbers and code addresses that
     * only hold for the exe that wrote it, and from another one, decals made after the load lose their methods.
     * It has to keep client data: without it, entities have no position history and emitters no curves, and the
     * viewer's sim crashes on the first trail in view after the load.
     */
    HANDLE sPrepareJob = nullptr;
    HANDLE sPrepareProcess = nullptr;
    std::int32_t sPreparedTick = -1;
    bool sPrepareStartDue = false;

    [[nodiscard]] std::filesystem::path PrepareDirectory()
    {
      return KeyframeDirectory() / "prepared";
    }

    void StopKeyframePreparation()
    {
      sPrepareStartDue = false;
      sPreparedTick = -1;
      {
        const std::lock_guard<std::mutex> lock(sCompressLock);
        sPrepareScanning = false;
      }
      if (sPrepareProcess != nullptr) {
        ::TerminateProcess(sPrepareProcess, 0u);
        ::WaitForSingleObject(sPrepareProcess, 3000u);
        ::CloseHandle(sPrepareProcess);
        sPrepareProcess = nullptr;
      }
      if (sPrepareJob != nullptr) {
        ::CloseHandle(sPrepareJob);
        sPrepareJob = nullptr;
      }
    }

    void StartKeyframePreparation()
    {
      sPrepareStartDue = false;
      if (!replay_PrepareKeyframes || replay_KeyframeEvery <= 0) {
        return;
      }
      wchar_t exePath[MAX_PATH] = {};
      fa::vector<fa::string> initArgs;
      if (::GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0 || !CFG_GetArgOption("/init", 1u, &initArgs) || initArgs.empty()) {
        gpg::Logf("Replay timeline: no keyframes prepared ahead: no /init to give the hidden process");
        return;
      }
      const std::filesystem::path self(exePath);
      std::error_code ignored;
      const std::filesystem::path directory = PrepareDirectory();
      std::filesystem::create_directories(directory, ignored);

      char every[32];
      std::snprintf(every, sizeof(every), "%d", replay_KeyframeEvery);
      char first[16];
      std::snprintf(first, sizeof(first), "%d", kFirstKeyframeTick);
      const std::string command = "\"" + self.string() + "\" /replaykeyframes --keep-client-data --label prepare --replay \"" + sReplayPath + "\" /init \""
        + initArgs[0].c_str() + "\" /nobugreport /nosound /log \"" + (directory / "prepare.log").string()
        + "\" --keyframe-every " + every + " --keyframe-first " + first + " --keyframe-dir \"" + directory.string() + "\" --keyframe-prepare"
        + (replay_KeyframeQuietDisk ? " --keyframe-quiet" : "");

      STARTUPINFOA startup{};
      startup.cb = sizeof(startup);
      PROCESS_INFORMATION process{};
      std::string mutableCommand = command;
      const std::string folder = self.parent_path().string();
      if (!::CreateProcessA(
            nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED, nullptr, folder.c_str(), &startup, &process
          )) {
        gpg::Warnf("Replay timeline: no keyframes prepared ahead: can't start %s (%lu)", self.string().c_str(), ::GetLastError());
        return;
      }
      sPrepareJob = ::CreateJobObjectA(nullptr, nullptr);
      if (sPrepareJob != nullptr) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        ::SetInformationJobObject(sPrepareJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
        ::AssignProcessToJobObject(sPrepareJob, process.hProcess);
      }
      ::ResumeThread(process.hThread);
      ::CloseHandle(process.hThread);
      sPrepareProcess = process.hProcess;
      {
        const std::lock_guard<std::mutex> lock(sCompressLock);
        sPrepareScanFrom = directory;
        sPrepareScanTo = KeyframeDirectory();
        sPrepareScanning = true;
        StartFileThread();
        sCompressWake.notify_one();
      }
      gpg::Logf("Replay timeline: preparing keyframes ahead with a hidden %s", self.string().c_str());
    }

    /** Takes in what the background thread has moved up from the hidden process: compressed like our own. */
    [[nodiscard]] bool HaveKeyframeNear(const std::int32_t tick)
    {
      const auto next = sKeyframes.lower_bound(tick - kKeyframeSameSpotTicks);
      return next != sKeyframes.end() && next->first <= tick + kKeyframeSameSpotTicks;
    }

    void TakePreparedKeyframes()
    {
      std::vector<SPreparedKeyframe> found;
      {
        const std::lock_guard<std::mutex> lock(sCompressLock);
        found.swap(sPreparedFound);
      }
      for (const SPreparedKeyframe& prepared : found) {
        const std::int32_t tick = prepared.tick;
        sPreparedTick = std::max(sPreparedTick, tick);
        if (prepared.path.empty()) {
          continue;
        }
        // The same file as one here, which the move up has replaced.
        if (const auto same = sKeyframes.find(tick); same != sKeyframes.end() && same->second.path == prepared.path) {
          continue;
        }
        // One the viewer saved as it passed here is as good, and a second only takes disk.
        if (HaveKeyframeNear(tick)) {
          RemoveFileLater(prepared.path);
          continue;
        }
        const std::string& path = prepared.path;
        sKeyframeBytes += prepared.bytes;
        sKeyframes[tick] = SKeyframeFile{path, prepared.bytes};
        if (prepared.compressed) {
          continue;
        }
        QueueKeyframeCompression(tick, path);
      }
    }

    void ForgetKeyframes()
    {
      StopKeyframePreparation();
      StopKeyframeCompression();
      sKeyframes.clear();
      sKeyframeBytes = 0;
      sLastKeyframeTick = 0;
      sLastSaveSeconds = 0.0;
    }

    /** Past the budget: every second one of the older half goes, oldest first, so the newest stay close together. */
    void TrimKeyframes()
    {
      const std::uint64_t cap = static_cast<std::uint64_t>(std::max(replay_KeyframeMaxMB, 1)) * 1024u * 1024u;
      if (sKeyframeBytes <= cap) {
        return;
      }
      while (sKeyframeBytes > cap && sKeyframes.size() > kMinKeyframes) {
        std::size_t olderHalf = sKeyframes.size() / 2u;
        bool keep = true;
        for (auto entry = sKeyframes.begin(); olderHalf != 0u && sKeyframeBytes > cap; --olderHalf) {
          if (keep) {
            ++entry;
          } else {
            sKeyframeBytes -= std::min(entry->second.bytes, sKeyframeBytes);
            RemoveFileLater(entry->second.path);
            entry = sKeyframes.erase(entry);
          }
          keep = !keep;
        }
      }
      gpg::Logf(
        "Replay timeline: keyframes thinned to the %d MB budget: %d kept, %.0f MB", replay_KeyframeMaxMB,
        static_cast<int>(sKeyframes.size()), static_cast<double>(sKeyframeBytes) / (1024.0 * 1024.0)
      );
    }

    /** On the main thread: the keyframes the background thread has finished take their small files. */
    void TakeCompressedKeyframes()
    {
      std::vector<SCompressedKeyframe> done;
      {
        const std::lock_guard<std::mutex> lock(sCompressLock);
        done.swap(sCompressDone);
      }
      for (const SCompressedKeyframe& keyframe : done) {
        const auto entry = sKeyframes.find(keyframe.tick);
        if (!keyframe.ok) {
          continue; // it stays plain, or the budget has already removed it
        }
        if (entry == sKeyframes.end() || entry->second.path != keyframe.plainPath) {
          RemoveFileLater(keyframe.path);
          continue;
        }
        sKeyframeBytes = sKeyframeBytes - std::min(entry->second.bytes, sKeyframeBytes) + keyframe.bytes;
        gpg::Logf(
          "Replay timeline: keyframe of tick %d compressed from %.1f to %.1f MB, %.0f MB kept", keyframe.tick,
          static_cast<double>(entry->second.bytes) / (1024.0 * 1024.0), static_cast<double>(keyframe.bytes) / (1024.0 * 1024.0),
          static_cast<double>(sKeyframeBytes) / (1024.0 * 1024.0)
        );
        entry->second.path = keyframe.path;
        entry->second.bytes = keyframe.bytes;
      }
      // Each frame, as the budget can also have just been lowered: nothing new need arrive for it to count.
      TrimKeyframes();
    }

    /** A keyframe ready to read from its start: the plain file, or its compressed one unpacked into a file that goes when closed. */
    [[nodiscard]] std::FILE* OpenKeyframeFile(const std::string& path)
    {
      std::FILE* file = nullptr;
      if (path.size() < 4u || path.compare(path.size() - 4u, 4u, ".zst") != 0) {
        return fopen_s(&file, path.c_str(), "rb") == 0 ? file : nullptr;
      }
      const auto start = Clock::now();
      static int sRestoreFileNumber = 0;
      const std::string plainPath = (KeyframeDirectory() / ("restoring_" + std::to_string(++sRestoreFileNumber) + ".bin")).string();
      std::FILE* input = nullptr;
      if (fopen_s(&input, path.c_str(), "rb") != 0 || input == nullptr) {
        return nullptr;
      }
      bool ok = false;
      if (fopen_s(&file, plainPath.c_str(), replay_KeyframeQuietDisk ? "w+bDT" : "w+bD") == 0 && file != nullptr) {
        ok = DecompressStream(input, file) && std::fflush(file) == 0;
      }
      std::fclose(input);
      if (!ok) {
        if (file != nullptr) {
          std::fclose(file);
        }
        return nullptr;
      }
      std::rewind(file);
      gpg::Logf(
        "Replay timeline: keyframe unpacked in %.2f s", std::chrono::duration<double>(Clock::now() - start).count()
      );
      return file;
    }

    /** As `CKeyframeRequest` in headless: the sim's thread saves into it between beats. */
    class CTimelineKeyframeRequest final : public ISaveRequest
    {
    public:
      CTimelineKeyframeRequest(const Sim& sim, std::string path)
        : mSim(sim)
        , mPath(std::move(path))
      {}

      gpg::WriteArchive* GetArchive() override
      {
        gSimExactSaveCount.fetch_add(1u);
        gSimExactArchive.store(true);
        std::FILE* file = nullptr;
        if (fopen_s(&file, mPath.c_str(), replay_KeyframeQuietDisk ? "wbT" : "wb") != 0 || file == nullptr) {
          throw std::runtime_error("cannot write " + mPath);
        }
        mFile = boost::shared_ptr<std::FILE>(file, SFileStarCloser{});
        SSimKeyframeHeader header{};
        SIM_CaptureKeyframeHeader(mSim, header);
        mTick = static_cast<std::int32_t>(header.tick);
        if (!SIM_WriteKeyframeHeader(file, header)) {
          throw std::runtime_error("cannot write " + mPath);
        }
        mArchive = gpg::CreateFastBinaryWriteArchive(mFile);
        return mArchive;
      }

      void Save(const SSaveGameDispatchData& data) override
      {
        delete mArchive;
        mArchive = nullptr;
        mFile.reset();
        sKeyframePending = false;
        sLastSaveSeconds = std::chrono::duration<double>(Clock::now() - mAsked).count();
        if (data.useSuggestedName) {
          std::error_code ignored;
          const std::uintmax_t size = std::filesystem::file_size(mPath, ignored);
          sKeyframeBytes += ignored ? 0u : size;
          sKeyframes[mTick] = SKeyframeFile{mPath, ignored ? 0u : static_cast<std::uint64_t>(size)};
          gpg::Logf(
            "Replay timeline: keyframe of tick %d saved in %.2f s", mTick, sLastSaveSeconds
          );
          QueueKeyframeCompression(mTick, mPath);
        } else {
          gpg::Warnf("Replay timeline: a keyframe failed at tick %d: %s", mTick, data.saveName.c_str());
          RemoveFile(mPath);
        }
        delete this;
      }

    private:
      ~CTimelineKeyframeRequest()
      {
        delete mArchive;
      }

      const Sim& mSim;
      std::string mPath;
      Clock::time_point mAsked = Clock::now();
      std::int32_t mTick = 0;
      boost::shared_ptr<std::FILE> mFile;
      gpg::WriteArchive* mArchive = nullptr;
    };

    void StartFastForward(const CWldSession& session, const std::int32_t tick)
    {
      sTargetTick = tick;
      sStartTick = session.mGameTick;
      sFastForwarding = true;
      sRunStart = Clock::now();
      sRunStartTick = session.mGameTick;
      sLastProgress = Clock::now();
      sLastProgressTick = session.mGameTick;
      gReplayFastForward.store(true);
    }

    void EndSeek()
    {
      sFastForwarding = false;
      sTargetTick = -1;
      gReplayFastForward.store(false);
    }

    /** Asks for a new sim at the newest keyframe at or before `tick`, or at the replay's start. */
    void RequestRestart(const std::int32_t tick)
    {
      sRestoreFile.reset();
      sRestoreHeader = SSimKeyframeHeader{};
      auto keyframe = sKeyframes.upper_bound(tick);
      while (keyframe != sKeyframes.begin()) {
        --keyframe;
        if (std::FILE* const file = OpenKeyframeFile(keyframe->second.path); file != nullptr) {
          boost::shared_ptr<std::FILE> opened(file, SFileStarCloser{});
          SSimKeyframeHeader header{};
          if (SIM_ReadKeyframeHeader(file, header)) {
            sRestoreFile = opened;
            sRestoreHeader = header;
            break;
          }
        }
        gpg::Warnf("Replay timeline: can't read the keyframe of tick %d", keyframe->first);
      }
      sTargetTick = tick;
      sStartTick = 0;
      sHeldTick = -1;
      sRestartAsked = Clock::now();
      sFastForwarding = false;
      // The screen holds what it shows until the target: nothing old or in between is drawn.
      gReplayFastForward.store(true);
      sRestartWanted = true;
      sRestarting = true;
    }

    /**
     * What a move from `current` does: true to load a keyframe, false to play the ticks in between. Back always loads.
     * Forward loads when the ticks a keyframe saves would take longer to play than it takes to load.
     */
    bool SeekLoadsKeyframe(const std::int32_t current, const std::int32_t tick)
    {
      if (tick < current) {
        return true;
      }
      const auto next = sKeyframes.upper_bound(tick);
      if (next == sKeyframes.begin()) {
        return false;
      }
      const std::int32_t saved = std::prev(next)->first - current;
      return static_cast<double>(saved) > sLoadSeconds * sTicksPerSecond;
    }
  } // namespace

  fa::auto_ptr<SWldSessionInfo> REPLAY_SetupViewerSession(const char* const path, fa::string* const failureReason)
  {
    gVcrScanReplayLength = true;
    gVcrReplayBeats = 0;
    fa::auto_ptr<SWldSessionInfo> sessionInfo = VCR_SetupReplaySession(path, failureReason);
    gVcrScanReplayLength = false;
    if (sessionInfo.get() == nullptr) {
      return sessionInfo;
    }

    ForgetKeyframes();
    RemoveLeftoverKeyframes();
    gpg::Logf("Replay timeline: keyframes go in %s", KeyframeRoot().string().c_str());
    EndSeek();
    sReplayPath = path;
    sTotalBeats = gVcrReplayBeats;
    sLaunchPending = true;
    sPrepareStartDue = true;
    sRestartWanted = false;
    sRestarting = false;
    sStartMap.reset();
    sDeferredTarget = -1;
    gRuleKeepScriptBlueprints = true;
    return sessionInfo;
  }

  std::int32_t REPLAY_TotalTicks()
  {
    return sTotalBeats;
  }

  std::vector<std::int32_t> REPLAY_KeyframeTicks()
  {
    std::vector<std::int32_t> ticks;
    ticks.reserve(sKeyframes.size());
    for (const auto& keyframe : sKeyframes) {
      ticks.push_back(keyframe.first);
    }
    return ticks;
  }

  void REPLAY_SeekTo(CWldSession& session, std::int32_t tick)
  {
    if (!session.IsReplay || sReplayPath.empty()) {
      return;
    }
    tick = std::max(tick, 0);
    if (sTotalBeats > 0) {
      tick = std::min(tick, sTotalBeats);
    }

    // Further along the way a new sim is already going: only its target changes.
    if (sRestarting && sHeldTick >= 0 && tick >= sHeldTick) {
      sTargetTick = tick;
      sDeferredTarget = -1;
      return;
    }

    // The sim can't be replaced in the middle of a save, or while it is being replaced.
    if (sKeyframePending || sRestartWanted || sRestarting) {
      sDeferredTarget = tick;
      return;
    }

    const std::int32_t current = session.mGameTick;
    if (tick == current) {
      return;
    }
    StartSeekClock(current);
    if (SeekLoadsKeyframe(current, tick)) {
      RequestRestart(tick);
      return;
    }
    StartFastForward(session, tick);
  }

  EReplaySeekKind REPLAY_SeekKind(const CWldSession& session, const std::int32_t tick)
  {
    // While the sim is being replaced, the tick a new move would start from isn't known yet.
    if (!session.IsReplay || sReplayPath.empty() || sRestartWanted || sRestarting || tick == session.mGameTick) {
      return EReplaySeekKind::None;
    }
    return SeekLoadsKeyframe(session.mGameTick, tick) ? EReplaySeekKind::LoadKeyframe : EReplaySeekKind::PlayForward;
  }

  void REPLAY_CancelSeek()
  {
    sDeferredTarget = -1;
    if (!sRestartWanted && !sRestarting) {
      EndSeek();
    } else if (sHeldTick >= 0) {
      sTargetTick = sHeldTick; // stops where the new sim has got to
    }
  }

  bool REPLAY_IsSeeking()
  {
    return sFastForwarding || sRestartWanted || sRestarting || sDeferredTarget >= 0;
  }

  SReplaySeekProgress REPLAY_SeekProgress(const CWldSession& session)
  {
    SReplaySeekProgress progress{};
    progress.targetTick = sDeferredTarget >= 0 ? sDeferredTarget : sTargetTick;
    progress.currentTick = sHeldTick >= 0 ? sHeldTick : session.mGameTick;
    progress.restarting = sRestartWanted || (sRestarting && sHeldTick < 0);
    const std::int32_t span = sTargetTick - sStartTick;
    if ((sFastForwarding || sHeldTick >= 0) && span > 0) {
      progress.progress = std::clamp(static_cast<float>(progress.currentTick - sStartTick) / static_cast<float>(span), 0.0f, 1.0f);
    }
    return progress;
  }

  void REPLAY_MainFrame(ISTIDriver& driver, CWldSession& session)
  {
    if (!session.IsReplay || sReplayPath.empty()) {
      return;
    }

    // Once the game is showing, as the hidden process competes with the game's own load.
    if (sPrepareStartDue) {
      StartKeyframePreparation();
    }
    // Turned off while it runs: the CPU it uses comes back at once, and what it has written stays.
    if (!replay_PrepareKeyframes && sPrepareProcess != nullptr) {
      TakePreparedKeyframes();
      StopKeyframePreparation();
    }
    TakePreparedKeyframes();
    TakeCompressedKeyframes();

    if (sDeferredTarget >= 0 && !sKeyframePending) {
      const std::int32_t tick = sDeferredTarget;
      sDeferredTarget = -1;
      REPLAY_SeekTo(session, tick);
      return;
    }

    if (replay_KeyframeEvery <= 0 || sKeyframePending || sRestarting) {
      return;
    }
    const std::int32_t tick = session.mGameTick;
    const std::int32_t spacing = std::max(replay_KeyframeEvery, static_cast<std::int32_t>(sLastSaveSeconds * kKeyframeTicksPerSaveSecond));
    if (tick < (sLastKeyframeTick == 0 ? kFirstKeyframeTick : sLastKeyframeTick + spacing)) {
      return;
    }
    sLastKeyframeTick = tick;
    // The hidden process is past here: this sim needn't stop to save.
    if (sPreparedTick >= tick) {
      return;
    }
    // Or will be: a save stops the sim, which shows.
    if (replay_KeyframeQuietDisk && sPrepareProcess != nullptr && ::WaitForSingleObject(sPrepareProcess, 0u) == WAIT_TIMEOUT) {
      return;
    }
    if (HaveKeyframeNear(tick)) {
      return;
    }

    const auto* const simDriver = dynamic_cast<CSimDriver*>(&driver);
    const Sim* const sim = simDriver != nullptr ? simDriver->GetSimForReplayCheck() : nullptr;
    if (sim == nullptr) {
      return;
    }
    sKeyframePending = true;
    const std::string path = (KeyframeDirectory() / ("keyframe_" + std::to_string(tick) + ".bin")).string();
    driver.RequestSaveGame(new CTimelineKeyframeRequest(*sim, path));
  }

  std::int32_t REPLAY_FastForwardTarget()
  {
    return sFastForwarding ? sTargetTick : -1;
  }

  void REPLAY_AfterFastForwardFrame(const CWldSession& session, const std::int32_t beatsApplied)
  {
    if (!sFastForwarding) {
      return;
    }
    const Clock::time_point now = Clock::now();
    if (beatsApplied > 0 || session.mGameTick != sLastProgressTick) {
      sLastProgress = now;
      sLastProgressTick = session.mGameTick;
    }
    const bool stalled = std::chrono::duration<double>(now - sLastProgress).count() > kFastForwardStallSeconds;
    if (session.mGameTick >= sTargetTick || session.IsGameOver != 0 || stalled) {
      NoteRunEnd(session.mGameTick);
      LogSeekArrival(session.mGameTick);
      EndSeek();
    }
  }

  void REPLAY_OnTeardown()
  {
    // The teardown before this replay's session starts, not the end of the replay.
    if (sLaunchPending) {
      return;
    }
    ForgetKeyframes();
    RemoveLeftoverKeyframes();
    EndSeek();
    sReplayPath.clear();
    sTotalBeats = 0;
    sRestartWanted = false;
    sRestarting = false;
    sHeldTick = -1;
    sDeferredTarget = -1;
    sRestoreFile.reset();
    sStartMap.reset();
    gRuleKeepScriptBlueprints = false;
    gSimBeatOrigin.store(0); // a later session in this process starts from its own
  }

  void REPLAY_NoteHeldTick(const std::int32_t tick)
  {
    if (sHeldTick < 0) {
      sStartTick = tick;
      sRunStart = Clock::now();
      sRunStartTick = tick;
      sLoadSeconds = std::chrono::duration<double>(sRunStart - sRestartAsked).count();
    }
    sHeldTick = tick;
    sLastProgress = Clock::now();
  }

  bool REPLAY_HoldIsDone(const std::size_t beatsHeld)
  {
    const bool stalled = std::chrono::duration<double>(Clock::now() - sLastProgress).count() > kFastForwardStallSeconds;
    return sHeldTick >= sTargetTick || beatsHeld >= kMaxHeldBeats || stalled;
  }

  void REPLAY_SimRestarted(const CWldSession& session)
  {
    NoteRunEnd(session.mGameTick);
    gpg::Logf("Replay timeline: a keyframe loads in %.1f s, and ticks play at %.0f a second", sLoadSeconds, sTicksPerSecond);
    sRestarting = false;
    sHeldTick = -1;
    const std::int32_t tick = sTargetTick;
    sTargetTick = -1;
    if (tick > session.mGameTick) {
      StartFastForward(session, tick);
    } else {
      LogSeekArrival(session.mGameTick);
      gReplayFastForward.store(false);
    }
  }

  STIMap* REPLAY_CloneStartMap()
  {
    return new STIMap(sStartMap.get());
  }

  bool REPLAY_RestartWanted()
  {
    return sRestartWanted;
  }

  fa::auto_ptr<SWldSessionInfo> REPLAY_CreateRestartSession()
  {
    sRestartWanted = false;
    const int skipBeats = sRestoreFile.get() != nullptr ? static_cast<int>(sRestoreHeader.beat) - 1 : 0;
    fa::string failure;
    fa::auto_ptr<SWldSessionInfo> sessionInfo = VCR_SetupReplaySession(sReplayPath.c_str(), &failure, nullptr, skipBeats);
    if (sessionInfo.get() == nullptr) {
      gpg::Warnf("Replay timeline: can't restart the replay: %s", failure.c_str());
      sRestoreFile.reset();
      sRestarting = false;
      sTargetTick = -1;
      gReplayFastForward.store(false);
    }
    return sessionInfo;
  }

  void REPLAY_PrepareSession(SWldSessionInfo& sessionInfo)
  {
    sLaunchPending = false;
    // Not the viewer: a rejoining player's restore has just set the beat origin.
    if (sReplayPath.empty()) {
      return;
    }
    if (!sStartMap) {
      sStartMap.reset(new STIMap(sessionInfo.mLaunchInfo->mMap));
    }
    if (sRestoreFile.get() == nullptr) {
      gSimBeatOrigin.store(0); // an earlier session in this process may have been restored
      return;
    }

    LaunchInfoBase* const launchInfo = sessionInfo.mLaunchInfo.get();
    boost::shared_ptr<LaunchInfoLoad> loadInfo;
    (void)boost::ConstructSharedLaunchInfoLoadFromRaw(&loadInfo, new LaunchInfoLoad());
    loadInfo->mGameRules = launchInfo->mGameRules;
    loadInfo->mMap = launchInfo->mMap;
    launchInfo->mMap = nullptr;
    loadInfo->mGameMods = launchInfo->mGameMods;
    loadInfo->mScenarioInfo = launchInfo->mScenarioInfo;
    loadInfo->mArmyLaunchInfo = launchInfo->mArmyLaunchInfo;
    loadInfo->mCommandSources = launchInfo->mCommandSources;
    loadInfo->mLanguage = launchInfo->mLanguage;
    loadInfo->mCheatsEnabled = launchInfo->mCheatsEnabled;
    loadInfo->mReadArchive = gpg::CreateBinaryReadArchive(sRestoreFile);
    sRestoreFile.reset();
    SIM_BeginKeyframeRestore(sRestoreHeader);
    sessionInfo.mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(loadInfo);
    gpg::Logf("Replay timeline: restoring the keyframe of beat %u", sRestoreHeader.beat);
  }
} // namespace moho
