#include "moho/sim/DesyncRecorder.h"

#include <algorithm>
#include <atomic>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <zlib.h>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/diagnostics/CrashReport.h"
#include "gpg/core/utils/Logging.h"
#include "moho/command/ICommandSink.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimWorkerPool.h"

namespace moho
{
  bool sim_DesyncRecorder = false;

  TConVar<bool> gTConVar_sim_DesyncRecorder(
    "sim_DesyncRecorder",
    "Keep recent beats of sync-log text in memory and write a zip next to the game log when a "
    "checksum mismatches (next game). Same checksums either way.",
    &sim_DesyncRecorder
  );

  int sim_DesyncRecorderMB = 32;

  TConVar<int> gTConVar_sim_DesyncRecorderMB(
    "sim_DesyncRecorderMB",
    "Memory cap in MB for the desync recorder's compressed beats; the oldest beats go first.",
    &sim_DesyncRecorderMB
  );

  int sim_DesyncTestNudgeBeat = -1;

  TConVar<int> gTConVar_sim_DesyncTestNudgeBeat(
    "sim_DesyncTestNudgeBeat",
    "Test only: at this beat this client alone raises its lowest-id unit's health by one float "
    "step, which desyncs the game. -1 does nothing.",
    &sim_DesyncTestNudgeBeat
  );

  const Sim* CDesyncRecorder::sSim = nullptr;
  CDesyncRecorder* CDesyncRecorder::sInstance = nullptr;

  namespace
  {
    /// The dump is taken on the mismatched beat + kDumpBeatsAfterMismatch, the same beat on every
    /// client, so their state snapshots line up; and at least kBeatsAfterDesync beats after the
    /// mismatch was seen, so the dump shows the difference spreading.
    constexpr int kDumpBeatsAfterMismatch = 30;
    constexpr int kBeatsAfterDesync = 10;

    /// The ring reaches back to the last agreed beat: one checksum period (50) before the
    /// mismatched beat, up to 128 beats of report delay (`VerifyChecksum`'s window) and the 10
    /// beats after it. Fewer would drop the oldest beats, the ones where the difference begins.
    constexpr std::size_t kMaxBeats = 192u;

    /// `VerifyChecksum` accepts a report up to 128 beats old; older checks are let go.
    constexpr int kChecksumWindowBeats = 128;

    /// A source silent for this many checksum periods no longer holds back "everyone agreed"
    /// (a player who left, an observer that sends nothing).
    constexpr int kQuietPeriods = 3;

    /// Text waiting for the recorder thread beyond this is dropped, not queued without limit.
    constexpr std::size_t kMaxPendingBytes = 64u * 1024u * 1024u;

    struct SBeatRecord
    {
      int mBeat = 0;
      std::uint32_t mCrc = 0;
      std::uint32_t mRawSize = 0;
      std::vector<unsigned char> mDeflated;
      SFpuControlState mFpu{};
      unsigned int mWorkers = 0;
      unsigned int mCommands = 0;
    };

    struct SChecksumReport
    {
      int mSource = 0;
      gpg::MD5Digest mReported{};
    };

    struct SChecksumBeat
    {
      gpg::MD5Digest mOurs{};
      std::vector<SChecksumReport> mReports;
      bool mMismatch = false;
    };

    struct SDesyncRecord
    {
      int mBeat = 0;
      int mSource = 0;
      int mDetectedAtBeat = 0;
      std::string mOurs;
      std::string mReported;
    };

    // The user side's facts and the published dump path; any thread.
    std::mutex sSharedMutex;
    std::string sMapName;
    bool sIsReplay = false;
    std::string sDumpPath;

    [[nodiscard]] bool DeflateRaw(const void* const data, const std::size_t size, const int level, std::vector<unsigned char>& out)
    {
      out.clear();
      z_stream stream;
      std::memset(&stream, 0, sizeof(stream));
      if (deflateInit2_(&stream, level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, sizeof(z_stream)) != Z_OK) {
        return false;
      }

      stream.next_in = static_cast<Bytef*>(const_cast<void*>(data));
      stream.avail_in = static_cast<uInt>(size);
      unsigned char chunk[64 * 1024];
      int status = Z_OK;
      while (status == Z_OK) {
        stream.next_out = chunk;
        stream.avail_out = sizeof(chunk);
        status = deflate(&stream, Z_FINISH);
        out.insert(out.end(), chunk, chunk + (sizeof(chunk) - stream.avail_out));
      }
      (void)deflateEnd(&stream);
      return status == Z_STREAM_END;
    }

    [[nodiscard]] std::uint32_t Crc32(const void* const data, const std::size_t size)
    {
      return static_cast<std::uint32_t>(crc32(0uL, static_cast<const Bytef*>(data), static_cast<uInt>(size)));
    }

    /// A zip archive written front to back; the last entry can be rewritten in place later.
    class CZipOut
    {
    public:
      struct SEntry
      {
        std::string mName;
        std::uint32_t mCrc = 0;
        std::uint32_t mCompressedSize = 0;
        std::uint32_t mRawSize = 0;
        std::uint32_t mOffset = 0;
      };

      explicit CZipOut(std::FILE* const file)
        : mFile(file)
      {
        const std::time_t now = std::time(nullptr);
        std::tm local{};
#if defined(_WIN32)
        (void)localtime_s(&local, &now);
#else
        (void)localtime_r(&now, &local);
#endif
        mDosTime = static_cast<std::uint16_t>((local.tm_hour << 11) | (local.tm_min << 5) | (local.tm_sec / 2));
        mDosDate = static_cast<std::uint16_t>(((local.tm_year - 80) << 9) | ((local.tm_mon + 1) << 5) | local.tm_mday);
      }

      /// One entry whose data is already a raw deflate stream.
      void AddDeflated(const std::string& name, const std::vector<unsigned char>& deflated, const std::uint32_t crc, const std::uint32_t rawSize)
      {
        SEntry entry;
        entry.mName = name;
        entry.mCrc = crc;
        entry.mCompressedSize = static_cast<std::uint32_t>(deflated.size());
        entry.mRawSize = rawSize;
        entry.mOffset = static_cast<std::uint32_t>(std::ftell(mFile));

        Put32(0x04034B50u);
        Put16(20u);
        Put16(0u);
        Put16(8u);
        Put16(mDosTime);
        Put16(mDosDate);
        Put32(entry.mCrc);
        Put32(entry.mCompressedSize);
        Put32(entry.mRawSize);
        Put16(static_cast<std::uint16_t>(name.size()));
        Put16(0u);
        (void)std::fwrite(name.data(), 1u, name.size(), mFile);
        if (!deflated.empty()) {
          (void)std::fwrite(deflated.data(), 1u, deflated.size(), mFile);
        }
        mEntries.push_back(std::move(entry));
      }

      void AddText(const std::string& name, const std::string& text)
      {
        std::vector<unsigned char> deflated;
        if (DeflateRaw(text.data(), text.size(), Z_DEFAULT_COMPRESSION, deflated)) {
          AddDeflated(name, deflated, Crc32(text.data(), text.size()), static_cast<std::uint32_t>(text.size()));
        }
      }

      /// Writes the central directory; returns the archive's size.
      std::uint32_t Finish()
      {
        const auto directoryOffset = static_cast<std::uint32_t>(std::ftell(mFile));
        for (const SEntry& entry : mEntries) {
          Put32(0x02014B50u);
          Put16(20u);
          Put16(20u);
          Put16(0u);
          Put16(8u);
          Put16(mDosTime);
          Put16(mDosDate);
          Put32(entry.mCrc);
          Put32(entry.mCompressedSize);
          Put32(entry.mRawSize);
          Put16(static_cast<std::uint16_t>(entry.mName.size()));
          Put16(0u);
          Put16(0u);
          Put16(0u);
          Put16(0u);
          Put32(0u);
          Put32(entry.mOffset);
          (void)std::fwrite(entry.mName.data(), 1u, entry.mName.size(), mFile);
        }
        const auto directorySize = static_cast<std::uint32_t>(std::ftell(mFile)) - directoryOffset;
        Put32(0x06054B50u);
        Put16(0u);
        Put16(0u);
        Put16(static_cast<std::uint16_t>(mEntries.size()));
        Put16(static_cast<std::uint16_t>(mEntries.size()));
        Put32(directorySize);
        Put32(directoryOffset);
        Put16(0u);
        return static_cast<std::uint32_t>(std::ftell(mFile));
      }

      /// Drops the last entry and moves the file position back to where it began.
      void RewindLast()
      {
        if (!mEntries.empty()) {
          (void)std::fseek(mFile, static_cast<long>(mEntries.back().mOffset), SEEK_SET);
          mEntries.pop_back();
        }
      }

      void SetFile(std::FILE* const file) noexcept
      {
        mFile = file;
      }

    private:
      void Put16(const std::uint32_t value)
      {
        const unsigned char bytes[2] = {static_cast<unsigned char>(value), static_cast<unsigned char>(value >> 8)};
        (void)std::fwrite(bytes, 1u, sizeof(bytes), mFile);
      }

      void Put32(const std::uint32_t value)
      {
        const unsigned char bytes[4] = {
          static_cast<unsigned char>(value), static_cast<unsigned char>(value >> 8),
          static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 24)
        };
        (void)std::fwrite(bytes, 1u, sizeof(bytes), mFile);
      }

      std::FILE* mFile;
      std::vector<SEntry> mEntries;
      std::uint16_t mDosTime = 0;
      std::uint16_t mDosDate = 0;
    };

    [[nodiscard]] std::string JsonString(const std::string& text)
    {
      std::string out = "\"";
      for (const char c : text) {
        switch (c) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        default:
          if (static_cast<unsigned char>(c) < 0x20u) {
            char escaped[8];
            std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
            out += escaped;
          } else {
            out += c;
          }
        }
      }
      out += '"';
      return out;
    }

    [[nodiscard]] std::string Printf(const char* const format, ...)
    {
      va_list args;
      va_start(args, format);
      char buffer[1024];
      const int written = std::vsnprintf(buffer, sizeof(buffer), format, args);
      va_end(args);
      return written > 0 ? std::string(buffer, std::min<std::size_t>(static_cast<std::size_t>(written), sizeof(buffer) - 1u)) : std::string();
    }

    /// Text a `FILE*` writer produces, through a temporary file the CRT deletes on close.
    [[nodiscard]] std::string CaptureFileText(void (*writer)(std::FILE*))
    {
      std::string text;
      std::FILE* const file = std::tmpfile();
      if (file == nullptr) {
        return text;
      }
      writer(file);
      const long size = std::ftell(file);
      if (size > 0) {
        text.resize(static_cast<std::size_t>(size));
        std::rewind(file);
        text.resize(std::fread(text.data(), 1u, text.size(), file));
      }
      (void)std::fclose(file);
      return text;
    }

    /// The FAF game id from `/savereplay gpgnet://host:port/<game id>/<player>.SCFAreplay`, or empty.
    [[nodiscard]] std::string FafGameIdFromCommandLine()
    {
      msvc8::vector<msvc8::string> args;
      if (!CFG_GetArgOption("/savereplay", 1u, &args) || args.empty()) {
        return {};
      }
      const std::string uri = args[0].c_str();
      constexpr const char kScheme[] = "gpgnet://";
      if (uri.compare(0, sizeof(kScheme) - 1u, kScheme) != 0) {
        return {};
      }
      const std::size_t hostEnd = uri.find('/', sizeof(kScheme) - 1u);
      if (hostEnd == std::string::npos) {
        return {};
      }
      const std::size_t idEnd = uri.find('/', hostEnd + 1u);
      std::string id = uri.substr(hostEnd + 1u, idEnd == std::string::npos ? std::string::npos : idEnd - hostEnd - 1u);
      const bool numeric = !id.empty() && std::all_of(id.begin(), id.end(), [](const char c) { return c >= '0' && c <= '9'; });
      return numeric ? id : std::string();
    }

    /// The folder of `/log <file>`, else the working folder.
    [[nodiscard]] std::filesystem::path DumpFolder()
    {
      msvc8::vector<msvc8::string> args;
      if (CFG_GetArgOption("/log", 1u, &args) && !args.empty()) {
        std::error_code error;
        const std::filesystem::path folder = std::filesystem::path(args[0].c_str()).parent_path();
        if (!folder.empty() && std::filesystem::is_directory(folder, error)) {
          return folder;
        }
      }
      std::error_code error;
      return std::filesystem::current_path(error);
    }

    /// `name=value` for every console variable whose name starts with `sim_` or `lua_`.
    [[nodiscard]] std::string ConsoleSwitches()
    {
      msvc8::string names;
      CON_GetCommandList(names, false);
      std::string out;
      const std::string all = names.c_str();
      std::size_t begin = 0;
      while (begin < all.size()) {
        std::size_t end = all.find('\n', begin);
        if (end == std::string::npos) {
          end = all.size();
        }
        const std::string name = all.substr(begin, end - begin);
        begin = end + 1u;
        if (name.compare(0, 4, "sim_") != 0 && name.compare(0, 4, "lua_") != 0) {
          continue;
        }
        CConCommand* const command = CON_FindCommand(name.c_str());
        std::string value;
        if (const auto* const asBool = dynamic_cast<TConVar<bool>*>(command)) {
          value = *asBool->mValue ? "1" : "0";
        } else if (const auto* const asInt = dynamic_cast<TConVar<int>*>(command)) {
          value = std::to_string(*asInt->mValue);
        } else if (const auto* const asUint = dynamic_cast<TConVar<std::uint32_t>*>(command)) {
          value = std::to_string(*asUint->mValue);
        } else if (const auto* const asByte = dynamic_cast<TConVar<std::uint8_t>*>(command)) {
          value = std::to_string(static_cast<unsigned>(*asByte->mValue));
        } else if (const auto* const asFloat = dynamic_cast<TConVar<float>*>(command)) {
          value = Printf("%.6g", static_cast<double>(*asFloat->mValue));
        } else if (const auto* const asString = dynamic_cast<TConVar<msvc8::string>*>(command)) {
          value = asString->mValue->c_str();
        } else {
          continue; // a sim-side variable (DoSimCommand alias) or a command
        }
        out += name + "=" + value + "\n";
      }
      return out;
    }

    [[nodiscard]] unsigned int SimWorkerCount()
    {
      return CSimWorkerPool::ParallelEnabled() ? CSimWorkerPool::Get().WorkerCount() : 0u;
    }
  } // namespace

  struct CDesyncRecorder::Impl
  {
    // Sim thread.
    std::string mText;
    SFpuControlState mBeatFpu{};
    unsigned int mBeatWorkers = 0;
    std::atomic<unsigned int> mBeatCommands{0}; // the decoder's thread may differ from the sim's
    bool mRecording = true;
    std::map<int, SChecksumBeat> mChecks;
    std::size_t mCommandSourceCount = 0;
    std::map<int, int> mLastReportBeat; // per source
    int mCheckSpacing = 50;             // beats between checksums, as reports show it
    SFpuControlState mStartFpu{};
    int mLastAgreedBeat = INT_MIN;
    std::vector<SDesyncRecord> mDesyncs;
    bool mDesyncSeen = false;
    bool mDumpTaken = false;
    int mDumpAtBeat = 0;
    int mLocalArmy = -1;
    std::string mDumpPath;
    std::size_t mPendingBytes = 0; // also read by the recorder thread under mQueueMutex

    // Recorder thread.
    std::deque<SBeatRecord> mRing;
    std::size_t mRingBytes = 0;
    SBeatRecord mBeatZero;
    bool mHaveBeatZero = false;
    std::vector<std::string> mNotes;
    unsigned int mDroppedBeats = 0;
    bool mDumpWritten = false;
    std::unique_ptr<CZipOut> mZip;

    // Queue.
    std::mutex mQueueMutex;
    std::condition_variable mQueueSignal;
    std::deque<std::function<void()>> mQueue;
    bool mStopping = false;
    std::thread mThread;

    void Post(std::function<void()> job)
    {
      {
        std::lock_guard<std::mutex> lock(mQueueMutex);
        mQueue.push_back(std::move(job));
      }
      mQueueSignal.notify_one();
    }

    void Run()
    {
      for (;;) {
        std::function<void()> job;
        {
          std::unique_lock<std::mutex> lock(mQueueMutex);
          mQueueSignal.wait(lock, [this] { return mStopping || !mQueue.empty(); });
          if (mQueue.empty()) {
            return;
          }
          job = std::move(mQueue.front());
          mQueue.pop_front();
        }
        try {
          job();
        } catch (const std::exception& exception) {
          gpg::Warnf("Desync recorder: %s", exception.what());
        }
      }
    }

    /// Recorder thread: compresses one beat into the ring and trims it.
    void StoreBeat(SBeatRecord record, const std::string& text, const int trimBefore, const std::size_t capBytes)
    {
      record.mRawSize = static_cast<std::uint32_t>(text.size());
      record.mCrc = Crc32(text.data(), text.size());
      if (!DeflateRaw(text.data(), text.size(), 1, record.mDeflated)) {
        ++mDroppedBeats;
        return;
      }
      if (record.mBeat == 0) {
        mBeatZero = std::move(record);
        mHaveBeatZero = true;
        return;
      }

      mRingBytes += record.mDeflated.size();
      mRing.push_back(std::move(record));
      while (!mRing.empty()
             && (mRing.size() > kMaxBeats || mRingBytes > capBytes || mRing.front().mBeat < trimBefore)) {
        mRingBytes -= mRing.front().mDeflated.size();
        mRing.pop_front();
      }
    }

    [[nodiscard]] std::string NotesText() const
    {
      std::string text;
      for (const std::string& line : mNotes) {
        text += line;
        text += '\n';
      }
      return text;
    }

    /// Recorder thread: writes the zip. `notes.txt` goes last so a later note can rewrite it alone.
    void WriteDump(
      const std::string& path, const std::string& header, const std::string& hashes, const std::string& state,
      const std::string& recentLog
    )
    {
      std::FILE* const file = std::fopen(path.c_str(), "wb");
      if (file == nullptr) {
        gpg::Warnf("Desync recorder: can't create %s", path.c_str());
        return;
      }
      mZip = std::make_unique<CZipOut>(file);
      mZip->AddText("header.json", header);
      mZip->AddText("hashes.csv", hashes);

      std::string beats = "beat,raw_bytes,stored_bytes,x87_control,mxcsr,sim_workers,commands\n";
      const auto addBeat = [this, &beats](const SBeatRecord& record) {
        mZip->AddDeflated(Printf("beats/beat%05d.log", record.mBeat), record.mDeflated, record.mCrc, record.mRawSize);
        beats += Printf(
          "%d,%u,%u,0x%04x,0x%08x,%u,%u\n", record.mBeat, record.mRawSize, static_cast<unsigned>(record.mDeflated.size()),
          record.mFpu.mX87ControlWord, record.mFpu.mMxcsr, record.mWorkers, record.mCommands
        );
      };
      if (mHaveBeatZero) {
        addBeat(mBeatZero);
      }
      for (const SBeatRecord& record : mRing) {
        addBeat(record);
      }
      mZip->AddText("beats.csv", beats);
      mZip->AddText("state.txt", state);
      mZip->AddText("log.txt", recentLog);
      mZip->AddText("environment.txt", CaptureFileText(&gpg::diag::WriteEnvironmentReport));
      mZip->AddText("modules.txt", CaptureFileText(&gpg::diag::WriteModuleList));
      if (mDroppedBeats != 0u) {
        mNotes.push_back(Printf("%u beats were not recorded (compression failed or the recorder fell behind)", mDroppedBeats));
      }
      mZip->AddText("notes.txt", NotesText());
      const std::uint32_t size = mZip->Finish();
      (void)std::fclose(file);
      mZip->SetFile(nullptr);
      mDumpWritten = true;
      mRing.clear();
      mRingBytes = 0;
      gpg::Logf("Desync recorder: wrote %s (%u bytes)", path.c_str(), size);
    }

    /// Recorder thread: one more note; once the zip exists, its notes entry is rewritten.
    void AddNote(const std::string& line, const std::string& path)
    {
      mNotes.push_back(line);
      if (!mDumpWritten || !mZip) {
        return;
      }
      std::FILE* const file = std::fopen(path.c_str(), "r+b");
      if (file == nullptr) {
        return;
      }
      mZip->SetFile(file);
      mZip->RewindLast();
      mZip->AddText("notes.txt", NotesText());
      const std::uint32_t size = mZip->Finish();
      (void)std::fclose(file);
      mZip->SetFile(nullptr);
      std::error_code error;
      std::filesystem::resize_file(path, size, error);
    }
  };

  CDesyncRecorder::CDesyncRecorder(Sim& sim)
    : mImpl(std::make_unique<Impl>())
  {
    mImpl->mText.reserve(1024u * 1024u);
    mImpl->mBeatFpu = SFpuControlState::Capture();
    mImpl->mBeatWorkers = SimWorkerCount();
    mImpl->mStartFpu = mImpl->mBeatFpu;
    mImpl->mCommandSourceCount = sim.mCommandSources.size();
    mImpl->mThread = std::thread([impl = mImpl.get()] { impl->Run(); });
  }

  CDesyncRecorder::~CDesyncRecorder()
  {
    {
      std::lock_guard<std::mutex> lock(mImpl->mQueueMutex);
      mImpl->mStopping = true;
    }
    mImpl->mQueueSignal.notify_one();
    if (mImpl->mThread.joinable()) {
      mImpl->mThread.join();
    }
  }

  void CDesyncRecorder::Attach(Sim& sim)
  {
    static bool sSeeded = false;
    if (!sSeeded) {
      sSeeded = true;
      if (CFG_GetArgOption("/desyncrecorder", 0u, nullptr)) {
        sim_DesyncRecorder = true;
      }
      msvc8::vector<msvc8::string> args;
      if (CFG_GetArgOption("/desynctestbeat", 1u, &args) && !args.empty()) {
        sim_DesyncTestNudgeBeat = std::atoi(args[0].c_str());
      }
    }

    {
      std::lock_guard<std::mutex> lock(sSharedMutex);
      sDumpPath.clear();
    }
    if (!sim_DesyncRecorder || sInstance != nullptr) {
      return;
    }
    sInstance = new CDesyncRecorder(sim);
    sSim = &sim;
    gpg::Logf("Desync recorder: on, cap %d MB", sim_DesyncRecorderMB);
  }

  void CDesyncRecorder::Detach(const Sim& sim)
  {
    CDesyncRecorder* const recorder = For(&sim);
    if (recorder == nullptr) {
      return;
    }
    if (recorder->mImpl->mDesyncSeen && !recorder->mImpl->mDumpTaken) {
      recorder->TakeDump(sim);
    }
    {
      std::lock_guard<std::mutex> lock(sSharedMutex);
      sInstance = nullptr;
      sSim = nullptr;
    }
    delete recorder; // waits for the dump
  }

  void CDesyncRecorder::SetSessionInfo(const char* const mapName, const bool isReplay)
  {
    std::lock_guard<std::mutex> lock(sSharedMutex);
    sMapName = mapName != nullptr ? mapName : "";
    sIsReplay = isReplay;
  }

  std::string CDesyncRecorder::DumpPath()
  {
    std::lock_guard<std::mutex> lock(sSharedMutex);
    return sDumpPath;
  }

  void CDesyncRecorder::AddNote(const std::string& line)
  {
    std::lock_guard<std::mutex> lock(sSharedMutex);
    if (sInstance != nullptr) {
      Impl* const impl = sInstance->mImpl.get();
      impl->Post([impl, line, path = sDumpPath] { impl->AddNote(line, path); });
    }
  }

  bool CDesyncRecorder::IsRecording() const noexcept
  {
    return mImpl->mRecording;
  }

  void CDesyncRecorder::Append(const char* const format, va_list args)
  {
    // A line from a worker would land in a different place on each machine (issue #216 risk).
    MOHO_ASSERT_NOT_SIM_WORKER("Sim::Logf");
    if (!mImpl->mRecording) {
      return;
    }
    char buffer[1024];
    va_list copy;
    va_copy(copy, args);
    const int written = std::vsnprintf(buffer, sizeof(buffer), format, copy);
    va_end(copy);
    if (written <= 0) {
      return;
    }
    std::string& text = mImpl->mText;
    if (static_cast<std::size_t>(written) < sizeof(buffer)) {
      text.append(buffer, static_cast<std::size_t>(written));
      return;
    }
    const std::size_t start = text.size();
    text.resize(start + static_cast<std::size_t>(written) + 1u);
    va_copy(copy, args);
    (void)std::vsnprintf(text.data() + start, static_cast<std::size_t>(written) + 1u, format, copy);
    va_end(copy);
    text.resize(start + static_cast<std::size_t>(written));
  }

  void CDesyncRecorder::Append(const char* const text, const std::size_t length)
  {
    if (mImpl->mRecording) {
      mImpl->mText.append(text, length);
    }
  }

  void CDesyncRecorder::NoteCommandFor(const ICommandSink* const sink) noexcept
  {
    if (sInstance != nullptr && sink == static_cast<const ICommandSink*>(sSim)) {
      sInstance->mImpl->mBeatCommands.fetch_add(1u, std::memory_order_relaxed);
    }
  }

  void CDesyncRecorder::EndBeat(Sim& sim, const int beat)
  {
    Impl& impl = *mImpl;
    if (impl.mRecording) {
      SBeatRecord record;
      record.mBeat = beat;
      record.mFpu = impl.mBeatFpu;
      record.mWorkers = impl.mBeatWorkers;
      record.mCommands = impl.mBeatCommands.exchange(0u, std::memory_order_relaxed);

      auto text = std::make_shared<std::string>(std::move(impl.mText));
      impl.mText.clear();
      impl.mText.reserve(text->size() + text->size() / 8u);

      bool queued = false;
      {
        std::lock_guard<std::mutex> lock(impl.mQueueMutex);
        if (impl.mPendingBytes + text->size() <= kMaxPendingBytes) {
          impl.mPendingBytes += text->size();
          queued = true;
        }
      }
      if (queued) {
        const int trimBefore = impl.mDesyncSeen ? INT_MIN : impl.mLastAgreedBeat;
        const std::size_t capBytes = static_cast<std::size_t>(std::max(1, sim_DesyncRecorderMB)) * 1024u * 1024u;
        impl.Post([&impl, record = std::move(record), text, trimBefore, capBytes]() mutable {
          impl.StoreBeat(std::move(record), *text, trimBefore, capBytes);
          std::lock_guard<std::mutex> lock(impl.mQueueMutex);
          impl.mPendingBytes -= text->size();
        });
      } else {
        impl.Post([&impl] { ++impl.mDroppedBeats; });
      }

      impl.mBeatFpu = SFpuControlState::Capture();
      impl.mBeatWorkers = SimWorkerCount();
    }

    if (impl.mDesyncSeen && !impl.mDumpTaken && beat >= impl.mDumpAtBeat) {
      TakeDump(sim);
    }
  }

  void CDesyncRecorder::NoteChecksum(
    Sim& sim, const int beat, const int source, const gpg::MD5Digest& reported, const gpg::MD5Digest& ours
  )
  {
    Impl& impl = *mImpl;
    if (const auto previous = impl.mChecks.lower_bound(beat); previous != impl.mChecks.begin()) {
      const int spacing = beat - std::prev(previous)->first;
      if (spacing > 0 && previous == impl.mChecks.end()) {
        impl.mCheckSpacing = spacing;
      }
    }
    SChecksumBeat& entry = impl.mChecks[beat];
    entry.mOurs = ours;
    entry.mReports.push_back(SChecksumReport{source, reported});
    int& lastReport = impl.mLastReportBeat[source];
    lastReport = std::max(lastReport, beat);

    const int oldest = static_cast<int>(sim.mCurBeat) - kChecksumWindowBeats - kBeatsAfterDesync;
    impl.mChecks.erase(impl.mChecks.begin(), impl.mChecks.lower_bound(oldest));

    const bool match = std::memcmp(&reported, &ours, sizeof(gpg::MD5Digest)) == 0;
    if (match) {
      // A beat is agreed once every live source matched it. A source counts until it has been
      // silent for kQuietPeriods checksum periods; one that never reported counts as having
      // reported at beat 0, so at the start of a game nobody's late hash is taken as agreement.
      const int quietBefore = beat - kQuietPeriods * impl.mCheckSpacing;
      std::size_t live = 0;
      for (std::size_t index = 0; index < impl.mCommandSourceCount; ++index) {
        const auto it = impl.mLastReportBeat.find(static_cast<int>(index));
        live += (it != impl.mLastReportBeat.end() ? it->second : 0) >= quietBefore ? 1u : 0u;
      }
      for (const auto& [reporter, last] : impl.mLastReportBeat) {
        live += reporter >= static_cast<int>(impl.mCommandSourceCount) && last >= quietBefore ? 1u : 0u;
      }
      if (!entry.mMismatch && entry.mReports.size() >= live) {
        impl.mLastAgreedBeat = std::max(impl.mLastAgreedBeat, beat);
      }
      return;
    }

    entry.mMismatch = true;
    SDesyncRecord desync;
    desync.mBeat = beat;
    desync.mSource = source;
    desync.mDetectedAtBeat = static_cast<int>(sim.mCurBeat);
    desync.mOurs = ours.ToString().c_str();
    desync.mReported = reported.ToString().c_str();
    const std::string sourceName = sim.GetCurrentCommandSourceName();

    if (impl.mDesyncSeen) {
      if (impl.mDumpTaken) {
        AddNote(Printf(
          "later desync: beat %d, %s (source %d) sent %s, ours %s, seen at beat %d", beat, sourceName.c_str(), source,
          desync.mReported.c_str(), desync.mOurs.c_str(), desync.mDetectedAtBeat
        ));
      }
      impl.mDesyncs.push_back(std::move(desync));
      return;
    }

    impl.mDesyncSeen = true;
    impl.mDumpAtBeat = std::max(beat + kDumpBeatsAfterMismatch, static_cast<int>(sim.mCurBeat) + kBeatsAfterDesync);
    impl.mDesyncs.push_back(std::move(desync));
    impl.mLocalArmy = sim.mSyncFilter.focusArmy;

    std::string gameId = FafGameIdFromCommandLine();
    if (gameId.empty()) {
      gameId = LOG_GenerateFilenamePrefix().c_str();
    }
    const std::string fileName = Printf("desync_%s_beat%d_army%d.zip", gameId.c_str(), beat, impl.mLocalArmy);
    impl.mDumpPath = (DumpFolder() / fileName).string();
    {
      std::lock_guard<std::mutex> lock(sSharedMutex);
      sDumpPath = impl.mDumpPath;
    }
    gpg::Warnf(
      "Desync recorder: beat %d mismatched with %s; recording to beat %d, then writing %s", beat, sourceName.c_str(),
      impl.mDumpAtBeat, impl.mDumpPath.c_str()
    );
  }

  void CDesyncRecorder::TakeDump(const Sim& sim)
  {
    Impl& impl = *mImpl;
    impl.mDumpTaken = true;
    impl.mRecording = false;

    std::string mapName;
    bool isReplay = false;
    {
      std::lock_guard<std::mutex> lock(sSharedMutex);
      mapName = sMapName;
      isReplay = sIsReplay;
    }

    const int firstBeat = impl.mDesyncs.empty() ? -1 : impl.mDesyncs.front().mBeat;
    const int detectedAt = impl.mDesyncs.empty() ? -1 : impl.mDesyncs.front().mDetectedAtBeat;
    const SFpuControlState fpuNow = SFpuControlState::Capture();

    std::string header = "{\n";
    header += "  \"format\": 1,\n";
    header += "  \"build\": {\"label\": " + JsonString(gpg::diag::BuildLabel()) + ", \"identity\": "
      + JsonString(gpg::diag::BuildIdentity()) + ", \"commit\": " + JsonString(gpg::diag::BuildCommit())
      + ", \"arch\": " + JsonString(gpg::diag::BuildArch()) + ", \"dirty\": "
      + (gpg::diag::BuildDirty() ? "true" : "false") + "},\n";
    header += Printf(
      "  \"game\": {\"faf_game_version\": %d, \"sim_fixes\": %u, \"map\": %s, \"replay\": %s, \"faf_game_id\": %s},\n",
      FAF_GetSessionGameVersion(), static_cast<unsigned>(gFafSessionSimFixes), JsonString(mapName).c_str(),
      isReplay ? "true" : "false", JsonString(FafGameIdFromCommandLine()).c_str()
    );

    header += "  \"command_sources\": [";
    for (std::size_t i = 0; i < sim.mCommandSources.size(); ++i) {
      header += (i == 0 ? "" : ", ") + Printf("{\"index\": %u, \"name\": ", static_cast<unsigned>(i))
        + JsonString(sim.mCommandSources[i].mName.c_str()) + "}";
    }
    header += "],\n";
    header += "  \"armies\": [";
    bool firstArmy = true;
    for (const CArmyImpl* const army : sim.mArmiesList) {
      if (army == nullptr) {
        continue;
      }
      header += (firstArmy ? "" : ", ") + Printf("{\"index\": %d, \"player\": ", army->mConstDat.mArmyIndex)
        + JsonString(army->mConstDat.mPlayerName.raw_data_unsafe()) + ", \"army\": "
        + JsonString(army->mConstDat.mArmyName.raw_data_unsafe()) + "}";
      firstArmy = false;
    }
    header += "],\n";
    header += Printf("  \"local_army\": %d,\n", impl.mLocalArmy);

    header += Printf(
      "  \"desync\": {\"first_mismatched_beat\": %d, \"last_agreed_beat\": %d, \"detected_at_beat\": %d, "
      "\"delay_beats\": %d, \"dump_beat\": %d, \"records\": [",
      firstBeat, impl.mLastAgreedBeat == INT_MIN ? -1 : impl.mLastAgreedBeat, detectedAt,
      firstBeat >= 0 ? detectedAt - firstBeat : -1, static_cast<int>(sim.mCurBeat)
    );
    for (std::size_t i = 0; i < impl.mDesyncs.size(); ++i) {
      const SDesyncRecord& desync = impl.mDesyncs[i];
      header += (i == 0 ? "" : ", ")
        + Printf("{\"beat\": %d, \"source\": %d, \"detected_at_beat\": %d, ", desync.mBeat, desync.mSource, desync.mDetectedAtBeat)
        + "\"ours\": " + JsonString(desync.mOurs) + ", \"reported\": " + JsonString(desync.mReported) + "}";
    }
    header += "]},\n";

    // The x87 control word reads 0 on x64 builds, which do no x87 arithmetic (SFpuControlState).
    header += Printf(
      "  \"settings\": {\"sim_ChecksumPeriod\": %d, \"sim_workers_in_use\": %u, \"sse2\": %s, "
      "\"x87_control\": \"0x%04x\", \"mxcsr\": \"0x%08x\", \"x87_control_at_start\": \"0x%04x\", "
      "\"mxcsr_at_start\": \"0x%08x\", \"switches\": ",
      SIM_GetChecksumPeriod(sim), SimWorkerCount(), CFG_GetArgOption("/sse2", 0u, nullptr) ? "true" : "false",
      fpuNow.mX87ControlWord, fpuNow.mMxcsr, impl.mStartFpu.mX87ControlWord, impl.mStartFpu.mMxcsr
    );
    header += JsonString(ConsoleSwitches()) + "},\n";

    msvc8::vector<msvc8::string> replayArgs;
    const std::string replayPath =
      CFG_GetArgOption("/savereplay", 1u, &replayArgs) && !replayArgs.empty() ? replayArgs[0].c_str() : "";
    header += "  \"replay\": " + JsonString(replayPath) + "\n";
    header += "}\n";

    std::string hashes = "beat,source,name,reported,ours,match\n";
    for (const auto& [beat, entry] : impl.mChecks) {
      const std::string ours = entry.mOurs.ToString().c_str();
      for (const SChecksumReport& report : entry.mReports) {
        std::string name = report.mSource >= 0 && static_cast<std::size_t>(report.mSource) < sim.mCommandSources.size()
          ? sim.mCommandSources[static_cast<std::size_t>(report.mSource)].mName.c_str()
          : "?";
        std::replace(name.begin(), name.end(), ',', ' ');
        const bool match = std::memcmp(&report.mReported, &entry.mOurs, sizeof(gpg::MD5Digest)) == 0;
        hashes += Printf(
          "%d,%d,%s,%s,%s,%d\n", beat, report.mSource, name.c_str(), report.mReported.ToString().c_str(), ours.c_str(),
          match ? 1 : 0
        );
      }
    }

    std::string state;
    SIM_DescribeStateForDesync(sim, state);
    const std::string recentLog = gpg::GetRecentLogLines().c_str();

    impl.Post([&impl, path = impl.mDumpPath, header = std::move(header), hashes = std::move(hashes),
               state = std::move(state), recentLog] { impl.WriteDump(path, header, hashes, state, recentLog); });
  }
} // namespace moho
