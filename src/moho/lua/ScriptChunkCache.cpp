#include "moho/lua/ScriptChunkCache.h"

#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/LocalCache.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaCrashDump.h"
#include "lua/LuaObject.h"
#include "lua/LuaParser.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CZipFile.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CVFSImpl.h"
#include "platform/X87Precision.h"

namespace moho
{
  bool res_ScriptChunkCache = true;

  TConVar<bool> gTConVar_res_ScriptChunkCache(
    "res_ScriptChunkCache",
    "During a session load, take each script's compiled chunk from the cache kept with the shaders when it holds the "
    "same source (1, the default), or compile every script (0). The same functions either way.",
    &res_ScriptChunkCache
  );

  bool res_PrecompileScripts = true;

  TConVar<bool> gTConVar_res_PrecompileScripts(
    "res_PrecompileScripts",
    "With res_ScriptChunkCache, compile the blueprints and scripts the rules' scripts list with DiskFindFiles on helper "
    "threads ahead of their doscript (1, the default), or each when it is run (0). The same functions either way.",
    &res_PrecompileScripts
  );

  bool res_UiScriptChunkCache = true;

  TConVar<bool> gTConVar_res_UiScriptChunkCache(
    "res_UiScriptChunkCache",
    "Take each script the user interface runs on the main thread (menus, lobby, in-game UI) from a compiled-chunk "
    "cache of its own when it holds the same source (1, the default), or compile them (0). Read at startup, before "
    "/con: /nouichunkcache sets 0.",
    &res_UiScriptChunkCache
  );
} // namespace moho

namespace
{
  // Bump when the file's layout changes; the compiler itself is keyed by the executable.
  constexpr char kMagic[8] = {'F', 'A', 'F', 'L', 'U', 'A', 'C', '2'};
  constexpr std::uint64_t kMaxFileBytes = 512ULL << 20U;

  /// Milliseconds on a steady clock, for the flush's idle wait.
  [[nodiscard]] std::uint64_t SteadyMs() noexcept
  {
    return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
    );
  }

  /// A chunk's name and source, hashed two ways, and the source's length.
  struct SChunkKey
  {
    std::uint64_t first = 0;
    std::uint64_t second = 0;
    std::uint64_t bytes = 0;

    bool operator==(const SChunkKey&) const = default;
  };

  struct SChunkKeyHash
  {
    std::size_t operator()(const SChunkKey& key) const noexcept { return static_cast<std::size_t>(key.first); }
  };

  [[nodiscard]] std::uint64_t Rotate(const std::uint64_t value, const int bits) noexcept
  {
    return (value << bits) | (value >> (64 - bits));
  }

  /// Eight bytes at a time, two lanes with their own multipliers: not for an adversary, only to tell
  /// sources apart (the file is ours, and a match also needs the same length).
  class ChunkHasher
  {
  public:
    void Add(const std::string_view text) noexcept
    {
      std::size_t index = 0;
      for (; index + 8U <= text.size(); index += 8U) {
        std::uint64_t word = 0;
        std::memcpy(&word, text.data() + index, 8U);
        Mix(word);
      }
      std::uint64_t tail = 0;
      std::memcpy(&tail, text.data() + index, text.size() - index);
      Mix(tail ^ (static_cast<std::uint64_t>(text.size() - index) << 56U));
      mBytes += text.size();
    }

    [[nodiscard]] SChunkKey Key() const noexcept
    {
      return {Finish(mFirst ^ mBytes), Finish(mSecond + mBytes), mBytes};
    }

  private:
    void Mix(const std::uint64_t word) noexcept
    {
      mFirst = Rotate((mFirst ^ word) * 0x9E3779B97F4A7C15ULL, 29);
      mSecond = Rotate((mSecond + Rotate(word, 31)) * 0xC2B2AE3D27D4EB4FULL, 33);
    }

    [[nodiscard]] static std::uint64_t Finish(std::uint64_t value) noexcept
    {
      value ^= value >> 33U;
      value *= 0xFF51AFD7ED558CCDULL;
      value ^= value >> 33U;
      value *= 0xC4CEB9FE1A85EC53ULL;
      return value ^ (value >> 33U);
    }

    std::uint64_t mFirst = 0x243F6A8885A308D3ULL;
    std::uint64_t mSecond = 0x13198A2E03707344ULL;
    std::uint64_t mBytes = 0;
  };

  constexpr std::size_t kHeaderBytes = sizeof(kMagic) + sizeof(std::uint64_t) + sizeof(SChunkKey);

  /// The file after its header.
  template <class Bytes>
  [[nodiscard]] std::string_view Payload(const Bytes& file)
  {
    return std::string_view(file.data() + kHeaderBytes, file.size() - kHeaderBytes);
  }

  [[nodiscard]] SChunkKey Checksum(const std::string_view payload)
  {
    ChunkHasher hasher;
    hasher.Add(payload);
    return hasher.Key();
  }

  /// A chunk no batch used in this many writes is not written again: its script changed or went
  /// away, or belongs to a mod set (or a part of the user interface) not loaded since.
  constexpr std::uint8_t kMaxIdleWrites = 8;

  struct SCachedChunk
  {
    std::string_view code; // into ScriptChunks::mFile or ScriptChunks::mCompiled
    bool used = false;
    std::uint8_t idleWrites = 0; // writes since a batch last used it
  };

  /// A chunk as the next write keeps it.
  struct SKeptChunk
  {
    SChunkKey key;
    std::string_view code;
    std::uint8_t idleWrites = 0;
  };

  /// The chunks of the batch in progress (only one thread loads a session at a time; the lock is for
  /// any other thread that opens a batch of its own).
  class ScriptChunks
  {
  public:
    explicit ScriptChunks(const char* const fileName)
      : mFileName(fileName)
    {}

    void Begin()
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      if (mBatches++ == 0) {
        Read();
      }
    }

    void End()
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      if (--mBatches != 0) {
        return;
      }
      if (mCompiledAny) {
        Write(Path(), Kept());
      }
      mChunks.clear();
      mCompiled.clear();
      mFile.clear();
      mFile.shrink_to_fit();
      mCompiledAny = false;
    }

    /**
     * Writes the batch's chunks without ending it, when it compiled anything since the last write and
     * has compiled nothing for a few seconds (on a helper thread, as the file is megabytes), or at once
     * with `now`. For the batch the main thread keeps open for as long as the user interface runs,
     * which never ends: the chunks the helper writes stay where they are (mFile, mCompiled).
     */
    void Flush(const bool now)
    {
      if (now && mWriter.joinable()) {
        mWriter.join();
      }
      std::vector<SKeptChunk> kept;
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        if (mBatches == 0 || !mCompiledAny || (!now && SteadyMs() - mLastCompiled < 3000U)) {
          return;
        }
        kept = Kept();
        mCompiledAny = false;
      }
      if (mWriter.joinable()) {
        mWriter.join();
      }
      if (now) {
        Write(Path(), kept);
      } else {
        mWriter = std::thread([path = Path(), kept = std::move(kept)] { Write(path, kept); });
      }
    }

    [[nodiscard]] bool Find(const SChunkKey& key, std::string& outCode)
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      const auto found = mChunks.find(key);
      if (found == mChunks.end()) {
        return false;
      }
      found->second.used = true;
      outCode.assign(found->second.code);
      return true;
    }

    [[nodiscard]] bool Contains(const SChunkKey& key)
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      return mChunks.find(key) != mChunks.end();
    }

    /// `used`: kept by the batch's loader, not ahead of it by a helper (which may compile a chunk the
    /// loader then asks for with other text, such as a hooked script).
    void Keep(const SChunkKey& key, std::string code, const bool used)
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      if (mBatches == 0) {
        return;
      }
      const auto found = mChunks.find(key);
      if (found != mChunks.end()) {
        found->second.used = found->second.used || used;
        return;
      }
      const std::string& kept = mCompiled.emplace_back(std::move(code));
      // One a helper compiled that its loader did not take is not written unless a loader takes it.
      mChunks.emplace(key, SCachedChunk{kept, used, used ? std::uint8_t{0} : kMaxIdleWrites});
      mCompiledAny = true;
      mLastCompiled = SteadyMs();
    }

  private:
    [[nodiscard]] std::string Path() const
    {
      const std::string& directory = gpg::LocalCacheDirectory();
      return directory.empty() ? std::string() : directory + mFileName;
    }

    // magic, executable identity, checksum of the rest, then per chunk: key (first, second, bytes),
    // the code's length, the writes since it was last used, then the code. A file whose checksum does
    // not match is not used at all.
    void Read()
    {
      const std::string path = Path();
      if (path.empty()) {
        return;
      }
      HANDLE const file = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      LARGE_INTEGER size{};
      bool ok = ::GetFileSizeEx(file, &size) && size.QuadPart >= static_cast<LONGLONG>(kHeaderBytes) && static_cast<std::uint64_t>(size.QuadPart) < kMaxFileBytes;
      if (ok) {
        mFile.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        ok = ::ReadFile(file, mFile.data(), static_cast<DWORD>(mFile.size()), &read, nullptr) && read == mFile.size();
      }
      ::CloseHandle(file);

      const std::uint64_t identity = gpg::ExecutableIdentity();
      if (!ok || std::memcmp(mFile.data(), kMagic, sizeof(kMagic)) != 0 ||
          std::memcmp(mFile.data() + sizeof(kMagic), &identity, sizeof(identity)) != 0) {
        mFile.clear();
        return;
      }
      if (const SChunkKey checksum = Checksum(Payload(mFile));
          std::memcmp(mFile.data() + sizeof(kMagic) + sizeof(identity), &checksum, sizeof(checksum)) != 0) {
        mFile.clear();
        return;
      }
      std::size_t offset = kHeaderBytes;
      while (offset + kEntryHeader <= mFile.size()) {
        SChunkKey key;
        std::uint64_t codeBytes = 0;
        std::uint8_t idleWrites = 0;
        std::memcpy(&key, mFile.data() + offset, sizeof(key));
        std::memcpy(&codeBytes, mFile.data() + offset + sizeof(key), sizeof(codeBytes));
        std::memcpy(&idleWrites, mFile.data() + offset + sizeof(key) + sizeof(codeBytes), sizeof(idleWrites));
        offset += kEntryHeader;
        if (codeBytes > mFile.size() - offset) {
          break;
        }
        const std::string_view code(mFile.data() + offset, static_cast<std::size_t>(codeBytes));
        mChunks.insert_or_assign(key, SCachedChunk{code, false, idleWrites});
        offset += static_cast<std::size_t>(codeBytes);
      }
    }

    static constexpr std::size_t kEntryHeader = sizeof(SChunkKey) + sizeof(std::uint64_t) + sizeof(std::uint8_t);

    /// What the next write keeps: what a batch used since the file was read, and what the file held
    /// that has not gone kMaxIdleWrites writes unused.
    [[nodiscard]] std::vector<SKeptChunk> Kept() const
    {
      std::vector<SKeptChunk> kept;
      kept.reserve(mChunks.size());
      for (const auto& [key, chunk] : mChunks) {
        const int idleWrites = chunk.used ? 0 : chunk.idleWrites + 1;
        if (idleWrites <= kMaxIdleWrites) {
          kept.push_back({key, chunk.code, static_cast<std::uint8_t>(idleWrites)});
        }
      }
      return kept;
    }

    static void Write(const std::string& path, const std::vector<SKeptChunk>& kept)
    {
      if (path.empty()) {
        return;
      }
      std::string out(kMagic, sizeof(kMagic));
      const std::uint64_t identity = gpg::ExecutableIdentity();
      out.append(reinterpret_cast<const char*>(&identity), sizeof(identity));
      out.append(sizeof(SChunkKey), '\0');
      for (const SKeptChunk& chunk : kept) {
        const std::uint64_t codeBytes = chunk.code.size();
        out.append(reinterpret_cast<const char*>(&chunk.key), sizeof(chunk.key));
        out.append(reinterpret_cast<const char*>(&codeBytes), sizeof(codeBytes));
        out.append(reinterpret_cast<const char*>(&chunk.idleWrites), sizeof(chunk.idleWrites));
        out.append(chunk.code);
      }
      const SChunkKey checksum = Checksum(Payload(out));
      std::memcpy(out.data() + sizeof(kMagic) + sizeof(identity), &checksum, sizeof(checksum));

      char suffix[32]{};
      std::snprintf(suffix, sizeof(suffix), ".%lu.tmp", static_cast<unsigned long>(::GetCurrentProcessId()));
      const std::string temporary = path + suffix;
      HANDLE const file = ::CreateFileA(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      DWORD written = 0;
      const bool ok = ::WriteFile(file, out.data(), static_cast<DWORD>(out.size()), &written, nullptr) && written == out.size();
      ::CloseHandle(file);
      std::error_code renamed;
      if (ok) {
        std::filesystem::rename(temporary, path, renamed); // replaces the old file, as MoveFileEx's REPLACE_EXISTING
      }
      if (!ok || renamed) {
        ::DeleteFileA(temporary.c_str());
      }
    }

    std::mutex mMutex;
    std::thread mWriter; // Flush's write; only the thread that flushes touches it
    int mBatches = 0;
    const char* mFileName;
    std::uint64_t mLastCompiled = 0;
    bool mCompiledAny = false;
    std::vector<char> mFile;
    std::deque<std::string> mCompiled;
    std::unordered_map<SChunkKey, SCachedChunk, SChunkKeyHash> mChunks;
  };

  /// Never destroyed: a batch may still be ending on a loader thread at exit.
  /// The session load's chunks (the loader thread's batches and the precompile helpers).
  [[nodiscard]] ScriptChunks& Chunks()
  {
    static ScriptChunks* const sChunks = new ScriptChunks("script-chunks.bin");
    return *sChunks;
  }

  /// Engine addition (res_UiScriptChunkCache): the user interface's chunks, which the main thread's
  /// batch keeps; a file of its own, so neither batch's write drops the other's chunks.
  [[nodiscard]] ScriptChunks& UiChunks()
  {
    static ScriptChunks* const sUiChunks = new ScriptChunks("ui-script-chunks.bin");
    return *sUiChunks;
  }

  thread_local int tBatchDepth = 0;
  thread_local ScriptChunks* tBatchChunks = nullptr; // the chunks this thread's batch loads from

  struct SWholeBuffer
  {
    std::string_view text;
    bool done = false;
  };

  const char* ReadWholeBuffer(lua_State* /*state*/, void* const userData, std::size_t* const outSize)
  {
    auto* const buffer = static_cast<SWholeBuffer*>(userData);
    if (buffer->done || buffer->text.empty()) {
      return nullptr;
    }
    buffer->done = true;
    *outSize = buffer->text.size();
    return buffer->text.data();
  }

  int AppendDump(lua_State* /*state*/, const void* const bytes, const std::size_t size, void* const userData)
  {
    static_cast<std::string*>(userData)->append(static_cast<const char*>(bytes), size);
    return 0;
  }

  /**
   * A chunk that is already compiled (a mod's precompiled script) starts with the signature's escape
   * byte, as lua_load tells them apart. Such a chunk is never kept: each load goes to the parser,
   * which logs it and refuses it when lua_AllowPrecompiledChunks is off.
   */
  [[nodiscard]] bool IsCompiledChunk(const std::string_view text) noexcept
  {
    return !text.empty() && text.front() == '\033';
  }

  [[nodiscard]] int LoadBuffer(lua_State* const state, const std::string_view text, const char* const chunkName)
  {
    SWholeBuffer buffer{text};
    return lua_load(state, reinterpret_cast<lua_Chunkreader>(ReadWholeBuffer), &buffer, chunkName);
  }

  [[nodiscard]] SChunkKey KeyOf(const char* const chunkName, const std::string_view source)
  {
    ChunkHasher hasher;
    hasher.Add(chunkName != nullptr ? std::string_view(chunkName) : std::string_view("?"));
    hasher.Add(source);
    return hasher.Key();
  }

  /**
   * Engine addition (`res_PrecompileScripts`): helpers that compile, each in a Lua state of its
   * own, the scripts a batch's DiskFindFiles listed, in the order listed, and keep them in the
   * batch's chunks for its doscript to find. Each compiles the text that doscript would load when
   * the script has no hooks: the file as mapped, and a newline when it does not end with one (the
   * loader's concat reader), under `@` and the file's path. A hooked script has other text, so the
   * loader compiles it itself. Stopped, with what is queued dropped, before the batch ends.
   */
  class Precompiler
  {
  public:
    void Add(const fa::vector<fa::string>& mountedPaths)
    {
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        for (const fa::string& path : mountedPaths) {
          const std::string_view name = path.view();
          if (name.ends_with(".bp") || name.ends_with(".lua")) {
            mQueue.emplace_back(name);
          }
        }
        if (mHelpers.empty() && !mQueue.empty()) {
          mStopping = false;
          const unsigned count = std::clamp(std::thread::hardware_concurrency() / 2U, 1U, 4U);
          for (unsigned index = 0; index < count; ++index) {
            mHelpers.emplace_back([this] { Run(); });
          }
        }
      }
      mWake.notify_all();
    }

    void Stop()
    {
      {
        const std::lock_guard<std::mutex> lock(mMutex);
        mStopping = true;
        mQueue.clear();
      }
      mWake.notify_all();
      for (std::thread& helper : mHelpers) {
        helper.join();
      }
      mHelpers.clear();
    }

  private:
    void Run()
    {
      gpg::SetThreadName(0xFFFFFFFFu, "Script precompile");
      platform::SetX87PrecisionControl(_PC_24); // as the loader thread, so number literals read alike
      const moho::CZipFileReadScope archiveReads;
      LuaPlus::LuaState compiler(LuaPlus::LuaState::LIB_BASE);
      lua::NameLuaVm(compiler.m_state, "Script precompile"); // diagnostics label only
      for (;;) {
        std::string mountedPath;
        {
          std::unique_lock<std::mutex> lock(mMutex);
          mWake.wait(lock, [this] { return mStopping || !mQueue.empty(); });
          if (mStopping) {
            return;
          }
          mountedPath = std::move(mQueue.front());
          mQueue.pop_front();
        }
        try {
          Compile(compiler.m_state, mountedPath);
        } catch (...) {
          // The loader compiles it itself and reports any failure.
        }
      }
    }

    static void Compile(lua_State* const state, const std::string& mountedPath)
    {
      moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
        return;
      }
      fa::string diskPath{};
      waitHandleSet->mHandle->FindFile(&diskPath, mountedPath.c_str(), nullptr);
      if (diskPath.empty()) {
        return;
      }
      const gpg::MemBuffer<const char> file = moho::DISK_MemoryMapFile(diskPath.c_str());
      if (file.mBegin == nullptr || file.mEnd == file.mBegin) {
        return;
      }
      std::string source(file.mBegin, file.mEnd);
      if (IsCompiledChunk(source)) {
        return; // never cached (IsCompiledChunk): doscript loads it as before
      }
      if (source.back() != '\n') {
        source += '\n';
      }
      const std::string chunkName = "@" + std::string(diskPath.view());
      const SChunkKey key = KeyOf(chunkName.c_str(), source);
      if (Chunks().Contains(key)) {
        return;
      }
      const int top = lua_gettop(state);
      std::string code;
      if (LoadBuffer(state, source, chunkName.c_str()) == 0 &&
          lua_dump(state, reinterpret_cast<lua_Chunkwriter>(AppendDump), &code) != 0) {
        Chunks().Keep(key, std::move(code), false);
      }
      lua_settop(state, top);
    }

    std::mutex mMutex;
    std::condition_variable mWake;
    std::deque<std::string> mQueue;
    std::vector<std::thread> mHelpers;
    bool mStopping = false;
  };

  /// Never destroyed, as Chunks().
  [[nodiscard]] Precompiler& Precompile()
  {
    static Precompiler* const sPrecompiler = new Precompiler();
    return *sPrecompiler;
  }
} // namespace

moho::ScriptChunkCacheBatch::ScriptChunkCacheBatch()
{
  if (tBatchDepth++ == 0 && res_ScriptChunkCache) {
    tBatchChunks = &Chunks();
    Chunks().Begin();
  }
}

moho::ScriptChunkCacheBatch::~ScriptChunkCacheBatch()
{
  if (--tBatchDepth == 0 && res_ScriptChunkCache && tBatchChunks == &Chunks()) {
    Precompile().Stop();
    Chunks().End();
    tBatchChunks = nullptr;
  }
}

void moho::SCR_BeginUiScriptChunkCache()
{
  if (CFG_GetArgOption("/nouichunkcache", 0, nullptr)) {
    res_UiScriptChunkCache = false; // read before /con runs, so the switch has a startup flag
  }
  if (tBatchDepth != 0 || !res_UiScriptChunkCache || !res_ScriptChunkCache) {
    return;
  }
  ++tBatchDepth; // never ended: written by SCR_FlushUiScriptChunkCache
  tBatchChunks = &UiChunks();
  UiChunks().Begin();
}

void moho::SCR_FlushUiScriptChunkCache(const bool now)
{
  UiChunks().Flush(now);
}

void moho::SCR_PrecompileScripts(const fa::vector<fa::string>& mountedPaths)
{
  if (SCR_ScriptChunkCacheActive() && res_PrecompileScripts && tBatchChunks == &Chunks()) {
    Precompile().Add(mountedPaths);
  }
}

bool moho::SCR_ScriptChunkCacheActive()
{
  return tBatchDepth > 0 && res_ScriptChunkCache && tBatchChunks != nullptr;
}

int moho::SCR_LoadScriptChunk(lua_State* const state, const std::string_view source, const char* const chunkName)
{
  if (IsCompiledChunk(source)) {
    return LoadBuffer(state, source, chunkName); // never cached, so the parser checks it each time
  }
  const SChunkKey key = KeyOf(chunkName, source);

  ScriptChunks& chunks = *tBatchChunks;
  std::string code;
  if (chunks.Find(key, code)) {
    const int top = lua_gettop(state);
    lua_LoadingCachedChunk = true;
    const int status = LoadBuffer(state, code, chunkName);
    lua_LoadingCachedChunk = false;
    if (status == 0) {
      return 0;
    }
    lua_settop(state, top); // a damaged entry: compile it again
  }

  const int status = LoadBuffer(state, source, chunkName);
  code.clear();
  if (status == 0 && lua_dump(state, reinterpret_cast<lua_Chunkwriter>(AppendDump), &code) != 0) {
    chunks.Keep(key, std::move(code), true);
  }
  return status;
}
