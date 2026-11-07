#pragma once

#include <string_view>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct lua_State;

namespace moho
{
  /**
   * Engine addition (`res_ScriptChunkCache`): while one of these is alive, the thread loads each
   * script it runs (`doscript`, `import`, every blueprint) from compiled chunks kept in the shader
   * cache directory (`script-chunks.bin`), by the exact source text and chunk name, and compiles
   * and keeps what it does not find there. The outermost batch reads the file when it starts and,
   * if it compiled anything, writes back what the batch used when it ends.
   */
  class ScriptChunkCacheBatch
  {
  public:
    ScriptChunkCacheBatch();
    ~ScriptChunkCacheBatch();

    ScriptChunkCacheBatch(const ScriptChunkCacheBatch&) = delete;
    ScriptChunkCacheBatch& operator=(const ScriptChunkCacheBatch&) = delete;
  };

  /** Whether this thread is in a ScriptChunkCacheBatch and the cache is on. */
  [[nodiscard]] bool SCR_ScriptChunkCacheActive();

  /**
   * lua_load of `source` (the text exactly as the loader would stream it) under `chunkName`: the
   * function the parser would build is left on the stack, taken from the cache when it holds this
   * source and name, and otherwise compiled and kept. Returns lua_load's status; a source that does
   * not compile leaves its error, as lua_load does. Only inside a batch (SCR_ScriptChunkCacheActive).
   */
  [[nodiscard]] int SCR_LoadScriptChunk(lua_State* state, std::string_view source, const char* chunkName);

  /**
   * Engine addition (`res_PrecompileScripts`): hands the scripts (`.bp`, `.lua`) a `DiskFindFiles`
   * found to helpers that compile them into the batch's chunks ahead of their doscript, when this
   * thread is in a batch (SCR_ScriptChunkCacheActive).
   */
  void SCR_PrecompileScripts(const fa::vector<fa::string>& mountedPaths);

  /**
   * Engine addition (res_UiScriptChunkCache): opens a batch on this thread (the main thread, which
   * runs the user interface's scripts) that stays open, on a cache file of its own.
   */
  void SCR_BeginUiScriptChunkCache();

  /** Writes what the main thread's batch compiled, once it has compiled nothing for a few seconds, or at once with `now`. */
  void SCR_FlushUiScriptChunkCache(bool now);
} // namespace moho
