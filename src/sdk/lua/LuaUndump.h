#pragma once

#include <cstddef>

#include "lua/LuaRuntimeTypes.h"

/**
 * The buffered input stream the lexer and the bytecode loader both read
 * through - upstream's `ZIO`, from `lzio.h`.
 *
 * The reader callback hands back a whole block at a time; `remainingBytes`
 * and `cursor` walk it, and `luaZ_fill` calls the reader again when it runs
 * out. Layout is `luaZ_init` (0x0092BA10), which takes (z, reader, data,
 * name) and writes exactly:
 *
 *   mov [eax+0x08], ecx   reader
 *   mov [eax+0x0C], edx   readerData
 *   mov [eax+0x10], ecx   chunkName
 *   mov [eax+0x00], 0     remainingBytes
 *   mov [eax+0x04], 0     cursor
 *
 * `remainingBytes` is unsigned, not an int: `luaZ_read` (0x0092BA40) picks
 * this block's contribution with `cmp ebx, edi` / `ja` at 0x0092BA9D, an
 * unsigned compare of the requested count against it. Upstream types it
 * `size_t` for the same reason.
 *
 * Field names here stay descriptive rather than upstream's one-letter
 * `n`/`p`/`b`; the structures are the same, only the spelling differs.
 */
struct ZIO
{
	std::size_t remainingBytes; // +0x00  ZIO::n      bytes left in this block
	const char* cursor;         // +0x04  ZIO::p      read position within it
	lua_Chunkreader reader;     // +0x08  ZIO::reader block source
	void* readerData;           // +0x0C  ZIO::data   reader's own context
	const char* chunkName;      // +0x10  ZIO::name   for error messages
};

static_assert(offsetof(ZIO, remainingBytes) == 0x00, "ZIO::remainingBytes offset must be 0x00");
static_assert(offsetof(ZIO, cursor) == 0x04, "ZIO::cursor offset must be 0x04");
static_assert(offsetof(ZIO, reader) == 0x08, "ZIO::reader offset must be 0x08");
static_assert(offsetof(ZIO, readerData) == 0x0C, "ZIO::readerData offset must be 0x0C");
static_assert(offsetof(ZIO, chunkName) == 0x10, "ZIO::chunkName offset must be 0x10");
static_assert(sizeof(ZIO) == 0x14, "ZIO size must be 0x14");

/// End-of-stream sentinel the reader lane returns (upstream's `EOZ`).
constexpr int kLuaEndOfStream = -1;

/**
 * Everything the binary-chunk loader threads through its sub-loaders -
 * upstream's `LoadState`, private to `lundump.c` there but shared here
 * because `luaU_undump` lives in LuaParser.cpp while the sub-loaders it
 * drives are recovered in LuaObject.cpp.
 *
 * `swapBytes` is set when the chunk's endianness does not match the host,
 * and every multi-byte read flips accordingly.
 */
struct LoadState
{
	lua_State* state;       // +0x00  LoadState::L
	ZIO* stream;            // +0x04  LoadState::Z
	Mbuffer* scratchBuffer; // +0x08  LoadState::b
	int swapBytes;          // +0x0C  LoadState::swap
	const char* chunkName;  // +0x10  LoadState::name
};

static_assert(offsetof(LoadState, state) == 0x00, "LoadState::state offset must be 0x00");
static_assert(offsetof(LoadState, stream) == 0x04, "LoadState::stream offset must be 0x04");
static_assert(offsetof(LoadState, scratchBuffer) == 0x08, "LoadState::scratchBuffer offset must be 0x08");
static_assert(offsetof(LoadState, swapBytes) == 0x0C, "LoadState::swapBytes offset must be 0x0C");
static_assert(offsetof(LoadState, chunkName) == 0x10, "LoadState::chunkName offset must be 0x10");
static_assert(sizeof(LoadState) == 0x14, "LoadState size must be 0x14");

namespace LuaPlus
{
	// Binary-chunk loader entry points, recovered in LuaObject.cpp alongside
	// the file-private sub-loaders they drive. External linkage so
	// `luaU_undump` in LuaParser.cpp can invoke them by name.
	void LuaLoadChunkHeader(LoadState* loadState);
	Proto* LuaLoadProtoObject(LoadState* loadState, TString* fallbackSource);
}
