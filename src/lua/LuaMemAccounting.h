#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "lua/LuaRuntimeTypes.h"

namespace gpg
{
  class RType;
}

/**
 * Lua 5.0's allocator interface (lmem.h), with x86 byte accounting.
 *
 * The collector starts when `global_State::nblocks` reaches `GCthreshold`, and
 * the VM sizes its own objects, so on x64 - where every Lua object carrying a
 * pointer is bigger - `nblocks` grew faster and collections ran on different
 * beats than in the 2007 x86 binary. FAF's sim Lua keeps weak tables, whose
 * contents a collection changes, so collection timing is simulation state
 * (plan 4.1b).
 *
 * Every allocation therefore carries two sizes: the real one this build needs,
 * and the one the x86 binary allocated, which is what `nblocks` counts. On x86
 * the two are equal by construction (the asserts at the end of this header);
 * the x86 sizes come from the binary's allocation constants, cited per type.
 */

/// x86 byte size of one T as the 2007 binary allocates it. Every type the VM
/// allocates is listed, so a new one cannot silently fall back to its x64 size.
template <class T>
struct LuaX86Size;

template <class T>
struct LuaX86Size<T*> : std::integral_constant<lu_mem, 4u>
{};
template <>
struct LuaX86Size<char> : std::integral_constant<lu_mem, 1u>
{};
template <>
struct LuaX86Size<int> : std::integral_constant<lu_mem, 4u>
{};
template <>
struct LuaX86Size<Instruction> : std::integral_constant<lu_mem, 4u>
{};
/// `TObject`: tt + value, 8 bytes (luaD_reallocstack/luaH_resize scale by 8).
template <>
struct LuaX86Size<LuaPlus::TObject> : std::integral_constant<lu_mem, 0x08u>
{};
/// luaH_new / setnodevector: node array stride 0x14.
template <>
struct LuaX86Size<Node> : std::integral_constant<lu_mem, 0x14u>
{};
/// luaH_new (0x00927320): `push 24h`.
template <>
struct LuaX86Size<Table> : std::integral_constant<lu_mem, 0x24u>
{};
/// Userdata header; the payload follows at +0x10 (LuaObject::GetUserData 0x00907BC0).
template <>
struct LuaX86Size<Udata> : std::integral_constant<lu_mem, 0x10u>
{};
template <>
struct LuaX86Size<LocVar> : std::integral_constant<lu_mem, 0x0Cu>
{};
/// luaF_newproto (0x00915010): `push 70h`.
template <>
struct LuaX86Size<Proto> : std::integral_constant<lu_mem, 0x70u>
{};
/// luaF_newupval (0x00914F40): `push 14h`.
template <>
struct LuaX86Size<UpVal> : std::integral_constant<lu_mem, 0x14u>
{};
template <>
struct LuaX86Size<CallInfo> : std::integral_constant<lu_mem, 0x28u>
{};
/// f_luaopen (0x00924470): `luaM_realloc(&thread, 0, 0, 0x160)`.
template <>
struct LuaX86Size<global_State> : std::integral_constant<lu_mem, 0x160u>
{};
/// lua_open / luaE_newthread: `push 48h`.
template <>
struct LuaX86Size<lua_State> : std::integral_constant<lu_mem, 0x48u>
{};

template <class T>
inline constexpr lu_mem kLuaX86Size = LuaX86Size<T>::value;

/// newlstr (0x00924860): `lea eax, [ebp+15h]` = 0x14-byte header + len + NUL.
inline constexpr lu_mem kLuaX86TStringHeader = 0x14u;
/// luaF_newCclosure (0x00914E90): `lea eax, [ebx*8+40h]`.
inline constexpr lu_mem kLuaX86CClosureHeader = 0x40u;
/// luaF_newLclosure (0x00914EF0): `lea eax, [ebx*4+1Ch]`.
inline constexpr lu_mem kLuaX86LClosureHeader = 0x1Cu;

/// `luaC_checkGC`'s gate (plan 4.2). The binary compares the two counters as
/// 32-bit unsigned words (`jb`, 0x00913F06..0x00913F12). They hold x86 byte
/// counts on every build, and comparing their low 32 bits keeps the binary's
/// wraparound and its 0xFFFFFFFF "never" threshold (lua_setgcthreshold) exactly.
[[nodiscard]] inline bool LuaGcThresholdReached(const global_State* const globalState) noexcept
{
  return static_cast<std::uint32_t>(globalState->nblocks) >= static_cast<std::uint32_t>(globalState->GCthreshold);
}

/// One block's real size and the size the x86 binary allocated for it.
struct LuaBlockSize
{
  lu_mem real;
  lu_mem accounted;
};

/// lstring.h `sizestring(l)`.
[[nodiscard]] constexpr LuaBlockSize sizestring(const std::size_t length) noexcept
{
  return {static_cast<lu_mem>(offsetof(TString, str) + length + 1u),
          static_cast<lu_mem>(kLuaX86TStringHeader + length + 1u)};
}

/// lfunc.h `sizeCclosure(n)`: the header plus n upvalue TObjects.
[[nodiscard]] constexpr LuaBlockSize sizeCclosure(const int upvalueCount) noexcept
{
  return {static_cast<lu_mem>(offsetof(CClosure, upvalue) + sizeof(LuaPlus::TObject) * upvalueCount),
          static_cast<lu_mem>(kLuaX86CClosureHeader + kLuaX86Size<LuaPlus::TObject> * upvalueCount)};
}

/// lfunc.h `sizeLclosure(n)`: the header plus n UpVal pointers.
[[nodiscard]] constexpr LuaBlockSize sizeLclosure(const int upvalueCount) noexcept
{
  return {static_cast<lu_mem>(offsetof(LClosure, upvals) + sizeof(UpVal*) * upvalueCount),
          static_cast<lu_mem>(kLuaX86LClosureHeader + kLuaX86Size<UpVal*> * upvalueCount)};
}

/// lstring.h `sizeudata(l)` for this fork, whose userdata carries a reflected
/// payload of `type` (null for `newproxy`'s empty userdata). The accounted
/// payload is the type's x86 size: see `LuaX86PayloadSize`.
[[nodiscard]] LuaBlockSize sizeudata(const gpg::RType* type) noexcept;

/// The x86 byte size of a reflected userdata payload.
[[nodiscard]] lu_mem LuaX86PayloadSize(const gpg::RType* type) noexcept;

extern "C"
{
  /**
   * Address: 0x0091A240 (FUN_0091A240, luaM_realloc)
   *
   * IDA signature:
   * void *__cdecl luaM_realloc(lua_State *L, void *block, lu_mem oldsize, lu_mem size);
   *
   * `accountedOldSize`/`accountedSize` (not in the binary) are what `nblocks`
   * moves by; see the top of this header.
   */
  void* luaM_realloc(
    lua_State* L, void* block, lu_mem oldsize, lu_mem size, lu_mem accountedOldSize, lu_mem accountedSize
  );

  /**
   * Address: 0x0091A310 (FUN_0091A310, luaM_growaux)
   *
   * IDA signature:
   * void *__cdecl luaM_growaux(lua_State *L, void *block, int *size, int size_elems, int limit, char *what);
   *
   * `accountedSizeElems` (not in the binary) is the element's x86 size.
   */
  void* luaM_growaux(
    lua_State* L, void* block, int* size, int sizeElems, int accountedSizeElems, int limit, const char* what
  );
}

/// One block resized from `oldSize` to `newSize`.
inline void* luaM_reallocblock(
  lua_State* const L, void* const block, const LuaBlockSize oldSize, const LuaBlockSize newSize
)
{
  return luaM_realloc(L, block, oldSize.real, newSize.real, oldSize.accounted, newSize.accounted);
}

/// lmem.h `luaM_new(L, t)`.
template <class T>
[[nodiscard]] T* luaM_new(lua_State* const L)
{
  return static_cast<T*>(luaM_realloc(L, nullptr, 0u, sizeof(T), 0u, kLuaX86Size<T>));
}

/// lmem.h `luaM_freelem(L, b)`.
template <class T>
void luaM_freelem(lua_State* const L, T* const block)
{
  (void)luaM_realloc(L, block, sizeof(T), 0u, kLuaX86Size<T>, 0u);
}

/// lmem.h `luaM_reallocvector(L, v, oldn, n, t)`.
template <class T>
[[nodiscard]] T* luaM_reallocvector(lua_State* const L, T* const block, const lu_mem oldCount, const lu_mem newCount)
{
  return static_cast<T*>(luaM_realloc(
    L, block, sizeof(T) * oldCount, sizeof(T) * newCount, kLuaX86Size<T> * oldCount, kLuaX86Size<T> * newCount
  ));
}

/// lmem.h `luaM_newvector(L, n, t)`.
template <class T>
[[nodiscard]] T* luaM_newvector(lua_State* const L, const lu_mem count)
{
  return luaM_reallocvector<T>(L, nullptr, 0u, count);
}

/// lmem.h `luaM_freearray(L, b, n, t)`.
template <class T>
void luaM_freearray(lua_State* const L, T* const block, const lu_mem count)
{
  (void)luaM_reallocvector<T>(L, block, count, 0u);
}

/// lmem.h `luaM_growvector(L, v, nelems, size, t, limit, e)`: grows `block`
/// through luaM_growaux when `count + 1` no longer fits in `capacity`.
template <class T>
void luaM_growvector(
  lua_State* const L, T*& block, const int count, int& capacity, const int limit, const char* const what
)
{
  if (count + 1 > capacity) {
    block = static_cast<T*>(luaM_growaux(
      L, block, &capacity, static_cast<int>(sizeof(T)), static_cast<int>(kLuaX86Size<T>), limit, what
    ));
  }
}

#if defined(_M_IX86)
// On x86 every accounted size is the real size, so x86 behaviour cannot drift.
static_assert(kLuaX86Size<LuaPlus::TObject> == sizeof(LuaPlus::TObject));
static_assert(kLuaX86Size<Node> == sizeof(Node));
static_assert(kLuaX86Size<Table> == sizeof(Table));
static_assert(kLuaX86Size<Udata> == sizeof(Udata));
static_assert(kLuaX86Size<LocVar> == sizeof(LocVar));
static_assert(kLuaX86Size<Proto> == sizeof(Proto));
static_assert(kLuaX86Size<UpVal> == sizeof(UpVal));
static_assert(kLuaX86Size<CallInfo> == sizeof(CallInfo));
static_assert(kLuaX86Size<global_State> == sizeof(global_State));
static_assert(kLuaX86Size<lua_State> == sizeof(lua_State));
static_assert(kLuaX86Size<GCObject*> == sizeof(GCObject*));
static_assert(kLuaX86TStringHeader == offsetof(TString, str));
static_assert(kLuaX86CClosureHeader == offsetof(CClosure, upvalue));
static_assert(kLuaX86LClosureHeader == offsetof(LClosure, upvals));
#endif
