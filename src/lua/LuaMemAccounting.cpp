#include "lua/LuaMemAccounting.h"

#include <cstring>
#include <mutex>
#include <set>
#include <string>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"

namespace
{
  /// x86 payload sizes of the reflected value types FAF scripts wrap as
  /// userdata, keyed by reflected name. Pointer payloads need no entry
  /// (4 bytes on x86).
  struct LuaX86PayloadEntry
  {
    const char* typeName;
    lu_mem x86Size;
  };

  /// Found by running replay 26935800 with FAF_LUAGC_LOG=1 on x64 (every
  /// value type reaching luaS_newudata/luaS_newudata2); sizes are each
  /// type's x86 size assert.
  constexpr LuaX86PayloadEntry kLuaX86Payloads[] = {
    {"EntityCategory", 0x28u}, // EntityCategorySet, EntityCategoryReflection.h
    {"CPrefetchSet", 0x10u},   // CPrefetchSet.h
    {"WrapFile", 0x08u},       // LuaObject.cpp (io library file handle)
  };

  [[nodiscard]] lu_mem LookupX86PayloadSize(const gpg::RType* const type) noexcept
  {
    if (type->IsPointer() != nullptr) {
      return 4u;
    }

    const char* const name = type->GetName();
    for (const LuaX86PayloadEntry& entry : kLuaX86Payloads) {
      if (name != nullptr && std::strcmp(entry.typeName, name) == 0) {
        return entry.x86Size;
      }
    }

    // Unknown value type: account this build's size and say so once, so a
    // FAF_LUAGC_LOG comparison that drifts points at the missing entry.
    static std::mutex reportedLock;
    static std::set<std::string> reported;
    {
      const std::lock_guard<std::mutex> lock(reportedLock);
      if (reported.insert(name != nullptr ? name : "<unnamed>").second) {
        gpg::Warnf(
          "[LUAGC] userdata payload %s has no x86 size entry; accounting its %d-byte native size",
          name != nullptr ? name : "<unnamed>", type->size_
        );
      }
    }
    return static_cast<lu_mem>(type->size_);
  }
} // namespace

lu_mem LuaX86PayloadSize(const gpg::RType* const type) noexcept
{
  if (type == nullptr) {
    return 0u;
  }
#if defined(_M_IX86)
  return static_cast<lu_mem>(type->size_);
#else
  return LookupX86PayloadSize(type);
#endif
}

LuaBlockSize sizeudata(const gpg::RType* const type) noexcept
{
  const lu_mem payload = (type != nullptr) ? static_cast<lu_mem>(type->size_) : 0u;
  return {static_cast<lu_mem>(sizeof(Udata)) + payload, kLuaX86Size<Udata> + LuaX86PayloadSize(type)};
}
