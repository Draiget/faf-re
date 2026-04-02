#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "lua/LuaObject.h"

namespace moho
{
  class ScrWatch
  {
  public:
    /**
     * Address: 0x004D6AE0 (FUN_004D6AE0, Moho::ScrWatch::ScrWatch)
     *
     * What it does:
     * Initializes one watch entry with empty name and nil Lua object payload.
     */
    ScrWatch();

    /**
     * Address: 0x004D6B30 (FUN_004D6B30, Moho::ScrWatch::ScrWatch)
     *
     * msvc8::string const &,LuaPlus::LuaObject const &
     *
     * What it does:
     * Initializes one watch entry from display-name text and Lua value object.
     */
    ScrWatch(const msvc8::string& watchName, const LuaPlus::LuaObject& valueObject);

    /**
     * Address: 0x004BA710 (FUN_004BA710, Moho::ScrWatch::operator=)
     *
     * What it does:
     * Rebinds one watch object to copied name and Lua value lanes.
     */
    ScrWatch& operator=(const ScrWatch& other);

    /**
     * Address: 0x004D6B70 (FUN_004D6B70, Moho::ScrWatch::~ScrWatch)
     *
     * What it does:
     * Releases Lua object ownership and tears down watch name storage.
     */
    virtual ~ScrWatch();

    /**
     * Address: 0x004D6BE0 (FUN_004D6BE0, Moho::ScrWatch::GetType)
     *
     * What it does:
     * Returns one printable Lua type-name lane for this watch value object.
     */
    [[nodiscard]] msvc8::string GetType() const;

    /**
     * Address: 0x004D6C30 (FUN_004D6C30, Moho::ScrWatch::GetValue)
     *
     * What it does:
     * Formats one printable Lua value lane for this watch entry.
     */
    [[nodiscard]] msvc8::string GetValue() const;

  public:
    msvc8::string name; // +0x04
    LuaPlus::LuaObject obj; // +0x20
  };

  static_assert(offsetof(ScrWatch, name) == 0x04, "ScrWatch::name offset must be 0x04");
  static_assert(offsetof(ScrWatch, obj) == 0x20, "ScrWatch::obj offset must be 0x20");
  static_assert(sizeof(ScrWatch) == 0x34, "ScrWatch size must be 0x34");
} // namespace moho
