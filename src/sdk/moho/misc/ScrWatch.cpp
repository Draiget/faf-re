#include "moho/misc/ScrWatch.h"

#include <new>
#include <sstream>

namespace moho
{
  namespace
  {
    [[nodiscard]] int GetLuaTypeTag(const LuaPlus::LuaObject& valueObject) noexcept
    {
      return valueObject.m_object.tt;
    }

    [[nodiscard]] const char* GetLuaTypeName(const int typeTag) noexcept
    {
      switch (typeTag) {
        case LUA_TNIL:
          return "nil";
        case LUA_TBOOLEAN:
          return "boolean";
        case LUA_TLIGHTUSERDATA:
          return "lightuserdata";
        case LUA_TNUMBER:
          return "number";
        case LUA_TSTRING:
          return "string";
        case LUA_TTABLE:
          return "table";
        case LUA_CFUNCTION:
        case LUA_TFUNCTION:
          return "function";
        case LUA_TUSERDATA:
          return "userdata";
        case LUA_TTHREAD:
          return "thread";
        case LUA_TPROTO:
          return "proto";
        case LUA_TUPVALUE:
          return "upvalue";
        default:
          return "<unknown>";
      }
    }

    /**
     * Address: 0x004B9070 (FUN_004B9070)
     *
     * What it does:
     * Executes one deleting-destructor thunk lane for `ScrWatch` by
     * running teardown and conditionally freeing storage.
     */
    [[maybe_unused]] ScrWatch* DestructScrWatchDeleting(
      ScrWatch* const self,
      const unsigned char deleteFlag
    ) noexcept
    {
      self->~ScrWatch();
      if ((deleteFlag & 1U) != 0U) {
        ::operator delete(static_cast<void*>(self));
      }
      return self;
    }
  } // namespace

  /**
   * Address: 0x004D6AE0 (FUN_004D6AE0, Moho::ScrWatch::ScrWatch)
   *
   * What it does:
   * Initializes one watch entry with empty name and default Lua object payload.
   */
  ScrWatch::ScrWatch()
    : name()
    , obj()
  {
  }

  /**
   * Address: 0x004D6B30 (FUN_004D6B30, Moho::ScrWatch::ScrWatch)
   *
   * msvc8::string const &,LuaPlus::LuaObject const &
   *
   * What it does:
   * Initializes one watch entry from copied display-name and Lua object lanes.
   */
  ScrWatch::ScrWatch(const msvc8::string& watchName, const LuaPlus::LuaObject& valueObject)
    : name()
    , obj(valueObject)
  {
    name.assign(watchName, 0U, msvc8::string::npos);
  }

  /**
   * Address: 0x004BA710 (FUN_004BA710, Moho::ScrWatch::operator=)
   *
   * What it does:
   * Rebinds one watch object to copied name and Lua value lanes.
   */
  ScrWatch& ScrWatch::operator=(const ScrWatch& other)
  {
    if (this == &other) {
      return *this;
    }

    name.assign(other.name, 0U, msvc8::string::npos);
    obj = other.obj;
    return *this;
  }

  /**
   * Address: 0x004D6B70 (FUN_004D6B70, Moho::ScrWatch::~ScrWatch)
   */
  ScrWatch::~ScrWatch() = default;

  /**
   * Address: 0x004D6BE0 (FUN_004D6BE0, Moho::ScrWatch::GetType)
   *
   * What it does:
   * Returns one printable Lua type-name lane for this watch value object.
   */
  msvc8::string ScrWatch::GetType() const
  {
    msvc8::string typeName{};
    typeName.assign_owned(GetLuaTypeName(GetLuaTypeTag(obj)));
    return typeName;
  }

  /**
   * Address: 0x004D6C30 (FUN_004D6C30, Moho::ScrWatch::GetValue)
   *
   * What it does:
   * Formats one printable Lua value lane for this watch entry.
   */
  msvc8::string ScrWatch::GetValue() const
  {
    msvc8::string valueText{};

    switch (GetLuaTypeTag(obj)) {
      case LUA_TBOOLEAN:
        valueText.assign_owned(obj.GetBoolean() ? "true" : "false");
        break;

      case LUA_TNUMBER: {
        std::ostringstream numberStream{};
        numberStream << static_cast<float>(obj.GetNumber());
        const std::string formattedNumber = numberStream.str();
        valueText.assign_owned(formattedNumber);
        break;
      }

      case LUA_TSTRING:
        valueText.assign_owned(obj.GetString());
        break;

      case LUA_TNIL:
      case LUA_TLIGHTUSERDATA:
      case LUA_TTABLE:
      case LUA_CFUNCTION:
      case LUA_TFUNCTION:
        valueText.clear();
        break;

      default:
        valueText.assign_owned("<unknown>");
        break;
    }

    return valueText;
  }
} // namespace moho
