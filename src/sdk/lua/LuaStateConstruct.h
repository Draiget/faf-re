#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
} // namespace gpg

namespace LuaPlus
{
  /**
   * VFTABLE: 0x00D44F70
   * COL: 0x00E518C0
   */
  class LuaStateConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920C70 (FUN_00920C70, lua_StateConstruct::Construct)
     *
     * What it does:
     * Reads one ownership flag from the archive and either aliases the owner
     * lua state as unowned or allocates one child thread and returns it owned.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(LuaStateConstruct, vftable_) == 0x00, "LuaStateConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LuaStateConstruct, mNext) == 0x04, "LuaStateConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LuaStateConstruct, mPrev) == 0x08, "LuaStateConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LuaStateConstruct, mConstruct) == 0x0C, "LuaStateConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LuaStateConstruct) == 0x10, "LuaStateConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00D44F90
   * COL: 0x00E518E0
   */
  class LClosureConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920A80 (FUN_00920A80, LClosureConstruct::Construct)
     *
     * What it does:
     * Reads one upvalue-count lane from the archive, allocates one new Lua
     * closure bound to the owner thread globals table, and returns it owned.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(LClosureConstruct, vftable_) == 0x00, "LClosureConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LClosureConstruct, mNext) == 0x04, "LClosureConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LClosureConstruct, mPrev) == 0x08, "LClosureConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LClosureConstruct, mConstruct) == 0x0C, "LClosureConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LClosureConstruct) == 0x10, "LClosureConstruct size must be 0x10");

  class UpValConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920B10 (FUN_00920B10, UpValConstruct::Construct)
     *
     * What it does:
     * Allocates one open upvalue lane in the owner Lua state and returns it as
     * an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(UpValConstruct, vftable_) == 0x00, "UpValConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(UpValConstruct, mNext) == 0x04, "UpValConstruct::mNext offset must be 0x04");
  static_assert(offsetof(UpValConstruct, mPrev) == 0x08, "UpValConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(UpValConstruct, mConstruct) == 0x0C, "UpValConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(UpValConstruct) == 0x10, "UpValConstruct size must be 0x10");

  class ProtoConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920C20 (FUN_00920C20, ProtoConstruct::Construct)
     *
     * What it does:
     * Allocates one empty Lua function prototype in the owner Lua state and
     * returns it as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(ProtoConstruct, vftable_) == 0x00, "ProtoConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(ProtoConstruct, mNext) == 0x04, "ProtoConstruct::mNext offset must be 0x04");
  static_assert(offsetof(ProtoConstruct, mPrev) == 0x08, "ProtoConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(ProtoConstruct, mConstruct) == 0x0C, "ProtoConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(ProtoConstruct) == 0x10, "ProtoConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00D44F80
   * COL: 0x00E518D0
   */
  class UdataConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

    /**
     * Address: 0x00920D30 (FUN_00920D30, UdataConstruct::Construct)
     *
     * What it does:
     * Reads one userdata payload type-handle, allocates one typed Lua userdata
     * object in the owner Lua state, and returns it as an owned construct ref.
     */
    static void Construct(gpg::ReadArchive* archive, int version, gpg::RRef* ref, gpg::SerConstructResult* result);

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(UdataConstruct, vftable_) == 0x00, "UdataConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(UdataConstruct, mNext) == 0x04, "UdataConstruct::mNext offset must be 0x04");
  static_assert(offsetof(UdataConstruct, mPrev) == 0x08, "UdataConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(UdataConstruct, mConstruct) == 0x0C, "UdataConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(UdataConstruct) == 0x10, "UdataConstruct size must be 0x10");
} // namespace LuaPlus
