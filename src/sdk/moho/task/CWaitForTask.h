#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "CTaskEvent.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"

namespace moho
{
  class CWaitForTask : public CTask
  {
  public:
    /**
     * Address: 0x004CA470 (FUN_004CA470, sub_4CA470)
     *
     * What it does:
     * Default-constructs a wait task with empty linkage and empty Lua payload.
     */
    CWaitForTask();

    /**
     * Address: 0x004CA520 (FUN_004CA520, ??0CWaitForTask@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
     *
     * What it does:
     * Constructs a wait task and copies the Lua payload object to watch.
     */
    explicit CWaitForTask(const LuaPlus::LuaObject& payload);

    /**
     * Address: 0x004CA500 (scalar deleting thunk)
     * Address: 0x004CA5B0 (FUN_004CA5B0, sub_4CA5B0)
     *
     * VFTable SLOT: 0
     */
    ~CWaitForTask() override;

    /**
     * Address: 0x004CA660 (FUN_004CA660, ?Execute@CWaitForTask@Moho@@UAEHXZ)
     *
     * What it does:
     * Resolves a script event from Lua payload, registers wait-link on that
     * event, and keeps yielding while the weak-link owner slot remains active.
     */
    int Execute() override;

    /**
     * Address: 0x004CC3B0 (FUN_004CC3B0, Moho::CWaitForTask::MemberSerialize in export label)
     *
     * What it does:
     * Loads base `CTask`, wait-link weak pointer, and Lua payload object from archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004CC460 (FUN_004CC460, Moho::CWaitForTask::MemberDeserialize in export label)
     *
     * What it does:
     * Saves base `CTask`, wait-link weak pointer, and Lua payload object to archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

  public:
    // 0x18: reserved/unknown dword (constructors 0x004CA470/0x004CA520 do not initialize it).
    std::uint32_t mReserved18;
    WeakPtr<STaskEventLinkage> mEventLinkRef; // 0x1C
    LuaPlus::LuaObject mEventObject;          // 0x24
  };

  class CWaitForTaskConstruct
  {
  public:
    /**
     * Address: 0x004CB1B0 (FUN_004CB1B0, sub_4CB1B0)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into CWaitForTask RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CWaitForTaskSerializer
  {
  public:
    /**
     * Address: 0x004CB230 (FUN_004CB230, sub_4CB230)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CWaitForTask RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CWaitForTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004CA3C0 (FUN_004CA3C0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CWaitForTaskTypeInfo() override;

    /**
     * Address: 0x004CA3B0 (FUN_004CA3B0, ?GetName@CWaitForTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004CA390 (FUN_004CA390, ?Init@CWaitForTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CWaitForTask) == 0x38, "CWaitForTask size must be 0x38");
  static_assert(offsetof(CWaitForTask, mReserved18) == 0x18, "CWaitForTask::mReserved18 offset must be 0x18");
  static_assert(offsetof(CWaitForTask, mEventLinkRef) == 0x1C, "CWaitForTask::mEventLinkRef offset must be 0x1C");
  static_assert(offsetof(CWaitForTask, mEventObject) == 0x24, "CWaitForTask::mEventObject offset must be 0x24");
  static_assert(sizeof(CWaitForTaskConstruct) == 0x14, "CWaitForTaskConstruct size must be 0x14");
  static_assert(sizeof(CWaitForTaskSerializer) == 0x14, "CWaitForTaskSerializer size must be 0x14");
  static_assert(sizeof(CWaitForTaskTypeInfo) == 0x64, "CWaitForTaskTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC6280 (FUN_00BC6280, CWaitForTask startup type-info registration)
   *
   * What it does:
   * Pre-registers `CWaitForTask` reflected type metadata and schedules
   * type-info cleanup at process exit.
   */
  void register_CWaitForTaskTypeInfo();

  /**
   * Address: 0x00BC62A0 (FUN_00BC62A0, CWaitForTask startup construct registration)
   *
   * What it does:
   * Initializes construct/delete callback helper lanes for `CWaitForTask` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CWaitForTaskConstruct();

  /**
   * Address: 0x00BC62E0 (FUN_00BC62E0, register_CWaitForTaskSerializer)
   *
   * What it does:
   * Initializes startup serializer callback lanes for `CWaitForTask` and
   * schedules intrusive helper cleanup at process exit.
   */
  void register_CWaitForTaskSerializer();

  /**
     * Address: 0x004CA830 (FUN_004CA830)
     * Address: 0x004CA860 (FUN_004CA860)
   *
   * What it does:
   * Unlinks static serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CWaitForTaskSerializer();
} // namespace moho
