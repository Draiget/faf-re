#pragma once

#include <cstddef>
#include <cstdint>

#include "CTask.h"
#include "CTaskEvent.h"
#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  class CWaitForTask : public CTask, public InstanceCounter<CWaitForTask>
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
     * Address: 0x004CA500 (FUN_004CA500, scalar deleting thunk)
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
     * Address: 0x004CA750 (FUN_004CA750)
     *
     * What it does:
     * Builds a new `CWaitForTask` for an archive load and hands it back unowned; its
     * members are loaded over it afterwards.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

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

  class CWaitForTaskSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC62E0 (FUN_00BC62E0, dynamic initializer for the global
     * `CWaitForTaskSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CWaitForTaskSerializer();

    /**
     * Address: 0x00BF0C40 (FUN_00BF0C40, Moho::CWaitForTaskSerializer::~CWaitForTaskSerializer)
     */
    ~CWaitForTaskSerializer();

    /**
     * Address: 0x004CA7E0 (FUN_004CA7E0, CWaitForTaskSerializer::Deserialize callback)
     * Chain:   0x004CC3B0 (FUN_004CC3B0)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004CA7F0 (FUN_004CA7F0, CWaitForTaskSerializer::Serialize callback)
     * Chain:   0x004CC460 (FUN_004CC460)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004CB230 (FUN_004CB230, sub_4CB230)
     *
     * What it does:
     * Binds load/save serializer callbacks into CWaitForTask RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  static_assert(
    offsetof(CWaitForTaskSerializer, mSerLoadFunc) == 0x0C, "CWaitForTaskSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CWaitForTaskSerializer, mSerSaveFunc) == 0x10, "CWaitForTaskSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(CWaitForTaskSerializer) == 0x14, "CWaitForTaskSerializer size must be 0x14");

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
  static_assert(sizeof(CWaitForTaskTypeInfo) == 0x64, "CWaitForTaskTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC6280 (FUN_00BC6280, CWaitForTask startup type-info registration)
   *
   * What it does:
   * Pre-registers `CWaitForTask` reflected type metadata.
   */
  void register_CWaitForTaskTypeInfo();
} // namespace moho
