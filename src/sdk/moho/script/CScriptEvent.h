#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTaskEvent.h"

namespace moho
{
  class CScriptEvent : public CTaskEvent, public CScriptObject
  {
  public:
    /**
     * Address: 0x004C9420 (FUN_004C9420, ??0CScriptEvent@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs task-event and script-object subobjects, then installs
     * CScriptEvent vtables for both base views.
     */
    CScriptEvent();

    /**
     * Address: 0x004C94A0 (scalar deleting thunk)
     * Address: 0x004C94C0 (FUN_004C94C0, ??1CScriptEvent@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0
     */
    ~CScriptEvent() override;

    /**
     * Address: 0x004C93E0 (FUN_004C93E0, ?GetClass@CScriptEvent@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x004C9400 (FUN_004C9400, ?GetDerivedObjectRef@CScriptEvent@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

  public:
    static gpg::RType* sType;
  };

  class CScriptEventSerializer
  {
  public:
    /**
     * Address: 0x004CB0A0 (FUN_004CB0A0, sub_4CB0A0)
     * Slot: 0
     *
     * What it does:
     * Binds CScriptEvent serializer callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CScriptEventTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004CA1D0 (FUN_004CA1D0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CScriptEventTypeInfo() override;

    /**
     * Address: 0x004CA1C0 (FUN_004CA1C0, ?GetName@CScriptEventTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004CA170 (FUN_004CA170, ?Init@CScriptEventTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x004C8270 (FUN_004C8270, func_GetCObj_CScriptObject)
   *
   * What it does:
   * Resolves `_c_object` from Lua userdata/table payload and returns the
   * underlying CScriptObject pointer.
   */
  [[nodiscard]]
  CScriptObject* SCR_GetScriptObjectFromLuaObject(const LuaPlus::LuaObject& object);

  /**
   * Address: 0x004C9030 (FUN_004C9030, func_RRefCScriptObject)
   *
   * What it does:
   * Builds an RTTI-aware `gpg::RRef` for a CScriptObject pointer.
   */
  [[nodiscard]]
  gpg::RRef SCR_MakeScriptObjectRef(CScriptObject* object);

  /**
   * Address: 0x004CBE30 (FUN_004CBE30, func_UpCastCScriptEventUnsafe)
   *
   * What it does:
   * Upcasts an arbitrary object reference to CScriptEvent and returns null
   * when cast fails.
   */
  [[nodiscard]]
  CScriptEvent* SCR_UpCastScriptEventUnsafe(const gpg::RRef& source);

  /**
   * Address: 0x004CB980 (FUN_004CB980, sub_4CB980)
   *
   * What it does:
   * Converts Lua payload object to CScriptEvent by chaining script-object
   * extraction and RTTI upcast.
   */
  [[nodiscard]]
  CScriptEvent* SCR_GetScriptEventFromLuaObject(const LuaPlus::LuaObject& object);

  static_assert(sizeof(CScriptEvent) == 0x44, "CScriptEvent size must be 0x44");
  static_assert(sizeof(CScriptEventSerializer) == 0x14, "CScriptEventSerializer size must be 0x14");
  static_assert(sizeof(CScriptEventTypeInfo) == 0x64, "CScriptEventTypeInfo size must be 0x64");
} // namespace moho
