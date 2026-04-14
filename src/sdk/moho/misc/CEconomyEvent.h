#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "lua/LuaObject.h"
#include "moho/containers/TDatList.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptEvent.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Runtime economy pair used by CEconomyEvent serializers and transfer logic.
   *
   * Address context:
   * - 0x00776140 (FUN_00776140): serialized as one reflected value at +0x54.
   * - 0x00776010 (FUN_00776010): deserialized into +0x54.
   */
  struct SEconValue
  {
    float energy;
    float mass;

    static gpg::RType* sType;
  };
  static_assert(sizeof(SEconValue) == 0x08, "SEconValue size must be 0x08");
  static_assert(offsetof(SEconValue, energy) == 0x00, "SEconValue::energy offset must be 0x00");
  static_assert(offsetof(SEconValue, mass) == 0x04, "SEconValue::mass offset must be 0x04");

  /**
   * Army economy queue node consumed by CEconomyEvent tick path.
   *
   * Address context:
   * - 0x00774EF0 (FUN_00774EF0): allocated as 0x18 bytes, linked into army economy list.
   * - 0x00775270 (FUN_00775270): reads granted values at +0x10/+0x14.
   */
  struct CEconRequest
  {
    /**
     * Address: 0x00773990 (FUN_00773990, Moho::CEconRequest::MemberConstruct)
     *
     * What it does:
     * Allocates one `CEconRequest`, resets intrusive links/economy values, and
     * publishes the object as an unowned construct result.
     */
    static void MemberConstruct(gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result);

    /**
     * Address: 0x00774A60 (FUN_00774A60, Moho::CEconRequest::MemberDeserialize)
     *
     * What it does:
     * Deserializes requested and granted economy-value lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00774AE0 (FUN_00774AE0, Moho::CEconRequest::MemberSerialize)
     *
     * What it does:
     * Serializes requested and granted economy-value lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    TDatListItem<void, void> mNode; // +0x00
    SEconValue mRequested;          // +0x08
    SEconValue mGranted;            // +0x10

    static gpg::RType* sType;
  };
  static_assert(sizeof(CEconRequest) == 0x18, "CEconRequest size must be 0x18");
  static_assert(offsetof(CEconRequest, mNode) == 0x00, "CEconRequest::mNode offset must be 0x00");
  static_assert(offsetof(CEconRequest, mRequested) == 0x08, "CEconRequest::mRequested offset must be 0x08");
  static_assert(offsetof(CEconRequest, mGranted) == 0x10, "CEconRequest::mGranted offset must be 0x10");

  /**
   * VFTABLE: 0x00E36F88
   * COL:  0x00E90BB8
   */
  class CEconomyEvent : public CScriptEvent
  {
  public:
    /**
     * Address: 0x00774EF0 (FUN_00774EF0, ??0CEconomyEvent@Moho@@QAE@@Z)
     *
     * What it does:
     * Creates one timed economy request event for a unit, wires Lua object
     * state, and links request data into army economy processing lists.
     */
    CEconomyEvent(
      Unit* unit,
      float requestedEnergy,
      float requestedMass,
      float durationSeconds,
      const LuaPlus::LuaObject& progressCallback
    );

    /**
     * Address: 0x00775140 (FUN_00775140, sub_775140)
     *
     * What it does:
     * Default constructor used by serializer construct helper paths.
     */
    CEconomyEvent();

    /**
     * Address: 0x00775120 (FUN_00775120, scalar deleting thunk)
     * Address: 0x007751C0 (FUN_007751C0, sub_7751C0)
     *
     * VFTable SLOT: 0
     */
    ~CEconomyEvent() override;

    /**
     * Address: 0x00775B20 (FUN_00775B20, ?GetClass@CEconomyEvent@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 1 (CScriptObject subobject)
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00775B40 (FUN_00775B40, ?GetDerivedObjectRef@CEconomyEvent@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 2 (CScriptObject subobject)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00775270 (FUN_00775270, sub_775270)
     *
     * What it does:
     * Processes one economy-event tick: mirrors request rates to owning unit,
     * consumes granted resources, invokes progress callback, and signals the
     * task event when complete.
     */
    void ProcessTick();

    [[nodiscard]]
    bool IsDone() const noexcept;

  public:
    static gpg::RType* sType;

    TDatListItem<void, void> mUnitEventNode; // +0x48
    Unit* mUnit;                             // +0x50
    SEconValue mRequestedPerTick;            // +0x54
    CEconRequest* mRequest;                  // +0x5C
    LuaPlus::LuaObject mProgressCallback;    // +0x60
    std::int32_t mRemainingTicks;            // +0x74
    std::int32_t mTotalTicks;                // +0x78
  };

  /**
   * VFTABLE: 0x00E36FD4
   * COL:  0x00E90B08
   */
  template <>
  class CScrLuaMetatableFactory<CEconomyEvent> final : public CScrLuaObjectFactory
  {
  public:
    /**
     * Address: 0x1001FDE0 (MohoEngine.dll constructor shape)
     */
    CScrLuaMetatableFactory();

    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00775B80 (FUN_00775B80)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  /**
   * VFTABLE: 0x00E36FE4
   * COL:  0x00E90A24
   */
  class CEconomyEventConstruct
  {
  public:
    /**
     * Address: 0x00775C40 (FUN_00775C40, sub_775C40)
     *
     * What it does:
     * Registers construct/delete callbacks for CEconomyEvent into RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  /**
   * VFTABLE: 0x00E36FF4
   * COL:  0x00E90978
   */
  class CEconomyEventSerializer
  {
  public:
    /**
     * Address: 0x00775CC0 (FUN_00775CC0, sub_775CC0)
     *
     * What it does:
     * Registers load/save callbacks for CEconomyEvent into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E36FA4
   * COL:  0x00E90B54
   */
  class CEconomyEventTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00774E40 (FUN_00774E40, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CEconomyEventTypeInfo() override;

    /**
     * Address: 0x00774E30 (FUN_00774E30, ?GetName@CEconomyEventTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00774E00 (FUN_00774E00, ?Init@CEconomyEventTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  /**
   * VFTABLE: 0x00E3700C
   * COL:  0x00E9089C
   */
  using CreateEconomyEvent_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E37014
   * COL:  0x00E9084C
   */
  using RemoveEconomyEvent_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * VFTABLE: 0x00E3701C
   * COL:  0x00E907FC
   */
  using EconomyEventIsDone_LuaFuncDef = ::moho::CScrLuaBinder;

  /**
   * Address: 0x00775630 (FUN_00775630, cfunc_CreateEconomyEvent)
   */
  int cfunc_CreateEconomyEvent(lua_State* luaContext);

  /**
   * Address: 0x007756B0 (FUN_007756B0, cfunc_CreateEconomyEventL)
   */
  int cfunc_CreateEconomyEventL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00775650 (FUN_00775650, func_CreateEconomyEvent_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateEconomyEvent`.
   */
  CScrLuaInitForm* func_CreateEconomyEvent_LuaFuncDef();

  /**
   * Address: 0x00775910 (FUN_00775910, cfunc_RemoveEconomyEvent)
   */
  int cfunc_RemoveEconomyEvent(lua_State* luaContext);

  /**
   * Address: 0x00775990 (FUN_00775990, cfunc_RemoveEconomyEventL)
   */
  int cfunc_RemoveEconomyEventL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00775930 (FUN_00775930, func_RemoveEconomyEvent_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RemoveEconomyEvent`.
   */
  CScrLuaInitForm* func_RemoveEconomyEvent_LuaFuncDef();

  /**
   * Address: 0x00775A40 (FUN_00775A40, cfunc_EconomyEventIsDone)
   */
  int cfunc_EconomyEventIsDone(lua_State* luaContext);

  /**
   * Address: 0x00775AC0 (FUN_00775AC0, cfunc_EconomyEventIsDoneL)
   */
  int cfunc_EconomyEventIsDoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00775A60 (FUN_00775A60, func_EconomyEventIsDone_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `EconomyEventIsDone`.
   */
  CScrLuaInitForm* func_EconomyEventIsDone_LuaFuncDef();

  /**
   * Address: 0x00775EC0 (FUN_00775EC0, func_GetCEconomyEvent)
   */
  [[nodiscard]]
  CEconomyEvent* func_GetCEconomyEvent(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state);

#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(offsetof(CEconomyEvent, mUnitEventNode) == 0x48, "CEconomyEvent::mUnitEventNode offset must be 0x48");
  static_assert(offsetof(CEconomyEvent, mUnit) == 0x50, "CEconomyEvent::mUnit offset must be 0x50");
  static_assert(
    offsetof(CEconomyEvent, mRequestedPerTick) == 0x54, "CEconomyEvent::mRequestedPerTick offset must be 0x54"
  );
  static_assert(offsetof(CEconomyEvent, mRequest) == 0x5C, "CEconomyEvent::mRequest offset must be 0x5C");
  static_assert(
    offsetof(CEconomyEvent, mProgressCallback) == 0x60, "CEconomyEvent::mProgressCallback offset must be 0x60"
  );
  static_assert(offsetof(CEconomyEvent, mRemainingTicks) == 0x74, "CEconomyEvent::mRemainingTicks offset must be 0x74");
  static_assert(offsetof(CEconomyEvent, mTotalTicks) == 0x78, "CEconomyEvent::mTotalTicks offset must be 0x78");
  static_assert(sizeof(CEconomyEvent) == 0x7C, "CEconomyEvent size must be 0x7C");
#endif
  static_assert(
    sizeof(CScrLuaMetatableFactory<CEconomyEvent>) == 0x08, "CScrLuaMetatableFactory<CEconomyEvent> size must be 0x08"
  );
  static_assert(sizeof(CEconomyEventConstruct) == 0x14, "CEconomyEventConstruct size must be 0x14");
  static_assert(sizeof(CEconomyEventSerializer) == 0x14, "CEconomyEventSerializer size must be 0x14");
  static_assert(sizeof(CEconomyEventTypeInfo) == 0x64, "CEconomyEventTypeInfo size must be 0x64");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x005D1C70 (FUN_005D1C70, gpg::RRef_CEconRequest)
   *
   * What it does:
   * Builds a typed reflection reference for `CEconRequest*`, upgrading to the
   * dynamic derived type and applying base-offset adjustment when needed.
   */
  gpg::RRef* RRef_CEconRequest(gpg::RRef* outRef, moho::CEconRequest* value);
} // namespace gpg
