#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityMotor.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/script/CScriptObject.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  /**
   * Address: 0x00696500 (FUN_00696500, ctor lane)
   *
   * What it does:
   * Concrete entity motor that keeps one sink-speed lane and exposes script-object behavior.
   */
  class MotorSinkAway final : public EntityMotor, public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00696500 (FUN_00696500, default ctor)
     */
    MotorSinkAway();

    /**
     * Address: 0x006963F0 (FUN_006963F0, Lua ctor lane)
     */
    MotorSinkAway(LuaPlus::LuaState* state, float sinkDeltaY);

    /**
     * Address: 0x00696580 (FUN_00696580, deleting-thunk chain)
     * Address: 0x006965A0 (FUN_006965A0, non-deleting body)
     */
    ~MotorSinkAway() override;

    /**
     * Address: 0x006963B0 (FUN_006963B0, Moho::MotorSinkAway::GetClass)
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x006963D0 (FUN_006963D0, Moho::MotorSinkAway::GetDerivedObjectRef)
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00696940 (FUN_00696940, update lane)
     */
    void Update(Entity* entity) override;

    /**
     * Address: 0x00697200 (FUN_00697200, Moho::MotorSinkAway::MemberDeserialize)
     *
     * What it does:
     * Loads `EntityMotor` and `CScriptObject` base state, then the sink-speed
     * scalar.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00697290 (FUN_00697290, Moho::MotorSinkAway::MemberSerialize)
     *
     * What it does:
     * Saves `EntityMotor` and `CScriptObject` base state, then the sink-speed
     * scalar.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    float mSinkDeltaY; // +0x38
  };

  static_assert(offsetof(MotorSinkAway, mSinkDeltaY) == 0x38, "MotorSinkAway::mSinkDeltaY offset must be 0x38");
  static_assert(sizeof(MotorSinkAway) == 0x3C, "MotorSinkAway size must be 0x3C");

  template <>
  class CScrLuaMetatableFactory<MotorSinkAway> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00696FD0 (FUN_00696FD0, Moho::CScrLuaMetatableFactory<Moho::MotorSinkAway>::Create)
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<MotorSinkAway>) == 0x08,
    "CScrLuaMetatableFactory<MotorSinkAway> size must be 0x8"
  );

  /**
   * Address: 0x006971D0 (FUN_006971D0)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<MotorSinkAway>` and returns that singleton.
   */
  CScrLuaMetatableFactory<MotorSinkAway>* startup_CScrLuaMetatableFactory_MotorSinkAway_Index();

  class MotorSinkAwayTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00696600 (FUN_00696600, Moho::MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo)
     */
    MotorSinkAwayTypeInfo();

    /**
     * Address: 0x006966A0 (FUN_006966A0, Moho::MotorSinkAwayTypeInfo::dtr)
     */
    ~MotorSinkAwayTypeInfo() override;

    /**
     * Address: 0x00696690 (FUN_00696690, Moho::MotorSinkAwayTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00696660 (FUN_00696660, Moho::MotorSinkAwayTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00696E90 (FUN_00696E90, Moho::MotorSinkAwayTypeInfo::AddBase_CScriptObject)
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x00696EF0 (FUN_00696EF0, Moho::MotorSinkAwayTypeInfo::AddBase_Motor)
     */
    static void AddBase_Motor(gpg::RType* typeInfo);
  };

  static_assert(sizeof(MotorSinkAwayTypeInfo) == 0x64, "MotorSinkAwayTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E292C8
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::MotorSinkAway>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer: 0x00BD5DB0 (__xc_a-reachable;
   *    dead zero-xref COMDAT duplicate: 0x00696CB0)
   *  - dtor: 0x00BFD2A0 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x00696CE0
   *  - Deserialize(): 0x00696880
   *  - Serialize(): 0x00696890
   */
  using MotorSinkAwaySerializer = gpg::SerSaveLoadHelper<MotorSinkAway>;

  class MotorSinkAwayConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5D70 (FUN_00BD5D70, dynamic initializer for the global
     * `MotorSinkAwayConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    MotorSinkAwayConstruct();

    /**
     * Address: 0x00BFD270 (FUN_00BFD270, Moho::MotorSinkAwayConstruct::~MotorSinkAwayConstruct)
     */
    ~MotorSinkAwayConstruct();

    /**
     * Address: 0x00696C60 (FUN_00696C60, Moho::MotorSinkAwayConstruct::Init)
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

  static_assert(
    offsetof(MotorSinkAwayConstruct, mConstructCallback) == 0x0C,
    "MotorSinkAwayConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(MotorSinkAwayConstruct, mDeleteCallback) == 0x10,
    "MotorSinkAwayConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(MotorSinkAwayConstruct) == 0x14, "MotorSinkAwayConstruct size must be 0x14");

  /**
   * Address: 0x00BFD210 (FUN_00BFD210, cleanup_MotorSinkAwayTypeInfo)
   */
  void cleanup_MotorSinkAwayTypeInfo();

  /**
   * Address: 0x00BD5D50 (FUN_00BD5D50, register_MotorSinkAwayTypeInfo)
   */
  void register_MotorSinkAwayTypeInfo();

  /**
   * Address: 0x00BD5DB0 (FUN_00BD5DB0, register_MotorSinkAwaySerializer)
   *
   * What it does:
   * Forces this translation unit's global `MotorSinkAwaySerializer` instance
   * to link into the reflection bootstrap sequence. The ctor/vtable-install/
   * atexit-dtor-registration sequence this address decompiles to is MSVC's
   * own compiler-generated dynamic initializer for that global, not
   * hand-written source -- see `gpg::SerSaveLoadHelper<T>` in Reflection.h.
   */
  int register_MotorSinkAwaySerializer();

  /**
   * Address: 0x00BD5E00 (FUN_00BD5E00, register_CScrLuaMetatableFactory_MotorSinkAway_Index)
   */
  int register_CScrLuaMetatableFactory_MotorSinkAway_Index();
} // namespace moho
