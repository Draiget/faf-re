#pragma once

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x00BD1980 (FUN_00BD1980, register_sim_SimInits_mForms_offVariant1)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A08`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant1();

  /**
   * Address: 0x00BD21F0 (FUN_00BD21F0, register_sim_SimInits_mForms_offVariant2)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A20`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant2();

  /**
   * Address: 0x00BD2210 (FUN_00BD2210, sub_BD2210) -- record at 0x00F59A38
   *
   * What it does:
   * Declares `CAimManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.AimManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CAimManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD2230 (FUN_00BD2230, register_TConVar_dbg_Ballistics)
   *
   * What it does:
   * Registers startup console convar `dbg_Ballistics` and installs process-exit
   * cleanup.
   */
  void register_TConVar_dbg_Ballistics();

  /**
   * Address: 0x00BFA8D0 (FUN_00BFA8D0, cleanup_TConVar_dbg_Ballistics)
   *
   * What it does:
   * Unregisters startup console convar `dbg_Ballistics`.
   */
  void cleanup_TConVar_dbg_Ballistics();

  /**
   * Address: 0x00BD2270 (FUN_00BD2270, register_CAimManipulatorTypeInfo)
   *
   * What it does:
   * Registers `CAimManipulator` RTTI startup owner and installs process-exit
   * cleanup.
   */
  void register_CAimManipulatorTypeInfo();

  /**
   * Address: 0x00BD2290 (FUN_00BD2290, register_CAimManipulatorSerializer)
   *
   * What it does:
   * Registers `CAimManipulator` serializer startup owner and installs
   * process-exit cleanup.
   */
  void register_CAimManipulatorSerializer();

  /**
   * Address: 0x00BD2350 (FUN_00BD2350, register_CScrLuaMetatableFactory_CAimManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CAimManipulator`.
   */
  int register_CScrLuaMetatableFactory_CAimManipulator_Index();

  /**
   * Address: 0x00BD2370 (FUN_00BD2370, register_CScrLuaMetatableFactory_IAniManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `IAniManipulator`.
   */
  int register_CScrLuaMetatableFactory_IAniManipulator_Index();

  /**
   * Address: 0x00BD2400 (FUN_00BD2400, register_sim_SimInits_mForms_offVariant4)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A64`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant4();

  /**
   * Address: 0x00BD2420 (FUN_00BD2420, sub_BD2420) -- record at 0x00F59A7C
   *
   * What it does:
   * Declares `CBoneEntityManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.BoneEntityManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CBoneEntityManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD24C0 (FUN_00BD24C0, register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index)
   *
   * What it does:
   * Allocates and stores the startup metatable-factory index for
   * `CBoneEntityManipulator`.
   */
  int register_CScrLuaMetatableFactory_CBoneEntityManipulator_Index();

  /**
   * Address: 0x00BD2550 (FUN_00BD2550, register_sim_SimInits_mForms_offVariant6)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59A98`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant6();

  /**
   * Address: 0x00BD2570 (FUN_00BD2570, sub_BD2570) -- record at 0x00F59AB0
   *
   * What it does:
   * Declares `CBuilderArmManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.BuilderArmManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CBuilderArmManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD29C0 (FUN_00BD29C0, register_sim_SimInits_mForms_offVariant8)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B00`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant8();

  /**
   * Address: 0x00BD29E0 (FUN_00BD29E0, sub_BD29E0) -- record at 0x00F59B18
   *
   * What it does:
   * Declares `CFootPlantManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.FootPlantManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CFootPlantManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD2630 (FUN_00BD2630, register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CBuilderArmManipulator`.
   */
  int register_CScrLuaMetatableFactory_CBuilderArmManipulator_Index();

  /**
   * Address: 0x00BD27B0 (FUN_00BD27B0, register_CScrLuaMetatableFactory_CCollisionManipulator_Index)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CCollisionManipulator`.
   */
  int register_CScrLuaMetatableFactory_CCollisionManipulator_Index();

  /**
   * Address: 0x00BD2A70 (FUN_00BD2A70, register_CScrLuaMetatableFactory_CFootPlantManipulator_Index)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CFootPlantManipulator`.
   */
  int register_CScrLuaMetatableFactory_CFootPlantManipulator_Index();

  /**
   * Address: 0x00BD2C00 (FUN_00BD2C00, register_sim_SimInits_mForms_offVariant9)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B34`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant9();

  /**
   * Address: 0x00BD2D50 (FUN_00BD2D50, register_sim_SimInits_mForms_off_F59B34_mFactory)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane
   * `off_F59B34.mFactory`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59B34_mFactory();

  /**
   * Address: 0x00BD2D70 (FUN_00BD2D70, sub_BD2D70) -- record at 0x00F59B64
   *
   * What it does:
   * Declares `CAnimationManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.AnimationManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CAnimationManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD2F00 (FUN_00BD2F00, register_RVectorType_bool)
   *
   * What it does:
   * Registers startup reflection metadata for `std::vector<bool>` and installs
   * process-exit cleanup.
   */
  int register_RVectorType_bool();

  /**
   * Address: 0x00BD2F20 (FUN_00BD2F20, sub_BD2F20)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CAnimationManipulator`.
   */
  int register_CScrLuaMetatableFactory_CAnimationManipulator_Index();

  /**
   * Address: 0x00BD3100 (FUN_00BD3100, sub_BD3100)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CRotateManipulator`.
   */
  int register_CScrLuaMetatableFactory_CRotateManipulator_Index();

  /**
   * Address: 0x00BD3250 (FUN_00BD3250, sub_BD3250)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CSlaveManipulator`.
   */
  int register_CScrLuaMetatableFactory_CSlaveManipulator_Index();

  /**
   * Address: 0x00BD3570 (FUN_00BD3570, sub_BD3570)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CSlideManipulator`.
   */
  int register_CScrLuaMetatableFactory_CSlideManipulator_Index();

  /**
   * Address: 0x00BD36B0 (FUN_00BD36B0, sub_BD36B0)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CStorageManipulator`.
   */
  int register_CScrLuaMetatableFactory_CStorageManipulator_Index();

  /**
   * Address: 0x00BD3800 (FUN_00BD3800, sub_BD3800)
   *
   * What it does:
   * Allocates/stores the recovered startup Lua metatable-factory index lane for
   * `CThrustManipulator`.
   */
  int register_CScrLuaMetatableFactory_CThrustManipulator_Index();

  /**
   * Address: 0x00BD2FB0 (FUN_00BD2FB0, sub_BD2FB0)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B80`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant11();

  /**
   * Address: 0x00BD2FD0 (FUN_00BD2FD0, sub_BD2FD0) -- record at 0x00F59B98
   *
   * What it does:
   * Declares `CRotateManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.RotateManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CRotateManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD3190 (FUN_00BD3190, sub_BD3190)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59BB4`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant13();

  /**
   * Address: 0x00BD31B0 (FUN_00BD31B0, sub_BD31B0) -- record at 0x00F59BCC
   *
   * What it does:
   * Declares `CSlaveManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.SlaveManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CSlaveManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD3460 (FUN_00BD3460, sub_BD3460)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59BE8`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant15();

  /**
   * Address: 0x00BD3480 (FUN_00BD3480, sub_BD3480) -- record at 0x00F59C00
   *
   * What it does:
   * Declares `CSlideManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.SlideManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CSlideManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD3600 (FUN_00BD3600, sub_BD3600)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C1C`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant17();

  /**
   * Address: 0x00BD3620 (FUN_00BD3620, sub_BD3620) -- record at 0x00F59C34
   *
   * What it does:
   * Declares `CStorageManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.StorageManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CStorageManipulatorLuaBaseClass();

  /**
   * Address: 0x00BD3740 (FUN_00BD3740, sub_BD3740)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C50`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant19();

  /**
   * Address: 0x00BD3760 (FUN_00BD3760, sub_BD3760) -- record at 0x00F59C68
   *
   * What it does:
   * Declares `CThrustManipulator` as deriving from `IAniManipulator` for the Lua
   * class system, so `moho.ThrustManipulator` carries
   * `moho.manipulator_methods` in its array part.
   */
  CScrLuaInitForm* register_CThrustManipulatorLuaBaseClass();
} // namespace moho
