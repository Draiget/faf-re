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
   * Address: 0x00BD2210 (FUN_00BD2210, register_sim_SimInits_mForms_offVariant3)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A38`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant3();

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
   * Address: 0x00BD2420 (FUN_00BD2420, register_sim_SimInits_mForms_offVariant5)
   *
   * What it does:
   * Saves the current `sim` Lua-init form head and relinks the list to
   * `off_F59A7C`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant5();

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
   * Address: 0x00BD2570 (FUN_00BD2570, register_sim_SimInits_mForms_off_F59A98_mFactory)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane
   * `off_F59A98.mFactory`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59A98_mFactory();

  /**
   * Address: 0x00BD29C0 (FUN_00BD29C0, register_sim_SimInits_mForms_offVariant8)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B00`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant8();

  /**
   * Address: 0x00BD29E0 (FUN_00BD29E0, register_sim_SimInits_mForms_off_F59B00_mFactory)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane
   * `off_F59B00.mFactory`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_off_F59B00_mFactory();

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
   * Address: 0x00BD2D70 (FUN_00BD2D70, register_sim_SimInits_mForms_offVariant10)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B64`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant10();

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
   * Address: 0x00BD2FD0 (FUN_00BD2FD0, sub_BD2FD0)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59B98`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant12();

  /**
   * Address: 0x00BD3190 (FUN_00BD3190, sub_BD3190)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59BB4`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant13();

  /**
   * Address: 0x00BD31B0 (FUN_00BD31B0, sub_BD31B0)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59BCC`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant14();

  /**
   * Address: 0x00BD3460 (FUN_00BD3460, sub_BD3460)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59BE8`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant15();

  /**
   * Address: 0x00BD3480 (FUN_00BD3480, sub_BD3480)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C00`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant16();

  /**
   * Address: 0x00BD3600 (FUN_00BD3600, sub_BD3600)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C1C`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant17();

  /**
   * Address: 0x00BD3620 (FUN_00BD3620, sub_BD3620)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C34`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant18();

  /**
   * Address: 0x00BD3740 (FUN_00BD3740, sub_BD3740)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C50`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant19();

  /**
   * Address: 0x00BD3760 (FUN_00BD3760, sub_BD3760)
   *
   * What it does:
   * Re-links `sim` startup Lua-init chain head to recovered lane `off_F59C68`.
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_offVariant20();
} // namespace moho
