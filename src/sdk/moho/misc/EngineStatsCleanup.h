#pragma once

namespace moho
{
  class EngineStats;

  /**
   * Address: 0x00BFA4A0 (FUN_00BFA4A0, cleanup_EngineStatsSlotVariant11)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B1F4C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant11();

  /**
   * Address: 0x00BFA700 (FUN_00BFA700, cleanup_EngineStatsSlotVariant12)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2014`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant12();

  /**
   * Address: 0x00BFA8B0 (FUN_00BFA8B0, cleanup_EngineStatsSlotVariant13)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2258`
   * if it is present, then frees the allocation.
  */
  void cleanup_EngineStatsSlotVariant13();

  /**
   * Address: 0x00BD1AA0 (FUN_00BD1AA0, register_EngineStatsCleanupSlotVariant11)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B1F4C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant11();

  /**
   * Address: 0x00BD1DD0 (FUN_00BD1DD0, register_EngineStatsCleanupSlotVariant12)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2014`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant12();

  /**
   * Address: 0x00BD2180 (FUN_00BD2180, register_EngineStatsCleanupSlotVariant13)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2258`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant13();

  /**
   * Address: 0x00BD2540 (FUN_00BD2540, register_EngineStatsCleanupSlotVariant14)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B24B4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant14();

  /**
   * Address: 0x00BFAA40 (FUN_00BFAA40, cleanup_EngineStatsSlotVariant14)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B24B4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant14();

  /**
   * Address: 0x00BD26B0 (FUN_00BD26B0, register_EngineStatsCleanupSlotVariant15)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B25A0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant15();

  /**
   * Address: 0x00BFAAF0 (FUN_00BFAAF0, cleanup_EngineStatsSlotVariant15)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B25A0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant15();

  /**
   * Address: 0x00BD2830 (FUN_00BD2830, register_EngineStatsCleanupSlotVariant16)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B26F0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant16();

  /**
   * Address: 0x00BFABA0 (FUN_00BFABA0, cleanup_EngineStatsSlotVariant16)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B26F0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant16();

  /**
   * Address: 0x00BD2AF0 (FUN_00BD2AF0, register_EngineStatsCleanupSlotVariant17)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2848`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant17();

  /**
   * Address: 0x00BFAC50 (FUN_00BFAC50, cleanup_EngineStatsSlotVariant17)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2848`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant17();

  /**
   * Address: 0x00BD2D40 (FUN_00BD2D40, register_EngineStatsCleanupSlotVariant18)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2B10`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant18();

  /**
   * Address: 0x00BFAF70 (FUN_00BFAF70, cleanup_EngineStatsSlotVariant18)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2B10`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant18();

  /**
   * Address: 0x00BD2FA0 (FUN_00BD2FA0, register_EngineStatsCleanupSlotVariant19)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2CD0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant19();

  /**
   * Address: 0x00BFB0E0 (FUN_00BFB0E0, cleanup_EngineStatsSlotVariant19)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2CD0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant19();

  /**
   * Address: 0x00BD3180 (FUN_00BD3180, register_EngineStatsCleanupSlotVariant20)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2DC4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant20();

  /**
   * Address: 0x00BFB190 (FUN_00BFB190, cleanup_EngineStatsSlotVariant20)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2DC4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant20();

  /**
   * Address: 0x00BD32D0 (FUN_00BD32D0, register_EngineStatsCleanupSlotVariant21)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3000`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant21();

  /**
   * Address: 0x00BFB240 (FUN_00BFB240, cleanup_EngineStatsSlotVariant21)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3000`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant21();

  /**
   * Address: 0x00BF81C0 (FUN_00BF81C0, cleanup_EngineStatsSlotVariant9)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B0318`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant9();

  /**
   * Address: 0x00BF8850 (FUN_00BF8850, cleanup_EngineStatsSlotVariant10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B054C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant10();

  /**
   * Address: 0x00BCE4E0 (FUN_00BCE4E0, register_EngineStatsCleanupSlotVariant9)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B0318`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant9();

  /**
   * Address: 0x00BCEB60 (FUN_00BCEB60, register_EngineStatsCleanupSlotVariant10)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B054C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant10();

  /**
   * Address: 0x00BF8940 (FUN_00BF8940, cleanup_EngineStatsSlotVariant66)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B0878`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant66();

  /**
   * Address: 0x00BCECA0 (FUN_00BCECA0, register_EngineStatsCleanupSlotVariant66)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B0878`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant66();

  /**
   * Address: 0x00BFA990 (FUN_00BFA990, cleanup_EngineStatsSlotVariant67)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B2368`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant67();

  /**
   * Address: 0x00BD23F0 (FUN_00BD23F0, register_EngineStatsCleanupSlotVariant67)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B2368`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant67();

  /**
   * Address: 0x00BF8F70 (FUN_00BF8F70, cleanup_EngineStatsSlotVariant68)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B09B8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant68();

  /**
   * Address: 0x00BCF0C0 (FUN_00BCF0C0, register_EngineStatsCleanupSlotVariant68)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B09B8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant68();

  /**
   * Address: 0x00BF8020 (FUN_00BF8020, cleanup_EngineStatsSlotVariant69)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10AFE28`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant69();

  /**
   * Address: 0x00BCE1B0 (FUN_00BCE1B0, register_EngineStatsCleanupSlotVariant69)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10AFE28`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant69();

  /**
   * Address: 0x00BD35F0 (FUN_00BD35F0, register_EngineStatsCleanupSlotVariant22)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B306C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant22();

  /**
   * Address: 0x00BFB2F0 (FUN_00BFB2F0, cleanup_EngineStatsSlotVariant22)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B306C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant22();

  /**
   * Address: 0x00BD3730 (FUN_00BD3730, register_EngineStatsCleanupSlotVariant23)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B313C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant23();

  /**
   * Address: 0x00BFB3A0 (FUN_00BFB3A0, cleanup_EngineStatsSlotVariant23)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B313C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant23();

  /**
   * Address: 0x00BD3820 (FUN_00BD3820, register_EngineStatsCleanupSlotVariant24)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3268`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant24();

  /**
   * Address: 0x00BFB450 (FUN_00BFB450, cleanup_EngineStatsSlotVariant24)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3268`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant24();

  /**
   * Address: 0x00BD3AC0 (FUN_00BD3AC0, register_EngineStatsCleanupSlotVariant25)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B32D8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant25();

  /**
   * Address: 0x00BFB650 (FUN_00BFB650, cleanup_EngineStatsSlotVariant25)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B32D8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant25();

  /**
   * Address: 0x00BD3BB0 (FUN_00BD3BB0, register_EngineStatsCleanupSlotVariant26)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3438`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant26();

  /**
   * Address: 0x00BFB680 (FUN_00BFB680, cleanup_EngineStatsSlotVariant26)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3438`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant26();

  /**
   * Address: 0x00BD3C00 (FUN_00BD3C00, register_EngineStatsCleanupSlotVariant27)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3640`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant27();

  /**
   * Address: 0x00BFB6C0 (FUN_00BFB6C0, cleanup_EngineStatsSlotVariant27)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3640`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant27();

  /**
   * Address: 0x00BD3D30 (FUN_00BD3D30, register_EngineStatsCleanupSlotVariant28)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B375C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant28();

  /**
   * Address: 0x00BFB710 (FUN_00BFB710, cleanup_EngineStatsSlotVariant28)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B375C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant28();

  /**
   * Address: 0x00BD3DF0 (FUN_00BD3DF0, register_EngineStatsCleanupSlotVariant29)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B384C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant29();

  /**
   * Address: 0x00BFB830 (FUN_00BFB830, cleanup_EngineStatsSlotVariant29)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B384C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant29();

  /**
   * Address: 0x00BD3EE0 (FUN_00BD3EE0, register_EngineStatsCleanupSlotVariant30)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3A58`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant30();

  /**
   * Address: 0x00BFB860 (FUN_00BFB860, cleanup_EngineStatsSlotVariant30)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3A58`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant30();

  /**
   * Address: 0x00BD40B0 (FUN_00BD40B0, register_EngineStatsCleanupSlotVariant31)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3AF0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant31();

  /**
   * Address: 0x00BFB9A0 (FUN_00BFB9A0, cleanup_EngineStatsSlotVariant31)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3AF0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant31();

  /**
   * Address: 0x00BD41A0 (FUN_00BD41A0, register_EngineStatsCleanupSlotVariant32)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3BEC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant32();

  /**
   * Address: 0x00BFBC90 (FUN_00BFBC90, cleanup_EngineStatsSlotVariant32)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3BEC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant32();

  /**
   * Address: 0x00BD4450 (FUN_00BD4450, register_EngineStatsCleanupSlotVariant33)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3C84`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant33();

  /**
   * Address: 0x00BFBF30 (FUN_00BFBF30, cleanup_EngineStatsSlotVariant33)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3C84`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant33();

  /**
   * Address: 0x00BD4500 (FUN_00BD4500, register_EngineStatsCleanupSlotVariant34)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B3D68`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant34();

  /**
   * Address: 0x00BFBF80 (FUN_00BFBF80, cleanup_EngineStatsSlotVariant34)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B3D68`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant34();

  /**
   * Address: 0x00BD4E10 (FUN_00BD4E10, register_EngineStatsCleanupSlotVariant35)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B440C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant35();

  /**
   * Address: 0x00BFC610 (FUN_00BFC610, cleanup_EngineStatsSlotVariant35)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B440C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant35();

  /**
   * Address: 0x00BD5170 (FUN_00BD5170, sub_BD5170)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4534`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant36();

  /**
   * Address: 0x00BFCA50 (FUN_00BFCA50, sub_BFCA50)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4534`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant36();

  /**
   * Address: 0x00BD5290 (FUN_00BD5290, sub_BD5290)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4D0C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant37();

  /**
   * Address: 0x00BFCC80 (FUN_00BFCC80, sub_BFCC80)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4D0C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant37();

  /**
   * Address: 0x00BD5760 (FUN_00BD5760, sub_BD5760)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B4F74`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant38();

  /**
   * Address: 0x00BFCCA0 (FUN_00BFCCA0, sub_BFCCA0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B4F74`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant38();

  /**
   * Address: 0x00BC3B30 (FUN_00BC3B30, register_engine_stats_7)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_7`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant1();

  /**
   * Address: 0x00BEEE50 (FUN_00BEEE50, sub_BEEE50)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_7`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant1();

  /**
   * Address: 0x00BC3C40 (FUN_00BC3C40, register_engine_stats_8)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_8`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant2();

  /**
   * Address: 0x00BEEEB0 (FUN_00BEEEB0, sub_BEEEB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_8`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant2();

  /**
   * Address: 0x00BC3C90 (FUN_00BC3C90, register_engine_stats_9)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `engine_stats_9`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant3();

  /**
   * Address: 0x00BEEF10 (FUN_00BEEF10, sub_BEEF10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `engine_stats_9`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant3();

  /**
   * Address: 0x00BC3FE0 (FUN_00BC3FE0, sub_BC3FE0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7918`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant4();

  /**
   * Address: 0x00BEF120 (FUN_00BEF120, sub_BEF120)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7918`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant4();

  /**
   * Address: 0x00BC4050 (FUN_00BC4050, register_EngineStatsCleanupSlotVariant5)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7930`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant5();

  /**
   * Address: 0x00BEF170 (FUN_00BEF170, cleanup_EngineStatsSlotVariant5)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7930`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant5();

  /**
   * Address: 0x00BC40E0 (FUN_00BC40E0, register_EngineStatsCleanupSlotVariant6)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A79A4`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant6();

  /**
   * Address: 0x00BEF1D0 (FUN_00BEF1D0, cleanup_EngineStatsSlotVariant6)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A79A4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant6();

  /**
   * Address: 0x00BC4260 (FUN_00BC4260, register_EngineStatsCleanupSlotVariant7)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7A28`
   * with `atexit`.
   */
  void register_EngineStatsCleanupSlotVariant7();

  /**
   * Address: 0x00BEF350 (FUN_00BEF350, cleanup_EngineStatsSlotVariant7)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7A28`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant7();

  /**
   * Address: 0x00BC42D0 (FUN_00BC42D0, register_EngineStatsCleanupSlotVariant8)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10A7AD0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant8();

  /**
   * Address: 0x00BEF370 (FUN_00BEF370, cleanup_EngineStatsSlotVariant8)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10A7AD0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant8();

  /**
   * Address: 0x00BD59D0 (FUN_00BD59D0, register_EngineStatsCleanupSlotVariant39)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B51F4`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant39();

  /**
   * Address: 0x00BFCF90 (FUN_00BFCF90, cleanup_EngineStatsSlotVariant39)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B51F4`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant39();

  /**
   * Address: 0x00BD5D40 (FUN_00BD5D40, register_EngineStatsCleanupSlotVariant40)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5304`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant40();

  /**
   * Address: 0x00BFD1F0 (FUN_00BFD1F0, cleanup_EngineStatsSlotVariant40)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5304`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant40();

  /**
   * Address: 0x00BD5F50 (FUN_00BD5F50, register_EngineStatsCleanupSlotVariant41)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B53BC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant41();

  /**
   * Address: 0x00BFD3C0 (FUN_00BFD3C0, cleanup_EngineStatsSlotVariant41)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B53BC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant41();

  /**
   * Address: 0x00BD5FC0 (FUN_00BD5FC0, register_EngineStatsCleanupSlotVariant42)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B53CC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant42();

  /**
   * Address: 0x00BFD3E0 (FUN_00BFD3E0, cleanup_EngineStatsSlotVariant42)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B53CC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant42();

  /**
   * Address: 0x00BD6100 (FUN_00BD6100, register_EngineStatsCleanupSlotVariant43)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B55E0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant43();

  /**
   * Address: 0x00BFD4F0 (FUN_00BFD4F0, cleanup_EngineStatsSlotVariant43)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B55E0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant43();

  /**
   * Address: 0x00BFD820 (FUN_00BFD820, cleanup_EngineStatsSlotVariant44)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5680`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant44();

  /**
   * Address: 0x00BD6500 (FUN_00BD6500, register_EngineStatsCleanupSlotVariant44)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5680`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant44();

  /**
   * Address: 0x00BFD840 (FUN_00BFD840, cleanup_EngineStatsSlotVariant45)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5A38`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant45();

  /**
   * Address: 0x00BD65D0 (FUN_00BD65D0, register_EngineStatsCleanupSlotVariant45)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5A38`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant45();

  /**
   * Address: 0x00BFD860 (FUN_00BFD860, cleanup_EngineStatsSlotVariant46)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `0x10B5C54`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant46();

  /**
   * Address: 0x00BD6800 (FUN_00BD6800, register_EngineStatsCleanupSlotVariant46)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `0x10B5C54`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant46();

  /**
   * Address: 0x00BD6C80 (FUN_00BD6C80, register_EngineStatsCleanupSlotVariant47)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5CC0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant47();

  /**
   * Address: 0x00BFDD30 (FUN_00BFDD30, cleanup_EngineStatsSlotVariant47)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5CC0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant47();

  /**
   * Address: 0x00BD6D70 (FUN_00BD6D70, register_EngineStatsCleanupSlotVariant48)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B5F7C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant48();

  /**
   * Address: 0x00BFDE10 (FUN_00BFDE10, cleanup_EngineStatsSlotVariant48)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B5F7C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant48();

  /**
   * Address: 0x00BD72C0 (FUN_00BD72C0, register_EngineStatsCleanupSlotVariant49)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B61C0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant49();

  /**
   * Address: 0x00BFE0D0 (FUN_00BFE0D0, cleanup_EngineStatsSlotVariant49)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B61C0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant49();

  /**
   * Address: 0x00BD7530 (FUN_00BD7530, sub_BD7530)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B6224`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant50();

  /**
   * Address: 0x00BFE150 (FUN_00BFE150, sub_BFE150)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B6224`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant50();

  /**
   * Address: 0x00BD7780 (FUN_00BD7780, sub_BD7780)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B72BC`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant51();

  /**
   * Address: 0x00BFE170 (FUN_00BFE170, sub_BFE170)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B72BC`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant51();

  /**
   * Address: 0x00BD8450 (FUN_00BD8450, sub_BD8450)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B764C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant52();

  /**
   * Address: 0x00BD8520 (FUN_00BD8520, sub_BD8520)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7C20`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant53();

  /**
   * Address: 0x00BFE3D0 (FUN_00BFE3D0, sub_BFE3D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B764C`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant52();

  /**
   * Address: 0x00BFE510 (FUN_00BFE510, sub_BFE510)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7C20`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant53();

  /**
   * Address: 0x00BD8C30 (FUN_00BD8C30, sub_BD8C30)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E60`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant54();

  /**
   * Address: 0x00BD8D70 (FUN_00BD8D70, sub_BD8D70)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E80`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant55();

  /**
   * Address: 0x00BD8DE0 (FUN_00BD8DE0, sub_BD8DE0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7E90`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant56();

  /**
   * Address: 0x00BD8E50 (FUN_00BD8E50, sub_BD8E50)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7EA0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant57();

  /**
   * Address: 0x00BD8E60 (FUN_00BD8E60, sub_BD8E60)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B7F3C`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant58();

  /**
   * Address: 0x00BD9070 (FUN_00BD9070, sub_BD9070)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8618`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant59();

  /**
   * Address: 0x00BD9610 (FUN_00BD9610, sub_BD9610)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8768`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant60();

  /**
   * Address: 0x00BFF2A0 (FUN_00BFF2A0, sub_BFF2A0)
   *
   * What it does:
   * Tears down the first recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant63();

  /**
   * Address: 0x00BFE920 (FUN_00BFE920, sub_BFE920)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7E60`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant54();

  /**
   * Address: 0x00BFEAC0 (FUN_00BFEAC0, sub_BFEAC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B7E80`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant55();

  /**
   * Address: 0x00BFF260 (FUN_00BFF260, sub_BFF260)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B8844`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant61();

  /**
   * Address: 0x00BFF4D0 (FUN_00BFF4D0, sub_BFF4D0)
   *
   * What it does:
   * Tears down the second recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant64();

  /**
   * Address: 0x00BFF280 (FUN_00BFF280, sub_BFF280)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B88C0`
   * if it is present, then frees the allocation.
   */
  void cleanup_EngineStatsSlotVariant62();

  /**
   * Address: 0x00BFF550 (FUN_00BFF550, sub_BFF550)
   *
   * What it does:
   * Tears down the third recovered `EngineStats` singleton slot at process exit.
   */
  void cleanup_EngineStatsSlotVariant65();

  /**
   * Address: 0x00BD9AB0 (FUN_00BD9AB0, sub_BD9AB0)
   *
   * What it does:
   * Registers the first `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant63();

  /**
   * Address: 0x00BD9950 (FUN_00BD9950, sub_BD9950)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B8844`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant61();

  /**
   * Address: 0x00BD9C80 (FUN_00BD9C80, sub_BD9C80)
   *
   * What it does:
   * Registers the second `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant64();

  /**
   * Address: 0x00BD99C0 (FUN_00BD99C0, sub_BD99C0)
   *
   * What it does:
   * Registers the recovered `EngineStats` cleanup thunk for slot `dword_10B88C0`
   * with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant62();

  /**
   * Address: 0x00BD9FD0 (FUN_00BD9FD0, sub_BD9FD0)
   *
   * What it does:
   * Registers the third `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant65();

  /**
   * Address: 0x00BF9F10 (FUN_00BF9F10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B185C`.
   */
  void cleanup_EngineStatsSlotVariant70();

  /**
   * Address: 0x00BF9FC0 (FUN_00BF9FC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B199C`.
   */
  void cleanup_EngineStatsSlotVariant71();

  /**
   * Address: 0x00BFA100 (FUN_00BFA100)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1A78`.
   */
  void cleanup_EngineStatsSlotVariant72();

  /**
   * Address: 0x00BFA1E0 (FUN_00BFA1E0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1B2C`.
   */
  void cleanup_EngineStatsSlotVariant73();

  /**
   * Address: 0x00BFA290 (FUN_00BFA290)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1BF4`.
   */
  void cleanup_EngineStatsSlotVariant74();

  /**
   * Address: 0x00BFA340 (FUN_00BFA340)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1C2C`.
   */
  void cleanup_EngineStatsSlotVariant75();

  /**
   * Address: 0x00BFA3F0 (FUN_00BFA3F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10B1D44`.
   */
  void cleanup_EngineStatsSlotVariant76();

  /**
   * Address: 0x00BD0C50 (FUN_00BD0C50)
   *
   * What it does:
   * Registers the `dword_10B185C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant70();

  /**
   * Address: 0x00BD0EA0 (FUN_00BD0EA0)
   *
   * What it does:
   * Registers the `dword_10B199C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant71();

  /**
   * Address: 0x00BD1150 (FUN_00BD1150)
   *
   * What it does:
   * Registers the `dword_10B1A78` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant72();

  /**
   * Address: 0x00BD1380 (FUN_00BD1380)
   *
   * What it does:
   * Registers the `dword_10B1B2C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant73();

  /**
   * Address: 0x00BD1630 (FUN_00BD1630)
   *
   * What it does:
   * Registers the `dword_10B1BF4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant74();

  /**
   * Address: 0x00BD1880 (FUN_00BD1880)
   *
   * What it does:
   * Registers the `dword_10B1C2C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant75();

  /**
   * Address: 0x00BD1950 (FUN_00BD1950)
   *
   * What it does:
   * Registers the `dword_10B1D44` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant76();

  /**
   * Address: 0x00BF7790 (FUN_00BF7790, sub_BF7790)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AFADC`.
   */
  void cleanup_EngineStatsSlotVariant77();

  /**
   * Address: 0x00BF7D80 (FUN_00BF7D80, sub_BF7D80)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AFD24`.
   */
  void cleanup_EngineStatsSlotVariant78();

  /**
   * Address: 0x00BF73F0 (FUN_00BF73F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AF0AC`.
   */
  void cleanup_EngineStatsSlotVariant79();

  /**
   * Address: 0x00BCD980 (FUN_00BCD980, sub_BCD980)
   *
   * What it does:
   * Registers the `dword_10AFADC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant77();

  /**
   * Address: 0x00BCDFA0 (FUN_00BCDFA0, sub_BCDFA0)
   *
   * What it does:
   * Registers the `dword_10AFD24` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant78();

  /**
   * Address: 0x00BCD080 (FUN_00BCD080)
   *
   * What it does:
   * Registers the `dword_10AF0AC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant79();

  /**
   * Address: 0x00BF5EC0 (FUN_00BF5EC0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD404`.
   */
  void cleanup_EngineStatsSlotVariant80();

  /**
   * Address: 0x00BF5EE0 (FUN_00BF5EE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD414`.
   */
  void cleanup_EngineStatsSlotVariant81();

  /**
   * Address: 0x00BF5F60 (FUN_00BF5F60)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD6E4`.
   */
  void cleanup_EngineStatsSlotVariant82();

  /**
   * Address: 0x00BCAD60 (FUN_00BCAD60)
   *
   * What it does:
   * Registers the `dword_10AD404` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant80();

  /**
   * Address: 0x00BCADD0 (FUN_00BCADD0)
   *
   * What it does:
   * Registers the `dword_10AD414` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant81();

  /**
   * Address: 0x00BCAE60 (FUN_00BCAE60)
   *
   * What it does:
   * Registers the `dword_10AD6E4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant82();

  /**
   * Address: 0x00BF51A0 (FUN_00BF51A0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACB44`.
   */
  void cleanup_EngineStatsSlotVariant83();

  /**
   * Address: 0x00BF51C0 (FUN_00BF51C0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACDFC`.
   */
  void cleanup_EngineStatsSlotVariant84();

  /**
   * Address: 0x00BF5600 (FUN_00BF5600)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACEE8`.
   */
  void cleanup_EngineStatsSlotVariant85();

  /**
   * Address: 0x00BF5790 (FUN_00BF5790)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD100`.
   */
  void cleanup_EngineStatsSlotVariant86();

  /**
   * Address: 0x00BF57B0 (FUN_00BF57B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD110`.
   */
  void cleanup_EngineStatsSlotVariant87();

  /**
   * Address: 0x00BF57D0 (FUN_00BF57D0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AD300`.
   */
  void cleanup_EngineStatsSlotVariant88();

  /**
   * Address: 0x00BCA3B0 (FUN_00BCA3B0)
   *
   * What it does:
   * Registers the `dword_10ACB44` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant83();

  /**
   * Address: 0x00BCA430 (FUN_00BCA430)
   *
   * What it does:
   * Registers the `dword_10ACDFC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant84();

  /**
   * Address: 0x00BCA780 (FUN_00BCA780)
   *
   * What it does:
   * Registers the `dword_10ACEE8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant85();

  /**
   * Address: 0x00BCA990 (FUN_00BCA990)
   *
   * What it does:
   * Registers the `dword_10AD100` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant86();

  /**
   * Address: 0x00BCA9A0 (FUN_00BCA9A0)
   *
   * What it does:
   * Registers the `dword_10AD110` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant87();

  /**
   * Address: 0x00BCAA10 (FUN_00BCAA10)
   *
   * What it does:
   * Registers the `dword_10AD300` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant88();

  /**
   * Address: 0x00BF50B0 (FUN_00BF50B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ACA98`.
   */
  void cleanup_EngineStatsSlotVariant89();

  /**
   * Address: 0x00BCA280 (FUN_00BCA280)
   *
   * What it does:
   * Registers the `dword_10ACA98` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant89();

  /**
   * Address: 0x00BF4BD0 (FUN_00BF4BD0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC654`.
   */
  void cleanup_EngineStatsSlotVariant90();

  /**
   * Address: 0x00BC9DE0 (FUN_00BC9DE0)
   *
   * What it does:
   * Registers the `dword_10AC654` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant90();

  /**
   * Address: 0x00BF4BF0 (FUN_00BF4BF0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC77C`.
   */
  void cleanup_EngineStatsSlotVariant91();

  /**
   * Address: 0x00BC9DF0 (FUN_00BC9DF0)
   *
   * What it does:
   * Registers the `dword_10AC77C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant91();

  /**
   * Address: 0x00BF4D30 (FUN_00BF4D30)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC8A4`.
   */
  void cleanup_EngineStatsSlotVariant92();

  /**
   * Address: 0x00BC9F50 (FUN_00BC9F50)
   *
   * What it does:
   * Registers the `dword_10AC8A4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant92();

  /**
   * Address: 0x00BF4930 (FUN_00BF4930)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC644`.
   */
  void cleanup_EngineStatsSlotVariant93();

  /**
   * Address: 0x00BC9C10 (FUN_00BC9C10)
   *
   * What it does:
   * Registers the `dword_10AC644` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant93();

  /**
   * Address: 0x00BF4760 (FUN_00BF4760)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC454`.
   */
  void cleanup_EngineStatsSlotVariant94();

  /**
   * Address: 0x00BC9A20 (FUN_00BC9A20)
   *
   * What it does:
   * Registers the `dword_10AC454` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant94();

  /**
   * Address: 0x00BF4460 (FUN_00BF4460)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC2CC`.
   */
  void cleanup_EngineStatsSlotVariant95();

  /**
   * Address: 0x00BC9880 (FUN_00BC9880)
   *
   * What it does:
   * Registers the `dword_10AC2CC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant95();

  /**
   * Address: 0x00BF4170 (FUN_00BF4170)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AC054`.
   */
  void cleanup_EngineStatsSlotVariant96();

  /**
   * Address: 0x00BC9580 (FUN_00BC9580)
   *
   * What it does:
   * Registers the `dword_10AC054` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant96();

  /**
   * Address: 0x00BF3F10 (FUN_00BF3F10)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABDEC`.
   */
  void cleanup_EngineStatsSlotVariant97();

  /**
   * Address: 0x00BC9430 (FUN_00BC9430)
   *
   * What it does:
   * Registers the `dword_10ABDEC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant97();

  /**
   * Address: 0x00BF3930 (FUN_00BF3930)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABA84`.
   */
  void cleanup_EngineStatsSlotVariant98();

  /**
   * Address: 0x00BC8D50 (FUN_00BC8D50)
   *
   * What it does:
   * Registers the `dword_10ABA84` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant98();

  /**
   * Address: 0x00BF3B00 (FUN_00BF3B00)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABB4C`.
   */
  void cleanup_EngineStatsSlotVariant99();

  /**
   * Address: 0x00BC9050 (FUN_00BC9050)
   *
   * What it does:
   * Registers the `dword_10ABB4C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant99();

  /**
   * Address: 0x00BF3DE0 (FUN_00BF3DE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABCF0`.
   */
  void cleanup_EngineStatsSlotVariant100();

  /**
   * Address: 0x00BC9310 (FUN_00BC9310)
   *
   * What it does:
   * Registers the `dword_10ABCF0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant100();

  /**
   * Address: 0x00BF3E00 (FUN_00BF3E00)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10ABD00`.
   */
  void cleanup_EngineStatsSlotVariant101();

  /**
   * Address: 0x00BC9380 (FUN_00BC9380)
   *
   * What it does:
   * Registers the `dword_10ABD00` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant101();

  /**
   * Address: 0x00BF31B0 (FUN_00BF31B0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AB2B4`.
   */
  void cleanup_EngineStatsSlotVariant102();

  /**
   * Address: 0x00BC88A0 (FUN_00BC88A0)
   *
   * What it does:
   * Registers the `dword_10AB2B4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant102();

  /**
   * Address: 0x00BF2FB0 (FUN_00BF2FB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AAE1C`.
   */
  void cleanup_EngineStatsSlotVariant103();

  /**
   * Address: 0x00BC8740 (FUN_00BC8740)
   *
   * What it does:
   * Registers the `dword_10AAE1C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant103();

  /**
   * Address: 0x00BF2DB0 (FUN_00BF2DB0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AACDC`.
   */
  void cleanup_EngineStatsSlotVariant104();

  /**
   * Address: 0x00BC85E0 (FUN_00BC85E0)
   *
   * What it does:
   * Registers the `dword_10AACDC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant104();

  /**
   * Address: 0x00BF2BE0 (FUN_00BF2BE0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AAB5C`.
   */
  void cleanup_EngineStatsSlotVariant105();

  /**
   * Address: 0x00BC8500 (FUN_00BC8500)
   *
   * What it does:
   * Registers the `dword_10AAB5C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant105();

  /**
   * Address: 0x00BF27F0 (FUN_00BF27F0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA8BC`.
   */
  void cleanup_EngineStatsSlotVariant106();

  /**
   * Address: 0x00BC82D0 (FUN_00BC82D0)
   *
   * What it does:
   * Registers the `dword_10AA8BC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant106();

  /**
   * Address: 0x00BF26E0 (FUN_00BF26E0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA8AC`.
   */
  void cleanup_EngineStatsSlotVariant107();

  /**
   * Address: 0x00BC8220 (FUN_00BC8220)
   *
   * What it does:
   * Registers the `dword_10AA8AC` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant107();

  /**
   * Address: 0x00BF2420 (FUN_00BF2420)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA7B4`.
   */
  void cleanup_EngineStatsSlotVariant108();

  /**
   * Address: 0x00BC8040 (FUN_00BC8040)
   *
   * What it does:
   * Registers the `dword_10AA7B4` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant108();

  /**
   * Address: 0x00BF23A0 (FUN_00BF23A0)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA62C`.
   */
  void cleanup_EngineStatsSlotVariant109();

  /**
   * Address: 0x00BC7F50 (FUN_00BC7F50)
   *
   * What it does:
   * Registers the `dword_10AA62C` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant109();

  /**
   * Address: 0x00BF2380 (FUN_00BF2380)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA5B8`.
   */
  void cleanup_EngineStatsSlotVariant110();

  /**
   * Address: 0x00BC7EA0 (FUN_00BC7EA0)
   *
   * What it does:
   * Registers the `dword_10AA5B8` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant110();

  /**
   * Address: 0x00BF2050 (FUN_00BF2050)
   *
   * What it does:
   * Tears down the recovered `EngineStats` singleton slot at `dword_10AA3C0`.
   */
  void cleanup_EngineStatsSlotVariant111();

  /**
   * Address: 0x00BC7BF0 (FUN_00BC7BF0)
   *
   * What it does:
   * Registers the `dword_10AA3C0` `EngineStats` cleanup thunk with `atexit`.
   */
  int register_EngineStatsCleanupSlotVariant111();
} // namespace moho
