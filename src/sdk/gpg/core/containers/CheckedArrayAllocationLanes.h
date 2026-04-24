#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::core::legacy
{
  /**
   * Address: 0x004FDEC0 (FUN_004FDEC0)
   * Address: 0x005061D0 (FUN_005061D0)
   * Address: 0x005062A0 (FUN_005062A0)
   * Address: 0x005335B0 (FUN_005335B0)
   * Address: 0x005380D0 (FUN_005380D0)
   * Address: 0x00540CC0 (FUN_00540CC0)
   * Address: 0x00540D10 (FUN_00540D10)
   * Address: 0x006528F0 (FUN_006528F0)
   * Address: 0x0066AEC0 (FUN_0066AEC0)
   * Address: 0x0067FA80 (FUN_0067FA80)
   * Address: 0x0067FCC0 (FUN_0067FCC0)
   * Address: 0x006F9140 (FUN_006F9140)
   * Address: 0x00741B80 (FUN_00741B80)
   * Address: 0x00751DA0 (FUN_00751DA0)
   * Address: 0x0076CE90 (FUN_0076CE90)
   * Address: 0x0078AE70 (FUN_0078AE70)
   * Address: 0x007BCDD0 (FUN_007BCDD0)
   * Address: 0x007E5530 (FUN_007E5530)
   * Address: 0x0084A470 (FUN_0084A470)
   * Address: 0x00857330 (FUN_00857330)
   * Address: 0x0086A120 (FUN_0086A120)
   * Address: 0x0087D2C0 (FUN_0087D2C0)
   * Address: 0x0087D390 (FUN_0087D390)
   * Address: 0x0087D460 (FUN_0087D460)
   * Address: 0x0088AF50 (FUN_0088AF50)
   * Address: 0x008B37D0 (FUN_008B37D0)
   * Address: 0x008B5690 (FUN_008B5690)
   * Address: 0x008B80A0 (FUN_008B80A0)
   * Address: 0x00A53A20 (FUN_00A53A20, sub_A53A20)
   * Address: 0x005CA040 (FUN_005CA040)
   *
   * What it does:
   * Allocates a contiguous lane of 4-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateCheckedDwordLane(std::uint32_t elementCount);

  /**
   * Address: 0x00537F80 (FUN_00537F80)
   *
   * What it does:
   * Preserves one legacy zero-count allocation wrapper lane:
   * returns `AllocateCheckedDwordLane(elementCount)` when non-zero and
   * forwards to `operator new(0)` for the zero-count case.
   */
  [[nodiscard]] void* AllocateCheckedDwordLaneOrEmpty(std::uint32_t elementCount);

  /**
   * Address: 0x00946A00 (FUN_00946A00, sub_946A00)
   * Address: 0x00946AA0 (FUN_00946AA0, sub_946AA0)
   * Address: 0x00946B40 (FUN_00946B40, sub_946B40)
   * Address: 0x0094F340 (FUN_0094F340, sub_94F340)
   * Address: 0x00A3A530 (FUN_00A3A530, sub_A3A530)
   * Address: 0x005A1DF0 (FUN_005A1DF0, func_Create2LinkedListN)
   * Address: 0x005ABB00 (FUN_005ABB00)
   *
   * What it does:
   * Allocates a contiguous lane of 24-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked24ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x00931B60 (FUN_00931B60, sub_931B60)
   * Address: 0x00935D50 (FUN_00935D50, sub_935D50)
   *
   * What it does:
   * Allocates a contiguous lane of 32-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked32ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x0094F2D0 (FUN_0094F2D0, sub_94F2D0)
   *
   * What it does:
   * Allocates a contiguous lane of 40-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked40ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x00931C60 (FUN_00931C60, sub_931C60)
   *
   * What it does:
   * Allocates a contiguous lane of 80-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked80ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x004E4F70 (FUN_004E4F70)
   * Address: 0x004E4FF0 (FUN_004E4FF0)
   * Address: 0x00594170 (FUN_00594170)
   * Address: 0x005CA120 (FUN_005CA120)
   * Address: 0x005D09C0 (FUN_005D09C0)
   * Address: 0x0067FC60 (FUN_0067FC60)
   * Address: 0x0067FD10 (FUN_0067FD10)
   * Address: 0x0069FAF0 (FUN_0069FAF0)
   * Address: 0x0073A940 (FUN_0073A940)
   * Address: 0x00751AA0 (FUN_00751AA0)
   * Address: 0x00768D50 (FUN_00768D50)
   * Address: 0x0076CD90 (FUN_0076CD90)
   * Address: 0x007D96C0 (FUN_007D96C0)
   * Address: 0x0081BDC0 (FUN_0081BDC0)
   * Address: 0x0084A560 (FUN_0084A560)
   * Address: 0x00868990 (FUN_00868990)
   * Address: 0x008AFE10 (FUN_008AFE10)
   * Address: 0x008C6330 (FUN_008C6330)
   * Address: 0x008D7020 (FUN_008D7020)
   *
   * What it does:
   * Allocates a contiguous lane of 12-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked12ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x005334E0 (FUN_005334E0)
   * Address: 0x005941D0 (FUN_005941D0)
   * Address: 0x007045A0 (FUN_007045A0)
   * Address: 0x0073A9D0 (FUN_0073A9D0)
   * Address: 0x00741BE0 (FUN_00741BE0)
   * Address: 0x007B1160 (FUN_007B1160)
   * Address: 0x007CC020 (FUN_007CC020)
   * Address: 0x007CD150 (FUN_007CD150)
   * Address: 0x007D9660 (FUN_007D9660)
   * Address: 0x007E9760 (FUN_007E9760)
   * Address: 0x007F3590 (FUN_007F3590)
   * Address: 0x00831C90 (FUN_00831C90)
   * Address: 0x0084F8F0 (FUN_0084F8F0)
   * Address: 0x0085A860 (FUN_0085A860)
   * Address: 0x008B8010 (FUN_008B8010)
   *
   * What it does:
   * Allocates a contiguous lane of 16-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked16ByteLane(std::uint32_t elementCount);

  /**
   * Address: 0x00533710 (FUN_00533710)
   * Address: 0x005337B0 (FUN_005337B0)
   * Address: 0x00533850 (FUN_00533850)
   * Address: 0x005338F0 (FUN_005338F0)
   * Address: 0x00533990 (FUN_00533990)
   * Address: 0x00533A30 (FUN_00533A30)
   * Address: 0x00533AD0 (FUN_00533AD0)
   * Address: 0x005942B0 (FUN_005942B0)
   * Address: 0x00653A80 (FUN_00653A80)
   * Address: 0x006B1420 (FUN_006B1420)
   * Address: 0x00736930 (FUN_00736930)
   * Address: 0x007BCC10 (FUN_007BCC10)
   * Address: 0x007D4490 (FUN_007D4490)
   * Address: 0x007F3710 (FUN_007F3710)
   * Address: 0x0081A740 (FUN_0081A740)
   * Address: 0x008379C0 (FUN_008379C0)
   * Address: 0x0083C670 (FUN_0083C670)
   * Address: 0x00890080 (FUN_00890080)
   * Address: 0x0089B210 (FUN_0089B210)
   *
   * What it does:
   * Allocates a contiguous lane of 48-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  [[nodiscard]] void* AllocateChecked48ByteLane(std::uint32_t elementCount);
} // namespace gpg::core::legacy
