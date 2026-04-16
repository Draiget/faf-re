#include "gpg/core/containers/CheckedArrayAllocationLanes.h"

#include <limits>
#include <new>

namespace
{
  [[noreturn]] void ThrowBadAlloc()
  {
    throw std::bad_alloc{};
  }

  [[nodiscard]] void* AllocateCheckedElements(const std::uint32_t elementCount, const std::uint32_t elementSize)
  {
    const std::uint32_t maxCount = std::numeric_limits<std::uint32_t>::max() / elementSize;
    if (elementCount > maxCount) {
      ThrowBadAlloc();
    }

    const std::size_t allocationBytes =
      static_cast<std::size_t>(elementCount) * static_cast<std::size_t>(elementSize);
    return ::operator new(allocationBytes);
  }
} // namespace

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
   * Address: 0x00A53CB0 (FUN_00A53CB0, sub_A53CB0)
   * Address: 0x00A53D30 (FUN_00A53D30, sub_A53D30)
   *
   * What it does:
   * Allocates a contiguous lane of 4-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  void* AllocateCheckedDwordLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 4u);
  }

  /**
   * Address: 0x00537F80 (FUN_00537F80)
   * Address: 0x0078A5D0 (FUN_0078A5D0)
   *
   * What it does:
   * Preserves one legacy zero-count allocation wrapper lane:
   * returns `AllocateCheckedDwordLane(elementCount)` when non-zero and
   * forwards to `operator new(0)` for the zero-count case.
   */
  void* AllocateCheckedDwordLaneOrEmpty(const std::uint32_t elementCount)
  {
    if (elementCount != 0u) {
      return AllocateCheckedDwordLane(elementCount);
    }
    return ::operator new(0u);
  }

  /**
   * Address: 0x00946A00 (FUN_00946A00, sub_946A00)
   * Address: 0x00946AA0 (FUN_00946AA0, sub_946AA0)
   * Address: 0x00946B40 (FUN_00946B40, sub_946B40)
   * Address: 0x0094F340 (FUN_0094F340, sub_94F340)
   * Address: 0x00A3A530 (FUN_00A3A530, sub_A3A530)
   *
   * What it does:
   * Allocates a contiguous lane of 24-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  void* AllocateChecked24ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 24u);
  }

  /**
   * Address: 0x00946E00 (FUN_00946E00)
   *
   * What it does:
   * Legacy adapter lane that forwards one checked 24-byte allocation request to
   * the canonical allocator helper.
   */
  [[maybe_unused]] void* AllocateChecked24ByteLaneDispatchLaneA(const std::uint32_t elementCount)
  {
    return AllocateChecked24ByteLane(elementCount);
  }

  /**
   * Address: 0x00946E60 (FUN_00946E60)
   *
   * What it does:
   * Secondary adapter lane that forwards one checked 24-byte allocation
   * request to the canonical allocator helper.
   */
  [[maybe_unused]] void* AllocateChecked24ByteLaneDispatchLaneB(const std::uint32_t elementCount)
  {
    return AllocateChecked24ByteLane(elementCount);
  }

  /**
   * Address: 0x00946EC0 (FUN_00946EC0)
   *
   * What it does:
   * Tertiary adapter lane that forwards one checked 24-byte allocation request
   * to the canonical allocator helper.
   */
  [[maybe_unused]] void* AllocateChecked24ByteLaneDispatchLaneC(const std::uint32_t elementCount)
  {
    return AllocateChecked24ByteLane(elementCount);
  }

  /**
   * Address: 0x005A1980 (FUN_005A1980)
   *
   * What it does:
   * Allocates exactly one 24-byte lane through the checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked24ByteLaneAdapter()
  {
    return AllocateChecked24ByteLane(1u);
  }

  /**
   * Address: 0x00931B60 (FUN_00931B60, sub_931B60)
   * Address: 0x00935D50 (FUN_00935D50, sub_935D50)
   *
   * What it does:
   * Allocates a contiguous lane of 32-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  void* AllocateChecked32ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 32u);
  }

  /**
   * Address: 0x0094F2D0 (FUN_0094F2D0, sub_94F2D0)
   *
   * What it does:
   * Allocates a contiguous lane of 40-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  void* AllocateChecked40ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 40u);
  }

  /**
   * Address: 0x00931C60 (FUN_00931C60, sub_931C60)
   *
   * What it does:
   * Allocates a contiguous lane of 80-byte elements and applies the legacy
   * 32-bit overflow guard before forwarding to global `operator new`.
   */
  void* AllocateChecked80ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 80u);
  }

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
  void* AllocateChecked12ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 12u);
  }

  /**
   * Address: 0x0073A080 (FUN_0073A080)
   *
   * What it does:
   * Register-lane jump adapter that forces a single 12-byte checked allocation.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterG()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x005D03F0 (FUN_005D03F0)
   *
   * What it does:
   * Allocates exactly one 12-byte lane through the checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapter()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x0067E9E0 (FUN_0067E9E0)
   *
   * What it does:
   * Preserves one register-shape adapter that forces a single 12-byte lane
   * allocation through the canonical checked allocator lane.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneRegisterAdapter()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x004E2530 (FUN_004E2530)
   *
   * What it does:
   * Allocates one 12-byte lane and initializes the first two dword lanes to
   * self-pointer links (`node[0]=node`, `node[1]=node`).
   */
  [[maybe_unused]] std::uint32_t* AllocateSingleChecked12ByteSelfLinkedNodeAdapterA()
  {
    auto* const result = static_cast<std::uint32_t*>(AllocateChecked12ByteLane(1u));
    if (result != nullptr) {
      result[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }

    if (result != reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(0xFFFFFFFCu))) {
      result[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }
    return result;
  }

  /**
   * Address: 0x004E2610 (FUN_004E2610)
   *
   * What it does:
   * Secondary allocator-lane clone that allocates one 12-byte node and
   * initializes the first two dword lanes to self-pointer links
   * (`node[0]=node`, `node[1]=node`).
   */
  [[maybe_unused]] std::uint32_t* AllocateSingleChecked12ByteSelfLinkedNodeAdapterB()
  {
    auto* const result = static_cast<std::uint32_t*>(AllocateChecked12ByteLane(1u));
    if (result != nullptr) {
      result[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }

    if (result != reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(0xFFFFFFFCu))) {
      result[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }
    return result;
  }

  /**
   * Address: 0x008C5E10 (FUN_008C5E10)
   *
   * What it does:
   * Allocates one 12-byte lane and seeds the first two dword lanes with
   * self-links (`node[0]=node`, `node[1]=node`) while preserving the legacy
   * `result==-4` write-skip lane on the second store.
   */
  [[maybe_unused]] std::uint32_t* AllocateSingleChecked12ByteSelfLinkedNodeAdapterH()
  {
    auto* const result = static_cast<std::uint32_t*>(AllocateChecked12ByteLane(1u));
    if (result != nullptr) {
      result[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }

    if (result != reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(0xFFFFFFFCu))) {
      result[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }
    return result;
  }

  /**
   * Address: 0x006866E0 (FUN_006866E0)
   *
   * What it does:
   * Allocates one 12-byte lane and initializes the first two dword lanes to
   * self-pointer links (`node[0]=node`, `node[1]=node`).
   */
  [[maybe_unused]] std::uint32_t* AllocateSingleChecked12ByteSelfLinkedNode()
  {
    auto* const result = static_cast<std::uint32_t*>(AllocateChecked12ByteLane(1u));
    if (result != nullptr) {
      result[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }

    if (result != reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(0xFFFFFFFCu))) {
      result[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }
    return result;
  }

  struct SelfLinkedNodeHeadAndCountRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t* head = nullptr; // +0x04
    std::uint32_t count = 0u; // +0x08
  };
  static_assert(
    offsetof(SelfLinkedNodeHeadAndCountRuntimeView, head) == 0x04,
    "SelfLinkedNodeHeadAndCountRuntimeView::head offset must be 0x04"
  );
  static_assert(
    offsetof(SelfLinkedNodeHeadAndCountRuntimeView, count) == 0x08,
    "SelfLinkedNodeHeadAndCountRuntimeView::count offset must be 0x08"
  );
  static_assert(
    sizeof(SelfLinkedNodeHeadAndCountRuntimeView) == 0x0C,
    "SelfLinkedNodeHeadAndCountRuntimeView size must be 0x0C"
  );

  /**
   * Address: 0x00685900 (FUN_00685900)
   *
   * What it does:
   * Seeds one owner runtime lane with a freshly allocated self-linked node
   * head at `+0x04` and clears the dword counter lane at `+0x08`.
   */
  [[maybe_unused]] SelfLinkedNodeHeadAndCountRuntimeView* InitializeSelfLinkedNodeHeadAndClearCount(
    SelfLinkedNodeHeadAndCountRuntimeView* const runtime
  )
  {
    runtime->head = AllocateSingleChecked12ByteSelfLinkedNode();
    runtime->count = 0u;
    return runtime;
  }

  /**
   * Address: 0x008C5C00 (FUN_008C5C00)
   *
   * What it does:
   * Seeds one owner runtime lane with a freshly allocated self-linked node
   * head at `+0x04` via adapter lane H and clears the dword counter lane at
   * `+0x08`.
   */
  [[maybe_unused]] SelfLinkedNodeHeadAndCountRuntimeView*
  InitializeSelfLinkedNodeHeadAndClearCountAdapterH(SelfLinkedNodeHeadAndCountRuntimeView* const runtime)
  {
    runtime->head = AllocateSingleChecked12ByteSelfLinkedNodeAdapterH();
    runtime->count = 0u;
    return runtime;
  }

  /**
   * Address: 0x007D8A70 (FUN_007D8A70)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 12-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterB()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x0081BB10 (FUN_0081BB10)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 12-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterC()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x008AF9C0 (FUN_008AF9C0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 12-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterD()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x008C5FD0 (FUN_008C5FD0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 12-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterE()
  {
    return AllocateChecked12ByteLane(1u);
  }

  /**
   * Address: 0x008D6AE0 (FUN_008D6AE0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 12-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked12ByteLaneAdapterF()
  {
    return AllocateChecked12ByteLane(1u);
  }

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
  void* AllocateChecked16ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 16u);
  }

  /**
   * Address: 0x0073A220 (FUN_0073A220)
   *
   * What it does:
   * Register-lane jump adapter that forces a single 16-byte checked allocation.
   */
  [[maybe_unused]] void* AllocateSingleChecked16ByteLaneAdapterC()
  {
    return AllocateChecked16ByteLane(1u);
  }

  /**
   * Address: 0x00702C50 (FUN_00702C50)
   * Address: 0x007AFB40 (FUN_007AFB40)
   *
   * What it does:
   * Allocates exactly one 16-byte element lane through the checked-allocation
   * helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked16ByteLaneAdapter()
  {
    return AllocateChecked16ByteLane(1u);
  }

  /**
   * Address: 0x007CC5D0 (FUN_007CC5D0)
   *
   * What it does:
   * Preserves one jump-only adapter lane that forces a single 16-byte checked
   * allocation.
   */
  [[maybe_unused]] void* AllocateSingleChecked16ByteLaneAdapterB()
  {
    return AllocateChecked16ByteLane(1u);
  }

  /**
   * Address: 0x008308B0 (FUN_008308B0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 16-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked16ByteLaneAdapterD()
  {
    return AllocateChecked16ByteLane(1u);
  }

  /**
   * Address: 0x008B7BE0 (FUN_008B7BE0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 16-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked16ByteLaneAdapterE()
  {
    return AllocateChecked16ByteLane(1u);
  }

  /**
   * Address: 0x007AEFA0 (FUN_007AEFA0)
   *
   * What it does:
   * Allocates one 16-byte lane and initializes the first two dword lanes to
   * self-pointer links (`node[0]=node`, `node[1]=node`).
   */
  [[maybe_unused]] std::uint32_t* AllocateSingleChecked16ByteSelfLinkedNodeAdapterA()
  {
    auto* const result = static_cast<std::uint32_t*>(AllocateChecked16ByteLane(1u));
    if (result != nullptr) {
      result[0] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }

    if (result != reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(0xFFFFFFFCu))) {
      result[1] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    }
    return result;
  }

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
  void* AllocateChecked48ByteLane(const std::uint32_t elementCount)
  {
    return AllocateCheckedElements(elementCount, 48u);
  }

  /**
   * Address: 0x007366E0 (FUN_007366E0)
   *
   * What it does:
   * Register-lane jump adapter that forces a single 48-byte checked allocation.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterG()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x0089ABF0 (FUN_0089ABF0)
   *
   * What it does:
   * Duplicate register-lane jump adapter that forces a single 48-byte checked
   * allocation.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterH()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x0088FCC0 (FUN_0088FCC0)
   *
   * What it does:
   * Preserves one jump-only adapter lane that allocates exactly one 48-byte
   * checked element.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterI()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x00592F30 (FUN_00592F30)
   * Address: 0x006B03B0 (FUN_006B03B0)
   * Address: 0x007BBB80 (FUN_007BBB80)
   *
   * What it does:
   * Allocates one 48-byte element lane through the checked-allocation helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapter()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x007D43E0 (FUN_007D43E0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 48-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterB()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x007E4F70 (FUN_007E4F70)
   *
   * What it does:
   * Secondary jump-adapter lane that allocates exactly one 48-byte element
   * through the checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterC()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x007F3060 (FUN_007F3060)
   *
   * What it does:
   * Third jump-adapter lane that allocates exactly one 48-byte element through
   * the checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterD()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x0081A680 (FUN_0081A680)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 48-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterE()
  {
    return AllocateChecked48ByteLane(1u);
  }

  /**
   * Address: 0x0083C3A0 (FUN_0083C3A0)
   *
   * What it does:
   * Jump-adapter lane that allocates exactly one 48-byte element through the
   * checked allocator helper.
   */
  [[maybe_unused]] void* AllocateSingleChecked48ByteLaneAdapterF()
  {
    return AllocateChecked48ByteLane(1u);
  }
} // namespace gpg::core::legacy
