#include "moho/debug/RDebugGrid.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/sim/Sim.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace
{
  struct GridHeightSamplesView
  {
    const std::uint16_t* samples = nullptr;
    int width = 0;
    int height = 0;
  };

  struct ByteMaskGridRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    const std::int8_t* samples = nullptr; // +0x04
    std::uint32_t width = 0u; // +0x08
    std::uint32_t height = 0u; // +0x0C
  };
  static_assert(sizeof(ByteMaskGridRuntimeView) == 0x10, "ByteMaskGridRuntimeView size must be 0x10");
  static_assert(offsetof(ByteMaskGridRuntimeView, samples) == 0x04, "ByteMaskGridRuntimeView::samples offset must be 0x04");
  static_assert(offsetof(ByteMaskGridRuntimeView, width) == 0x08, "ByteMaskGridRuntimeView::width offset must be 0x08");
  static_assert(offsetof(ByteMaskGridRuntimeView, height) == 0x0C, "ByteMaskGridRuntimeView::height offset must be 0x0C");

  struct ByteMaskSelectionRuntimeView
  {
    const ByteMaskGridRuntimeView* grid = nullptr; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::int32_t selectedValue = 0; // +0x08
  };
  static_assert(sizeof(ByteMaskSelectionRuntimeView) == 0x0C, "ByteMaskSelectionRuntimeView size must be 0x0C");
  static_assert(
    offsetof(ByteMaskSelectionRuntimeView, selectedValue) == 0x08,
    "ByteMaskSelectionRuntimeView::selectedValue offset must be 0x08"
  );

  struct Stride712CursorRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uintptr_t baseAddress = 0u; // +0x04
  };
  static_assert(sizeof(Stride712CursorRuntimeView) == 0x08, "Stride712CursorRuntimeView size must be 0x08");
  static_assert(
    offsetof(Stride712CursorRuntimeView, baseAddress) == 0x04,
    "Stride712CursorRuntimeView::baseAddress offset must be 0x04"
  );

  struct Stride72RangeRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uintptr_t beginAddress = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uintptr_t endAddress = 0u; // +0x0C
  };
  static_assert(sizeof(Stride72RangeRuntimeView) == 0x10, "Stride72RangeRuntimeView size must be 0x10");
  static_assert(
    offsetof(Stride72RangeRuntimeView, beginAddress) == 0x04,
    "Stride72RangeRuntimeView::beginAddress offset must be 0x04"
  );
  static_assert(offsetof(Stride72RangeRuntimeView, endAddress) == 0x0C, "Stride72RangeRuntimeView::endAddress offset must be 0x0C");

  /**
   * Address: 0x0064CFA0 (FUN_0064CFA0)
   *
   * What it does:
   * Returns one signed byte-mask sample at `(x, y)` when indices are in-range;
   * otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t SampleSignedByteMaskAt(
    const ByteMaskGridRuntimeView* const grid,
    const std::uint32_t x,
    const std::uint32_t y
  ) noexcept
  {
    if (grid == nullptr || grid->samples == nullptr) {
      return 0;
    }
    if (x >= grid->width || y >= grid->height) {
      return 0;
    }

    const std::size_t sampleIndex = static_cast<std::size_t>(x + (y * grid->width));
    return static_cast<std::int32_t>(grid->samples[sampleIndex]);
  }

  /**
   * Address: 0x0064CFD0 (FUN_0064CFD0)
   *
   * What it does:
   * Returns one selector payload when the byte-mask lane at `(x, y)` is set;
   * otherwise returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t ResolveSelectionValueForByteMask(
    const std::uint32_t x,
    const ByteMaskSelectionRuntimeView* const selection,
    const std::uint32_t y
  ) noexcept
  {
    if (selection == nullptr || selection->grid == nullptr || selection->grid->samples == nullptr) {
      return 0;
    }
    if (x >= selection->grid->width || y >= selection->grid->height) {
      return 0;
    }

    const std::size_t sampleIndex = static_cast<std::size_t>(x + (y * selection->grid->width));
    return selection->grid->samples[sampleIndex] != 0 ? selection->selectedValue : 0;
  }

  /**
   * Address: 0x0064D1F0 (FUN_0064D1F0)
   *
   * What it does:
   * Maps one debug-grid mode selector to packed ARGB color lanes.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ResolveDebugGridColorByMode(const std::int32_t mode) noexcept
  {
    switch (mode) {
      case 0:
        return 0xFFFFFFFFu;
      case 1:
        return 0xFFFF0000u;
      case 2:
        return 0xFF00FF00u;
      default:
        return 0xFF0000FFu;
    }
  }

  /**
   * Address: 0x0064E240 (FUN_0064E240)
   *
   * What it does:
   * Returns one `base + index * 0x2C8` address lane from a stride-712 view.
   */
  [[maybe_unused]] [[nodiscard]] std::uintptr_t ResolveStride712ElementAddress(
    const std::int32_t index,
    const Stride712CursorRuntimeView* const view
  ) noexcept
  {
    return view->baseAddress + (static_cast<std::uintptr_t>(index) * 0x2C8u);
  }

  /**
   * Address: 0x0064E2D0 (FUN_0064E2D0)
   *
   * What it does:
   * Returns element count for one stride-72 pointer range, or zero when the
   * begin lane is null.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t CountStride72Elements(const Stride72RangeRuntimeView* const view) noexcept
  {
    if (view == nullptr || view->beginAddress == 0u) {
      return 0;
    }

    const std::intptr_t byteSpan =
      static_cast<std::intptr_t>(view->endAddress) - static_cast<std::intptr_t>(view->beginAddress);
    return static_cast<std::int32_t>(byteSpan / 72);
  }

  /**
   * Address: 0x0064CF00 (FUN_0064CF00)
   *
   * What it does:
   * Clamps one `(x,z)` index pair into the valid 16-bit sample grid and
   * returns world-space point `{x, sample/128.0f, z}`.
   */
  [[maybe_unused]] [[nodiscard]] Wm3::Vector3f BuildClampedGridSamplePoint(
    const GridHeightSamplesView& grid,
    const int x,
    const int z
  ) noexcept
  {
    Wm3::Vector3f out{};
    out.x = static_cast<float>(x);
    out.z = static_cast<float>(z);
    out.y = 0.0f;

    if (grid.samples == nullptr || grid.width <= 0 || grid.height <= 0) {
      return out;
    }

    const int clampedX = std::clamp(x, 0, grid.width - 1);
    const int clampedZ = std::clamp(z, 0, grid.height - 1);
    const std::size_t sampleIndex = static_cast<std::size_t>(clampedX + (clampedZ * grid.width));
    const std::uint16_t sample = grid.samples[sampleIndex];
    out.y = static_cast<float>(sample) * (1.0f / 128.0f);
    return out;
  }

  /**
   * Address: 0x0064D000 (FUN_0064D000)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `RDebugGrid`.
   */
  [[nodiscard]] gpg::RType* ResolveRDebugGridTypeCachePrimary()
  {
    gpg::RType* type = moho::RDebugGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugGrid));
      moho::RDebugGrid::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064E250 (FUN_0064E250)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches `RDebugGrid` reflection
   * type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveRDebugGridTypeCacheSecondary()
  {
    gpg::RType* type = moho::RDebugGrid::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::RDebugGrid));
      moho::RDebugGrid::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0064D1C0 (FUN_0064D1C0)
   *
   * What it does:
   * Returns one debug-grid distance lane by selector:
   * `0 -> 75.0f`, `1 -> 500.0f`, otherwise `+inf`.
   */
  [[maybe_unused]] float ResolveRDebugGridDistanceBySelector(const int selector) noexcept
  {
    if (selector == 0) {
      return 75.0f;
    }
    if (selector == 1) {
      return 500.0f;
    }
    return std::numeric_limits<float>::infinity();
  }

  /**
   * Address: 0x0064EDB0 (FUN_0064EDB0, Moho::RDebugGrid non-deleting dtor body)
   *
   * What it does:
   * Runs the typed debug-overlay intrusive unlink lane for one `RDebugGrid`
   * instance and restores singleton link state.
   */
  [[maybe_unused]] void DestroyRDebugGridNonDeletingBody(moho::RDebugGrid* const overlay) noexcept
  {
    if (overlay == nullptr) {
      return;
    }

    auto* const node = static_cast<moho::TDatListItem<moho::RDebugOverlay, void>*>(static_cast<moho::RDebugOverlay*>(overlay));
    node->ListUnlinkSelf();
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugGrid::sType = nullptr;

  /**
   * Address: 0x0064ED10 (FUN_0064ED10)
   *
   * What it does:
   * Initializes the grid-overlay vtable lane and inherited intrusive
   * debug-overlay links.
   */
  RDebugGrid::RDebugGrid() = default;

  /**
   * Address: 0x0064D020 (FUN_0064D020, Moho::RDebugGrid::GetClass)
   */
  gpg::RType* RDebugGrid::GetClass() const
  {
    return ResolveRDebugGridTypeCachePrimary();
  }

  /**
   * Address: 0x0064D040 (FUN_0064D040, Moho::RDebugGrid::GetDerivedObjectRef)
   */
  gpg::RRef RDebugGrid::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x0064ED30 (FUN_0064ED30, Moho::RDebugGrid::dtr)
   */
  RDebugGrid::~RDebugGrid() = default;

  /**
   * Address: 0x0064D7A0 (FUN_0064D7A0, Moho::RDebugGrid::OnTick)
   */
  void RDebugGrid::Tick(Sim* const sim)
  {
    if (sim == nullptr || sim->mMapData == nullptr) {
      return;
    }

    // FUN_0064D7A0 relies on the unrecovered recursive grid pass (FUN_0064D3A0 family).
    // Preserve current typed entry checks while helper lifting is pending.
    (void)sim->GetDebugCanvas();
  }
} // namespace moho
