#include "moho/math/Wm3DistanceFafExtras.h"
#include "Wm3Capsule3.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

namespace Wm3
{
  /**
   * Address: 0x00A57240 (FUN_00A57240, fn)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackA(void* /*self*/) noexcept {}

  /**
   * Address: 0x00A57250 (FUN_00A57250, nullsub_10)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackB(void* /*self*/) noexcept {}

  /**
   * Address: 0x00A766B0 (FUN_00A766B0, nullsub_11)
   *
   * What it does:
   * Preserves one legacy TRational query callback lane as an explicit no-op.
   */
  void QueryRationalNoOpCallbackC(void* /*self*/) noexcept {}

  /**
   * Address: 0x00A59860 (FUN_00A59860, sub_A59860)
   *
   * What it does:
   * Constructs three contiguous `TRational<32>` objects at `0x100`-byte stride
   * and returns the original destination pointer.
   */
  [[maybe_unused]] char* ConstructRational32TripleAtStride256(char* const destination) noexcept
  {
    auto* cursor = reinterpret_cast<std::uint8_t*>(destination);
    for (int index = 0; index < 3; ++index) {
      ::new (static_cast<void*>(cursor)) TRational<32>();
      cursor += 0x100u;
    }
    return destination;
  }

  /**
   * Address: 0x00A59880 (FUN_00A59880, sub_A59880)
   *
   * What it does:
   * Constructs three contiguous `TRational<64>` objects at `0x200`-byte stride
   * and returns the original destination pointer.
   */
  [[maybe_unused]] char* ConstructRational64TripleAtStride512(char* const destination) noexcept
  {
    auto* cursor = reinterpret_cast<std::uint8_t*>(destination);
    for (int index = 0; index < 3; ++index) {
      ::new (static_cast<void*>(cursor)) TRational<64>();
      cursor += 0x200u;
    }
    return destination;
  }

  /**
   * Address: 0x00A76BB0 (FUN_00A76BB0, sub_A76BB0)
   *
   * What it does:
   * Constructs two contiguous `TRational<16>` objects at `0x80`-byte stride
   * and returns the original destination pointer.
   */
  [[maybe_unused]] char* ConstructRational16PairAtStride128(char* const destination) noexcept
  {
    auto* cursor = reinterpret_cast<std::uint8_t*>(destination);
    for (int index = 0; index < 2; ++index) {
      ::new (static_cast<void*>(cursor)) TRational<16>();
      cursor += 0x80u;
    }
    return destination;
  }

  /**
   * Address: 0x00A76BD0 (FUN_00A76BD0, sub_A76BD0)
   *
   * What it does:
   * Constructs two contiguous `TRational<32>` objects at `0x100`-byte stride
   * and returns the original destination pointer.
   */
  [[maybe_unused]] char* ConstructRational32PairAtStride256(char* const destination) noexcept
  {
    auto* cursor = reinterpret_cast<std::uint8_t*>(destination);
    for (int index = 0; index < 2; ++index) {
      ::new (static_cast<void*>(cursor)) TRational<32>();
      cursor += 0x100u;
    }
    return destination;
  }

  namespace
  {
    struct VtableOnlyRuntime
    {
      void* vtable = nullptr;
    };

    std::uint8_t gIntersectorDouble2RuntimeVtableTag = 0;
    std::uint8_t gIntersectorDouble3RuntimeVtableTag = 0;
    std::uint8_t gQueryRuntimeVtableTag = 0;

    [[maybe_unused]] void* RebindIntersectorDouble2RuntimeBaseVtable(
      void* const intersectorRuntime
    ) noexcept
    {
      auto* const runtime = static_cast<VtableOnlyRuntime*>(intersectorRuntime);
      if (runtime != nullptr) {
        runtime->vtable = &gIntersectorDouble2RuntimeVtableTag;
      }
      return runtime;
    }

    [[maybe_unused]] void* RebindIntersectorDouble3RuntimeBaseVtable(
      void* const intersectorRuntime
    ) noexcept
    {
      auto* const runtime = static_cast<VtableOnlyRuntime*>(intersectorRuntime);
      if (runtime != nullptr) {
        runtime->vtable = &gIntersectorDouble3RuntimeVtableTag;
      }
      return runtime;
    }

    [[maybe_unused]] void* RebindWm3RuntimeVtableWithFlag(
      void* const runtimeObject,
      void* const reboundVtableTag,
      const std::uint8_t deleteFlags
    ) noexcept
    {
      auto* const runtime = static_cast<VtableOnlyRuntime*>(runtimeObject);
      if (runtime != nullptr) {
        runtime->vtable = reboundVtableTag;
      }
      if ((deleteFlags & 1u) != 0u) {
        ::operator delete(runtime);
      }
      return runtime;
    }
  } // namespace

  /**
   * Address: 0x00A45600 (FUN_00A45600)
   *
   * What it does:
   * Initializes one `Intersector<double, Vector2<double>>` runtime base lane
   * by binding the base vtable and clearing contact-time/type result lanes.
   */
  [[maybe_unused]] void* ConstructIntersectorDouble2RuntimeBase(
    void* const intersectorRuntime
  ) noexcept
  {
    struct IntersectorDouble2CtorRuntimeView
    {
      void* vtable = nullptr;               // +0x00
      std::uint8_t unknown04_07[0x04]{};    // +0x04
      double contactTime = 0.0;             // +0x08
      std::int32_t intersectionType = 0;    // +0x10
    };
    static_assert(
      offsetof(IntersectorDouble2CtorRuntimeView, contactTime) == 0x08,
      "IntersectorDouble2CtorRuntimeView::contactTime offset must be 0x08"
    );
    static_assert(
      offsetof(IntersectorDouble2CtorRuntimeView, intersectionType) == 0x10,
      "IntersectorDouble2CtorRuntimeView::intersectionType offset must be 0x10"
    );

    auto* const runtime = static_cast<IntersectorDouble2CtorRuntimeView*>(intersectorRuntime);
    if (runtime == nullptr) {
      return nullptr;
    }

    runtime->contactTime = 0.0;
    runtime->vtable = &gIntersectorDouble2RuntimeVtableTag;
    runtime->intersectionType = 0;
    return runtime;
  }

  /**
   * Address: 0x00A45690 (FUN_00A45690)
   *
   * What it does:
   * Initializes one `Intersector<double, Vector3<double>>` runtime base lane
   * by binding the base vtable and clearing contact-time/type result lanes.
   */
  [[maybe_unused]] void* ConstructIntersectorDouble3RuntimeBase(
    void* const intersectorRuntime
  ) noexcept
  {
    struct IntersectorDouble3CtorRuntimeView
    {
      void* vtable = nullptr;               // +0x00
      std::uint8_t unknown04_07[0x04]{};    // +0x04
      double contactTime = 0.0;             // +0x08
      std::int32_t intersectionType = 0;    // +0x10
    };
    static_assert(
      offsetof(IntersectorDouble3CtorRuntimeView, contactTime) == 0x08,
      "IntersectorDouble3CtorRuntimeView::contactTime offset must be 0x08"
    );
    static_assert(
      offsetof(IntersectorDouble3CtorRuntimeView, intersectionType) == 0x10,
      "IntersectorDouble3CtorRuntimeView::intersectionType offset must be 0x10"
    );

    auto* const runtime = static_cast<IntersectorDouble3CtorRuntimeView*>(intersectorRuntime);
    if (runtime == nullptr) {
      return nullptr;
    }

    runtime->contactTime = 0.0;
    runtime->vtable = &gIntersectorDouble3RuntimeVtableTag;
    runtime->intersectionType = 0;
    return runtime;
  }

  /**
   * Address: 0x00A45590 (FUN_00A45590)
   *
   * What it does:
   * Rebinds one `Intersector<double, Vector2<double>>` runtime object to the
   * base intersector vtable lane.
   */
  [[maybe_unused]] void RebindIntersectorDouble2RuntimeBaseVtableThunk(
    void* const intersectorRuntime
  ) noexcept
  {
    (void)RebindIntersectorDouble2RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A45620 (FUN_00A45620)
   *
   * What it does:
   * Rebinds one `Intersector<double, Vector3<double>>` runtime object to the
   * base intersector vtable lane.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3RuntimeBaseVtableLaneE(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A469C0 (FUN_00A469C0)
   *
   * What it does:
   * Tail-forwards one intersector base-vtable rebind thunk lane into the
   * canonical `Intersector<double, Vector3<double>>` base rebind helper.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3RuntimeBaseVtableThunkLaneB(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtableLaneE(intersectorRuntime);
  }

  /**
   * Address: 0x00A7F720 (FUN_00A7F720)
   *
   * What it does:
   * Thunk lane that forwards to the canonical
   * `Intersector<double, Vector3<double>>` base-vtable rebind helper.
   */
  [[maybe_unused]] void RebindIntersectorDouble3RuntimeBaseVtableThunkLane(
    void* const intersectorRuntime
  ) noexcept
  {
    (void)RebindIntersectorDouble3RuntimeBaseVtableLaneE(intersectorRuntime);
  }

  /**
   * Address: 0x00A75830 (FUN_00A75830)
   *
   * What it does:
   * Returns the signed 2x2 determinant `a1*a4 - a2*a3` in 64-bit precision.
   */
  [[maybe_unused]] std::int64_t ComputeDeterminant2x2Int64LaneA(
    const std::int64_t a1,
    const std::int64_t a2,
    const std::int64_t a3,
    const std::int64_t a4
  ) noexcept
  {
    return (a1 * a4) - (a2 * a3);
  }

  /**
   * Address: 0x00A75970 (FUN_00A75970)
   *
   * What it does:
   * Alias lane of the signed 2x2 determinant helper.
   */
  [[maybe_unused]] std::int64_t ComputeDeterminant2x2Int64LaneB(
    const std::int64_t a1,
    const std::int64_t a2,
    const std::int64_t a3,
    const std::int64_t a4
  ) noexcept
  {
    return ComputeDeterminant2x2Int64LaneA(a1, a2, a3, a4);
  }

  /**
   * Address: 0x00A778D0 (FUN_00A778D0)
   *
   * What it does:
   * Copies one 64-byte runtime lane from `source` into `destination`.
   */
  [[maybe_unused]] void* Copy64ByteRuntimeLaneA(
    void* const destination,
    const void* const source
  ) noexcept
  {
    Wm3::System::Memcpy(destination, 0x40u, source, 0x40u);
    return destination;
  }

  /**
   * Address: 0x00A778F0 (FUN_00A778F0)
   *
   * What it does:
   * Alias lane that copies one 64-byte runtime block.
   */
  [[maybe_unused]] void* Copy64ByteRuntimeLaneB(
    void* const destination,
    const void* const source
  ) noexcept
  {
    return Copy64ByteRuntimeLaneA(destination, source);
  }

  /**
   * Address: 0x00A77A80 (FUN_00A77A80)
   *
   * What it does:
   * Copies two adjacent 64-byte runtime lanes (128 bytes total) from source
   * into destination.
   */
  [[maybe_unused]] void* CopyDual64ByteRuntimeLaneA(
    void* const destination,
    const void* const source
  ) noexcept
  {
    auto* const destinationBytes = static_cast<std::uint8_t*>(destination);
    auto* const sourceBytes = static_cast<const std::uint8_t*>(source);
    Wm3::System::Memcpy(destinationBytes, 0x40u, sourceBytes, 0x40u);
    Wm3::System::Memcpy(destinationBytes + 0x40, 0x40u, sourceBytes + 0x40, 0x40u);
    return destination;
  }

  /**
   * Address: 0x00A77C40 (FUN_00A77C40)
   *
   * What it does:
   * Alias lane that copies two adjacent 64-byte runtime blocks.
   */
  [[maybe_unused]] void* CopyDual64ByteRuntimeLaneB(
    void* const destination,
    const void* const source
  ) noexcept
  {
    return CopyDual64ByteRuntimeLaneA(destination, source);
  }

  /**
   * Address: 0x00A41500 (FUN_00A41500)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector3<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3BaseAdapterLaneA(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A46390 (FUN_00A46390)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector3<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3BaseAdapterLaneB(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A469D0 (FUN_00A469D0)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector3<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3BaseAdapterLaneC(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A4FE20 (FUN_00A4FE20)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector3<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble3BaseAdapterLaneD(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble3RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A47C90 (FUN_00A47C90)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector2<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble2BaseAdapterLaneA(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble2RuntimeBaseVtable(intersectorRuntime);
  }

  /**
   * Address: 0x00A4E5D0 (FUN_00A4E5D0)
   *
   * What it does:
   * Adapter lane that forwards to the canonical helper that rebinds one
   * `Intersector<double, Vector2<double>>` runtime base vtable.
   */
  [[maybe_unused]] void* RebindIntersectorDouble2BaseAdapterLaneB(
    void* const intersectorRuntime
  ) noexcept
  {
    return RebindIntersectorDouble2RuntimeBaseVtable(intersectorRuntime);
  }

  namespace
  {
    struct IntrBox2Circle2dCtorRuntimeView
    {
      void* vtable = nullptr;                     // +0x00
      std::uint8_t lane04_17[0x14]{};            // +0x04
      const Box2<double>* box = nullptr;         // +0x18
      const void* circle = nullptr;              // +0x1C
    };
    static_assert(
      offsetof(IntrBox2Circle2dCtorRuntimeView, box) == 0x18,
      "IntrBox2Circle2dCtorRuntimeView::box offset must be 0x18"
    );
    static_assert(
      offsetof(IntrBox2Circle2dCtorRuntimeView, circle) == 0x1C,
      "IntrBox2Circle2dCtorRuntimeView::circle offset must be 0x1C"
    );
  }

  /**
   * Address: 0x00A4EE20 (FUN_00A4EE20)
   *
   * What it does:
   * Constructs one `IntrBox2Circle2<double>` runtime payload by initializing
   * the double-precision intersector base lane and binding box/circle owners.
   */
  [[maybe_unused]] IntrBox2Circle2dCtorRuntimeView* ConstructIntrBox2Circle2dRuntime(
    IntrBox2Circle2dCtorRuntimeView* const runtime,
    const Box2<double>* const box,
    const void* const circle
  ) noexcept
  {
    static std::uint8_t sIntrBox2Circle2dRuntimeVtableTag = 0;

    if (runtime == nullptr) {
      return nullptr;
    }

    (void)ConstructIntersectorDouble2RuntimeBase(runtime);
    runtime->box = box;
    runtime->vtable = &sIntrBox2Circle2dRuntimeVtableTag;
    runtime->circle = circle;
    return runtime;
  }

  /**
   * Address: 0x00A53080 (FUN_00A53080)
   *
   * What it does:
   * Rebinds one `Wm3::Query`-derived runtime object to the `Query` base
   * vtable lane.
   */
  [[maybe_unused]] void* RebindQueryRuntimeBaseVtableLaneA(
    void* const queryRuntime
  ) noexcept
  {
    auto* const runtime = static_cast<VtableOnlyRuntime*>(queryRuntime);
    if (runtime != nullptr) {
      runtime->vtable = &gQueryRuntimeVtableTag;
    }
    return runtime;
  }

  /**
   * Address: 0x00A53200 (FUN_00A53200)
   *
   * What it does:
   * Rebinds one `Wm3::Query`-derived runtime object to the `Query` base
   * vtable lane (alternate constructor lane).
   */
  [[maybe_unused]] void* RebindQueryRuntimeBaseVtableLaneB(
    void* const queryRuntime
  ) noexcept
  {
    return RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A74E50 (FUN_00A74E50)
   *
   * What it does:
   * Rebinds one `Wm3::Query`-derived runtime object to the `Query` base
   * vtable lane (2D rational query family lane A).
   */
  [[maybe_unused]] void* RebindQueryRuntimeBaseVtableLaneC(
    void* const queryRuntime
  ) noexcept
  {
    return RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A74FB0 (FUN_00A74FB0)
   *
   * What it does:
   * Rebinds one `Wm3::Query`-derived runtime object to the `Query` base
   * vtable lane (2D rational query family lane B).
   */
  [[maybe_unused]] void* RebindQueryRuntimeBaseVtableLaneD(
    void* const queryRuntime
  ) noexcept
  {
    return RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  namespace
  {
    struct QueryRuntimeOwnerPairView
    {
      void* vtable = nullptr;          // +0x00
      const void* ownerLane04 = nullptr; // +0x04
      const void* ownerLane08 = nullptr; // +0x08
    };
    static_assert(sizeof(QueryRuntimeOwnerPairView) == 0x0C, "QueryRuntimeOwnerPairView size must be 0x0C");
    static_assert(offsetof(QueryRuntimeOwnerPairView, ownerLane04) == 0x04, "QueryRuntimeOwnerPairView::ownerLane04 offset must be 0x04");
    static_assert(offsetof(QueryRuntimeOwnerPairView, ownerLane08) == 0x08, "QueryRuntimeOwnerPairView::ownerLane08 offset must be 0x08");

    [[nodiscard]] QueryRuntimeOwnerPairView* ConstructQueryRuntimeOwnerPairWithVtable(
      QueryRuntimeOwnerPairView* const runtime,
      const void* const ownerLane04,
      const void* const ownerLane08,
      void* const vtableTag
    ) noexcept
    {
      if (runtime == nullptr) {
        return nullptr;
      }

      runtime->vtable = vtableTag;
      runtime->ownerLane04 = ownerLane04;
      runtime->ownerLane08 = ownerLane08;
      return runtime;
    }
  } // namespace

  /**
   * Address: 0x00A51EA0 (FUN_00A51EA0)
   *
   * What it does:
   * Constructs one `Wm3::Query` runtime base lane by binding the base query
   * vtable and returning `this`.
   */
  [[maybe_unused]] VtableOnlyRuntime* ConstructQueryRuntimeBaseVtableLaneA(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    auto* const runtime = static_cast<VtableOnlyRuntime*>(RebindQueryRuntimeBaseVtableLaneA(queryRuntime));
    return runtime;
  }

  /**
   * Address: 0x00A51EB0 (FUN_00A51EB0)
   *
   * What it does:
   * Rebinds one `Wm3::Query` runtime object to the `Query` base vtable lane.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneE(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A53060 (FUN_00A53060)
   *
   * What it does:
   * Constructs one `Query3<float>` runtime lane by binding the derived vtable
   * and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3FloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3FloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3FloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A531E0 (FUN_00A531E0)
   *
   * What it does:
   * Constructs one `Query3<double>` runtime lane by binding the derived vtable
   * and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3DoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3DoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3DoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A53460 (FUN_00A53460)
   *
   * What it does:
   * Constructs one `Query3Int64<float>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3Int64FloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3Int64FloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3Int64FloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A535D0 (FUN_00A535D0)
   *
   * What it does:
   * Constructs one `Query3Int64<double>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3Int64DoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3Int64DoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3Int64DoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A53740 (FUN_00A53740)
   *
   * What it does:
   * Constructs one `Query3TInteger<float>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3TIntegerFloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3TIntegerFloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3TIntegerFloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A538B0 (FUN_00A538B0)
   *
   * What it does:
   * Constructs one `Query3TInteger<double>` runtime lane by binding the
   * derived vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery3TIntegerDoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery3TIntegerDoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery3TIntegerDoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A53F80 (FUN_00A53F80)
   *
   * What it does:
   * Rebinds one `Wm3::Query` runtime object to the `Query` base vtable lane.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneF(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A53F90 (FUN_00A53F90)
   *
   * What it does:
   * Secondary rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneG(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A53FA0 (FUN_00A53FA0)
   *
   * What it does:
   * Third rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneH(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A53FB0 (FUN_00A53FB0)
   *
   * What it does:
   * Fourth rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneI(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A74E30 (FUN_00A74E30)
   *
   * What it does:
   * Constructs one `Query2<float>` runtime lane by binding the derived vtable
   * and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2FloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2FloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2FloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A74F90 (FUN_00A74F90)
   *
   * What it does:
   * Constructs one `Query2<double>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2DoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2DoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2DoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A751C0 (FUN_00A751C0)
   *
   * What it does:
   * Constructs one `Query2Int64<float>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2Int64FloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2Int64FloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2Int64FloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A75310 (FUN_00A75310)
   *
   * What it does:
   * Constructs one `Query2Int64<double>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2Int64DoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2Int64DoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2Int64DoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A75430 (FUN_00A75430)
   *
   * What it does:
   * Constructs one `Query2TInteger<float>` runtime lane by binding the derived
   * vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2TIntegerFloatRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2TIntegerFloatRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2TIntegerFloatRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A75580 (FUN_00A75580)
   *
   * What it does:
   * Constructs one `Query2TInteger<double>` runtime lane by binding the
   * derived vtable and storing the two owner lanes at `+0x04` and `+0x08`.
   */
  [[maybe_unused]] QueryRuntimeOwnerPairView* ConstructQuery2TIntegerDoubleRuntimeLaneA(
    QueryRuntimeOwnerPairView* const queryRuntime,
    const void* const ownerLane04,
    const void* const ownerLane08
  ) noexcept
  {
    static std::uint8_t sQuery2TIntegerDoubleRuntimeVtableTag = 0;
    return ConstructQueryRuntimeOwnerPairWithVtable(
      queryRuntime,
      ownerLane04,
      ownerLane08,
      &sQuery2TIntegerDoubleRuntimeVtableTag
    );
  }

  /**
   * Address: 0x00A756E0 (FUN_00A756E0)
   *
   * What it does:
   * Rebinds one `Wm3::Query` runtime object to the `Query` base vtable lane.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneJ(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A756F0 (FUN_00A756F0)
   *
   * What it does:
   * Secondary rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneK(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A75700 (FUN_00A75700)
   *
   * What it does:
   * Third rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneL(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A75710 (FUN_00A75710)
   *
   * What it does:
   * Fourth rebind lane for one `Wm3::Query` runtime object's base vtable.
   */
  [[maybe_unused]] void RebindQueryRuntimeBaseVtableLaneM(
    VtableOnlyRuntime* const queryRuntime
  ) noexcept
  {
    (void)RebindQueryRuntimeBaseVtableLaneA(queryRuntime);
  }

  /**
   * Address: 0x00A456B0 (FUN_00A456B0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for the
   * `Intersector<float, Vector2<float>>` runtime base object.
   */
  [[maybe_unused]] void* ResetIntersectorFloat2VtableWithFlagRuntime(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    static std::uint8_t sIntersectorFloat2RuntimeVtableTag = 0;
    return RebindWm3RuntimeVtableWithFlag(intersectorRuntime, &sIntersectorFloat2RuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A456F0 (FUN_00A456F0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for the
   * `Intersector<double, Vector2<double>>` runtime base object.
   */
  [[maybe_unused]] void* ResetIntersectorDouble2VtableWithFlagRuntime(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(intersectorRuntime, &gIntersectorDouble2RuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A45710 (FUN_00A45710)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for the
   * `Intersector<double, Vector3<double>>` runtime base object.
   */
  [[maybe_unused]] void* ResetIntersectorDouble3VtableWithFlagRuntime(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(intersectorRuntime, &gIntersectorDouble3RuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A4F520 (FUN_00A4F520)
   *
   * What it does:
   * Deleting-dtor thunk lane for `IntrBox2Circle2<double>` that rebinds the
   * object to the `Intersector<double, Vector2<double>>` base vtable and
   * deletes storage when bit0 of `deleteFlags` is set.
   */
  [[maybe_unused]] void* ResetIntrBox2Circle2DoubleVtableWithFlagRuntimeAlias(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return ResetIntersectorDouble2VtableWithFlagRuntime(intersectorRuntime, deleteFlags);
  }

  /**
   * Address: 0x00A50200 (FUN_00A50200)
   *
   * What it does:
   * Deleting-dtor thunk lane for `IntrLine3Box3<double>` that rebinds the
   * object to the `Intersector<double, Vector3<double>>` base vtable and
   * deletes storage when bit0 of `deleteFlags` is set.
   */
  [[maybe_unused]] void* ResetIntrLine3Box3DoubleVtableWithFlagRuntimeAlias(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return ResetIntersectorDouble3VtableWithFlagRuntime(intersectorRuntime, deleteFlags);
  }

  /**
   * Address: 0x00A6C050 (FUN_00A6C050)
   *
   * What it does:
   * Deleting-dtor thunk lane for `IntrSegment3Capsule3<double>` that rebinds
   * the object to the `Intersector<double, Vector3<double>>` base vtable and
   * deletes storage when bit0 of `deleteFlags` is set.
   */
  [[maybe_unused]] void* ResetIntrSegment3Capsule3DoubleVtableWithFlagRuntimeAlias(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return ResetIntersectorDouble3VtableWithFlagRuntime(intersectorRuntime, deleteFlags);
  }

  /**
   * Address: 0x00A7F900 (FUN_00A7F900)
   *
   * What it does:
   * Deleting-dtor thunk lane for `IntrLine3Capsule3<double>` that rebinds the
   * object to the `Intersector<double, Vector3<double>>` base vtable and
   * deletes storage when bit0 of `deleteFlags` is set.
   */
  [[maybe_unused]] void* ResetIntrLine3Capsule3DoubleVtableWithFlagRuntimeAlias(
    void* const intersectorRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return ResetIntersectorDouble3VtableWithFlagRuntime(intersectorRuntime, deleteFlags);
  }

  /**
   * Address: 0x00A53F40 (FUN_00A53F40)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3<float>` runtime object
   * by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3FloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A53F60 (FUN_00A53F60)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3<double>` runtime object
   * by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3DoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A55130 (FUN_00A55130)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query` runtime base object.
   */
  [[maybe_unused]] void* ResetQueryVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A571C0 (FUN_00A571C0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3Int64<float>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3Int64FloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A571E0 (FUN_00A571E0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3Int64<double>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3Int64DoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A57200 (FUN_00A57200)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3TInteger<float>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3TIntegerFloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A57220 (FUN_00A57220)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query3TInteger<double>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery3TIntegerDoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A756A0 (FUN_00A756A0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2<float>` runtime object by
   * rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2FloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A756C0 (FUN_00A756C0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2<double>` runtime object
   * by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2DoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A76630 (FUN_00A76630)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2Int64<float>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2Int64FloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A76650 (FUN_00A76650)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2Int64<double>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2Int64DoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A76670 (FUN_00A76670)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2TInteger<float>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2TIntegerFloatVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A76690 (FUN_00A76690)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for one `Query2TInteger<double>` runtime
   * object by rebinding to the `Query` base vtable lane.
   */
  [[maybe_unused]] void* ResetQuery2TIntegerDoubleVtableWithFlagRuntime(
    void* const queryRuntime,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    return RebindWm3RuntimeVtableWithFlag(queryRuntime, &gQueryRuntimeVtableTag, deleteFlags);
  }

  /**
   * Address: 0x00A4A4B0 (FUN_00A4A4B0)
   *
   * What it does:
   * Builds one `(center.xyz, radiusSquared)` sphere lane from two opposite
   * axis-aligned bounds corners.
   */
  float* ComputeSphereCenterAndRadiusSquaredFromBoundsEndpoints(
    float* const outCenterRadiusSquared,
    const float* const minCorner,
    const float* const maxCorner
  ) noexcept
  {
    if (outCenterRadiusSquared == nullptr || minCorner == nullptr || maxCorner == nullptr) {
      return outCenterRadiusSquared;
    }

    const float centerX = (minCorner[0] + maxCorner[0]) * 0.5f;
    const float centerY = (minCorner[1] + maxCorner[1]) * 0.5f;
    const float centerZ = (minCorner[2] + maxCorner[2]) * 0.5f;
    outCenterRadiusSquared[0] = centerX;
    outCenterRadiusSquared[1] = centerY;
    outCenterRadiusSquared[2] = centerZ;

    const float deltaX = maxCorner[0] - minCorner[0];
    const float deltaY = maxCorner[1] - minCorner[1];
    const float deltaZ = maxCorner[2] - minCorner[2];
    outCenterRadiusSquared[3] = (deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ) * 0.25f;
    return outCenterRadiusSquared;
  }

  struct MinSphereSupportState
  {
    std::int32_t supportCount; // +0x00
    std::int32_t firstIndex;   // +0x04
    std::int32_t secondIndex;  // +0x08
    std::int32_t thirdIndex;   // +0x0C
    std::int32_t fourthIndex;  // +0x10
  };
  static_assert(sizeof(MinSphereSupportState) == 0x14, "MinSphereSupportState size must be 0x14");
  static_assert(offsetof(MinSphereSupportState, supportCount) == 0x00, "MinSphereSupportState::supportCount offset must be 0x00");
  static_assert(offsetof(MinSphereSupportState, firstIndex) == 0x04, "MinSphereSupportState::firstIndex offset must be 0x04");
  static_assert(offsetof(MinSphereSupportState, secondIndex) == 0x08, "MinSphereSupportState::secondIndex offset must be 0x08");
  static_assert(offsetof(MinSphereSupportState, thirdIndex) == 0x0C, "MinSphereSupportState::thirdIndex offset must be 0x0C");
  static_assert(offsetof(MinSphereSupportState, fourthIndex) == 0x10, "MinSphereSupportState::fourthIndex offset must be 0x10");

  /**
   * Address: 0x00A4ACF0 (FUN_00A4ACF0)
   *
   * What it does:
   * Builds one 2-point support sphere from the current support's first point
   * and one candidate point, then records the updated support state.
   */
  [[maybe_unused]] float* UpdateTwoPointSupportSphereFromCandidate(
    float* const outCenterRadiusSquared,
    const std::int32_t candidatePointIndex,
    const float* const* const shuffledPointTable,
    MinSphereSupportState* const supportState
  ) noexcept
  {
    ComputeSphereCenterAndRadiusSquaredFromBoundsEndpoints(
      outCenterRadiusSquared,
      shuffledPointTable[supportState->firstIndex],
      shuffledPointTable[candidatePointIndex]
    );
    supportState->secondIndex = candidatePointIndex;
    supportState->supportCount = 2;
    return outCenterRadiusSquared;
  }

  namespace
  {
    using RuntimeVectorElementDestructor = void (*)(void*);

    void RunRuntimeVectorDestructorIterator(
      void* const start,
      const std::size_t elementSize,
      const int elementCount,
      const RuntimeVectorElementDestructor destructor
    ) noexcept
    {
      if (start == nullptr || destructor == nullptr || elementCount <= 0) {
        return;
      }

      auto* cursor = static_cast<std::uint8_t*>(start) + (elementSize * static_cast<std::size_t>(elementCount));
      for (int index = elementCount; index > 0; --index) {
        cursor -= elementSize;
        destructor(cursor);
      }
    }

    void DestroyRational16PairLane(void* const element) noexcept
    {
      RunRuntimeVectorDestructorIterator(element, 0x80u, 2, &QueryRationalNoOpCallbackC);
    }

    void DestroyRational32PairLane(void* const element) noexcept
    {
      RunRuntimeVectorDestructorIterator(element, 0x100u, 2, &QueryRationalNoOpCallbackA);
    }
  } // namespace

  /**
   * Address: 0x00A78750 (FUN_00A78750)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for nested `TRational<16>` array
   * storage, handling both cookie-backed array and in-place fixed-lane forms.
   */
  [[maybe_unused]] char* DestroyNestedRational16ArrayWithFlags(
    char* const start,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    if ((deleteFlags & 0x02u) != 0u) {
      const auto count = *reinterpret_cast<const std::uint32_t*>(start - 4);
      RunRuntimeVectorDestructorIterator(start, 0x100u, static_cast<int>(count), &DestroyRational16PairLane);
      if ((deleteFlags & 0x01u) != 0u) {
        ::operator delete[](start - 4);
      }
      return start - 4;
    }

    RunRuntimeVectorDestructorIterator(start, 0x80u, 2, &QueryRationalNoOpCallbackC);
    if ((deleteFlags & 0x01u) != 0u) {
      ::operator delete(start);
    }
    return start;
  }

  /**
   * Address: 0x00A787C0 (FUN_00A787C0)
   *
   * What it does:
   * Runs one deleting-dtor thunk lane for nested `TRational<32>` array
   * storage, handling both cookie-backed array and in-place fixed-lane forms.
   */
  [[maybe_unused]] char* DestroyNestedRational32ArrayWithFlags(
    char* const start,
    const std::uint8_t deleteFlags
  ) noexcept
  {
    if ((deleteFlags & 0x02u) != 0u) {
      const auto count = *reinterpret_cast<const std::uint32_t*>(start - 4);
      RunRuntimeVectorDestructorIterator(start, 0x200u, static_cast<int>(count), &DestroyRational32PairLane);
      if ((deleteFlags & 0x01u) != 0u) {
        ::operator delete[](start - 4);
      }
      return start - 4;
    }

    RunRuntimeVectorDestructorIterator(start, 0x100u, 2, &QueryRationalNoOpCallbackA);
    if ((deleteFlags & 0x01u) != 0u) {
      ::operator delete(start);
    }
    return start;
  }

  /**
   * Address: 0x00A78D40 (FUN_00A78D40)
   *
   * What it does:
   * Computes one `TRational<16>` addition-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<16>* AddAssignRational16Normalized(
    TRational<16>* const value,
    const TRational<16>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<16> sum = *value + *rhs;
    *value = sum;
    return value;
  }

  /**
   * Address: 0x00A78D90 (FUN_00A78D90)
   *
   * What it does:
   * Computes one `TRational<16>` multiply-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<16>* MultiplyAssignRational16Normalized(
    TRational<16>* const value,
    const TRational<16>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<16> product = *value * *rhs;
    *value = product;
    return value;
  }

  /**
   * Address: 0x00A78DE0 (FUN_00A78DE0)
   *
   * What it does:
   * Computes one `TRational<16>` divide-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<16>* DivideAssignRational16Normalized(
    TRational<16>* const value,
    const TRational<16>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<16> quotient = *value / *rhs;
    *value = quotient;
    return value;
  }

  /**
   * Address: 0x00A78870 (FUN_00A78870, Wm3::Query2TIntegerf::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the integer circumcircle query lane
   * in `Query2TIntegerf`.
   */
  TInteger<4> Query2TIntegerfDet3(
    const TInteger<4>& x0,
    const TInteger<4>& y0,
    const TInteger<4>& z0,
    const TInteger<4>& x1,
    const TInteger<4>& y1,
    const TInteger<4>& z1,
    const TInteger<4>& x2,
    const TInteger<4>& y2,
    const TInteger<4>& z2
  )
  {
    const TInteger<4> c00 = y1 * z2 - y2 * z1;
    const TInteger<4> c01 = y2 * z0 - y0 * z2;
    const TInteger<4> c02 = y0 * z1 - y1 * z0;
    return x0 * c00 + x1 * c01 + x2 * c02;
  }

  /**
   * Address: 0x00A78A20 (FUN_00A78A20, Wm3::Query2TIntegerd::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the integer circumcircle query lane
   * in `Query2TIntegerd`.
   */
  TInteger<4> Query2TIntegerdDet3(
    const TInteger<4>& x0,
    const TInteger<4>& y0,
    const TInteger<4>& z0,
    const TInteger<4>& x1,
    const TInteger<4>& y1,
    const TInteger<4>& z1,
    const TInteger<4>& x2,
    const TInteger<4>& y2,
    const TInteger<4>& z2
  )
  {
    const TInteger<4> c00 = y1 * z2 - y2 * z1;
    const TInteger<4> c01 = y2 * z0 - y0 * z2;
    const TInteger<4> c02 = y0 * z1 - y1 * z0;
    return x0 * c00 + x1 * c01 + x2 * c02;
  }

  /**
   * Address: 0x00A7B5C0 (FUN_00A7B5C0, Wm3::Query2TRationalf::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the rational circumcircle query lane
   * in `Query2TRationalf`.
   */
  TRational<16> Query2TRationalfDet3(
    const TRational<16>& x0,
    const TRational<16>& y0,
    const TRational<16>& z0,
    const TRational<16>& x1,
    const TRational<16>& y1,
    const TRational<16>& z1,
    const TRational<16>& x2,
    const TRational<16>& y2,
    const TRational<16>& z2
  )
  {
    const TRational<16> c00 = y1 * z2 - y2 * z1;
    const TRational<16> c01 = y2 * z0 - y0 * z2;
    const TRational<16> c02 = y0 * z1 - y1 * z0;
    return x0 * c00 + x1 * c01 + x2 * c02;
  }

  /**
   * Address: 0x00A7B7B0 (FUN_00A7B7B0, Wm3::Query2TRationald::Det3 helper lane)
   *
   * What it does:
   * Evaluates the 3x3 determinant used by the rational circumcircle query lane
   * in `Query2TRationald`.
   */
  TRational<32> Query2TRationaldDet3(
    const TRational<32>& x0,
    const TRational<32>& y0,
    const TRational<32>& z0,
    const TRational<32>& x1,
    const TRational<32>& y1,
    const TRational<32>& z1,
    const TRational<32>& x2,
    const TRational<32>& y2,
    const TRational<32>& z2
  )
  {
    const TRational<32> c00 = y1 * z2 - y2 * z1;
    const TRational<32> c01 = y2 * z0 - y0 * z2;
    const TRational<32> c02 = y0 * z1 - y1 * z0;
    return x0 * c00 + x1 * c01 + x2 * c02;
  }

  /**
   * Address: 0x00A3A5E0 (FUN_00A3A5E0)
   *
   * What it does:
   * Lexicographically compares two packed 3-double lanes as raw bytes.
   */
  [[maybe_unused]] int ComparePackedVector3dLaneBytes(
    const void* const lhsPackedVector3d,
    const void* const rhsPackedVector3d
  ) noexcept
  {
    return std::memcmp(lhsPackedVector3d, rhsPackedVector3d, 0x18u);
  }

  /**
   * Address: 0x00A3AB80 (FUN_00A3AB80)
   *
   * What it does:
   * Writes one double-precision 3D cross product (`lhs x rhs`) into
   * `outCross` and returns that output pointer.
   */
  Vector3<double>* CrossVector3dInto(
    const Vector3<double>& lhs,
    Vector3<double>* const outCross,
    const Vector3<double>& rhs
  ) noexcept
  {
    if (outCross == nullptr) {
      return outCross;
    }

    *outCross = Vector3<double>::Cross(lhs, rhs);
    return outCross;
  }

  /**
   * Address: 0x00A3AC80 (FUN_00A3AC80)
   *
   * What it does:
   * Writes one double-precision 3D vector scaled by `scale` into `outScaled`
   * and returns that output pointer.
   */
  [[maybe_unused]] Vector3<double>* ScaleVector3dInto(
    Vector3<double>* const outScaled,
    const double scale,
    const Vector3<double>& value
  ) noexcept
  {
    if (outScaled == nullptr) {
      return outScaled;
    }

    outScaled->x = value.x * scale;
    outScaled->y = value.y * scale;
    outScaled->z = value.z * scale;
    return outScaled;
  }

  /**
   * Address: 0x00A45570 (FUN_00A45570, ??0Intersector3f@Wm3@@QAE@@Z)
   * Mangled: ??0Intersector3f@Wm3@@QAE@@Z
   *
   * What it does:
   * Shared base-class initializer for every `Wm3::IntrSegment3*` / `Wm3::IntrBox3*`
   * intersector variant: clears the contact-time lane, installs the
   * `Intersector<float, Vector3<float>>` vftable tag, and resets intersection-type
   * to 0 (none).
   */
  class Intersector3f
  {
  public:
    Intersector3f() noexcept = default;
    virtual ~Intersector3f() = default;

    [[nodiscard]] float GetContactTime() const noexcept { return mContactTime; }
    [[nodiscard]] std::int32_t GetIntersectionType() const noexcept { return mIntersectionType; }

  protected:
    float mContactTime = 0.0f;          // +0x04 (vftable occupies +0x00)
    std::int32_t mIntersectionType = 0; // +0x08
  };
  static_assert(offsetof(Intersector3f, mContactTime) == 0x04, "Intersector3f::mContactTime offset must be 0x04");
  static_assert(offsetof(Intersector3f, mIntersectionType) == 0x08, "Intersector3f::mIntersectionType offset must be 0x08");
  static_assert(sizeof(Intersector3f) == 0x0C, "Intersector3f size must be 0x0C");

  /**
   * Address: 0x00A6BE80 (FUN_00A6BE80, ??0?$IntrSegment3Capsule3@M@Wm3@@QAE@ABV?$Segment3@M@1@ABV?$Capsule3@M@1@@Z)
   *
   * IDA signature:
   * int __thiscall sub_A6BE80(IntrSegment3Capsule3<float> *this, const Segment3<float>* rkSegment,
   *                           const Capsule3<float>* rkCapsule);
   *
   * What it does:
   * Builds one segment/capsule intersector object: runs the shared Intersector3f
   * base initializer, stores non-owning pointers to the input segment (+0x0C)
   * and capsule (+0x10), and installs the IntrSegment3Capsule3<float> vftable.
   * Callers then invoke Test/Find/StaticTest/StaticFind virtuals on the object.
   */
  class IntrSegment3Capsule3f : public Intersector3f
  {
  public:
    IntrSegment3Capsule3f(
      const Segment3<float>& segment,
      const Capsule3<float>& capsule
    ) noexcept
      : Intersector3f()
      , mSegment(&segment)
      , mCapsule(&capsule)
    {
    }

    [[nodiscard]] const Segment3<float>& GetSegment() const noexcept { return *mSegment; }
    [[nodiscard]] const Capsule3<float>& GetCapsule() const noexcept { return *mCapsule; }

  private:
    const Segment3<float>* mSegment = nullptr; // +0x0C
    const Capsule3<float>* mCapsule = nullptr; // +0x10
  };
  static_assert(sizeof(IntrSegment3Capsule3f) == 0x14, "IntrSegment3Capsule3f size must be 0x14");

  struct IntrSegment3Capsule3fRootsRuntimeView
  {
    std::uint8_t reserved00_2F[0x30]{};
    float roots[2]{}; // +0x30
  };
  static_assert(
    offsetof(IntrSegment3Capsule3fRootsRuntimeView, roots) == 0x30,
    "IntrSegment3Capsule3fRootsRuntimeView::roots offset must be 0x30"
  );

  struct IntrSegment3Capsule3dRootsRuntimeView
  {
    std::uint8_t reserved00_57[0x58]{};
    double roots[2]{}; // +0x58
  };
  static_assert(
    offsetof(IntrSegment3Capsule3dRootsRuntimeView, roots) == 0x58,
    "IntrSegment3Capsule3dRootsRuntimeView::roots offset must be 0x58"
  );

  /**
   * Address: 0x00A6BE00 (FUN_00A6BE00)
   *
   * What it does:
   * Returns one cached float root lane from `IntrSegment3Capsule3f` by index.
   */
  [[maybe_unused]] float IntrSegment3Capsule3fGetRootByIndex(
    const IntrSegment3Capsule3fRootsRuntimeView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return runtime->roots[index];
  }

  /**
   * Address: 0x00A6BE50 (FUN_00A6BE50)
   *
   * What it does:
   * Returns one cached double root lane from `IntrSegment3Capsule3d` by index.
   */
  [[maybe_unused]] double IntrSegment3Capsule3dGetRootByIndex(
    const IntrSegment3Capsule3dRootsRuntimeView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return runtime->roots[index];
  }

  namespace
  {
    constexpr float kWm3Epsilon = 0.000001f;

    inline bool NearlyZero(const float v, const float eps = kWm3Epsilon) noexcept
    {
      return std::fabs(v) <= eps;
    }

    int AddUniqueRoot(const float value, float* const outRoots, int count) noexcept
    {
      if (!std::isfinite(value)) {
        return count;
      }

      for (int i = 0; i < count; ++i) {
        if (std::fabs(outRoots[i] - value) <= 0.0001f) {
          return count;
        }
      }

      outRoots[count] = value;
      return count + 1;
    }

    int SolveQuadratic(const float a, const float b, const float c, float* const outRoots) noexcept
    {
      if (NearlyZero(a)) {
        if (NearlyZero(b)) {
          return 0;
        }
        outRoots[0] = -c / b;
        return 1;
      }

      const float discr = b * b - 4.0f * a * c;
      if (discr < 0.0f) {
        return 0;
      }

      if (NearlyZero(discr)) {
        outRoots[0] = -b / (2.0f * a);
        return 1;
      }

      const float root = SqrtfBinary(discr);
      const float inv2a = 1.0f / (2.0f * a);
      float r0 = (-b - root) * inv2a;
      float r1 = (-b + root) * inv2a;
      if (r1 < r0) {
        std::swap(r0, r1);
      }
      outRoots[0] = r0;
      outRoots[1] = r1;
      return 2;
    }

    int LineCapsuleIntersectionRoots(
      const Vector3<float>& lineOrigin,
      const Vector3<float>& lineDirection,
      const Capsule3<float>& capsule,
      float* const outRoots
    ) noexcept
    {
      int count = 0;

      const Vector3<float> axisScaled = Vector3<float>::Scale(capsule.Segment.Direction, capsule.Segment.Extent);
      const Vector3<float> segA = Vector3<float>::Sub(capsule.Segment.Origin, axisScaled);
      const Vector3<float> segB = Vector3<float>::Add(capsule.Segment.Origin, axisScaled);
      const Vector3<float> segV = Vector3<float>::Sub(segB, segA);

      const float segVV = Vector3<float>::Dot(segV, segV);
      if (NearlyZero(segVV)) {
        float roots[2]{};
        const Vector3<float> w0 = Vector3<float>::Sub(lineOrigin, segA);
        const float a = Vector3<float>::Dot(lineDirection, lineDirection);
        const float b = 2.0f * Vector3<float>::Dot(lineDirection, w0);
        const float c = Vector3<float>::Dot(w0, w0) - capsule.Radius * capsule.Radius;
        const int rc = SolveQuadratic(a, b, c, roots);
        for (int i = 0; i < rc; ++i) {
          count = AddUniqueRoot(roots[i], outRoots, count);
        }
        if (count == 2 && outRoots[1] < outRoots[0]) {
          std::swap(outRoots[0], outRoots[1]);
        }
        return count;
      }

      const Vector3<float> w0 = Vector3<float>::Sub(lineOrigin, segA);
      const float dd = Vector3<float>::Dot(lineDirection, lineDirection);
      const float dw = Vector3<float>::Dot(lineDirection, w0);
      const float ww = Vector3<float>::Dot(w0, w0);
      const float dv = Vector3<float>::Dot(lineDirection, segV);
      const float wv = Vector3<float>::Dot(w0, segV);
      const float rr = capsule.Radius * capsule.Radius;

      auto addRegionRoots =
        [&](const float minS, const float maxS, const bool endpointA, const bool endpointB) noexcept {
          float roots[2]{};

          if (endpointA || endpointB) {
            const Vector3<float> endpoint = endpointA ? segA : segB;
            const Vector3<float> we = Vector3<float>::Sub(lineOrigin, endpoint);
            const float a = dd;
            const float b = 2.0f * Vector3<float>::Dot(lineDirection, we);
            const float c = Vector3<float>::Dot(we, we) - rr;
            const int rc = SolveQuadratic(a, b, c, roots);
            for (int i = 0; i < rc; ++i) {
              const float s = wv + roots[i] * dv;
              if (s >= minS - 0.0001f && s <= maxS + 0.0001f) {
                count = AddUniqueRoot(roots[i], outRoots, count);
              }
            }
            return;
          }

          const float a = dd - (dv * dv) / segVV;
          const float b = 2.0f * (dw - (wv * dv) / segVV);
          const float c = ww - (wv * wv) / segVV - rr;
          const int rc = SolveQuadratic(a, b, c, roots);
          for (int i = 0; i < rc; ++i) {
            const float s = wv + roots[i] * dv;
            if (s >= minS - 0.0001f && s <= maxS + 0.0001f) {
              count = AddUniqueRoot(roots[i], outRoots, count);
            }
          }
        };

      // Region where closest point is endpoint A.
      addRegionRoots(-std::numeric_limits<float>::infinity(), 0.0f, true, false);
      // Region where closest point is interior of segment AB.
      addRegionRoots(0.0f, segVV, false, false);
      // Region where closest point is endpoint B.
      addRegionRoots(segVV, std::numeric_limits<float>::infinity(), false, true);

      if (count > 1) {
        std::sort(outRoots, outRoots + count);
      }
      if (count > 2) {
        count = 2;
      }
      return count;
    }

    int ClipRootsToPathExtent(
      const float* const roots, const int rootCount, const float extent, float* const clipped
    ) noexcept
    {
      int count = 0;
      for (int i = 0; i < rootCount; ++i) {
        if (std::fabs(roots[i]) <= extent + 0.0001f) {
          count = AddUniqueRoot(roots[i], clipped, count);
        }
      }
      if (count > 1) {
        std::sort(clipped, clipped + count);
      }
      return count;
    }

    struct IntrBox3Sphere3fState
    {
      float sphereRadius{};
      float contactTime{};
    };

    inline void WriteIfNotNull(float* const out, const float value) noexcept
    {
      if (out) {
        *out = value;
      }
    }

    bool RayIntersectsOrientedBox(
      const Vector3<float>& rayOrigin,
      const Vector3<float>& rayDirection,
      const Box3<float>& box,
      float* const tEnterOut
    ) noexcept
    {
      const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
      const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
      const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};
      const Vector3<float> center{box.Center[0], box.Center[1], box.Center[2]};

      const Vector3<float> diff = Vector3<float>::Sub(rayOrigin, center);
      const float o[3] = {
        Vector3<float>::Dot(diff, axis0), Vector3<float>::Dot(diff, axis1), Vector3<float>::Dot(diff, axis2)
      };
      const float d[3] = {
        Vector3<float>::Dot(rayDirection, axis0),
        Vector3<float>::Dot(rayDirection, axis1),
        Vector3<float>::Dot(rayDirection, axis2)
      };

      float t0 = 0.0f;
      float t1 = std::numeric_limits<float>::max();
      for (int i = 0; i < 3; ++i) {
        const float extent = box.Extent[i];
        if (NearlyZero(d[i])) {
          if (o[i] < -extent || o[i] > extent) {
            return false;
          }
          continue;
        }

        const float invD = 1.0f / d[i];
        float tNear = (-extent - o[i]) * invD;
        float tFar = (extent - o[i]) * invD;
        if (tNear > tFar) {
          std::swap(tNear, tFar);
        }

        t0 = std::max(t0, tNear);
        t1 = std::min(t1, tFar);
        if (t0 > t1) {
          return false;
        }
      }

      if (tEnterOut) {
        *tEnterOut = t0;
      }
      return true;
    }

    /**
     * Address: 0x00A41880 (FUN_00A41880, sub_A41880)
     *
     * this, float, float, float, float, float, float, float, float, float, float*, float*, float*, bool
     *
     * IDA signature:
     * int __thiscall sub_A41880(int this, float arg0, float arg4, float a4, float a5, float a6, float a7, float a8,
     * float a9, float a10, float *a11, float *a12, float *a13, float a14);
     *
     * What it does:
     * Solves face-region sweep intersection for one outside axis and emits local contact coordinates.
     */
    int IntrBox3Sphere3fSubA41880(
      IntrBox3Sphere3fState& state,
      const float arg0,
      const float arg4,
      const float a4,
      const float a5,
      const float a6,
      const float a7,
      const float a8,
      const float a9,
      const float a10,
      float* const a11,
      float* const a12,
      float* const a13,
      const bool a14
    ) noexcept
    {
      if (a4 + state.sphereRadius >= a7 && a14) {
        state.contactTime = 0.0f;
        return -1;
      }

      if (a10 >= 0.0f) {
        return 0;
      }

      const float radiusSquared = state.sphereRadius * state.sphereRadius;
      const float v40 = a8 * a8 + a10 * a10;
      const float v41 = a10 * a10 + a9 * a9;
      const float v36 = a7 - a4;

      int v37 = 1;
      float v49 = a5 - arg0;
      float v32 = v36 * a8 - v49 * a10;
      if (a8 < 0.0f) {
        v37 = -1;
        v49 = arg0 + a5;
        v32 = v49 * a10 - v36 * a8;
      }

      int v39 = 1;
      float v35 = a6 - arg4;
      float v31 = v36 * a9 - v35 * a10;
      if (a9 < 0.0f) {
        v39 = -1;
        v35 = arg4 + a6;
        v31 = v35 * a10 - v36 * a9;
      }

      const float v42 = a8 * state.sphereRadius * static_cast<float>(v37);
      if (v42 >= v32) {
        const float v50 = a9 * state.sphereRadius * static_cast<float>(v39);
        if (v50 >= v31) {
          state.contactTime = (state.sphereRadius - v36) / a10;
          WriteIfNotNull(a11, a8 * state.contactTime + a5);
          WriteIfNotNull(a12, a9 * state.contactTime + a6);
          WriteIfNotNull(a13, a4);
          return 1;
        }

        if (v41 * radiusSquared >= v31 * v31) {
          state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(v35, v36, a9, a10, v41, radiusSquared);
          WriteIfNotNull(a11, state.contactTime * a8 + a5);
          WriteIfNotNull(a12, static_cast<float>(v39) * arg4);
          WriteIfNotNull(a13, a4);
          return 1;
        }

        return 0;
      }

      if (v40 * radiusSquared < v32 * v32) {
        return 0;
      }

      const float v46 = a9 * state.sphereRadius * static_cast<float>(v39);
      if (v46 >= v31) {
        state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(v49, v36, a8, a10, v40, radiusSquared);
        WriteIfNotNull(a11, static_cast<float>(v37) * arg0);
        WriteIfNotNull(a12, a9 * state.contactTime + a6);
        WriteIfNotNull(a13, a4);
        return 1;
      }

      if (v41 * radiusSquared < v31 * v31) {
        return 0;
      }

      const Vector3<float> a3{a8, a9, a10};
      const Vector3<float> v44{v49, v35, v36};
      const Vector3<float> a2 = Vector3<float>::Cross(v44, a3);
      if (Vector3<float>::LengthSq(a2) > Vector3<float>::LengthSq(a3) * radiusSquared) {
        return 0;
      }

      state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v49, v35, v36, a8, a9, a10, radiusSquared);
      WriteIfNotNull(a11, static_cast<float>(v37) * arg0);
      WriteIfNotNull(a12, static_cast<float>(v39) * arg4);
      WriteIfNotNull(a13, a4);
      return 1;
    }

    /**
     * Address: 0x00A41CC0 (FUN_00A41CC0, sub_A41CC0)
     *
     * this, float, float, float, float, float, float, float, float, float, float*, float*, float*
     *
     * IDA signature:
     * int __thiscall sub_A41CC0(int this, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float
     * a9, float a10, float *a11, float *a12, float *a13);
     *
     * What it does:
     * Solves edge/vertex transition sweep for mixed edge-region cases.
     */
    int IntrBox3Sphere3fSubA41CC0(
      IntrBox3Sphere3fState& state,
      const float a2,
      const float a3,
      const float a4,
      const float a5,
      const float a6,
      const float a7,
      const float a8,
      const float a9,
      const float a10,
      float* const a11,
      float* const a12,
      float* const a13
    ) noexcept
    {
      const float radiusSquared = state.sphereRadius * state.sphereRadius;

      int v47 = 1;
      float v46 = a2 - a4;
      float v17 = a6 * a9;
      const float v18 = a8;
      float v19 = v46 * a8;
      float v57 = v17 - v19;
      float v20 = v46 * a10;
      const float v21 = a10;
      float v58 = a7 * a9 - v20;
      if (a9 < 0.0f) {
        v47 = -1;
        v46 = a2 + a4;
        v19 = v46 * a8;
        v17 = a6 * a9;
        v57 = v19 - v17;
        v20 = v46 * a10;
        v58 = v20 - a7 * a9;
      }

      if (v57 < 0.0f || v58 < 0.0f || state.sphereRadius * state.sphereRadius * (a9 * a9) >= v58 * v58 + v57 * v57) {
        const float v56 = v18 * v18 + v21 * v21;
        state.contactTime = IntrBox3Sphere3fGetEdgeIntersection(a6, a7, v18, v21, v56, radiusSquared);
        WriteIfNotNull(a11, a3);
        WriteIfNotNull(a12, state.contactTime * a9 + a2);
        WriteIfNotNull(a13, a5);
        return 1;
      }

      const float v51 = v20 - a7 * a9;
      const float v52 = a7 * v18 - a6 * v21;
      const float v53 = v17 - v19;
      const float v54 = v53 * v53 + v52 * v52 + v51 * v51;
      const float v55 = v21 * v21 + v18 * v18 + a9 * a9;
      if (v54 > v55 * radiusSquared) {
        return 0;
      }

      state.contactTime = IntrBox3Sphere3fGetVertexIntersection(a6, v46, a7, v18, a9, v21, radiusSquared);
      WriteIfNotNull(a11, a3);
      WriteIfNotNull(a12, static_cast<float>(v47) * a4);
      WriteIfNotNull(a13, a5);
      return 1;
    }
  } // namespace

  /**
   * Address: 0x00A41740 (FUN_00A41740, Wm3::IntrBox3Sphere3f::GetVertexIntersection)
   *
   * float, float, float, float, float, float, float
   *
   * IDA signature:
   * double __cdecl Wm3::IntrBox3Sphere3f::GetVertexIntersection(float a1, float a2, float a3, float a4, float a5, float
   * a6, float a7);
   *
   * What it does:
   * Solves contact-time root for a vertex-region sweep test against sphere radius.
   */
  float IntrBox3Sphere3fGetVertexIntersection(
    const float a1, const float a2, const float a3, const float a4, const float a5, const float a6, const float a7
  ) noexcept
  {
    const float v10 = a2 * a5 + a1 * a4 + a3 * a6;
    const float v9 = a1 * a1 + a2 * a2 + a3 * a3 - a7;
    const float v11 = a6 * a6 + a4 * a4 + a5 * a5;
    const float v12 = v10 * v10 - v11 * v9;
    const float v13 = SqrtfBinary(std::fabs(v12));
    const float v14 = 1.0f / v13;
    return static_cast<float>(v14 * v9 / (1.0f - v14 * v10));
  }

  /**
   * Address: 0x00A41800 (FUN_00A41800, Wm3::IntrBox3Sphere3f::GetEdgeIntersection)
   *
   * float, float, float, float, float, float
   *
   * IDA signature:
   * double __cdecl Wm3::IntrBox3Sphere3f::GetEdgeIntersection(float a1, float a2, float a3, float a4, float a5, float
   * a6);
   *
   * What it does:
   * Solves contact-time root for an edge-region sweep test against sphere radius.
   */
  float IntrBox3Sphere3fGetEdgeIntersection(
    const float a1, const float a2, const float a3, const float a4, const float a5, const float a6
  ) noexcept
  {
    const float v12 = a1 * a3 + a2 * a4;
    const float v7 = a1 * a1 + a2 * a2 - a6;
    const float v9 = v12 * v12 - v7 * a5;
    const float v10 = SqrtfBinary(std::fabs(v9));
    const float v11 = 1.0f / v10;
    return static_cast<float>(v11 * v7 / (1.0f - v11 * v12));
  }

  /**
   * Address: 0x00A41F50 (FUN_00A41F50, Wm3::IntrBox3Sphere3f::FindEdgeRegionIntersection)
   *
   * float, float, float, float, float, float, float, float, float, float*, float*, float*, bool
   *
   * IDA signature:
   * int __thiscall Wm3::IntrBox3Sphere3f::FindEdgeRegionIntersection(int this, float a2, float a3, float a4, float a5,
   * float a6, float a7, float a8, float a9, float a10, int a11, int a12, int a13, float a14);
   *
   * What it does:
   * Handles edge-region sweep logic and writes local contact coordinates when a candidate is found.
   * Return codes match binary convention: -1 immediate overlap, 0 no hit, 1 hit.
   */
  int IntrBox3Sphere3fFindEdgeRegionIntersection(
    const float sphereRadius,
    const float a2,
    const float a3,
    const float a4,
    const float a5,
    const float a6,
    const float a7,
    const float a8,
    const float a9,
    const float a10,
    float* const a11,
    float* const a12,
    float* const a13,
    const bool a14,
    float* const contactTime
  ) noexcept
  {
    IntrBox3Sphere3fState state{};
    state.sphereRadius = sphereRadius;
    state.contactTime = 0.0f;

    const float v20 = a5 - a2;
    const float v21 = a7 - a4;
    if (a14) {
      const float v23 = v21 * v21 + v20 * v20 - state.sphereRadius * state.sphereRadius;
      if (v23 <= 0.0f) {
        state.contactTime = 0.0f;
        WriteIfNotNull(contactTime, state.contactTime);
        return -1;
      }
    }

    const float v24 = v21 * a10 + v20 * a8;
    if (v24 >= 0.0f) {
      WriteIfNotNull(contactTime, state.contactTime);
      return 0;
    }

    const float v25 = v20 * a10 - v21 * a8;
    int result = 0;
    if (v25 >= 0.0f) {
      if (a8 < 0.0f) {
        const float v26 = -state.sphereRadius * a8;
        if (v26 < v25) {
          result = IntrBox3Sphere3fSubA41880(state, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, false);
        } else {
          result = IntrBox3Sphere3fSubA41CC0(state, a6, a4, a3, a2, v21, v20, a10, a9, a8, a13, a12, a11);
        }
      }
    } else if (a10 < 0.0f) {
      const float v27 = state.sphereRadius * a10;
      if (v27 > v25) {
        result = IntrBox3Sphere3fSubA41880(state, a4, a3, a2, a7, a6, a5, a10, a9, a8, a13, a12, a11, false);
      } else {
        result = IntrBox3Sphere3fSubA41CC0(state, a6, a2, a3, a4, v20, v21, a8, a9, a10, a11, a12, a13);
      }
    }

    WriteIfNotNull(contactTime, state.contactTime);
    return result;
  }

  /**
   * Address: 0x00A421E0 (FUN_00A421E0, Wm3::IntrBox3Sphere3f::FindVertexRegionIntersection)
   *
   * float, float, float, float, float, float, float, float, float, float*, float*, float*
   *
   * IDA signature:
   * int __thiscall sub_A421E0(int this, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float a9,
   * float a10, float *a11, float *a12, float *a13);
   *
   * What it does:
   * Handles vertex-region sweep logic and may recurse into edge-region helper paths.
   * Return codes match binary convention: -1 immediate overlap, 0 no hit, 1 hit.
   */
  int IntrBox3Sphere3fFindVertexRegionIntersection(
    const float sphereRadius,
    const float a2,
    const float a3,
    const float a4,
    const float a5,
    const float a6,
    const float a7,
    const float a8,
    const float a9,
    const float a10,
    float* const a11,
    float* const a12,
    float* const a13,
    float* const contactTime
  ) noexcept
  {
    IntrBox3Sphere3fState state{};
    state.sphereRadius = sphereRadius;
    state.contactTime = 0.0f;

    const float v45 = a5 - a2;
    const float v47 = a6 - a3;
    const float v41 = a7 - a4;
    const float v40 = state.sphereRadius * state.sphereRadius;
    const float v48 = v41 * v41 + v47 * v47 + v45 * v45 - v40;
    if (v48 <= 0.0f) {
      state.contactTime = 0.0f;
      WriteIfNotNull(contactTime, state.contactTime);
      return -1;
    }

    if (v41 * a10 + v47 * a9 + v45 * a8 >= 0.0f) {
      WriteIfNotNull(contactTime, state.contactTime);
      return 0;
    }

    const float v42 = v41 * a9 - v47 * a10;
    const float v43 = v41 * a8 - v45 * a10;
    const float v39 = v45 * a9 - v47 * a8;
    const float v49 = v42 * v42;
    const float v46 = v43 * v43;
    const float v44 = v39 * v39;

    const float v21 = 0.0f;
    if (v43 < 0.0f && v39 >= 0.0f) {
      const float v50 = a8 * a8;
      if (v50 * v40 >= v44 + v46) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
    }

    if (v21 > v39 && v21 > v42) {
      const float v51 = a9 * a9;
      if (v51 * v40 >= v44 + v49) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
    }

    float v22 = v21;
    float v23 = a8;
    if (!(v21 > v43 || v21 > v42)) {
      const float v52 = a10 * a10;
      if (v52 * v40 >= v46 + v49) {
        state.contactTime = IntrBox3Sphere3fGetVertexIntersection(v45, v47, v41, a8, a9, a10, v40);
        WriteIfNotNull(a11, state.contactTime * a8 + a5);
        WriteIfNotNull(a12, state.contactTime * a9 + a6);
        WriteIfNotNull(a13, state.contactTime * a10 + a7);
        WriteIfNotNull(contactTime, state.contactTime);
        return 1;
      }
      v22 = 0.0f;
      v23 = a8;
    }

    int result = 0;
    if (v22 <= v43 || v22 > v39) {
      if (v22 <= v39 || v22 <= v42) {
        result = IntrBox3Sphere3fFindEdgeRegionIntersection(
          state.sphereRadius, a2, a4, a3, a5, a7, a6, v23, a10, a9, a11, a13, a12, false, &state.contactTime
        );
      } else {
        result = IntrBox3Sphere3fFindEdgeRegionIntersection(
          state.sphereRadius, a2, a3, a4, a5, a6, a7, v23, a9, a10, a11, a12, a13, false, &state.contactTime
        );
      }
    } else {
      result = IntrBox3Sphere3fFindEdgeRegionIntersection(
        state.sphereRadius, a3, a2, a4, a6, a5, a7, a9, v23, a10, a12, a11, a13, false, &state.contactTime
      );
    }

    WriteIfNotNull(contactTime, state.contactTime);
    return result;
  }

  /**
   * Address: 0x00A45C00 (FUN_00A45C00, Wm3::DistVector3Box3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::GetSquared(Wm3::DistVector3Box3f *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented box and writes the closest point.
   */
  float DistVector3Box3fGetSquared(
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> center{box.Center[0], box.Center[1], box.Center[2]};
    const Vector3<float> diff = Vector3<float>::Sub(vector, center);

    Vector3<float> closest = center;
    float squaredDistance = 0.0f;

    for (int i = 0; i < 3; ++i) {
      const Vector3<float> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const float projected = Vector3<float>::Dot(diff, axis);

      float clamped = projected;
      if (projected < -box.Extent[i]) {
        const float delta = projected + box.Extent[i];
        squaredDistance += delta * delta;
        clamped = -box.Extent[i];
      } else if (projected > box.Extent[i]) {
        const float delta = projected - box.Extent[i];
        squaredDistance += delta * delta;
        clamped = box.Extent[i];
      }

      closest = Vector3<float>::Add(closest, Vector3<float>::Scale(axis, clamped));
    }

    if (closestPointOnBox) {
      *closestPointOnBox = closest;
    }
    return squaredDistance;
  }

  /**
   * Address: 0x00A457E0 (FUN_00A457E0, Wm3::DistVector3Box3f::Get)
   *
   * Wm3::Vector3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::Get(Wm3::DistVector3Box3f *this);
   *
   * What it does:
   * Returns distance from a point to an oriented box.
   */
  float DistVector3Box3fGet(
    const Vector3<float>& vector, const Box3<float>& box, Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    return SqrtfBinary(DistVector3Box3fGetSquared(vector, box, closestPointOnBox));
  }

  /**
   * Address: 0x00A458C0 (FUN_00A458C0, Wm3::DistVector3Box3f::StaticGet)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::StaticGet(Wm3::DistVector3Box3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns point-to-box distance.
   */
  float DistVector3Box3fStaticGet(
    const float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Box3<float> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3fGet(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A45A60 (FUN_00A45A60, Wm3::DistVector3Box3f::StaticGetSquared)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3f::StaticGetSquared(Wm3::DistVector3Box3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns squared point-to-box distance.
   */
  float DistVector3Box3fStaticGetSquared(
    const float t,
    const Vector3<float>& vector,
    const Box3<float>& box,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& boxVelocity,
    Vector3<float>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Box3<float> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3fGetSquared(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A460D0 (FUN_00A460D0, Wm3::DistVector3Box3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::GetSquared(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Computes squared distance from a point to an oriented box and optionally writes the closest point.
   */
  double DistVector3Box3dGetSquared(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> center{box.Center[0], box.Center[1], box.Center[2]};
    const Vector3<double> diff = Vector3<double>::Sub(vector, center);

    Vector3<double> closest = center;
    double squaredDistance = 0.0;

    for (int i = 0; i < 3; ++i) {
      const Vector3<double> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const double projected = Vector3<double>::Dot(diff, axis);

      double clamped = projected;
      if (projected < -box.Extent[i]) {
        const double delta = projected + box.Extent[i];
        squaredDistance += delta * delta;
        clamped = -box.Extent[i];
      } else if (projected > box.Extent[i]) {
        const double delta = projected - box.Extent[i];
        squaredDistance += delta * delta;
        clamped = box.Extent[i];
      }

      closest = Vector3<double>::Add(closest, Vector3<double>::Scale(axis, clamped));
    }

    if (closestPointOnBox) {
      *closestPointOnBox = closest;
    }
    return squaredDistance;
  }

  /**
   * Address: 0x00A45800 (FUN_00A45800, Wm3::DistVector3Box3d::Get)
   *
   * Wm3::Vector3<double> const&, Wm3::Box3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::Get(Wm3::DistVector3Box3d *this);
   *
   * What it does:
   * Returns distance from a point to an oriented box.
   */
  double DistVector3Box3dGet(
    const Vector3<double>& vector, const Box3<double>& box, Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistVector3Box3dGetSquared(vector, box, closestPointOnBox));
  }

  /**
   * Address: 0x00A3D220 (FUN_00A3D220)
   *
   * What it does:
   * Expands one `Box3<double>` center/axis/extent lane into eight packed
   * corner points (`24` doubles) and returns the output lane pointer.
   */
  [[maybe_unused]] double* ExpandBox3dToCornerTriplets(
    const Box3<double>* const sourceBox,
    double* const outCornerLanes
  ) noexcept
  {
    const double axis0X = sourceBox->Axis[0][0] * sourceBox->Extent[0];
    const double axis0Y = sourceBox->Axis[0][1] * sourceBox->Extent[0];
    const double axis0Z = sourceBox->Axis[0][2] * sourceBox->Extent[0];

    const double axis1X = sourceBox->Axis[1][0] * sourceBox->Extent[1];
    const double axis1Y = sourceBox->Axis[1][1] * sourceBox->Extent[1];
    const double axis1Z = sourceBox->Axis[1][2] * sourceBox->Extent[1];

    const double axis2X = sourceBox->Axis[2][0] * sourceBox->Extent[2];
    const double axis2Y = sourceBox->Axis[2][1] * sourceBox->Extent[2];
    const double axis2Z = sourceBox->Axis[2][2] * sourceBox->Extent[2];

    const double centerX = sourceBox->Center[0];
    const double centerY = sourceBox->Center[1];
    const double centerZ = sourceBox->Center[2];

    outCornerLanes[0] = centerX - axis0X - axis1X - axis2X;
    outCornerLanes[1] = centerY - axis0Y - axis1Y - axis2Y;
    outCornerLanes[2] = centerZ - axis0Z - axis1Z - axis2Z;

    outCornerLanes[3] = centerX + axis0X - axis1X - axis2X;
    outCornerLanes[4] = centerY + axis0Y - axis1Y - axis2Y;
    outCornerLanes[5] = centerZ + axis0Z - axis1Z - axis2Z;

    outCornerLanes[6] = centerX + axis0X + axis1X - axis2X;
    outCornerLanes[7] = centerY + axis0Y + axis1Y - axis2Y;
    outCornerLanes[8] = centerZ + axis0Z + axis1Z - axis2Z;

    outCornerLanes[9] = centerX - axis0X + axis1X - axis2X;
    outCornerLanes[10] = centerY - axis0Y + axis1Y - axis2Y;
    outCornerLanes[11] = centerZ - axis0Z + axis1Z - axis2Z;

    outCornerLanes[12] = centerX - axis0X - axis1X + axis2X;
    outCornerLanes[13] = centerY - axis0Y - axis1Y + axis2Y;
    outCornerLanes[14] = centerZ - axis0Z - axis1Z + axis2Z;

    outCornerLanes[15] = centerX + axis0X - axis1X + axis2X;
    outCornerLanes[16] = centerY + axis0Y - axis1Y + axis2Y;
    outCornerLanes[17] = centerZ + axis0Z - axis1Z + axis2Z;

    outCornerLanes[18] = centerX + axis0X + axis1X + axis2X;
    outCornerLanes[19] = centerY + axis0Y + axis1Y + axis2Y;
    outCornerLanes[20] = centerZ + axis0Z + axis1Z + axis2Z;

    outCornerLanes[21] = centerX - axis0X + axis1X + axis2X;
    outCornerLanes[22] = centerY - axis0Y + axis1Y + axis2Y;
    outCornerLanes[23] = centerZ - axis0Z + axis1Z + axis2Z;
    return outCornerLanes;
  }

  /**
   * Address: 0x00A45850 (FUN_00A45850)
   *
   * What it does:
   * Initializes one `Box3<double>` lane from center, 3x3 axis matrix, and
   * extent vectors stored in caller-provided array lanes.
   */
  [[maybe_unused]] Box3<double>* InitializeBox3dFromLaneArrays(
    Box3<double>* const outBox,
    const double* const center,
    const double* const axisRows3x3,
    const double* const extent
  ) noexcept
  {
    if (outBox == nullptr || center == nullptr || axisRows3x3 == nullptr || extent == nullptr) {
      return outBox;
    }

    outBox->Center[0] = center[0];
    outBox->Center[1] = center[1];
    outBox->Center[2] = center[2];

    outBox->Axis[0][0] = axisRows3x3[0];
    outBox->Axis[0][1] = axisRows3x3[1];
    outBox->Axis[0][2] = axisRows3x3[2];
    outBox->Axis[1][0] = axisRows3x3[3];
    outBox->Axis[1][1] = axisRows3x3[4];
    outBox->Axis[1][2] = axisRows3x3[5];
    outBox->Axis[2][0] = axisRows3x3[6];
    outBox->Axis[2][1] = axisRows3x3[7];
    outBox->Axis[2][2] = axisRows3x3[8];

    outBox->Extent[0] = extent[0];
    outBox->Extent[1] = extent[1];
    outBox->Extent[2] = extent[2];
    return outBox;
  }

  /**
   * Address: 0x00A45E90 (FUN_00A45E90, Wm3::DistVector3Box3d::StaticGet)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Box3<double> const&, Wm3::Vector3<double> const&, Wm3::Vector3<double>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::StaticGet(Wm3::DistVector3Box3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns point-to-box distance.
   */
  double DistVector3Box3dStaticGet(
    const double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Box3<double> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3dGet(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A45FB0 (FUN_00A45FB0, Wm3::DistVector3Box3d::StaticGetSquared)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Box3<double> const&, Wm3::Vector3<double> const&, Wm3::Vector3<double>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Box3d::StaticGetSquared(Wm3::DistVector3Box3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/box forward by time `t` using the provided velocities, then returns squared point-to-box distance.
   */
  double DistVector3Box3dStaticGetSquared(
    const double t,
    const Vector3<double>& vector,
    const Box3<double>& box,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& boxVelocity,
    Vector3<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Box3<double> movedBox = box;
    movedBox.Center[0] = box.Center[0] + boxVelocity.x * t;
    movedBox.Center[1] = box.Center[1] + boxVelocity.y * t;
    movedBox.Center[2] = box.Center[2] + boxVelocity.z * t;

    return DistVector3Box3dGetSquared(movedVector, movedBox, closestPointOnBox);
  }

  /**
   * Address: 0x00A681E0 (FUN_00A681E0)
   *
   * What it does:
   * Expands one `Box2<float>` center/axis/extent lane into four packed corner
   * points (`8` floats) and returns the output lane pointer.
   */
  [[maybe_unused]] float* ExpandBox2fToCornerPairs(
    const Box2<float>* const sourceBox,
    float* const outCornerLanes
  ) noexcept
  {
    const float axis0X = sourceBox->Axis[0][0] * sourceBox->Extent[0];
    const float axis0Y = sourceBox->Axis[0][1] * sourceBox->Extent[0];
    const float axis1X = sourceBox->Axis[1][0] * sourceBox->Extent[1];
    const float axis1Y = sourceBox->Axis[1][1] * sourceBox->Extent[1];

    const float centerX = sourceBox->Center[0];
    const float centerY = sourceBox->Center[1];

    outCornerLanes[0] = centerX - axis0X - axis1X;
    outCornerLanes[1] = centerY - axis0Y - axis1Y;

    outCornerLanes[2] = centerX + axis0X - axis1X;
    outCornerLanes[3] = centerY + axis0Y - axis1Y;

    outCornerLanes[4] = centerX + axis0X + axis1X;
    outCornerLanes[5] = centerY + axis0Y + axis1Y;

    outCornerLanes[6] = centerX - axis0X + axis1X;
    outCornerLanes[7] = centerY - axis0Y + axis1Y;
    return outCornerLanes;
  }

  /**
   * Address: 0x00A68310 (FUN_00A68310)
   *
   * What it does:
   * Expands one `Box2<double>` center/axis/extent lane into four packed corner
   * points (`8` doubles) and returns the output lane pointer.
   */
  [[maybe_unused]] double* ExpandBox2dToCornerPairs(
    const Box2<double>* const sourceBox,
    double* const outCornerLanes
  ) noexcept
  {
    const double axis0X = sourceBox->Axis[0][0] * sourceBox->Extent[0];
    const double axis0Y = sourceBox->Axis[0][1] * sourceBox->Extent[0];
    const double axis1X = sourceBox->Axis[1][0] * sourceBox->Extent[1];
    const double axis1Y = sourceBox->Axis[1][1] * sourceBox->Extent[1];

    const double centerX = sourceBox->Center[0];
    const double centerY = sourceBox->Center[1];

    outCornerLanes[0] = centerX - axis0X - axis1X;
    outCornerLanes[1] = centerY - axis0Y - axis1Y;

    outCornerLanes[2] = centerX + axis0X - axis1X;
    outCornerLanes[3] = centerY + axis0Y - axis1Y;

    outCornerLanes[4] = centerX + axis0X + axis1X;
    outCornerLanes[5] = centerY + axis0Y + axis1Y;

    outCornerLanes[6] = centerX - axis0X + axis1X;
    outCornerLanes[7] = centerY - axis0Y + axis1Y;
    return outCornerLanes;
  }

  namespace
  {
    struct BestCandidate2DState
    {
      Vector2f point;   // +0x00
      Vector2f axisA;   // +0x08
      Vector2f axisB;   // +0x10
      float scalarA;    // +0x18
      float scalarB;    // +0x1C
    };
    static_assert(sizeof(BestCandidate2DState) == 0x20, "BestCandidate2DState size must be 0x20");
    static_assert(offsetof(BestCandidate2DState, point) == 0x00, "BestCandidate2DState::point offset must be 0x00");
    static_assert(offsetof(BestCandidate2DState, axisA) == 0x08, "BestCandidate2DState::axisA offset must be 0x08");
    static_assert(offsetof(BestCandidate2DState, axisB) == 0x10, "BestCandidate2DState::axisB offset must be 0x10");
    static_assert(offsetof(BestCandidate2DState, scalarA) == 0x18, "BestCandidate2DState::scalarA offset must be 0x18");
    static_assert(offsetof(BestCandidate2DState, scalarB) == 0x1C, "BestCandidate2DState::scalarB offset must be 0x1C");

    /**
     * Address: 0x00A68390 (FUN_00A68390)
     *
     * What it does:
     * Projects two half extents from the supplied axes, compares the resulting
     * metric against the current best value, and updates the packed 2D
     * candidate state when the new candidate is better.
     */
    [[maybe_unused]] void UpdateBestCandidate2D(
      const Vector2f& probePoint,
      BestCandidate2DState* const bestCandidate,
      const Vector2f& axisB,
      const Vector2f& axisA,
      const Vector2f& segmentStart,
      const Vector2f& segmentEnd,
      const Vector2f& referencePoint,
      float* const bestMetric
    ) noexcept
    {
      const float edgeDeltaX = segmentEnd.x - segmentStart.x;
      const float edgeDeltaY = segmentEnd.y - segmentStart.y;
      const float pointDeltaX = probePoint.x - referencePoint.x;
      const float pointDeltaY = probePoint.y - referencePoint.y;

      const float scalarA = 0.5f * ((axisA.x * edgeDeltaX) + (axisA.y * edgeDeltaY));
      const float scalarB = 0.5f * ((axisB.x * pointDeltaX) + (axisB.y * pointDeltaY));
      const float metric = scalarA * scalarB;

      if (*bestMetric > static_cast<double>(metric)) {
        *bestMetric = metric;

        bestCandidate->axisA.x = axisA.x;
        bestCandidate->axisA.y = axisA.y;
        bestCandidate->axisB.x = axisB.x;
        bestCandidate->axisB.y = axisB.y;
        bestCandidate->scalarA = scalarA;
        bestCandidate->scalarB = scalarB;

        const float axisBFromReferenceX = segmentStart.x - referencePoint.x;
        const float axisBFromReferenceY = segmentStart.y - referencePoint.y;
        const float axisBProjection = (axisB.x * axisBFromReferenceX) + (axisB.y * axisBFromReferenceY);
        const float adjustedScalarB = scalarB - axisBProjection;

        bestCandidate->point.x = segmentStart.x + (axisA.x * scalarA) + (axisB.x * adjustedScalarB);
        bestCandidate->point.y = segmentStart.y + (axisA.y * scalarA) + (axisB.y * adjustedScalarB);
      }
    }
  } // namespace

  /**
   * Address: 0x00A68500 (FUN_00A68500)
   *
   * What it does:
   * Projects one edge and one probe delta onto two axes, then updates the
   * best-candidate state when the projection product metric improves.
   */
  void UpdateBestCandidate2DByProjectionMetric(
    const Vector2<double>& probePoint,
    BestCandidate2DStateDouble* const bestCandidate,
    const Vector2<double>& axisB,
    const Vector2<double>& axisA,
    const Vector2<double>& segmentStart,
    const Vector2<double>& segmentEnd,
    const Vector2<double>& referencePoint,
    double* const bestMetric
  ) noexcept
  {
    const double axisAEdgeDeltaX = segmentEnd.x - segmentStart.x;
    const double axisAEdgeDeltaY = segmentEnd.y - segmentStart.y;
    const double axisBProbeDeltaX = probePoint.x - referencePoint.x;
    const double axisBProbeDeltaY = probePoint.y - referencePoint.y;

    const double axisAProjectionHalf =
      0.5 * ((axisAEdgeDeltaX * axisA.x) + (axisAEdgeDeltaY * axisA.y));
    const double axisBProjectionHalf =
      0.5 * ((axisBProbeDeltaX * axisB.x) + (axisBProbeDeltaY * axisB.y));

    const double metric = axisBProjectionHalf * axisAProjectionHalf;
    if (metric < *bestMetric) {
      *bestMetric = metric;

      bestCandidate->axisAX = axisA.x;
      bestCandidate->axisAY = axisA.y;
      bestCandidate->axisBX = axisB.x;
      bestCandidate->axisBY = axisB.y;
      bestCandidate->axisAProjectionHalf = axisAProjectionHalf;
      bestCandidate->axisBProjectionHalf = axisBProjectionHalf;

      const double axisBStartDeltaX = segmentStart.x - referencePoint.x;
      const double axisBStartDeltaY = segmentStart.y - referencePoint.y;
      const double axisBStartProjection = (axisBStartDeltaX * axisB.x) + (axisBStartDeltaY * axisB.y);
      const double adjustedAxisBProjectionHalf = axisBProjectionHalf - axisBStartProjection;

      bestCandidate->pointX = segmentStart.x + (axisA.x * axisAProjectionHalf) + (axisB.x * adjustedAxisBProjectionHalf);
      bestCandidate->pointY = segmentStart.y + (axisA.y * axisAProjectionHalf) + (axisB.y * adjustedAxisBProjectionHalf);
    }
  }

  namespace
  {
    template <typename Real>
    Box2<Real>* BuildAxisAlignedBox2FromPointArrayImpl(
      Box2<Real>* const outBox,
      const int pointCount,
      const Vector2<Real>* const points,
      const std::uint8_t* const activeMask
    ) noexcept
    {
      if (outBox == nullptr) {
        return outBox;
      }

      outBox->Center[0] = static_cast<Real>(0);
      outBox->Center[1] = static_cast<Real>(0);
      outBox->Axis[0][0] = static_cast<Real>(1);
      outBox->Axis[0][1] = static_cast<Real>(0);
      outBox->Axis[1][0] = static_cast<Real>(0);
      outBox->Axis[1][1] = static_cast<Real>(1);
      outBox->Extent[0] = static_cast<Real>(1);
      outBox->Extent[1] = static_cast<Real>(1);

      if (points == nullptr || pointCount <= 0) {
        outBox->Extent[0] = static_cast<Real>(-1);
        outBox->Extent[1] = static_cast<Real>(-1);
        return outBox;
      }

      int firstActiveIndex = 0;
      if (activeMask != nullptr) {
        while (firstActiveIndex < pointCount && activeMask[firstActiveIndex] == 0u) {
          ++firstActiveIndex;
        }
        if (firstActiveIndex == pointCount) {
          outBox->Extent[0] = static_cast<Real>(-1);
          outBox->Extent[1] = static_cast<Real>(-1);
          return outBox;
        }
      }

      Real minX = points[firstActiveIndex].x;
      Real minY = points[firstActiveIndex].y;
      Real maxX = minX;
      Real maxY = minY;

      for (int pointIndex = firstActiveIndex + 1; pointIndex < pointCount; ++pointIndex) {
        if (activeMask != nullptr && activeMask[pointIndex] == 0u) {
          continue;
        }

        const Real pointX = points[pointIndex].x;
        const Real pointY = points[pointIndex].y;

        if (pointX < minX) {
          minX = pointX;
        } else if (pointX > maxX) {
          maxX = pointX;
        }

        if (pointY < minY) {
          minY = pointY;
        } else if (pointY > maxY) {
          maxY = pointY;
        }
      }

      outBox->Center[0] = (minX + maxX) * static_cast<Real>(0.5);
      outBox->Center[1] = (minY + maxY) * static_cast<Real>(0.5);
      outBox->Extent[0] = (maxX - minX) * static_cast<Real>(0.5);
      outBox->Extent[1] = (maxY - minY) * static_cast<Real>(0.5);
      return outBox;
    }
  } // namespace

  /**
   * Address: 0x00A685F0 (FUN_00A685F0)
   *
   * What it does:
   * Builds one axis-aligned `Box2<float>` from a 2D point array and optional
   * byte-mask; if no masked points are active, marks extents invalid (`-1`).
   */
  Box2<float>* BuildAxisAlignedBox2fFromPointArray(
    Box2<float>* const outBox,
    const int pointCount,
    const Vector2<float>* const points,
    const std::uint8_t* const activeMask
  ) noexcept
  {
    return BuildAxisAlignedBox2FromPointArrayImpl(outBox, pointCount, points, activeMask);
  }

  /**
   * Address: 0x00A694F0 (FUN_00A694F0)
   *
   * What it does:
   * Builds one axis-aligned `Box2<double>` from a 2D point array and optional
   * byte-mask; if no masked points are active, marks extents invalid (`-1`).
   */
  Box2<double>* BuildAxisAlignedBox2dFromPointArray(
    Box2<double>* const outBox,
    const int pointCount,
    const Vector2<double>* const points,
    const std::uint8_t* const activeMask
  ) noexcept
  {
    return BuildAxisAlignedBox2FromPointArrayImpl(outBox, pointCount, points, activeMask);
  }

  /**
   * Address: 0x00A4D9F0 (FUN_00A4D9F0)
   *
   * What it does:
   * Builds one 3D bounding sphere from min/max bounds of a 3D point array and
   * optional byte-mask; if no masked points are active, sets radius sentinel
   * `-1`.
   */
  Sphere3<double>* BuildBoundingSphere3dFromPointArray(
    Sphere3<double>* const outSphere,
    const int pointCount,
    const Vector3<double>* const points,
    const std::uint8_t* const activeMask
  ) noexcept
  {
    if (outSphere == nullptr) {
      return outSphere;
    }

    outSphere->Center.x = 0.0;
    outSphere->Center.y = 0.0;
    outSphere->Center.z = 0.0;
    outSphere->Radius = 0.0;

    if (points == nullptr || pointCount <= 0) {
      outSphere->Radius = -1.0;
      return outSphere;
    }

    int firstActiveIndex = 0;
    if (activeMask != nullptr) {
      while (firstActiveIndex < pointCount && activeMask[firstActiveIndex] == 0u) {
        ++firstActiveIndex;
      }
      if (firstActiveIndex == pointCount) {
        outSphere->Radius = -1.0;
        return outSphere;
      }
    }

    double minX = points[firstActiveIndex].x;
    double minY = points[firstActiveIndex].y;
    double minZ = points[firstActiveIndex].z;
    double maxX = minX;
    double maxY = minY;
    double maxZ = minZ;

    for (int pointIndex = firstActiveIndex + 1; pointIndex < pointCount; ++pointIndex) {
      if (activeMask != nullptr && activeMask[pointIndex] == 0u) {
        continue;
      }

      const double pointX = points[pointIndex].x;
      const double pointY = points[pointIndex].y;
      const double pointZ = points[pointIndex].z;

      if (pointX < minX) {
        minX = pointX;
      } else if (pointX > maxX) {
        maxX = pointX;
      }

      if (pointY < minY) {
        minY = pointY;
      } else if (pointY > maxY) {
        maxY = pointY;
      }

      if (pointZ < minZ) {
        minZ = pointZ;
      } else if (pointZ > maxZ) {
        maxZ = pointZ;
      }
    }

    outSphere->Center.x = (minX + maxX) * 0.5;
    outSphere->Center.y = (minY + maxY) * 0.5;
    outSphere->Center.z = (minZ + maxZ) * 0.5;

    const double halfDeltaX = (maxX - minX) * 0.5;
    const double halfDeltaY = (maxY - minY) * 0.5;
    const double halfDeltaZ = (maxZ - minZ) * 0.5;

    using std::sqrt;
    outSphere->Radius = sqrt((halfDeltaX * halfDeltaX) + (halfDeltaY * halfDeltaY) + (halfDeltaZ * halfDeltaZ));
    return outSphere;
  }

  /**
   * Address: 0x00A6CB50 (FUN_00A6CB50, Wm3::DistVector2Box2d::StaticGet)
   *
   * double, Wm3::Vector2<double> const&, Wm3::Box2<double> const&, Wm3::Vector2<double> const&,
   * Wm3::Vector2<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector2Box2d::StaticGet(Wm3::DistVector2Box2d *this, double t,
   * Wm3::Vector2d *velocity0, Wm3::Vector2d *velocity1);
   *
   * What it does:
   * Moves the point and box forward by time `t`, then returns point-to-box distance.
   */
  double DistVector2Box2dStaticGet(
    const double t,
    const Vector2<double>& vector,
    const Box2<double>& box,
    const Vector2<double>& vectorVelocity,
    const Vector2<double>& boxVelocity,
    Vector2<double>* const closestPointOnBox
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistVector2Box2dStaticGetSquared(t, vector, box, vectorVelocity, boxVelocity, closestPointOnBox));
  }

  /**
   * Address: 0x00A6CC60 (FUN_00A6CC60, Wm3::DistVector2Box2d::StaticGetSquared)
   *
   * double, Wm3::Vector2<double> const&, Wm3::Box2<double> const&, Wm3::Vector2<double> const&,
   * Wm3::Vector2<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector2Box2d::StaticGetSquared(Wm3::DistVector2Box2d *this, double t,
   * Wm3::Vector2d *velocity0, Wm3::Vector2d *velocity1);
   *
   * What it does:
   * Moves the point and box forward by time `t`, then returns the squared distance from the moved point to the moved
   * oriented box.
   */
  double DistVector2Box2dStaticGetSquared(
    const double t,
    const Vector2<double>& vector,
    const Box2<double>& box,
    const Vector2<double>& vectorVelocity,
    const Vector2<double>& boxVelocity,
    Vector2<double>* const closestPointOnBox
  ) noexcept
  {
    const Vector2<double> movedVector = vector + vectorVelocity * t;

    Box2<double> movedBox = box;
    movedBox.Center = box.Center + boxVelocity * t;

    const Vector2<double> diff = movedVector - movedBox.Center;
    Vector2<double> closest = movedBox.Center;
    double squaredDistance = 0.0;

    for (int i = 0; i < 2; ++i) {
      const Vector2<double>& axis = movedBox.Axis[i];
      const double projected = Vector2<double>::Dot(diff, axis);

      double clamped = projected;
      if (projected < -movedBox.Extent[i]) {
        const double delta = projected + movedBox.Extent[i];
        squaredDistance += delta * delta;
        clamped = -movedBox.Extent[i];
      } else if (projected > movedBox.Extent[i]) {
        const double delta = projected - movedBox.Extent[i];
        squaredDistance += delta * delta;
        clamped = movedBox.Extent[i];
      }

      closest = closest + axis * clamped;
    }

    if (closestPointOnBox) {
      *closestPointOnBox = closest;
    }
    return squaredDistance;
  }

  /**
   * Address: 0x00A484F0 (FUN_00A484F0, Wm3::DistVector3Segment3f::GetSquared)
   *
   * Wm3::Vector3<float> const&, Wm3::Segment3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::GetSquared(Wm3::DistVector3Segment3f *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and writes the closest point.
   */
  float DistVector3Segment3fGetSquared(
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> diff = Vector3<float>::Sub(vector, segment.Origin);
    float t = Vector3<float>::Dot(segment.Direction, diff);

    if (t < -segment.Extent) {
      t = -segment.Extent;
    } else if (t > segment.Extent) {
      t = segment.Extent;
    }

    const Vector3<float> closest = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
    const Vector3<float> delta = Vector3<float>::Sub(closest, vector);

    if (closestPointOnSegment) {
      *closestPointOnSegment = closest;
    }
    return Vector3<float>::Dot(delta, delta);
  }

  /**
   * Address: 0x00A480E0 (FUN_00A480E0, Wm3::DistVector3Segment3f::Get)
   *
   * Wm3::Vector3<float> const&, Wm3::Segment3<float> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::Get(Wm3::DistVector3Segment3f *this);
   *
   * What it does:
   * Returns distance from a point to a segment.
   */
  float DistVector3Segment3fGet(
    const Vector3<float>& vector, const Segment3<float>& segment, Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    return SqrtfBinary(DistVector3Segment3fGetSquared(vector, segment, closestPointOnSegment));
  }

  /**
   * Address: 0x00A48190 (FUN_00A48190, Wm3::DistVector3Segment3f::StaticGet)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Segment3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::StaticGet(Wm3::DistVector3Segment3f *this, float fT, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns point-to-segment distance.
   */
  float DistVector3Segment3fStaticGet(
    const float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Segment3<float> movedSegment = segment;
    movedSegment.Origin = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segmentVelocity, t));

    return DistVector3Segment3fGet(movedVector, movedSegment, closestPointOnSegment);
  }

  /**
   * Address: 0x00A48340 (FUN_00A48340, Wm3::DistVector3Segment3f::StaticGetSquared)
   *
   * float, Wm3::Vector3<float> const&, Wm3::Segment3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3f::StaticGetSquared(Wm3::DistVector3Segment3f *this, float fT,
   * Wm3::Vector3f *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns squared point-to-segment
   * distance.
   */
  float DistVector3Segment3fStaticGetSquared(
    const float t,
    const Vector3<float>& vector,
    const Segment3<float>& segment,
    const Vector3<float>& vectorVelocity,
    const Vector3<float>& segmentVelocity,
    Vector3<float>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<float> movedVector = Vector3<float>::Add(vector, Vector3<float>::Scale(vectorVelocity, t));

    Segment3<float> movedSegment = segment;
    movedSegment.Origin = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segmentVelocity, t));

    return DistVector3Segment3fGetSquared(movedVector, movedSegment, closestPointOnSegment);
  }

  /**
   * Address: 0x00A48910 (FUN_00A48910, Wm3::DistVector3Segment3d::GetSquared)
   *
   * Wm3::Vector3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::GetSquared(Wm3::DistVector3Segment3d *this);
   *
   * What it does:
   * Computes squared distance from a point to a segment and writes the closest point.
   */
  double DistVector3Segment3dGetSquared(
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> diff = Vector3<double>::Sub(vector, segment.Origin);
    double t = Vector3<double>::Dot(segment.Direction, diff);

    if (t < -segment.Extent) {
      t = -segment.Extent;
    } else if (t > segment.Extent) {
      t = segment.Extent;
    }

    const Vector3<double> closest = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segment.Direction, t));
    const Vector3<double> delta = Vector3<double>::Sub(closest, vector);

    if (closestPointOnSegment) {
      *closestPointOnSegment = closest;
    }
    return Vector3<double>::Dot(delta, delta);
  }

  /**
   * Address: 0x00A48100 (FUN_00A48100, Wm3::DistVector3Segment3d::Get)
   *
   * Wm3::Vector3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::Get(Wm3::DistVector3Segment3d *this);
   *
   * What it does:
   * Returns distance from a point to a segment.
   */
  double DistVector3Segment3dGet(
    const Vector3<double>& vector, const Segment3<double>& segment, Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistVector3Segment3dGetSquared(vector, segment, closestPointOnSegment));
  }

  /**
   * Address: 0x00A486B0 (FUN_00A486B0, Wm3::DistVector3Segment3d::StaticGet)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::StaticGet(Wm3::DistVector3Segment3d *this, double t, Wm3::Vector3d
   * *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns point-to-segment distance.
   */
  double DistVector3Segment3dStaticGet(
    const double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistVector3Segment3dGet(movedVector, movedSegment, closestPointOnSegment);
  }

  /**
   * Address: 0x00A487E0 (FUN_00A487E0, Wm3::DistVector3Segment3d::StaticGetSquared)
   *
   * double, Wm3::Vector3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistVector3Segment3d::StaticGetSquared(Wm3::DistVector3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves point/segment forward by time `t` using the provided velocities, then returns squared point-to-segment
   * distance.
   */
  double DistVector3Segment3dStaticGetSquared(
    const double t,
    const Vector3<double>& vector,
    const Segment3<double>& segment,
    const Vector3<double>& vectorVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> movedVector = Vector3<double>::Add(vector, Vector3<double>::Scale(vectorVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistVector3Segment3dGetSquared(movedVector, movedSegment, closestPointOnSegment);
  }

  /**
   * Address: 0x00A81330 (FUN_00A81330, Wm3::DistLine3Segment3d::GetSquared)
   *
   * Wm3::Line3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * long double __thiscall Wm3::DistLine3Segment3d::GetSquared(Wm3::DistLine3Segment3d *this);
   *
   * What it does:
   * Computes squared distance between an infinite line and a bounded segment,
   * and writes closest points on both primitives.
   */
  double DistLine3Segment3dGetSquared(
    const Line3<double>& line,
    const Segment3<double>& segment,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    const Vector3<double> diff = Vector3<double>::Sub(line.Origin, segment.Origin);
    const double a01 = -Vector3<double>::Dot(line.Direction, segment.Direction);
    const double b0 = Vector3<double>::Dot(diff, line.Direction);
    const double c = Vector3<double>::Dot(diff, diff);
    const double det = std::fabs(1.0 - a01 * a01);

    double lineParam = 0.0;
    double segmentParam = 0.0;
    double sqrDist = 0.0;

    if (det < 0.00000001) {
      lineParam = -b0;
      segmentParam = 0.0;
      sqrDist = b0 * lineParam + c;
    } else {
      const double b1 = -Vector3<double>::Dot(diff, segment.Direction);
      const double segmentNumerator = a01 * b0 - b1;
      const double extDet = segment.Extent * det;

      if (segmentNumerator < -extDet) {
        segmentParam = -segment.Extent;
        lineParam = -(a01 * segmentParam + b0);
        sqrDist = -lineParam * lineParam + segmentParam * (segmentParam + 2.0 * b1) + c;
      } else if (segmentNumerator > extDet) {
        segmentParam = segment.Extent;
        lineParam = -(a01 * segmentParam + b0);
        sqrDist = -lineParam * lineParam + segmentParam * (segmentParam + 2.0 * b1) + c;
      } else {
        const double invDet = 1.0 / det;
        lineParam = (a01 * b1 - b0) * invDet;
        segmentParam = segmentNumerator * invDet;
        sqrDist = lineParam * (lineParam + a01 * segmentParam + 2.0 * b0) +
          segmentParam * (a01 * lineParam + segmentParam + 2.0 * b1) + c;
      }
    }

    const Vector3<double> closestLinePoint =
      Vector3<double>::Add(line.Origin, Vector3<double>::Scale(line.Direction, lineParam));
    const Vector3<double> closestSegmentPoint =
      Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segment.Direction, segmentParam));

    if (closestPointOnLine) {
      *closestPointOnLine = closestLinePoint;
    }
    if (closestPointOnSegment) {
      *closestPointOnSegment = closestSegmentPoint;
    }

    return std::fabs(sqrDist);
  }

  /**
   * Address: 0x00A809C0 (FUN_00A809C0, Wm3::DistLine3Segment3d::Get)
   *
   * Wm3::Line3<double> const&, Wm3::Segment3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::Get(Wm3::DistLine3Segment3d *this);
   *
   * What it does:
   * Returns distance between an infinite line and a bounded segment.
   */
  double DistLine3Segment3dGet(
    const Line3<double>& line,
    const Segment3<double>& segment,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    using std::sqrt;
    return sqrt(DistLine3Segment3dGetSquared(line, segment, closestPointOnLine, closestPointOnSegment));
  }

  /**
   * Address: 0x00A810B0 (FUN_00A810B0, Wm3::DistLine3Segment3d::StaticGet)
   *
   * double, Wm3::Line3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::StaticGet(Wm3::DistLine3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves line and segment origins by time `t` and returns line-to-segment distance.
   */
  double DistLine3Segment3dStaticGet(
    const double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    Line3<double> movedLine = line;
    movedLine.Origin = Vector3<double>::Add(line.Origin, Vector3<double>::Scale(lineVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistLine3Segment3dGet(movedLine, movedSegment, closestPointOnLine, closestPointOnSegment);
  }

  /**
   * Address: 0x00A811F0 (FUN_00A811F0, Wm3::DistLine3Segment3d::StaticGetSquared)
   *
   * double, Wm3::Line3<double> const&, Wm3::Segment3<double> const&, Wm3::Vector3<double> const&,
   * Wm3::Vector3<double> const&
   *
   * IDA signature:
   * double __thiscall Wm3::DistLine3Segment3d::StaticGetSquared(Wm3::DistLine3Segment3d *this, double t,
   * Wm3::Vector3d *velocity0, Wm3::Vector3d *velocity1);
   *
   * What it does:
   * Moves line and segment origins by time `t` and returns squared line-to-segment distance.
   */
  double DistLine3Segment3dStaticGetSquared(
    const double t,
    const Line3<double>& line,
    const Segment3<double>& segment,
    const Vector3<double>& lineVelocity,
    const Vector3<double>& segmentVelocity,
    Vector3<double>* const closestPointOnLine,
    Vector3<double>* const closestPointOnSegment
  ) noexcept
  {
    Line3<double> movedLine = line;
    movedLine.Origin = Vector3<double>::Add(line.Origin, Vector3<double>::Scale(lineVelocity, t));

    Segment3<double> movedSegment = segment;
    movedSegment.Origin = Vector3<double>::Add(segment.Origin, Vector3<double>::Scale(segmentVelocity, t));

    return DistLine3Segment3dGetSquared(movedLine, movedSegment, closestPointOnLine, closestPointOnSegment);
  }

  /**
   * Address: 0x00A41560 (FUN_00A41560, Wm3::IntrBox3Sphere3f::Test)
   *
   * Wm3::Box3<float> const&, Wm3::Sphere3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrBox3Sphere3f::Test(Wm3::IntrBox3Sphere3f *this);
   *
   * What it does:
   * Tests static overlap between oriented box and sphere.
   */
  bool IntrBox3Sphere3fTest(const Box3<float>& box, const Sphere3<float>& sphere) noexcept
  {
    const Vector3<float> delta{
      sphere.Center.x - box.Center[0], sphere.Center.y - box.Center[1], sphere.Center.z - box.Center[2]
    };

    float distanceSquared = 0.0f;
    for (int i = 0; i < 3; ++i) {
      const Vector3<float> axis{box.Axis[i][0], box.Axis[i][1], box.Axis[i][2]};
      const float projected = std::fabs(Vector3<float>::Dot(delta, axis));
      const float outside = projected - box.Extent[i];
      if (outside > 0.0f) {
        distanceSquared += outside * outside;
      }
    }

    return distanceSquared <= sphere.Radius * sphere.Radius;
  }

  /**
   * Address: 0x00A43420 (FUN_00A43420, Wm3::IntrBox3Sphere3f::StaticFind)
   *
   * float, Wm3::Box3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&,
   * float*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * char __thiscall Wm3::IntrBox3Sphere3f::StaticFind(Wm3::IntrBox3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Sweeps sphere center by relative velocity against box extents expanded by radius, then computes
   * first contact point on the original oriented box.
   */
  bool IntrBox3Sphere3fStaticFind(
    const float tMax,
    const Box3<float>& box,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* const contactTime,
    Vector3<float>* const contactPoint,
    int* const intrType
  ) noexcept
  {
    if (intrType) {
      *intrType = 0;
    }

    if (IntrBox3Sphere3fTest(box, sphere)) {
      if (contactTime) {
        *contactTime = 0.0f;
      }
      if (contactPoint) {
        *contactPoint = sphere.Center;
      }
      if (intrType) {
        *intrType = 8;
      }
      return true;
    }

    const Vector3<float> relativeVelocity = Vector3<float>::Sub(velocity1, velocity0);
    if (Vector3<float>::LengthSq(relativeVelocity) <= kWm3Epsilon * kWm3Epsilon) {
      return false;
    }

    Box3<float> expanded = box;
    expanded.Extent[0] += sphere.Radius;
    expanded.Extent[1] += sphere.Radius;
    expanded.Extent[2] += sphere.Radius;

    float tEnter = 0.0f;
    if (!RayIntersectsOrientedBox(sphere.Center, relativeVelocity, expanded, &tEnter)) {
      return false;
    }

    if (tEnter < 0.0f) {
      tEnter = 0.0f;
    }
    if (tMax < tEnter) {
      return false;
    }

    const Vector3<float> sphereCenterAtContact =
      Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(velocity1, tEnter));

    Vector3<float> closest{};
    DistVector3Box3fGetSquared(sphereCenterAtContact, box, &closest);

    if (contactTime) {
      *contactTime = tEnter;
    }
    if (contactPoint) {
      *contactPoint = closest;
    }
    if (intrType) {
      *intrType = 1;
    }
    return true;
  }

  /**
   * Address: 0x00A46440 (FUN_00A46440, Wm3::IntrSegment3Box3f::Test)
   *
   * Wm3::Segment3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Box3f::Test(Wm3::IntrSegment3Box3f *this);
   *
   * What it does:
   * Runs SAT overlap test between segment and oriented box.
   */
  bool IntrSegment3Box3fTest(const Segment3<float>& segment, const Box3<float>& box) noexcept
  {
    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const Vector3<float> diff{
      segment.Origin.x - box.Center[0], segment.Origin.y - box.Center[1], segment.Origin.z - box.Center[2]
    };

    const float directionDotAxis[3] = {
      Vector3<float>::Dot(segment.Direction, axis0),
      Vector3<float>::Dot(segment.Direction, axis1),
      Vector3<float>::Dot(segment.Direction, axis2)
    };
    const float absDirectionDotAxis[3] = {
      std::fabs(directionDotAxis[0]), std::fabs(directionDotAxis[1]), std::fabs(directionDotAxis[2])
    };

    const float diffDotAxis[3] = {
      Vector3<float>::Dot(diff, axis0), Vector3<float>::Dot(diff, axis1), Vector3<float>::Dot(diff, axis2)
    };
    const float absDiffDotAxis[3] = {std::fabs(diffDotAxis[0]), std::fabs(diffDotAxis[1]), std::fabs(diffDotAxis[2])};

    for (int i = 0; i < 3; ++i) {
      const float limit = segment.Extent * absDirectionDotAxis[i] + box.Extent[i];
      if (absDiffDotAxis[i] > limit) {
        return false;
      }
    }

    const Vector3<float> wCrossD = Vector3<float>::Cross(segment.Direction, diff);

    const float test0 = std::fabs(Vector3<float>::Dot(wCrossD, axis0));
    const float limit0 = box.Extent[1] * absDirectionDotAxis[2] + box.Extent[2] * absDirectionDotAxis[1];
    if (test0 > limit0) {
      return false;
    }

    const float test1 = std::fabs(Vector3<float>::Dot(wCrossD, axis1));
    const float limit1 = box.Extent[0] * absDirectionDotAxis[2] + box.Extent[2] * absDirectionDotAxis[0];
    if (test1 > limit1) {
      return false;
    }

    const float test2 = std::fabs(Vector3<float>::Dot(wCrossD, axis2));
    const float limit2 = box.Extent[0] * absDirectionDotAxis[1] + box.Extent[1] * absDirectionDotAxis[0];
    if (test2 > limit2) {
      return false;
    }

    return true;
  }

  /**
   * Address: 0x00A46C80 (FUN_00A46C80, Wm3::IntrSegment3Sphere3f::Test)
   *
   * Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Sphere3f::Test(Wm3::IntrSegment3Sphere3f *this);
   *
   * What it does:
   * Tests static overlap between a segment and sphere without emitting contact points.
   */
  bool IntrSegment3Sphere3fTest(const Segment3<float>& segment, const Sphere3<float>& sphere) noexcept
  {
    const Vector3<float> diff = Vector3<float>::Sub(segment.Origin, sphere.Center);
    const float a0 = Vector3<float>::Dot(diff, diff) - sphere.Radius * sphere.Radius;
    const float a1 = Vector3<float>::Dot(diff, segment.Direction);
    const float discr = a1 * a1 - a0;
    if (discr < 0.0f) {
      return false;
    }

    const float q0 = a0 + segment.Extent * segment.Extent;
    const float twoA1Extent = (a1 + a1) * segment.Extent;
    const float qMinus = q0 - twoA1Extent;
    const float qPlus = q0 + twoA1Extent;
    if (qPlus * qMinus <= 0.0f) {
      return true;
    }

    if (qMinus <= 0.0f) {
      return false;
    }
    return segment.Extent > std::fabs(a1);
  }

  /**
   * Address: 0x00A4FE60 (FUN_00A4FE60, Wm3::IntrLine3Box3f::Test)
   *
   * Wm3::Line3<float> const&, Wm3::Box3<float> const&
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrLine3Box3f::Test(Wm3::IntrLine3Box3f *this);
   *
   * What it does:
   * Runs SAT cross-axis checks for infinite line vs oriented box overlap.
   */
  bool IntrLine3Box3fTest(const Line3<float>& line, const Box3<float>& box) noexcept
  {
    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const Vector3<float> diff{
      line.Origin.x - box.Center[0], line.Origin.y - box.Center[1], line.Origin.z - box.Center[2]
    };

    const Vector3<float> wCrossD = Vector3<float>::Cross(line.Direction, diff);
    const float absDotD0 = std::fabs(Vector3<float>::Dot(axis0, line.Direction));
    const float absDotD1 = std::fabs(Vector3<float>::Dot(axis1, line.Direction));
    const float absDotD2 = std::fabs(Vector3<float>::Dot(axis2, line.Direction));

    const float absCross0 = std::fabs(Vector3<float>::Dot(axis0, wCrossD));
    if (box.Extent[1] * absDotD2 + box.Extent[2] * absDotD1 < absCross0) {
      return false;
    }

    const float absCross1 = std::fabs(Vector3<float>::Dot(axis1, wCrossD));
    if (box.Extent[0] * absDotD2 + box.Extent[2] * absDotD0 < absCross1) {
      return false;
    }

    const float absCross2 = std::fabs(Vector3<float>::Dot(axis2, wCrossD));
    return box.Extent[1] * absDotD0 + box.Extent[0] * absDotD1 >= absCross2;
  }

  /**
   * Address: 0x00A4FCC0 (FUN_00A4FCC0, Wm3::IntrLine3Box3f::Clip)
   *
   * float, float, float*, float*
   *
   * IDA signature:
   * bool __cdecl Wm3::IntrLine3Box3f::Clip(float fDenom, float fNumer, float *rfT0, float *rfT1);
   *
   * What it does:
   * Clips one parametric slab constraint and tightens [`t0`,`t1`] when possible.
   */
  bool IntrLine3Box3fClip(const float denom, const float numer, float* const t0, float* const t1) noexcept
  {
    if (denom > 0.0f) {
      if ((*t1) * denom < numer) {
        return false;
      }
      if ((*t0) * denom < numer) {
        *t0 = numer / denom;
      }
      return true;
    }

    if (denom < 0.0f) {
      if ((*t0) * denom < numer) {
        return false;
      }
      if ((*t1) * denom < numer) {
        *t1 = numer / denom;
      }
      return true;
    }

    return numer <= 0.0f;
  }

  /**
   * Address: 0x00A50220 (FUN_00A50220, Wm3::IntrLine3Box3f::DoClipping)
   *
   * float, float, Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, Wm3::Box3<float> const&, bool, int*,
   * Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * BOOL __cdecl Wm3::IntrLine3Box3f::DoClipping(float fT0, float fT1, Wm3::Vector3f *rkOrigin, Wm3::Vector3f
   * *rkDirection, const Wm3::Box3f *rkBox, char bSolid, int *riQuantity, Wm3::Vector3f *akPoint, int *riIntrType);
   *
   * What it does:
   * Clips a line interval against an oriented box and emits 0/1/2 intersection points plus type.
   */
  bool IntrLine3Box3fDoClipping(
    float t0,
    float t1,
    const Vector3<float>& origin,
    const Vector3<float>& direction,
    const Box3<float>& box,
    const bool solid,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    int localQuantity = 0;
    int localIntrType = 0;
    Vector3<float> localPoints[2]{};
    int* const outQuantity = quantity ? quantity : &localQuantity;
    int* const outIntrType = intrType ? intrType : &localIntrType;
    Vector3<float>* const outPoints = points ? points : localPoints;

    const Vector3<float> diff{origin.x - box.Center[0], origin.y - box.Center[1], origin.z - box.Center[2]};

    const Vector3<float> axis0{box.Axis[0][0], box.Axis[0][1], box.Axis[0][2]};
    const Vector3<float> axis1{box.Axis[1][0], box.Axis[1][1], box.Axis[1][2]};
    const Vector3<float> axis2{box.Axis[2][0], box.Axis[2][1], box.Axis[2][2]};

    const float boxOrigin[3] = {
      Vector3<float>::Dot(axis0, diff), Vector3<float>::Dot(axis1, diff), Vector3<float>::Dot(axis2, diff)
    };
    const float boxDirection[3] = {
      Vector3<float>::Dot(axis0, direction),
      Vector3<float>::Dot(axis1, direction),
      Vector3<float>::Dot(axis2, direction)
    };

    const float initialT0 = t0;
    const float initialT1 = t1;

    const bool clipped = IntrLine3Box3fClip(boxDirection[0], -boxOrigin[0] - box.Extent[0], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[0], boxOrigin[0] - box.Extent[0], &t0, &t1) &&
                         IntrLine3Box3fClip(boxDirection[1], -boxOrigin[1] - box.Extent[1], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[1], boxOrigin[1] - box.Extent[1], &t0, &t1) &&
                         IntrLine3Box3fClip(boxDirection[2], -boxOrigin[2] - box.Extent[2], &t0, &t1) &&
                         IntrLine3Box3fClip(-boxDirection[2], boxOrigin[2] - box.Extent[2], &t0, &t1);

    if (clipped && (solid || initialT0 != t0 || initialT1 != t1)) {
      if (t0 >= t1) {
        *outIntrType = 1;
        *outQuantity = 1;
        outPoints[0] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t0));
      } else {
        *outIntrType = 2;
        *outQuantity = 2;
        outPoints[0] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t0));
        outPoints[1] = Vector3<float>::Add(origin, Vector3<float>::Scale(direction, t1));
      }
      return *outIntrType != 0;
    }

    *outQuantity = 0;
    *outIntrType = 0;
    return false;
  }

  /**
   * Address: 0x00A508F0 (FUN_00A508F0, Wm3::IntrLine3Box3f::Find)
   *
   * Wm3::Line3<float> const&, Wm3::Box3<float> const&, int*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * BOOL __thiscall Wm3::IntrLine3Box3f::Find(Wm3::IntrLine3Box3f *this);
   *
   * What it does:
   * Wrapper over `DoClipping` that uses full line interval [`-FLT_MAX`, `+FLT_MAX`] and `bSolid=true`.
   */
  bool IntrLine3Box3fFind(
    const Line3<float>& line,
    const Box3<float>& box,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    const float maxT = std::numeric_limits<float>::max();
    return IntrLine3Box3fDoClipping(-maxT, maxT, line.Origin, line.Direction, box, true, quantity, points, intrType);
  }

  /**
   * Address: 0x00A462A0 (FUN_00A462A0, Wm3::IntrSegment3Box3f::Find)
   *
   * Wm3::Segment3<float> const&, Wm3::Box3<float> const&, bool, int*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Box3f::Find(Wm3::IntrSegment3Box3f *this);
   *
   * What it does:
   * Thin wrapper over `DoClipping` that clips `t` in [`-Extent`, `+Extent`] for segment-vs-box queries.
   */
  bool IntrSegment3Box3fFind(
    const Segment3<float>& segment,
    const Box3<float>& box,
    const bool solid,
    int* const quantity,
    Vector3<float>* const points,
    int* const intrType
  ) noexcept
  {
    return IntrLine3Box3fDoClipping(
      -segment.Extent, segment.Extent, segment.Origin, segment.Direction, box, solid, quantity, points, intrType
    );
  }

  /**
   * Address: 0x00A471C0 (FUN_00A471C0, Wm3::IntrSegment3Sphere3f::Find)
   *
   * Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, int*, Wm3::Vector3<float>*, float*, float
   *
   * IDA signature:
   * bool __thiscall Wm3::IntrSegment3Sphere3f::Find(Wm3::IntrSegment3Sphere3f *this);
   *
   * What it does:
   * Finds 0/1/2 static intersection points between a segment and sphere using the recovered threshold branch logic.
   */
  bool IntrSegment3Sphere3fFind(
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    int* const quantity,
    Vector3<float>* const points,
    float* const segmentT,
    const float zeroThreshold
  ) noexcept
  {
    int outQuantity = 0;

    const Vector3<float> diff = Vector3<float>::Sub(segment.Origin, sphere.Center);
    const float a0 = Vector3<float>::Dot(diff, diff) - sphere.Radius * sphere.Radius;
    const float a1 = Vector3<float>::Dot(segment.Direction, diff);
    const float discr = a1 * a1 - a0;

    if (discr < 0.0f) {
      if (quantity) {
        *quantity = 0;
      }
      return false;
    }

    const float q0 = a0 + segment.Extent * segment.Extent;
    const float q1 = 2.0f * a1 * segment.Extent;
    const float qMinus = q0 - q1;
    const float qPlus = q0 + q1;

    if (qPlus * qMinus > 0.0f) {
      if (qMinus <= 0.0f || segment.Extent <= std::fabs(a1)) {
        if (quantity) {
          *quantity = 0;
        }
        return false;
      }

      if (zeroThreshold > discr) {
        const float t = -a1;
        if (segmentT) {
          segmentT[0] = t;
        }
        if (points) {
          points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
        }
        outQuantity = 1;
      } else {
        const float root = SqrtfBinary(discr);
        const float t0 = -a1 - root;
        const float t1 = root - a1;

        if (segmentT) {
          segmentT[0] = t0;
          segmentT[1] = t1;
        }
        if (points) {
          points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t0));
          points[1] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t1));
        }
        outQuantity = 2;
      }
    } else {
      const float root = SqrtfBinary(discr);
      const float t = (qMinus <= 0.0f) ? (root - a1) : (-a1 - root);

      if (segmentT) {
        segmentT[0] = t;
      }
      if (points) {
        points[0] = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(segment.Direction, t));
      }
      outQuantity = 1;
    }

    if (quantity) {
      *quantity = outQuantity;
    }
    return outQuantity > 0;
  }

  /**
   * Address: 0x00A46B10 (FUN_00A46B10, Wm3::IntrSegment3Sphere3f::StaticTest)
   *
   * float, Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&
   *
   * IDA signature:
   * char __thiscall Wm3::IntrSegment3Sphere3f::StaticTest(Wm3::IntrSegment3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Dynamic overlap test path: first checks static segment-sphere overlap, then tests the relative sweep as
   * segment-vs-capsule.
   */
  bool IntrSegment3Sphere3fStaticTest(
    const float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1
  ) noexcept
  {
    (void)tMax;

    if (IntrSegment3Sphere3fTest(segment, sphere)) {
      return true;
    }

    Vector3<float> relative = Vector3<float>::Sub(velocity1, velocity0);
    const float relativeLength = Vector3<float>::Normalize(relative);

    Segment3<float> sweepSegment{};
    sweepSegment.Origin =
      Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(Vector3<float>::Sub(velocity1, velocity0), 0.5f));
    sweepSegment.Direction = relative;
    sweepSegment.Extent = relativeLength * 0.5f;

    Capsule3<float> capsule{};
    capsule.Segment = segment;
    capsule.Radius = sphere.Radius;

    const IntrSegment3Capsule3f intersector(sweepSegment, capsule);
    float roots[2]{};
    const int rootCount = LineCapsuleIntersectionRoots(
      intersector.GetSegment().Origin, intersector.GetSegment().Direction, intersector.GetCapsule(), roots);
    float clipped[2]{};
    return ClipRootsToPathExtent(roots, rootCount, intersector.GetSegment().Extent, clipped) > 0;
  }

  /**
   * Address: 0x00A46DB0 (FUN_00A46DB0, Wm3::IntrSegment3Sphere3f::StaticFind)
   *
   * float, Wm3::Segment3<float> const&, Wm3::Sphere3<float> const&, Wm3::Vector3<float> const&, Wm3::Vector3<float>
   * const&, float*, Wm3::Vector3<float>*, int*
   *
   * IDA signature:
   * char __thiscall Wm3::IntrSegment3Sphere3f::StaticFind(Wm3::IntrSegment3Sphere3f *this, float fTMax, Wm3::Vector3f
   * *rkVelocity0, Wm3::Vector3f *rkVelocity1);
   *
   * What it does:
   * Dynamic find path: resolves first relative sweep hit and computes contact point on the moving segment.
   */
  bool IntrSegment3Sphere3fStaticFind(
    const float tMax,
    const Segment3<float>& segment,
    const Sphere3<float>& sphere,
    const Vector3<float>& velocity0,
    const Vector3<float>& velocity1,
    float* const contactTime,
    Vector3<float>* const contactPoint,
    int* const intrType
  ) noexcept
  {
    int localQuantity = 0;
    Vector3<float> localPoints[2]{};
    float localSegmentT[2]{};
    if (IntrSegment3Sphere3fFind(segment, sphere, &localQuantity, localPoints, localSegmentT, kWm3Epsilon)) {
      if (contactTime) {
        *contactTime = 0.0f;
      }
      if (contactPoint) {
        *contactPoint = sphere.Center;
      }
      if (intrType) {
        *intrType = 8;
      }
      return true;
    }

    const Vector3<float> relativeDelta = Vector3<float>::Sub(velocity1, velocity0);
    Vector3<float> relativeDirection = relativeDelta;
    const float relativeLength = Vector3<float>::Normalize(relativeDirection);

    Segment3<float> sweepSegment{};
    sweepSegment.Origin = Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(relativeDelta, 0.5f));
    sweepSegment.Direction = relativeDirection;
    sweepSegment.Extent = relativeLength * 0.5f;

    Capsule3<float> capsule{};
    capsule.Segment = segment;
    capsule.Radius = sphere.Radius;

    const IntrSegment3Capsule3f intersector(sweepSegment, capsule);
    float roots[2]{};
    const int rootCount = LineCapsuleIntersectionRoots(
      intersector.GetSegment().Origin, intersector.GetSegment().Direction, intersector.GetCapsule(), roots);
    float clipped[2]{};
    const int clippedCount = ClipRootsToPathExtent(roots, rootCount, intersector.GetSegment().Extent, clipped);
    if (clippedCount <= 0) {
      if (intrType) {
        *intrType = 0;
      }
      return false;
    }

    const float t = clipped[0];
    if (tMax < t) {
      if (intrType) {
        *intrType = 0;
      }
      return false;
    }

    if (contactTime) {
      *contactTime = t;
    }

    const Vector3<float> sphereCenterAtT = Vector3<float>::Add(sphere.Center, Vector3<float>::Scale(velocity1, t));
    const Vector3<float> segmentOriginAtT = Vector3<float>::Add(segment.Origin, Vector3<float>::Scale(velocity0, t));

    const float projected =
      Vector3<float>::Dot(segment.Direction, Vector3<float>::Sub(sphereCenterAtT, segmentOriginAtT));
    float clamped = projected;
    if (clamped < -segment.Extent) {
      clamped = -segment.Extent;
    } else if (clamped > segment.Extent) {
      clamped = segment.Extent;
    }

    if (contactPoint) {
      *contactPoint = Vector3<float>::Add(segmentOriginAtT, Vector3<float>::Scale(segment.Direction, clamped));
    }

    if (intrType) {
      // Binary path leaves this as non-penetration type for dynamic-hit branch.
      *intrType = 0;
    }
    return true;
  }

  namespace
  {
    template <std::size_t kIsNilOffset>
    struct QueryTreeNodeKeyView
    {
      static_assert(kIsNilOffset >= 0x10, "QueryTreeNodeKeyView nil offset must be >= 0x10");

      QueryTreeNodeKeyView* left;   // +0x00
      QueryTreeNodeKeyView* parent; // +0x04
      QueryTreeNodeKeyView* right;  // +0x08
      std::uint32_t key;            // +0x0C
      std::uint8_t reserved[kIsNilOffset - 0x10];
      std::uint8_t isNil;           // +kIsNilOffset
    };

    using QueryTreeNodeKeyNil17 = QueryTreeNodeKeyView<0x11>;
    using QueryTreeNodeKeyNil21 = QueryTreeNodeKeyView<0x15>;
    using QueryTreeNodeKeyNil33 = QueryTreeNodeKeyView<0x21>;

    static_assert(offsetof(QueryTreeNodeKeyNil17, key) == 0x0C, "QueryTreeNodeKeyNil17::key offset must be 0x0C");
    static_assert(offsetof(QueryTreeNodeKeyNil17, isNil) == 0x11, "QueryTreeNodeKeyNil17::isNil offset must be 0x11");
    static_assert(offsetof(QueryTreeNodeKeyNil21, key) == 0x0C, "QueryTreeNodeKeyNil21::key offset must be 0x0C");
    static_assert(offsetof(QueryTreeNodeKeyNil21, isNil) == 0x15, "QueryTreeNodeKeyNil21::isNil offset must be 0x15");
    static_assert(offsetof(QueryTreeNodeKeyNil33, key) == 0x0C, "QueryTreeNodeKeyNil33::key offset must be 0x0C");
    static_assert(offsetof(QueryTreeNodeKeyNil33, isNil) == 0x21, "QueryTreeNodeKeyNil33::isNil offset must be 0x21");

    template <class TNode>
    struct QueryTreeOwnerView
    {
      std::uint32_t lane00; // +0x00
      TNode* head;          // +0x04
    };
    static_assert(sizeof(QueryTreeOwnerView<QueryTreeNodeKeyNil17>) == 0x08, "QueryTreeOwnerView size must be 0x08");
    static_assert(
      offsetof(QueryTreeOwnerView<QueryTreeNodeKeyNil17>, head) == 0x04,
      "QueryTreeOwnerView::head offset must be 0x04"
    );

    template <class TNode>
    struct QueryTreeEqualRangeResultView
    {
      QueryTreeOwnerView<TNode>* owner0; // +0x00
      TNode* lowerBound;                 // +0x04
      QueryTreeOwnerView<TNode>* owner2; // +0x08
      TNode* upperBound;                 // +0x0C
    };
    static_assert(
      sizeof(QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17>) == 0x10,
      "QueryTreeEqualRangeResultView size must be 0x10"
    );

    template <class TNode>
    struct QueryTreeNodeLookupResultView
    {
      QueryTreeOwnerView<TNode>* owner; // +0x00
      TNode* node;                      // +0x04
    };
    static_assert(
      sizeof(QueryTreeNodeLookupResultView<QueryTreeNodeKeyNil33>) == 0x08,
      "QueryTreeNodeLookupResultView size must be 0x08"
    );

    void SignalInvalidParameterRecoveredInvariant() noexcept
    {
      _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
    }

    template <class TOwner>
    struct QueryTreeOwnerKeyCursorView
    {
      TOwner* owner;         // +0x00
      std::uint32_t keyLane; // +0x04
    };
    static_assert(
      sizeof(QueryTreeOwnerKeyCursorView<QueryTreeOwnerView<QueryTreeNodeKeyNil17>>) == 0x08,
      "QueryTreeOwnerKeyCursorView size must be 0x08"
    );
    static_assert(
      offsetof(QueryTreeOwnerKeyCursorView<QueryTreeOwnerView<QueryTreeNodeKeyNil17>>, keyLane) == 0x04,
      "QueryTreeOwnerKeyCursorView::keyLane offset must be 0x04"
    );

    using QueryTreeOwnerKeyCursorNil17 = QueryTreeOwnerKeyCursorView<QueryTreeOwnerView<QueryTreeNodeKeyNil17>>;
    using QueryTreeOwnerKeyCursorNil21 = QueryTreeOwnerKeyCursorView<QueryTreeOwnerView<QueryTreeNodeKeyNil21>>;

    template <class TOwner>
    [[maybe_unused]] QueryTreeOwnerKeyCursorView<TOwner>* InitializeQueryTreeOwnerKeyCursor(
      QueryTreeOwnerKeyCursorView<TOwner>* const cursor,
      const std::uint32_t keyLane,
      TOwner* const owner
    ) noexcept
    {
      cursor->owner = nullptr;
      cursor->keyLane = keyLane;
      if (owner == nullptr) {
        SignalInvalidParameterRecoveredInvariant();
      }
      cursor->owner = owner;
      return cursor;
    }

    template <class TOwner>
    [[nodiscard]] bool AreQueryTreeOwnerKeyCursorsEqual(
      const QueryTreeOwnerKeyCursorView<TOwner>& lhs,
      const QueryTreeOwnerKeyCursorView<TOwner>& rhs
    ) noexcept
    {
      if (lhs.owner == nullptr || lhs.owner != rhs.owner) {
        SignalInvalidParameterRecoveredInvariant();
      }
      return lhs.keyLane == rhs.keyLane;
    }

    template <class TOwner>
    [[nodiscard]] bool AreQueryTreeOwnerKeyCursorsNotEqual(
      const QueryTreeOwnerKeyCursorView<TOwner>& lhs,
      const QueryTreeOwnerKeyCursorView<TOwner>& rhs
    ) noexcept
    {
      if (lhs.owner == nullptr || lhs.owner != rhs.owner) {
        SignalInvalidParameterRecoveredInvariant();
      }
      return lhs.keyLane != rhs.keyLane;
    }

    struct QueryWordChunkOwnerView
    {
      std::uint32_t lane00;            // +0x00
      std::uint32_t** wordChunkBases;  // +0x04
      std::uint32_t chunkBaseIndex;    // +0x08
      std::uint32_t firstWordIndex;    // +0x0C
      std::uint32_t wordCount;         // +0x10
    };
    static_assert(sizeof(QueryWordChunkOwnerView) == 0x14, "QueryWordChunkOwnerView size must be 0x14");
    static_assert(offsetof(QueryWordChunkOwnerView, wordChunkBases) == 0x04, "QueryWordChunkOwnerView::wordChunkBases offset must be 0x04");
    static_assert(offsetof(QueryWordChunkOwnerView, chunkBaseIndex) == 0x08, "QueryWordChunkOwnerView::chunkBaseIndex offset must be 0x08");
    static_assert(offsetof(QueryWordChunkOwnerView, firstWordIndex) == 0x0C, "QueryWordChunkOwnerView::firstWordIndex offset must be 0x0C");
    static_assert(offsetof(QueryWordChunkOwnerView, wordCount) == 0x10, "QueryWordChunkOwnerView::wordCount offset must be 0x10");

    struct QueryWordCursorView
    {
      std::uint32_t lane00;            // +0x00
      QueryWordChunkOwnerView* owner;  // +0x04
      std::uint32_t wordIndex;         // +0x08
    };
    static_assert(sizeof(QueryWordCursorView) == 0x0C, "QueryWordCursorView size must be 0x0C");
    static_assert(offsetof(QueryWordCursorView, owner) == 0x04, "QueryWordCursorView::owner offset must be 0x04");
    static_assert(offsetof(QueryWordCursorView, wordIndex) == 0x08, "QueryWordCursorView::wordIndex offset must be 0x08");

    [[maybe_unused]] QueryWordCursorView* InitializeQueryWordCursor(
      QueryWordCursorView* const cursor,
      const std::uint32_t wordIndex,
      QueryWordChunkOwnerView* const owner
    ) noexcept
    {
      cursor->lane00 = 0;
      if (owner == nullptr) {
        SignalInvalidParameterRecoveredInvariant();
      }

      const std::uint32_t firstWordIndex = owner->firstWordIndex;
      if (firstWordIndex > wordIndex || wordIndex > (firstWordIndex + owner->wordCount)) {
        SignalInvalidParameterRecoveredInvariant();
      }

      cursor->owner = owner;
      cursor->wordIndex = wordIndex;
      return cursor;
    }

    [[nodiscard]] std::uint32_t* ResolveQueryWordCursorElement(
      const QueryWordCursorView& cursor
    ) noexcept
    {
      std::uint32_t chunkIndex = cursor.wordIndex >> 2u;
      const std::uint32_t chunkLane = cursor.wordIndex & 3u;

      QueryWordChunkOwnerView* const owner = cursor.owner;
      if (owner == nullptr) {
        SignalInvalidParameterRecoveredInvariant();
      }
      if (cursor.wordIndex >= (owner->firstWordIndex + owner->wordCount)) {
        SignalInvalidParameterRecoveredInvariant();
      }

      const std::uint32_t baseChunkIndex = owner->chunkBaseIndex;
      if (baseChunkIndex <= chunkIndex) {
        chunkIndex -= baseChunkIndex;
      }

      return owner->wordChunkBases[chunkIndex] + chunkLane;
    }

    template <class TNode>
    [[nodiscard]] TNode* FindSubtreeLeftmostFromLeftChild(TNode* node) noexcept
    {
      if (node == nullptr) {
        return nullptr;
      }

      TNode* cursor = node->left;
      if (cursor == nullptr || cursor->isNil != 0u) {
        return node;
      }

      do {
        node = cursor;
        cursor = cursor->left;
      } while (cursor != nullptr && cursor->isNil == 0u);

      return node;
    }

    template <class TNode>
    [[nodiscard]] TNode* FindSubtreeRightmostFromRightChild(TNode* node) noexcept
    {
      if (node == nullptr) {
        return nullptr;
      }

      TNode* cursor = node->right;
      if (cursor == nullptr || cursor->isNil != 0u) {
        return node;
      }

      do {
        node = cursor;
        cursor = cursor->right;
      } while (cursor != nullptr && cursor->isNil == 0u);

      return node;
    }
  } // namespace

  struct Distance3fRuntimeView
  {
    void* vtable;                        // +0x00
    std::int32_t maximumIterations;      // +0x04
    float zeroThreshold;                 // +0x08
    float contactTime;                   // +0x0C
    Vector3<float> closestPoint0;        // +0x10
    Vector3<float> closestPoint1;        // +0x1C
    std::uint8_t hasMultipleClosest0;    // +0x28
    std::uint8_t hasMultipleClosest1;    // +0x29
    std::uint8_t padding2A2B[0x02];      // +0x2A
    float differenceStep;                // +0x2C
    float inverseTwoDifferenceStep;      // +0x30
  };
  static_assert(offsetof(Distance3fRuntimeView, closestPoint0) == 0x10, "Distance3fRuntimeView::closestPoint0 offset must be 0x10");
  static_assert(offsetof(Distance3fRuntimeView, closestPoint1) == 0x1C, "Distance3fRuntimeView::closestPoint1 offset must be 0x1C");
  static_assert(offsetof(Distance3fRuntimeView, hasMultipleClosest0) == 0x28, "Distance3fRuntimeView::hasMultipleClosest0 offset must be 0x28");
  static_assert(offsetof(Distance3fRuntimeView, hasMultipleClosest1) == 0x29, "Distance3fRuntimeView::hasMultipleClosest1 offset must be 0x29");

  struct Distance2dRuntimeView
  {
    void* vtable;                        // +0x00
    std::uint32_t reserved04;            // +0x04
    std::int32_t maximumIterations;      // +0x08
    std::uint32_t reserved0C;            // +0x0C
    double zeroThreshold;                // +0x10
    double contactTime;                  // +0x18
    Vector2<double> closestPoint0;       // +0x20
    Vector2<double> closestPoint1;       // +0x30
    std::uint8_t hasMultipleClosest0;    // +0x40
    std::uint8_t hasMultipleClosest1;    // +0x41
    std::uint8_t padding42_47[0x06];     // +0x42
    double differenceStep;               // +0x48
    double inverseTwoDifferenceStep;     // +0x50
  };
  static_assert(offsetof(Distance2dRuntimeView, closestPoint0) == 0x20, "Distance2dRuntimeView::closestPoint0 offset must be 0x20");
  static_assert(offsetof(Distance2dRuntimeView, closestPoint1) == 0x30, "Distance2dRuntimeView::closestPoint1 offset must be 0x30");
  static_assert(offsetof(Distance2dRuntimeView, hasMultipleClosest0) == 0x40, "Distance2dRuntimeView::hasMultipleClosest0 offset must be 0x40");
  static_assert(offsetof(Distance2dRuntimeView, hasMultipleClosest1) == 0x41, "Distance2dRuntimeView::hasMultipleClosest1 offset must be 0x41");

  struct Distance3dRuntimeView
  {
    void* vtable;                        // +0x00
    std::uint32_t reserved04;            // +0x04
    std::int32_t maximumIterations;      // +0x08
    std::uint32_t reserved0C;            // +0x0C
    double zeroThreshold;                // +0x10
    double contactTime;                  // +0x18
    Vector3<double> closestPoint0;       // +0x20
    Vector3<double> closestPoint1;       // +0x38
    std::uint8_t hasMultipleClosest0;    // +0x50
    std::uint8_t hasMultipleClosest1;    // +0x51
    std::uint8_t padding52_57[0x06];     // +0x52
    double differenceStep;               // +0x58
    double inverseTwoDifferenceStep;     // +0x60
  };
  static_assert(offsetof(Distance3dRuntimeView, closestPoint0) == 0x20, "Distance3dRuntimeView::closestPoint0 offset must be 0x20");
  static_assert(offsetof(Distance3dRuntimeView, closestPoint1) == 0x38, "Distance3dRuntimeView::closestPoint1 offset must be 0x38");
  static_assert(offsetof(Distance3dRuntimeView, hasMultipleClosest0) == 0x50, "Distance3dRuntimeView::hasMultipleClosest0 offset must be 0x50");
  static_assert(offsetof(Distance3dRuntimeView, hasMultipleClosest1) == 0x51, "Distance3dRuntimeView::hasMultipleClosest1 offset must be 0x51");

  struct QueryTreeNodePairNil21
  {
    QueryTreeNodePairNil21* left;        // +0x00
    QueryTreeNodePairNil21* parent;      // +0x04
    QueryTreeNodePairNil21* right;       // +0x08
    std::uint32_t keyLane;               // +0x0C
    std::uint32_t valueLane;             // +0x10
    std::uint8_t color;                  // +0x14
    std::uint8_t isNil;                  // +0x15
    std::uint8_t reserved16_17[0x02];    // +0x16
  };
  static_assert(sizeof(QueryTreeNodePairNil21) == 0x18, "QueryTreeNodePairNil21 size must be 0x18");
  static_assert(offsetof(QueryTreeNodePairNil21, color) == 0x14, "QueryTreeNodePairNil21::color offset must be 0x14");
  static_assert(offsetof(QueryTreeNodePairNil21, isNil) == 0x15, "QueryTreeNodePairNil21::isNil offset must be 0x15");

  using QueryTreePairOwnerNil21 = QueryTreeOwnerView<QueryTreeNodePairNil21>;

  struct QueryTreeOwnerNodeCursorNil21
  {
    QueryTreePairOwnerNil21* owner;      // +0x00
    QueryTreeNodePairNil21* node;        // +0x04
  };
  static_assert(sizeof(QueryTreeOwnerNodeCursorNil21) == 0x08, "QueryTreeOwnerNodeCursorNil21 size must be 0x08");

  struct QueryTreeOwnerKeyCursorResultNil21
  {
    QueryTreeOwnerKeyCursorNil21 cursor; // +0x00
    std::uint8_t inserted;               // +0x08
  };
  static_assert(
    offsetof(QueryTreeOwnerKeyCursorResultNil21, inserted) == 0x08,
    "QueryTreeOwnerKeyCursorResultNil21::inserted offset must be 0x08"
  );

  struct Intersector2fRuntimeView
  {
    void* vtable;                        // +0x00
    float contactTime;                   // +0x04
    std::int32_t intersectionType;       // +0x08
  };
  static_assert(offsetof(Intersector2fRuntimeView, contactTime) == 0x04, "Intersector2fRuntimeView::contactTime offset must be 0x04");

  struct IntrBox3Sphere3fRuntimeView
  {
    std::uint8_t reserved00_1F[0x20];    // +0x00
    Vector3<float> contactPoint;         // +0x20
  };
  static_assert(offsetof(IntrBox3Sphere3fRuntimeView, contactPoint) == 0x20, "IntrBox3Sphere3fRuntimeView::contactPoint offset must be 0x20");

  /**
   * Address: 0x00A39250 (FUN_00A39250)
   *
   * What it does:
   * Returns the second "multiple closest points" flag lane from one
   * `Distance3f` runtime object.
   */
  [[maybe_unused]] std::uint8_t GetDistance3fHasMultipleClosestPoints1(
    const Distance3fRuntimeView* const runtime
  ) noexcept
  {
    return runtime->hasMultipleClosest1;
  }

  /**
   * Address: 0x00A39810 (FUN_00A39810)
   *
   * What it does:
   * Returns one mutable pointer to the first closest-point lane of one
   * `Distance2d` runtime object.
   */
  [[maybe_unused]] Vector2<double>* GetDistance2dClosestPoint0(
    Distance2dRuntimeView* const runtime
  ) noexcept
  {
    return &runtime->closestPoint0;
  }

  /**
   * Address: 0x00A39820 (FUN_00A39820)
   *
   * What it does:
   * Returns one mutable pointer to the second closest-point lane of one
   * `Distance2d` runtime object.
   */
  [[maybe_unused]] Vector2<double>* GetDistance2dClosestPoint1(
    Distance2dRuntimeView* const runtime
  ) noexcept
  {
    return &runtime->closestPoint1;
  }

  /**
   * Address: 0x00A39830 (FUN_00A39830)
   *
   * What it does:
   * Returns the first "multiple closest points" flag lane from one
   * `Distance2d` runtime object.
   */
  [[maybe_unused]] std::uint8_t GetDistance2dHasMultipleClosestPoints0(
    const Distance2dRuntimeView* const runtime
  ) noexcept
  {
    return runtime->hasMultipleClosest0;
  }

  /**
   * Address: 0x00A39840 (FUN_00A39840)
   *
   * What it does:
   * Returns the second "multiple closest points" flag lane from one
   * `Distance2d` runtime object.
   */
  [[maybe_unused]] std::uint8_t GetDistance2dHasMultipleClosestPoints1(
    const Distance2dRuntimeView* const runtime
  ) noexcept
  {
    return runtime->hasMultipleClosest1;
  }

  /**
   * Address: 0x00A39E00 (FUN_00A39E00)
   *
   * What it does:
   * Returns one mutable pointer to the first closest-point lane of one
   * `Distance3d` runtime object.
   */
  [[maybe_unused]] Vector3<double>* GetDistance3dClosestPoint0(
    Distance3dRuntimeView* const runtime
  ) noexcept
  {
    return &runtime->closestPoint0;
  }

  /**
   * Address: 0x00A39E10 (FUN_00A39E10)
   *
   * What it does:
   * Returns one mutable pointer to the second closest-point lane of one
   * `Distance3d` runtime object.
   */
  [[maybe_unused]] Vector3<double>* GetDistance3dClosestPoint1(
    Distance3dRuntimeView* const runtime
  ) noexcept
  {
    return &runtime->closestPoint1;
  }

  /**
   * Address: 0x00A39E20 (FUN_00A39E20)
   *
   * What it does:
   * Returns the first "multiple closest points" flag lane from one
   * `Distance3d` runtime object.
   */
  [[maybe_unused]] std::uint8_t GetDistance3dHasMultipleClosestPoints0(
    const Distance3dRuntimeView* const runtime
  ) noexcept
  {
    return runtime->hasMultipleClosest0;
  }

  /**
   * Address: 0x00A39E30 (FUN_00A39E30)
   *
   * What it does:
   * Returns the second "multiple closest points" flag lane from one
   * `Distance3d` runtime object.
   */
  [[maybe_unused]] std::uint8_t GetDistance3dHasMultipleClosestPoints1(
    const Distance3dRuntimeView* const runtime
  ) noexcept
  {
    return runtime->hasMultipleClosest1;
  }

  /**
   * Address: 0x00A39FE0 (FUN_00A39FE0)
   *
   * What it does:
   * Clears the owner lane of one nil-`+0x15` query-tree key cursor while
   * preserving the key lane.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil21* ClearQueryTreeOwnerKeyCursorNil21OwnerLaneA(
    QueryTreeOwnerKeyCursorNil21* const cursor
  ) noexcept
  {
    cursor->owner = nullptr;
    return cursor;
  }

  /**
   * Address: 0x00A3A040 (FUN_00A3A040)
   *
   * What it does:
   * Alias lane that clears the owner lane of one nil-`+0x15` query-tree key
   * cursor.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil21* ClearQueryTreeOwnerKeyCursorNil21OwnerLaneB(
    QueryTreeOwnerKeyCursorNil21* const cursor
  ) noexcept
  {
    cursor->owner = nullptr;
    return cursor;
  }

  /**
   * Address: 0x00A3A0E0 (FUN_00A3A0E0)
   *
   * What it does:
   * Builds one `(cursor, inserted)` result lane for nil-`+0x15` query-tree
   * insertion results.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorResultNil21* BuildQueryTreeInsertResultNil21(
    QueryTreeOwnerKeyCursorResultNil21* const outResult,
    const QueryTreeOwnerKeyCursorNil21* const cursor,
    const std::uint8_t* const inserted
  ) noexcept
  {
    outResult->cursor = *cursor;
    outResult->inserted = *inserted;
    return outResult;
  }

  /**
   * Address: 0x00A3A200 (FUN_00A3A200)
   *
   * What it does:
   * Initializes one nil-`+0x15` red-black node lane with link pointers,
   * key/value payload lanes, color, and `isNil=0`.
   */
  [[maybe_unused]] QueryTreeNodePairNil21* InitializeQueryTreeNodePairNil21(
    QueryTreeNodePairNil21* const node,
    QueryTreeNodePairNil21* const left,
    QueryTreeNodePairNil21* const parent,
    QueryTreeNodePairNil21* const right,
    const std::uint32_t* const keyValuePair,
    const std::uint8_t color
  ) noexcept
  {
    node->left = left;
    node->right = right;
    node->parent = parent;
    node->keyLane = keyValuePair[0];
    node->valueLane = keyValuePair[1];
    node->color = color;
    node->isNil = 0u;
    return node;
  }

  /**
   * Address: 0x00A3A2B0 (FUN_00A3A2B0)
   *
   * What it does:
   * Returns one indexed double lane from storage where each lane is 8 bytes.
   */
  [[maybe_unused]] double* GetIndexedDoubleLaneStride8LaneA(
    double* const base,
    const std::int32_t index
  ) noexcept
  {
    return base + index;
  }

  /**
   * Address: 0x00A3A2E0 (FUN_00A3A2E0)
   *
   * What it does:
   * Returns one pointer to the second double lane (`base + 1`).
   */
  [[maybe_unused]] double* GetSecondDoubleLanePointerLaneA(
    double* const base
  ) noexcept
  {
    return base + 1;
  }

  /**
   * Address: 0x00A3A300 (FUN_00A3A300)
   *
   * What it does:
   * Returns one pointer to the third double lane (`base + 2`).
   */
  [[maybe_unused]] double* GetThirdDoubleLanePointerLaneA(
    double* const base
  ) noexcept
  {
    return base + 2;
  }

  /**
   * Address: 0x00A3A310 (FUN_00A3A310)
   *
   * What it does:
   * Returns one `Vector3<double>` z-lane (`+0x10`).
   */
  [[maybe_unused]] double GetVector3dZLane(
    const Vector3<double>* const vector
  ) noexcept
  {
    return vector->z;
  }

  /**
   * Address: 0x00A3A320 (FUN_00A3A320)
   *
   * What it does:
   * Copies one `Vector3<double>` lane set into destination storage.
   */
  [[maybe_unused]] Vector3<double>* CopyVector3dLaneA(
    Vector3<double>* const destination,
    const Vector3<double>* const source
  ) noexcept
  {
    destination->x = source->x;
    destination->y = source->y;
    destination->z = source->z;
    return destination;
  }

  /**
   * Address: 0x00A3A390 (FUN_00A3A390)
   *
   * What it does:
   * Adds one `Vector3<double>` source lane set into destination storage.
   */
  [[maybe_unused]] Vector3<double>* AddVector3dInPlaceLaneA(
    Vector3<double>* const destination,
    const Vector3<double>* const source
  ) noexcept
  {
    destination->x += source->x;
    destination->y += source->y;
    destination->z += source->z;
    return destination;
  }

  /**
   * Address: 0x00A3A3C0 (FUN_00A3A3C0)
   *
   * What it does:
   * Returns one `Vector3<double>` dot product.
   */
  [[maybe_unused]] double DotVector3dLaneA(
    const Vector3<double>* const lhs,
    const Vector3<double>* const rhs
  ) noexcept
  {
    return lhs->x * rhs->x + lhs->y * rhs->y + lhs->z * rhs->z;
  }

  /**
   * Address: 0x00A3A3E0 (FUN_00A3A3E0)
   *
   * What it does:
   * Initializes one `Box3<double>` from center, three axis vectors, and three
   * extent lanes.
   */
  [[maybe_unused]] Box3<double>* InitializeBox3dFromCenterAxesExtentsLaneA(
    Box3<double>* const box,
    const Vector3<double>* const center,
    const Vector3<double>* const axis0,
    const Vector3<double>* const axis1,
    const Vector3<double>* const axis2,
    const double extent0,
    const double extent1,
    const double extent2
  ) noexcept
  {
    box->Center = *center;
    box->Axis[0] = *axis0;
    box->Axis[1] = *axis1;
    box->Axis[2] = *axis2;
    box->Extent[0] = extent0;
    box->Extent[1] = extent1;
    box->Extent[2] = extent2;
    return box;
  }

  /**
   * Address: 0x00A3A470 (FUN_00A3A470)
   *
   * What it does:
   * Returns one pointer to the second double lane (`base + 1`).
   */
  [[maybe_unused]] double* GetSecondDoubleLanePointerLaneB(
    double* const base
  ) noexcept
  {
    return base + 1;
  }

  /**
   * Address: 0x00A3A480 (FUN_00A3A480)
   *
   * What it does:
   * Copies one `Vector2<double>` lane set into destination storage.
   */
  [[maybe_unused]] Vector2<double>* CopyVector2dLaneA(
    Vector2<double>* const destination,
    const Vector2<double>* const source
  ) noexcept
  {
    destination->x = source->x;
    destination->y = source->y;
    return destination;
  }

  /**
   * Address: 0x00A3A6A0 (FUN_00A3A6A0)
   *
   * What it does:
   * Alias lane that returns one indexed double lane from 8-byte lane storage.
   */
  [[maybe_unused]] double* GetIndexedDoubleLaneStride8LaneB(
    double* const base,
    const std::int32_t index
  ) noexcept
  {
    return GetIndexedDoubleLaneStride8LaneA(base, index);
  }

  /**
   * Address: 0x00A3A810 (FUN_00A3A810)
   *
   * What it does:
   * Clears both lanes of one nil-`+0x15` query-tree key cursor.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil21* ClearQueryTreeOwnerKeyCursorNil21(
    QueryTreeOwnerKeyCursorNil21* const cursor
  ) noexcept
  {
    cursor->owner = nullptr;
    cursor->keyLane = 0u;
    return cursor;
  }

  /**
   * Address: 0x00A3CE00 (FUN_00A3CE00)
   *
   * What it does:
   * Builds one owner/node cursor at tree begin position by taking `head->left`
   * from the owner lane.
   */
  [[maybe_unused]] QueryTreeOwnerNodeCursorNil21* InitializeQueryTreeOwnerNodeCursorAtBegin(
    QueryTreePairOwnerNil21* const owner,
    QueryTreeOwnerNodeCursorNil21* const outCursor
  ) noexcept
  {
    outCursor->node = owner->head->left;
    outCursor->owner = owner;
    return outCursor;
  }

  /**
   * Address: 0x00A3CE20 (FUN_00A3CE20)
   *
   * What it does:
   * Copies one owner/node cursor lane into caller-provided output storage.
   */
  [[maybe_unused]] QueryTreeOwnerNodeCursorNil21* CopyQueryTreeOwnerNodeCursorLaneA(
    QueryTreeOwnerNodeCursorNil21* const sourceCursor,
    QueryTreeOwnerNodeCursorNil21* const outCursor
  ) noexcept
  {
    outCursor->node = sourceCursor->node;
    outCursor->owner = sourceCursor->owner;
    return outCursor;
  }

  /**
   * Address: 0x00A414F0 (FUN_00A414F0)
   *
   * What it does:
   * Returns one mutable pointer to the cached contact point lane in one
   * `IntrBox3Sphere3f` runtime object.
   */
  [[maybe_unused]] Vector3<float>* GetIntrBox3Sphere3fContactPointLaneB(
    IntrBox3Sphere3fRuntimeView* const runtime
  ) noexcept
  {
    return &runtime->contactPoint;
  }

  /**
   * Address: 0x00A454C0 (FUN_00A454C0)
   *
   * What it does:
   * Returns one `Intersector2f` runtime contact-time lane.
   */
  [[maybe_unused]] float GetIntersector2fContactTimeLaneA(
    const Intersector2fRuntimeView* const runtime
  ) noexcept
  {
    return runtime->contactTime;
  }

  /**
   * Address: 0x00A3A100 (FUN_00A3A100)
   *
   * What it does:
   * Compares two nil-`+0x15` query-tree key cursors for key equality after
   * verifying they refer to the same non-null owner lane.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil21EqualLaneA(
    const QueryTreeOwnerKeyCursorNil21* const lhs,
    const QueryTreeOwnerKeyCursorNil21* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A3A1C0 (FUN_00A3A1C0)
   *
   * What it does:
   * Initializes one nil-`+0x15` query-tree key cursor `(owner, key)` lane.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil21* InitializeQueryTreeOwnerKeyCursorNil21LaneA(
    QueryTreeOwnerKeyCursorNil21* const cursor,
    const std::uint32_t keyLane,
    QueryTreeOwnerView<QueryTreeNodeKeyNil21>* const owner
  ) noexcept
  {
    return InitializeQueryTreeOwnerKeyCursor(cursor, keyLane, owner);
  }

  /**
   * Address: 0x00A3A170 (FUN_00A3A170)
   *
   * What it does:
   * Returns the left-most node in one query tree subtree that uses nil marker
   * byte offset `+0x15`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil21* QueryTreeLeftmostNil21LaneC(QueryTreeNodeKeyNil21* const node) noexcept
  {
    return FindSubtreeLeftmostFromLeftChild(node);
  }

  /**
   * Address: 0x00A3A240 (FUN_00A3A240)
   *
   * What it does:
   * Returns the right-most node in one query tree subtree that uses nil marker
   * byte offset `+0x15`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil21* QueryTreeRightmostNil21LaneC(QueryTreeNodeKeyNil21* const node) noexcept
  {
    return FindSubtreeRightmostFromRightChild(node);
  }

  /**
   * Address: 0x00A3A340 (FUN_00A3A340)
   *
   * What it does:
   * Divides one double-precision 3D vector by `scalar` and writes the result
   * into `outQuotient`; division by zero emits `DBL_MAX` in all lanes.
   */
  [[maybe_unused]] Vector3<double>* DivideVector3dByScalarInto(
    const Vector3<double>& source,
    Vector3<double>* const outQuotient,
    const double scalar
  ) noexcept
  {
    if (outQuotient == nullptr) {
      return nullptr;
    }

    if (scalar == 0.0) {
      constexpr double kMax = std::numeric_limits<double>::max();
      outQuotient->x = kMax;
      outQuotient->y = kMax;
      outQuotient->z = kMax;
      return outQuotient;
    }

    const double inverse = 1.0 / scalar;
    outQuotient->x = source.x * inverse;
    outQuotient->y = source.y * inverse;
    outQuotient->z = source.z * inverse;
    return outQuotient;
  }

  struct FourDoubleRuntimeLane
  {
    double x = 0.0;
    double y = 0.0;
    double z = 0.0;
    double w = 0.0;
  };
  static_assert(sizeof(FourDoubleRuntimeLane) == 0x20, "FourDoubleRuntimeLane size must be 0x20");

  /**
   * Address: 0x00A3A4C0 (FUN_00A3A4C0)
   *
   * What it does:
   * Copies one four-lane double runtime vector into destination storage.
   */
  [[maybe_unused]] FourDoubleRuntimeLane* CopyFourDoubleRuntimeLaneA(
    FourDoubleRuntimeLane* const destination,
    const FourDoubleRuntimeLane* const source
  ) noexcept
  {
    destination->x = source->x;
    destination->y = source->y;
    destination->z = source->z;
    destination->w = source->w;
    return destination;
  }

  /**
   * Address: 0x00A3A4E0 (FUN_00A3A4E0)
   *
   * What it does:
   * Returns the four-lane dot product of two double-precision runtime vectors.
   */
  [[maybe_unused]] double DotFourDoubleRuntimeLanes(
    const FourDoubleRuntimeLane* const lhs,
    const FourDoubleRuntimeLane* const rhs
  ) noexcept
  {
    return (lhs->x * rhs->x)
      + (lhs->y * rhs->y)
      + (lhs->z * rhs->z)
      + (lhs->w * rhs->w);
  }

  /**
   * Address: 0x00A3A820 (FUN_00A3A820)
   *
   * What it does:
   * Compares two nil-`+0x15` query-tree key cursors for key inequality after
   * verifying they refer to the same non-null owner lane.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil21NotEqualLaneA(
    const QueryTreeOwnerKeyCursorNil21* const lhs,
    const QueryTreeOwnerKeyCursorNil21* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsNotEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A3A870 (FUN_00A3A870)
   *
   * What it does:
   * Alternate lane that initializes one nil-`+0x15` query-tree key cursor
   * `(owner, key)`.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil21* InitializeQueryTreeOwnerKeyCursorNil21LaneB(
    QueryTreeOwnerKeyCursorNil21* const cursor,
    const std::uint32_t keyLane,
    QueryTreeOwnerView<QueryTreeNodeKeyNil21>* const owner
  ) noexcept
  {
    return InitializeQueryTreeOwnerKeyCursor(cursor, keyLane, owner);
  }

  /**
   * Address: 0x00A3BC10 (FUN_00A3BC10)
   *
   * What it does:
   * Returns true when one point lies inside one oriented box by projecting the
   * center-relative delta onto each box axis and comparing to extents.
   */
  [[maybe_unused]] bool Box3ContainsPointByAxisProjection(
    const Vector3<float>* const point,
    const Box3<float>* const box
  ) noexcept
  {
    const float deltaX = point->x - box->Center.x;
    const float deltaY = point->y - box->Center.y;
    const float deltaZ = point->z - box->Center.z;

    for (int axisIndex = 0; axisIndex < 3; ++axisIndex) {
      const Vector3<float>& axis = box->Axis[axisIndex];
      const float projection = axis.x * deltaX + axis.y * deltaY + axis.z * deltaZ;
      if (box->Extent[axisIndex] < std::fabs(projection)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Address: 0x00A4A3A0 (FUN_00A4A3A0)
   *
   * What it does:
   * Returns true when any indexed float3 lane in one candidate list lies
   * within `distanceSquaredThreshold` of the selected pivot point lane.
   */
  [[maybe_unused]] bool HasIndexedFloat3WithinDistanceSquared(
    const std::int32_t* const candidateIndexList,
    const std::int32_t pivotIndex,
    float* const* const pointTable,
    const float distanceSquaredThreshold
  ) noexcept
  {
    const std::int32_t candidateCount = candidateIndexList[0];
    if (candidateCount <= 0) {
      return false;
    }

    const float* const pivotPoint = pointTable[pivotIndex];
    for (std::int32_t index = 0; index < candidateCount; ++index) {
      const float* const candidatePoint = pointTable[candidateIndexList[index + 1]];
      const float dx = pivotPoint[0] - candidatePoint[0];
      const float dy = pivotPoint[1] - candidatePoint[1];
      const float dz = pivotPoint[2] - candidatePoint[2];
      if ((dx * dx + dy * dy + dz * dz) < distanceSquaredThreshold) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00A49600 (FUN_00A49600)
   *
   * What it does:
   * Computes point-to-sphere signed distance-squared (`distance^2 - radius^2`)
   * in single precision and returns whether the point is inside/on the sphere.
   */
  [[maybe_unused]] bool RuntimePointInsideSphereBySignedDistanceSquaredFloat(
    const float* const point3,
    const float* const sphereCenterRadius4,
    float* const outSignedDistanceSquared
  ) noexcept
  {
    const float deltaX = point3[0] - sphereCenterRadius4[0];
    const float deltaY = point3[1] - sphereCenterRadius4[1];
    const float deltaZ = point3[2] - sphereCenterRadius4[2];
    const float signedDistanceSquared =
      (deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ) - sphereCenterRadius4[3];
    *outSignedDistanceSquared = signedDistanceSquared;
    return signedDistanceSquared <= 0.0f;
  }

  /**
   * Address: 0x00A496A0 (FUN_00A496A0)
   *
   * What it does:
   * Computes point-to-sphere signed distance-squared (`distance^2 - radius^2`)
   * and returns whether the point is inside/on the sphere.
   */
  [[maybe_unused]] bool RuntimePointInsideSphereBySignedDistanceSquared(
    const double* const point3,
    const double* const sphereCenterRadius4,
    double* const outSignedDistanceSquared
  ) noexcept
  {
    const double deltaX = point3[0] - sphereCenterRadius4[0];
    const double deltaY = point3[1] - sphereCenterRadius4[1];
    const double deltaZ = point3[2] - sphereCenterRadius4[2];
    const double signedDistanceSquared =
      (deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ) - sphereCenterRadius4[3];
    *outSignedDistanceSquared = signedDistanceSquared;
    return signedDistanceSquared <= 0.0;
  }

  /**
   * Address: 0x00A4A440 (FUN_00A4A440)
   *
   * What it does:
   * Returns true when any indexed double3 lane in one candidate list lies
   * within `distanceSquaredThreshold` of the selected pivot point lane.
   */
  [[maybe_unused]] bool HasIndexedDouble3WithinDistanceSquared(
    const std::int32_t* const candidateIndexList,
    const std::int32_t pivotIndex,
    double* const* const pointTable,
    const double distanceSquaredThreshold
  ) noexcept
  {
    const std::int32_t candidateCount = candidateIndexList[0];
    if (candidateCount <= 0) {
      return false;
    }

    const double* const pivotPoint = pointTable[pivotIndex];
    for (std::int32_t index = 0; index < candidateCount; ++index) {
      const double* const candidatePoint = pointTable[candidateIndexList[index + 1]];
      const double dx = pivotPoint[0] - candidatePoint[0];
      const double dy = pivotPoint[1] - candidatePoint[1];
      const double dz = pivotPoint[2] - candidatePoint[2];
      if ((dx * dx + dy * dy + dz * dz) < distanceSquaredThreshold) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00A51F20 (FUN_00A51F20)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x44`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset68(char* const runtime) noexcept
  {
    return runtime + 0x44;
  }

  /**
   * Address: 0x00A51F30 (FUN_00A51F30)
   *
   * What it does:
   * Returns one indexed runtime payload lane at `this + 0x50 + index*0x0C`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset80IndexedBy12(
    char* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return runtime + 0x50 + (index * 0x0C);
  }

  /**
   * Address: 0x00A51F60 (FUN_00A51F60)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x70`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset112(char* const runtime) noexcept
  {
    return runtime + 0x70;
  }

  /**
   * Address: 0x00A51F70 (FUN_00A51F70)
   *
   * What it does:
   * Returns one indexed runtime payload lane at `this + 0x88 + index*0x18`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset136IndexedBy24(
    char* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return runtime + 0x88 + (index * 0x18);
  }

  /**
   * Address: 0x00A52110 (FUN_00A52110)
   *
   * What it does:
   * Compares two nil-`+0x11` query-tree key cursors for key equality after
   * verifying they refer to the same non-null owner lane.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil17EqualLaneA(
    const QueryTreeOwnerKeyCursorNil17* const lhs,
    const QueryTreeOwnerKeyCursorNil17* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A52200 (FUN_00A52200)
   *
   * What it does:
   * Alternate lane of nil-`+0x11` query-tree key cursor equality.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil17EqualLaneB(
    const QueryTreeOwnerKeyCursorNil17* const lhs,
    const QueryTreeOwnerKeyCursorNil17* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A523B0 (FUN_00A523B0)
   *
   * What it does:
   * Initializes one nil-`+0x11` query-tree key cursor `(owner, key)` lane.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil17* InitializeQueryTreeOwnerKeyCursorNil17LaneA(
    QueryTreeOwnerKeyCursorNil17* const cursor,
    const std::uint32_t keyLane,
    QueryTreeOwnerView<QueryTreeNodeKeyNil17>* const owner
  ) noexcept
  {
    return InitializeQueryTreeOwnerKeyCursor(cursor, keyLane, owner);
  }

  /**
   * Address: 0x00A524B0 (FUN_00A524B0)
   *
   * What it does:
   * Alternate lane that initializes one nil-`+0x11` query-tree key cursor
   * `(owner, key)`.
   */
  [[maybe_unused]] QueryTreeOwnerKeyCursorNil17* InitializeQueryTreeOwnerKeyCursorNil17LaneB(
    QueryTreeOwnerKeyCursorNil17* const cursor,
    const std::uint32_t keyLane,
    QueryTreeOwnerView<QueryTreeNodeKeyNil17>* const owner
  ) noexcept
  {
    return InitializeQueryTreeOwnerKeyCursor(cursor, keyLane, owner);
  }

  /**
   * Address: 0x00A52870 (FUN_00A52870)
   *
   * What it does:
   * Compares two nil-`+0x11` query-tree key cursors for key inequality after
   * verifying they refer to the same non-null owner lane.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil17NotEqualLaneA(
    const QueryTreeOwnerKeyCursorNil17* const lhs,
    const QueryTreeOwnerKeyCursorNil17* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsNotEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A52A40 (FUN_00A52A40)
   *
   * What it does:
   * Alternate lane of nil-`+0x11` query-tree key cursor inequality.
   */
  [[maybe_unused]] bool AreQueryTreeOwnerKeyCursorsNil17NotEqualLaneB(
    const QueryTreeOwnerKeyCursorNil17* const lhs,
    const QueryTreeOwnerKeyCursorNil17* const rhs
  ) noexcept
  {
    return AreQueryTreeOwnerKeyCursorsNotEqual(*lhs, *rhs);
  }

  /**
   * Address: 0x00A52AD0 (FUN_00A52AD0)
   *
   * What it does:
   * Resolves one packed query-word cursor into a dword lane pointer.
   */
  [[maybe_unused]] std::uint32_t* ResolveQueryWordCursorElementLaneA(
    const QueryWordCursorView* const cursor
  ) noexcept
  {
    return ResolveQueryWordCursorElement(*cursor);
  }

  /**
   * Address: 0x00A52B40 (FUN_00A52B40)
   *
   * What it does:
   * Alternate lane of packed query-word cursor element resolution.
   */
  [[maybe_unused]] std::uint32_t* ResolveQueryWordCursorElementLaneB(
    const QueryWordCursorView* const cursor
  ) noexcept
  {
    return ResolveQueryWordCursorElement(*cursor);
  }

  /**
   * Address: 0x00A52E70 (FUN_00A52E70)
   *
   * What it does:
   * Initializes one packed query-word cursor `(owner, wordIndex)` with
   * begin/end-inclusive range validation.
   */
  [[maybe_unused]] QueryWordCursorView* InitializeQueryWordCursorLaneA(
    QueryWordCursorView* const cursor,
    const std::uint32_t wordIndex,
    QueryWordChunkOwnerView* const owner
  ) noexcept
  {
    return InitializeQueryWordCursor(cursor, wordIndex, owner);
  }

  /**
   * Address: 0x00A52EB0 (FUN_00A52EB0)
   *
   * What it does:
   * Alternate lane that initializes one packed query-word cursor
   * `(owner, wordIndex)` with begin/end-inclusive range validation.
   */
  [[maybe_unused]] QueryWordCursorView* InitializeQueryWordCursorLaneB(
    QueryWordCursorView* const cursor,
    const std::uint32_t wordIndex,
    QueryWordChunkOwnerView* const owner
  ) noexcept
  {
    return InitializeQueryWordCursor(cursor, wordIndex, owner);
  }

  /**
   * Address: 0x00A52630 (FUN_00A52630)
   *
   * What it does:
   * Returns the right-most node in one query tree subtree that uses nil marker
   * byte offset `+0x11`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil17* QueryTreeRightmostNil17LaneC(QueryTreeNodeKeyNil17* const node) noexcept
  {
    return FindSubtreeRightmostFromRightChild(node);
  }

  /**
   * Address: 0x00A52650 (FUN_00A52650)
   *
   * What it does:
   * Returns the left-most node in one query tree subtree that uses nil marker
   * byte offset `+0x11`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil17* QueryTreeLeftmostNil17LaneC(QueryTreeNodeKeyNil17* const node) noexcept
  {
    return FindSubtreeLeftmostFromLeftChild(node);
  }

  /**
   * Address: 0x00A52680 (FUN_00A52680)
   *
   * What it does:
   * Alias lane of `QueryTreeRightmostNil17LaneC`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil17* QueryTreeRightmostNil17LaneD(QueryTreeNodeKeyNil17* const node) noexcept
  {
    return QueryTreeRightmostNil17LaneC(node);
  }

  /**
   * Address: 0x00A526A0 (FUN_00A526A0)
   *
   * What it does:
   * Alias lane of `QueryTreeLeftmostNil17LaneC`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil17* QueryTreeLeftmostNil17LaneD(QueryTreeNodeKeyNil17* const node) noexcept
  {
    return QueryTreeLeftmostNil17LaneC(node);
  }

  /**
   * Address: 0x00A52BD0 (FUN_00A52BD0)
   *
   * What it does:
   * Returns the right-most node in one query tree subtree that uses nil marker
   * byte offset `+0x21`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil33* QueryTreeRightmostNil33LaneA(QueryTreeNodeKeyNil33* const node) noexcept
  {
    return FindSubtreeRightmostFromRightChild(node);
  }

  /**
   * Address: 0x00A52BF0 (FUN_00A52BF0)
   *
   * What it does:
   * Returns the left-most node in one query tree subtree that uses nil marker
   * byte offset `+0x21`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil33* QueryTreeLeftmostNil33LaneA(QueryTreeNodeKeyNil33* const node) noexcept
  {
    return FindSubtreeLeftmostFromLeftChild(node);
  }

  /**
   * Address: 0x00A52D20 (FUN_00A52D20)
   *
   * What it does:
   * Alias lane of `QueryTreeRightmostNil33LaneA`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil33* QueryTreeRightmostNil33LaneB(QueryTreeNodeKeyNil33* const node) noexcept
  {
    return QueryTreeRightmostNil33LaneA(node);
  }

  /**
   * Address: 0x00A52D40 (FUN_00A52D40)
   *
   * What it does:
   * Alias lane of `QueryTreeLeftmostNil33LaneA`.
   */
  [[maybe_unused]] QueryTreeNodeKeyNil33* QueryTreeLeftmostNil33LaneB(QueryTreeNodeKeyNil33* const node) noexcept
  {
    return QueryTreeLeftmostNil33LaneA(node);
  }

  /**
   * Address: 0x00A59E20 (FUN_00A59E20)
   *
   * What it does:
   * Builds one equal-range iterator tuple `(owner, lower, owner, upper)` for a
   * dword-key query tree with nil marker byte offset `+0x11`.
   */
  [[maybe_unused]] QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17>* BuildQueryTreeEqualRangeNil17LaneA(
    QueryTreeOwnerView<QueryTreeNodeKeyNil17>* const tree,
    QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17>* const outRange,
    const std::uint32_t* const key
  ) noexcept
  {
    QueryTreeNodeKeyNil17* upperBound = tree->head;
    QueryTreeNodeKeyNil17* cursor = upperBound->parent;
    while (cursor->isNil == 0u) {
      if (*key >= cursor->key) {
        cursor = cursor->right;
      } else {
        upperBound = cursor;
        cursor = cursor->left;
      }
    }

    QueryTreeNodeKeyNil17* lowerBound = tree->head;
    cursor = lowerBound->parent;
    while (cursor->isNil == 0u) {
      if (cursor->key >= *key) {
        lowerBound = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }

    outRange->lowerBound = lowerBound;
    outRange->owner0 = tree;
    outRange->owner2 = tree;
    outRange->upperBound = upperBound;
    return outRange;
  }

  /**
   * Address: 0x00A59E80 (FUN_00A59E80)
   *
   * What it does:
   * Alias lane of `BuildQueryTreeEqualRangeNil17LaneA`.
   */
  [[maybe_unused]] QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17>* BuildQueryTreeEqualRangeNil17LaneB(
    QueryTreeOwnerView<QueryTreeNodeKeyNil17>* const tree,
    QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17>* const outRange,
    const std::uint32_t* const key
  ) noexcept
  {
    return BuildQueryTreeEqualRangeNil17LaneA(tree, outRange, key);
  }

  namespace
  {
    constexpr std::uint8_t kQueryTreeColorRed = 0u;
    constexpr std::uint8_t kQueryTreeColorBlack = 1u;

    template <class TNode>
    struct QueryTreeContainerWithSizeView
    {
      std::uint32_t lane00; // +0x00
      TNode* head;          // +0x04
      std::uint32_t size;   // +0x08
    };

    static_assert(
      sizeof(QueryTreeContainerWithSizeView<QueryTreeNodeKeyNil17>) == 0x0C,
      "QueryTreeContainerWithSizeView size must be 0x0C"
    );
    static_assert(
      offsetof(QueryTreeContainerWithSizeView<QueryTreeNodeKeyNil17>, head) == 0x04,
      "QueryTreeContainerWithSizeView::head offset must be 0x04"
    );
    static_assert(
      offsetof(QueryTreeContainerWithSizeView<QueryTreeNodeKeyNil17>, size) == 0x08,
      "QueryTreeContainerWithSizeView::size offset must be 0x08"
    );

    template <class TNode>
    [[nodiscard]] std::uint8_t& QueryTreeNodeColor(TNode* const node) noexcept
    {
      return reinterpret_cast<std::uint8_t*>(node)[0x10];
    }

    template <class TNode>
    [[nodiscard]] TNode* QueryTreeSubtreeMinimum(TNode* node) noexcept
    {
      while (node->left->isNil == 0u) {
        node = node->left;
      }
      return node;
    }

    template <class TNode>
    [[nodiscard]] TNode* QueryTreeSubtreeMaximum(TNode* node) noexcept
    {
      while (node->right->isNil == 0u) {
        node = node->right;
      }
      return node;
    }

    template <class TNode>
    [[nodiscard]] TNode* QueryTreeSuccessor(TNode* node, TNode* const head) noexcept
    {
      if (node->right->isNil == 0u) {
        return QueryTreeSubtreeMinimum(node->right);
      }

      TNode* parent = node->parent;
      while (parent->isNil == 0u && node == parent->right) {
        node = parent;
        parent = parent->parent;
      }
      return parent;
    }

    template <class TNode>
    void QueryTreeRotateLeft(QueryTreeContainerWithSizeView<TNode>* const tree, TNode* const pivot) noexcept
    {
      TNode* const head = tree->head;
      TNode* const replacement = pivot->right;

      pivot->right = replacement->left;
      if (replacement->left->isNil == 0u) {
        replacement->left->parent = pivot;
      }

      replacement->parent = pivot->parent;
      if (head->parent == pivot) {
        head->parent = replacement;
      } else if (pivot->parent->left == pivot) {
        pivot->parent->left = replacement;
      } else {
        pivot->parent->right = replacement;
      }

      replacement->left = pivot;
      pivot->parent = replacement;
    }

    template <class TNode>
    void QueryTreeRotateRight(QueryTreeContainerWithSizeView<TNode>* const tree, TNode* const pivot) noexcept
    {
      TNode* const head = tree->head;
      TNode* const replacement = pivot->left;

      pivot->left = replacement->right;
      if (replacement->right->isNil == 0u) {
        replacement->right->parent = pivot;
      }

      replacement->parent = pivot->parent;
      if (head->parent == pivot) {
        head->parent = replacement;
      } else if (pivot->parent->right == pivot) {
        pivot->parent->right = replacement;
      } else {
        pivot->parent->left = replacement;
      }

      replacement->right = pivot;
      pivot->parent = replacement;
    }

    template <class TNode>
    void QueryTreeRefreshBoundaryNodes(QueryTreeContainerWithSizeView<TNode>* const tree) noexcept
    {
      TNode* const head = tree->head;
      TNode* const root = head->parent;
      if (root->isNil != 0u) {
        head->left = head;
        head->right = head;
        return;
      }

      root->parent = head;
      head->left = QueryTreeSubtreeMinimum(root);
      head->right = QueryTreeSubtreeMaximum(root);
    }

    template <class TNode>
    void QueryTreeDeleteSubtreeNodes(TNode* const node) noexcept
    {
      if (node == nullptr || node->isNil != 0u) {
        return;
      }

      QueryTreeDeleteSubtreeNodes(node->right);
      QueryTreeDeleteSubtreeNodes(node->left);
      ::operator delete(node);
    }

    template <class TNode>
    void QueryTreeEraseSingleNode(
      QueryTreeContainerWithSizeView<TNode>* const tree,
      TNode* const erasedNode
    ) noexcept
    {
      TNode* const head = tree->head;
      TNode* nodeToDelete = erasedNode;
      TNode* fixNode = head;
      TNode* fixParent = head;

      if (erasedNode->left->isNil != 0u) {
        fixNode = erasedNode->right;
        fixParent = erasedNode->parent;
        if (fixNode->isNil == 0u) {
          fixNode->parent = fixParent;
        }

        if (head->parent == erasedNode) {
          head->parent = fixNode;
        } else if (fixParent->left == erasedNode) {
          fixParent->left = fixNode;
        } else {
          fixParent->right = fixNode;
        }
      } else if (erasedNode->right->isNil != 0u) {
        fixNode = erasedNode->left;
        fixParent = erasedNode->parent;
        if (fixNode->isNil == 0u) {
          fixNode->parent = fixParent;
        }

        if (head->parent == erasedNode) {
          head->parent = fixNode;
        } else if (fixParent->left == erasedNode) {
          fixParent->left = fixNode;
        } else {
          fixParent->right = fixNode;
        }
      } else {
        TNode* const successor = QueryTreeSubtreeMinimum(erasedNode->right);
        nodeToDelete = successor;
        fixNode = successor->right;

        if (successor == erasedNode->right) {
          fixParent = successor;
        } else {
          fixParent = successor->parent;
          if (fixNode->isNil == 0u) {
            fixNode->parent = fixParent;
          }

          fixParent->left = fixNode;
          successor->right = erasedNode->right;
          erasedNode->right->parent = successor;
        }

        if (head->parent == erasedNode) {
          head->parent = successor;
        } else if (erasedNode->parent->left == erasedNode) {
          erasedNode->parent->left = successor;
        } else {
          erasedNode->parent->right = successor;
        }

        successor->parent = erasedNode->parent;
        successor->left = erasedNode->left;
        erasedNode->left->parent = successor;

        const std::uint8_t successorColor = QueryTreeNodeColor(successor);
        QueryTreeNodeColor(successor) = QueryTreeNodeColor(erasedNode);
        QueryTreeNodeColor(erasedNode) = successorColor;
      }

      if (QueryTreeNodeColor(nodeToDelete) == kQueryTreeColorBlack) {
        while (fixNode != head->parent && QueryTreeNodeColor(fixNode) == kQueryTreeColorBlack) {
          if (fixNode == fixParent->left) {
            TNode* sibling = fixParent->right;
            if (QueryTreeNodeColor(sibling) == kQueryTreeColorRed) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorBlack;
              QueryTreeNodeColor(fixParent) = kQueryTreeColorRed;
              QueryTreeRotateLeft(tree, fixParent);
              sibling = fixParent->right;
            }

            if (sibling->isNil != 0u) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
              fixNode = fixParent;
              fixParent = fixParent->parent;
              continue;
            }

            if (QueryTreeNodeColor(sibling->left) == kQueryTreeColorBlack &&
                QueryTreeNodeColor(sibling->right) == kQueryTreeColorBlack) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
              fixNode = fixParent;
              fixParent = fixParent->parent;
            } else {
              if (QueryTreeNodeColor(sibling->right) == kQueryTreeColorBlack) {
                QueryTreeNodeColor(sibling->left) = kQueryTreeColorBlack;
                QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
                QueryTreeRotateRight(tree, sibling);
                sibling = fixParent->right;
              }

              QueryTreeNodeColor(sibling) = QueryTreeNodeColor(fixParent);
              QueryTreeNodeColor(fixParent) = kQueryTreeColorBlack;
              QueryTreeNodeColor(sibling->right) = kQueryTreeColorBlack;
              QueryTreeRotateLeft(tree, fixParent);
              break;
            }
          } else {
            TNode* sibling = fixParent->left;
            if (QueryTreeNodeColor(sibling) == kQueryTreeColorRed) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorBlack;
              QueryTreeNodeColor(fixParent) = kQueryTreeColorRed;
              QueryTreeRotateRight(tree, fixParent);
              sibling = fixParent->left;
            }

            if (sibling->isNil != 0u) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
              fixNode = fixParent;
              fixParent = fixParent->parent;
              continue;
            }

            if (QueryTreeNodeColor(sibling->right) == kQueryTreeColorBlack &&
                QueryTreeNodeColor(sibling->left) == kQueryTreeColorBlack) {
              QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
              fixNode = fixParent;
              fixParent = fixParent->parent;
            } else {
              if (QueryTreeNodeColor(sibling->left) == kQueryTreeColorBlack) {
                QueryTreeNodeColor(sibling->right) = kQueryTreeColorBlack;
                QueryTreeNodeColor(sibling) = kQueryTreeColorRed;
                QueryTreeRotateLeft(tree, sibling);
                sibling = fixParent->left;
              }

              QueryTreeNodeColor(sibling) = QueryTreeNodeColor(fixParent);
              QueryTreeNodeColor(fixParent) = kQueryTreeColorBlack;
              QueryTreeNodeColor(sibling->left) = kQueryTreeColorBlack;
              QueryTreeRotateRight(tree, fixParent);
              break;
            }
          }
        }

        QueryTreeNodeColor(fixNode) = kQueryTreeColorBlack;
      }

      ::operator delete(nodeToDelete);
      if (tree->size != 0u) {
        --tree->size;
      }

      QueryTreeRefreshBoundaryNodes(tree);
    }

    template <class TNode>
    [[nodiscard]] int QueryTreeCountNodesInRange(
      TNode* first,
      const TNode* const last,
      TNode* const head
    ) noexcept
    {
      int count = 0;
      while (first != last) {
        ++count;
        first = QueryTreeSuccessor(first, head);
      }
      return count;
    }

    template <class TNode>
    void QueryTreeEraseRange(
      QueryTreeContainerWithSizeView<TNode>* const tree,
      TNode* first,
      const TNode* const last
    ) noexcept
    {
      if (first == tree->head->left && last == tree->head) {
        QueryTreeDeleteSubtreeNodes(tree->head->parent);
        tree->head->parent = tree->head;
        tree->head->left = tree->head;
        tree->head->right = tree->head;
        tree->size = 0u;
        QueryTreeNodeColor(tree->head) = kQueryTreeColorBlack;
        return;
      }

      while (first != last) {
        TNode* const nodeToDelete = first;
        first = QueryTreeSuccessor(first, tree->head);
        QueryTreeEraseSingleNode(tree, nodeToDelete);
      }
    }
  } // namespace

  /**
   * Address: 0x00A65B60 (FUN_00A65B60)
   *
   * What it does:
   * Erases all nodes matching `*key` from one nil-`+0x11` query tree lane and
   * returns the number of erased nodes.
   */
  [[maybe_unused]] int EraseQueryTreeKeyRangeNil17LaneA(
    QueryTreeContainerWithSizeView<QueryTreeNodeKeyNil17>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    if (tree == nullptr || key == nullptr) {
      return 0;
    }

    QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17> range{};
    BuildQueryTreeEqualRangeNil17LaneA(
      reinterpret_cast<QueryTreeOwnerView<QueryTreeNodeKeyNil17>*>(tree),
      &range,
      key
    );

    const int erasedCount = QueryTreeCountNodesInRange(range.lowerBound, range.upperBound, tree->head);
    QueryTreeEraseRange(tree, range.lowerBound, range.upperBound);
    return erasedCount;
  }

  /**
   * Address: 0x00A65C10 (FUN_00A65C10)
   *
   * What it does:
   * Alternate lane of nil-`+0x11` query-tree erase-by-key; erases all nodes
   * matching `*key` and returns the number of erased nodes.
   */
  [[maybe_unused]] int EraseQueryTreeKeyRangeNil17LaneB(
    QueryTreeContainerWithSizeView<QueryTreeNodeKeyNil17>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    if (tree == nullptr || key == nullptr) {
      return 0;
    }

    QueryTreeEqualRangeResultView<QueryTreeNodeKeyNil17> range{};
    BuildQueryTreeEqualRangeNil17LaneB(
      reinterpret_cast<QueryTreeOwnerView<QueryTreeNodeKeyNil17>*>(tree),
      &range,
      key
    );

    const int erasedCount = QueryTreeCountNodesInRange(range.lowerBound, range.upperBound, tree->head);
    QueryTreeEraseRange(tree, range.lowerBound, range.upperBound);
    return erasedCount;
  }

  /**
   * Address: 0x00A5D060 (FUN_00A5D060)
   *
   * What it does:
   * Computes one `TRational<32>` divide-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<32>* DivideAssignRational32Normalized(
    TRational<32>* const value,
    const TRational<32>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<32> quotient = *value / *rhs;
    *value = quotient;
    return value;
  }

  /**
   * Address: 0x00A5D350 (FUN_00A5D350)
   *
   * What it does:
   * Computes one `TRational<64>` multiply-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<64>* MultiplyAssignRational64Normalized(
    TRational<64>* const value,
    const TRational<64>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<64> product = *value * *rhs;
    *value = product;
    return value;
  }

  /**
   * Address: 0x00A5D3C0 (FUN_00A5D3C0)
   *
   * What it does:
   * Computes one `TRational<64>` divide-assignment lane and normalizes the
   * result by removing powers of two.
   */
  [[maybe_unused]] TRational<64>* DivideAssignRational64Normalized(
    TRational<64>* const value,
    const TRational<64>* const rhs
  ) noexcept
  {
    if (value == nullptr || rhs == nullptr) {
      return value;
    }

    const TRational<64> quotient = *value / *rhs;
    *value = quotient;
    return value;
  }

  /**
   * Address: 0x00A5D810 (FUN_00A5D810)
   *
   * What it does:
   * Finds one exact dword-key node in a query tree with nil marker byte offset
   * `+0x21`; when not found, returns the tree head sentinel lane.
   */
  [[maybe_unused]] QueryTreeNodeLookupResultView<QueryTreeNodeKeyNil33>* FindExactQueryTreeNodeNil33LaneA(
    QueryTreeOwnerView<QueryTreeNodeKeyNil33>* const tree,
    QueryTreeNodeLookupResultView<QueryTreeNodeKeyNil33>* const outResult,
    const std::uint32_t* const key
  ) noexcept
  {
    QueryTreeNodeKeyNil33* candidate = tree->head;
    QueryTreeNodeKeyNil33* cursor = candidate->parent;
    while (cursor->isNil == 0u) {
      if (cursor->key >= *key) {
        candidate = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }

    outResult->owner = tree;
    if (candidate == tree->head || *key < candidate->key) {
      outResult->node = tree->head;
    } else {
      outResult->node = candidate;
    }
    return outResult;
  }

  /**
   * Address: 0x00A5D8A0 (FUN_00A5D8A0)
   *
   * What it does:
   * Alias lane of `FindExactQueryTreeNodeNil33LaneA`.
   */
  [[maybe_unused]] QueryTreeNodeLookupResultView<QueryTreeNodeKeyNil33>* FindExactQueryTreeNodeNil33LaneB(
    QueryTreeOwnerView<QueryTreeNodeKeyNil33>* const tree,
    QueryTreeNodeLookupResultView<QueryTreeNodeKeyNil33>* const outResult,
    const std::uint32_t* const key
  ) noexcept
  {
    return FindExactQueryTreeNodeNil33LaneA(tree, outResult, key);
  }

  struct HeapEntryFloatKey
  {
    float key;            // +0x00
    std::uint32_t payload; // +0x04
  };
  static_assert(sizeof(HeapEntryFloatKey) == 0x08, "HeapEntryFloatKey size must be 0x08");

  struct HeapEntryDoubleKeyPair
  {
    double key;           // +0x00
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
  };
  static_assert(sizeof(HeapEntryDoubleKeyPair) == 0x10, "HeapEntryDoubleKeyPair size must be 0x10");

  /**
   * Address: 0x00A72360 (FUN_00A72360)
   *
   * What it does:
   * Sifts one `{float key, dword payload}` heap lane upward between
   * `heapFloorIndex` and `insertIndex`, then writes the new lane.
   */
  [[maybe_unused]] std::uint32_t SiftUpHeapEntryFloatKeyLane(
    HeapEntryFloatKey* const heapEntries,
    std::int32_t insertIndex,
    const std::int32_t heapFloorIndex,
    const float key,
    const std::uint32_t payload
  ) noexcept
  {
    while (heapFloorIndex < insertIndex) {
      const std::int32_t parentIndex = (insertIndex - 1) / 2;
      if (heapEntries[parentIndex].key >= key) {
        break;
      }
      heapEntries[insertIndex] = heapEntries[parentIndex];
      insertIndex = parentIndex;
    }

    heapEntries[insertIndex].key = key;
    heapEntries[insertIndex].payload = payload;

    std::uint32_t keyBits = 0u;
    std::memcpy(&keyBits, &key, sizeof(keyBits));
    return keyBits;
  }

  /**
   * Address: 0x00A723D0 (FUN_00A723D0)
   *
   * What it does:
   * Sifts one `{double key, dword, dword}` heap lane upward between
   * `heapFloorIndex` and `insertIndex`, then writes the new lane.
   */
  [[maybe_unused]] std::uint32_t SiftUpHeapEntryDoubleKeyPairLane(
    HeapEntryDoubleKeyPair* const heapEntries,
    std::int32_t insertIndex,
    const std::int32_t heapFloorIndex,
    const double key,
    const std::uint32_t lane08,
    const std::uint32_t lane0C
  ) noexcept
  {
    while (heapFloorIndex < insertIndex) {
      const std::int32_t parentIndex = (insertIndex - 1) / 2;
      if (key <= heapEntries[parentIndex].key) {
        break;
      }
      heapEntries[insertIndex] = heapEntries[parentIndex];
      insertIndex = parentIndex;
    }

    heapEntries[insertIndex].key = key;
    heapEntries[insertIndex].lane08 = lane08;
    heapEntries[insertIndex].lane0C = lane0C;

    std::uint64_t keyBits = 0u;
    std::memcpy(&keyBits, &key, sizeof(keyBits));
    return static_cast<std::uint32_t>(keyBits >> 32);
  }

  /**
   * Address: 0x00A72990 (FUN_00A72990)
   *
   * What it does:
   * Sifts one `{double key, dword, dword}` heap hole down from
   * `heapFloorIndex`, then reinserts `insertionEntry` with the shared
   * sift-up lane to preserve binary max-heap ordering.
   */
  [[maybe_unused]] std::uint32_t SiftDownThenSiftUpHeapEntryDoubleKeyPairLane(
    HeapEntryDoubleKeyPair* const heapEntries,
    const std::int32_t heapFloorIndex,
    const std::int32_t heapCount,
    const HeapEntryDoubleKeyPair& insertionEntry
  ) noexcept
  {
    std::int32_t writeIndex = heapFloorIndex;
    std::int32_t childIndex = (heapFloorIndex * 2) + 2;
    while (childIndex < heapCount) {
      const std::int32_t leftChildIndex = childIndex - 1;
      if (heapEntries[leftChildIndex].key > heapEntries[childIndex].key) {
        childIndex = leftChildIndex;
      }

      heapEntries[writeIndex] = heapEntries[childIndex];
      writeIndex = childIndex;
      childIndex = (childIndex * 2) + 2;
    }

    if (childIndex == heapCount) {
      const std::int32_t leftOnlyChildIndex = heapCount - 1;
      heapEntries[writeIndex] = heapEntries[leftOnlyChildIndex];
      writeIndex = leftOnlyChildIndex;
    }

    return SiftUpHeapEntryDoubleKeyPairLane(
      heapEntries,
      writeIndex,
      heapFloorIndex,
      insertionEntry.key,
      insertionEntry.lane08,
      insertionEntry.lane0C
    );
  }

  /**
   * Address: 0x00A72B20 (FUN_00A72B20)
   *
   * What it does:
   * Pops one heap root lane into `outPoppedEntry`, then inserts
   * `insertionEntry` by routing through the shared double-key sift-down/sift-up
   * helper across the full `[begin, end)` heap range.
   */
  [[maybe_unused]] std::uint32_t PopHeapRootThenInsertHeapEntryDoubleKeyPairLane(
    HeapEntryDoubleKeyPair* const begin,
    HeapEntryDoubleKeyPair* const end,
    HeapEntryDoubleKeyPair* const outPoppedEntry,
    const HeapEntryDoubleKeyPair& insertionEntry
  ) noexcept
  {
    *outPoppedEntry = *begin;
    const std::int32_t heapCount = static_cast<std::int32_t>(end - begin);
    return SiftDownThenSiftUpHeapEntryDoubleKeyPairLane(begin, 0, heapCount, insertionEntry);
  }

  struct QueryCacheLaneRuntimeView
  {
    std::int32_t lane00 = 0;       // +0x00
    std::int32_t lane04 = 0;       // +0x04
    std::int32_t lane08 = 0;       // +0x08
    std::uint8_t reserved0C_17[0x0C]{};
    std::int32_t cachedResult = 0; // +0x18
    std::int32_t cachedKey = 0;    // +0x1C
  };
  static_assert(offsetof(QueryCacheLaneRuntimeView, cachedResult) == 0x18, "QueryCacheLaneRuntimeView::cachedResult offset must be 0x18");
  static_assert(offsetof(QueryCacheLaneRuntimeView, cachedKey) == 0x1C, "QueryCacheLaneRuntimeView::cachedKey offset must be 0x1C");

  using QueryCacheEvaluateFn =
    std::int32_t(__thiscall*)(void* evaluatorRuntime, std::int32_t key, std::int32_t lane00, std::int32_t lane04, std::int32_t lane08);

  /**
   * Address: 0x00A7D340 (FUN_00A7D340)
   *
   * What it does:
   * Re-evaluates one cached query lane when `key` changes, otherwise returns
   * the previously cached result.
   */
  [[maybe_unused]] std::int32_t QueryCacheUpdateAndGetLaneA(
    QueryCacheLaneRuntimeView* const cacheLane,
    const std::int32_t key,
    void* const evaluatorRuntime
  ) noexcept
  {
    if (key != cacheLane->cachedKey) {
      auto** const evaluatorVtable = *reinterpret_cast<void***>(evaluatorRuntime);
      const auto evaluate = reinterpret_cast<QueryCacheEvaluateFn>(evaluatorVtable[3]);
      cacheLane->cachedKey = key;
      cacheLane->cachedResult =
        evaluate(evaluatorRuntime, key, cacheLane->lane00, cacheLane->lane04, cacheLane->lane08);
    }
    return cacheLane->cachedResult;
  }

  /**
   * Address: 0x00A7D420 (FUN_00A7D420)
   *
   * What it does:
   * Alias lane of `QueryCacheUpdateAndGetLaneA`.
   */
  [[maybe_unused]] std::int32_t QueryCacheUpdateAndGetLaneB(
    QueryCacheLaneRuntimeView* const cacheLane,
    const std::int32_t key,
    void* const evaluatorRuntime
  ) noexcept
  {
    return QueryCacheUpdateAndGetLaneA(cacheLane, key, evaluatorRuntime);
  }

  struct TriplePointerSlotArrayView
  {
    std::uint8_t reserved00_0B[0x0C]{};
    void* slots[3]{};
  };
  static_assert(sizeof(TriplePointerSlotArrayView) == 0x18, "TriplePointerSlotArrayView size must be 0x18");
  static_assert(offsetof(TriplePointerSlotArrayView, slots) == 0x0C, "TriplePointerSlotArrayView::slots offset must be 0x0C");

  /**
   * Address: 0x00A7D3A0 (FUN_00A7D3A0)
   *
   * What it does:
   * Clears one owner slot and removes the same owner pointer from one
   * three-entry peer slot array; returns removed slot index or `-1`.
   */
  [[maybe_unused]] int RemoveOwnerFromTriplePointerSlotsLaneA(
    void* const ownerObject,
    const std::int32_t ownerSlotIndex,
    TriplePointerSlotArrayView* const peerSlots
  ) noexcept
  {
    auto* const ownerSlots = reinterpret_cast<void**>(static_cast<std::uint8_t*>(ownerObject) + 0x0Cu);
    ownerSlots[ownerSlotIndex] = nullptr;

    for (int slotIndex = 0; slotIndex < 3; ++slotIndex) {
      if (peerSlots->slots[slotIndex] == ownerObject) {
        peerSlots->slots[slotIndex] = nullptr;
        return slotIndex;
      }
    }

    return -1;
  }

  /**
   * Address: 0x00A7D480 (FUN_00A7D480)
   *
   * What it does:
   * Alias lane of `RemoveOwnerFromTriplePointerSlotsLaneA`.
   */
  [[maybe_unused]] int RemoveOwnerFromTriplePointerSlotsLaneB(
    void* const ownerObject,
    const std::int32_t ownerSlotIndex,
    TriplePointerSlotArrayView* const peerSlots
  ) noexcept
  {
    return RemoveOwnerFromTriplePointerSlotsLaneA(ownerObject, ownerSlotIndex, peerSlots);
  }

  namespace
  {
    struct RuntimeFloatLane04View
    {
      std::uint8_t reserved00_03[0x04]{};
      float lane04 = 0.0f; // +0x04
    };
    static_assert(offsetof(RuntimeFloatLane04View, lane04) == 0x04, "RuntimeFloatLane04View::lane04 offset must be 0x04");

    struct RuntimeDwordLane24_28View
    {
      std::uint8_t reserved00_23[0x24]{};
      std::uint32_t lane24 = 0; // +0x24
      std::uint32_t lane28 = 0; // +0x28
    };
    static_assert(offsetof(RuntimeDwordLane24_28View, lane24) == 0x24, "RuntimeDwordLane24_28View::lane24 offset must be 0x24");
    static_assert(offsetof(RuntimeDwordLane24_28View, lane28) == 0x28, "RuntimeDwordLane24_28View::lane28 offset must be 0x28");

    struct RuntimeDwordLane34_6CView
    {
      std::uint8_t reserved00_33[0x34]{};
      std::uint32_t lane34 = 0; // +0x34
      std::uint32_t lane38 = 0; // +0x38
      std::uint8_t reserved3C_67[0x2C]{};
      std::uint32_t lane68 = 0; // +0x68
      std::uint32_t lane6C = 0; // +0x6C
    };
    static_assert(offsetof(RuntimeDwordLane34_6CView, lane34) == 0x34, "RuntimeDwordLane34_6CView::lane34 offset must be 0x34");
    static_assert(offsetof(RuntimeDwordLane34_6CView, lane38) == 0x38, "RuntimeDwordLane34_6CView::lane38 offset must be 0x38");
    static_assert(offsetof(RuntimeDwordLane34_6CView, lane68) == 0x68, "RuntimeDwordLane34_6CView::lane68 offset must be 0x68");
    static_assert(offsetof(RuntimeDwordLane34_6CView, lane6C) == 0x6C, "RuntimeDwordLane34_6CView::lane6C offset must be 0x6C");

    struct RuntimeStride12EntryView
    {
      std::uint8_t payload[0x0C]{};
    };
    static_assert(sizeof(RuntimeStride12EntryView) == 0x0C, "RuntimeStride12EntryView size must be 0x0C");

    struct RuntimeStride24EntryView
    {
      std::uint8_t payload[0x18]{};
    };
    static_assert(sizeof(RuntimeStride24EntryView) == 0x18, "RuntimeStride24EntryView size must be 0x18");

    struct RuntimeStride12From24OwnerView
    {
      std::uint8_t reserved00_17[0x18]{};
      RuntimeStride12EntryView firstEntry{}; // +0x18
    };
    static_assert(offsetof(RuntimeStride12From24OwnerView, firstEntry) == 0x18, "RuntimeStride12From24OwnerView::firstEntry offset must be 0x18");

    struct RuntimeStride24From40OwnerView
    {
      std::uint8_t reserved00_27[0x28]{};
      RuntimeStride24EntryView firstEntry{}; // +0x28
    };
    static_assert(offsetof(RuntimeStride24From40OwnerView, firstEntry) == 0x28, "RuntimeStride24From40OwnerView::firstEntry offset must be 0x28");

    struct RuntimeStride24From48OwnerView
    {
      std::uint8_t reserved00_2F[0x30]{};
      RuntimeStride24EntryView firstEntry{}; // +0x30
    };
    static_assert(offsetof(RuntimeStride24From48OwnerView, firstEntry) == 0x30, "RuntimeStride24From48OwnerView::firstEntry offset must be 0x30");

    struct RuntimePayloadOffset20View
    {
      std::uint8_t reserved00_13[0x14]{};
      std::uint8_t payloadOffset20 = 0; // +0x14
    };
    static_assert(offsetof(RuntimePayloadOffset20View, payloadOffset20) == 0x14, "RuntimePayloadOffset20View::payloadOffset20 offset must be 0x14");

    struct RuntimePayloadOffset32View
    {
      std::uint8_t reserved00_1F[0x20]{};
      std::uint8_t payloadOffset32 = 0; // +0x20
    };
    static_assert(offsetof(RuntimePayloadOffset32View, payloadOffset32) == 0x20, "RuntimePayloadOffset32View::payloadOffset32 offset must be 0x20");

    struct RuntimePayloadOffset44View
    {
      std::uint8_t reserved00_2B[0x2C]{};
      std::uint8_t payloadOffset44 = 0; // +0x2C
    };
    static_assert(offsetof(RuntimePayloadOffset44View, payloadOffset44) == 0x2C, "RuntimePayloadOffset44View::payloadOffset44 offset must be 0x2C");

    struct RuntimePayloadOffset56View
    {
      std::uint8_t reserved00_37[0x38]{};
      std::uint8_t payloadOffset56 = 0; // +0x38
    };
    static_assert(offsetof(RuntimePayloadOffset56View, payloadOffset56) == 0x38, "RuntimePayloadOffset56View::payloadOffset56 offset must be 0x38");

    struct RuntimePayloadOffset64View
    {
      std::uint8_t reserved00_3F[0x40]{};
      std::uint8_t payloadOffset64 = 0; // +0x40
    };
    static_assert(offsetof(RuntimePayloadOffset64View, payloadOffset64) == 0x40, "RuntimePayloadOffset64View::payloadOffset64 offset must be 0x40");

    struct RuntimePayloadOffset88View
    {
      std::uint8_t reserved00_57[0x58]{};
      std::uint8_t payloadOffset88 = 0; // +0x58
    };
    static_assert(offsetof(RuntimePayloadOffset88View, payloadOffset88) == 0x58, "RuntimePayloadOffset88View::payloadOffset88 offset must be 0x58");

    struct FourDwordRuntimeLaneView
    {
      std::uint32_t lane00 = 0; // +0x00
      std::uint32_t lane04 = 0; // +0x04
      std::uint32_t lane08 = 0; // +0x08
      std::uint32_t lane0C = 0; // +0x0C
    };
    static_assert(sizeof(FourDwordRuntimeLaneView) == 0x10, "FourDwordRuntimeLaneView size must be 0x10");

    struct SingleDwordRuntimeView
    {
      std::uint32_t lane00 = 0; // +0x00
    };
    static_assert(sizeof(SingleDwordRuntimeView) == 0x04, "SingleDwordRuntimeView size must be 0x04");

    struct FourDwordRuntimeInputView
    {
      std::uint32_t lane00 = 0; // +0x00
      std::uint32_t lane04 = 0; // +0x04
      std::uint32_t lane08 = 0; // +0x08
      std::uint32_t lane0C = 0; // +0x0C
    };
    static_assert(sizeof(FourDwordRuntimeInputView) == 0x10, "FourDwordRuntimeInputView size must be 0x10");

    struct OneAndFourDwordRuntimeLaneView
    {
      std::uint32_t lane00 = 0; // +0x00
      std::uint32_t lane04 = 0; // +0x04
      std::uint32_t lane08 = 0; // +0x08
      std::uint32_t lane0C = 0; // +0x0C
      std::uint32_t lane10 = 0; // +0x10
    };
    static_assert(sizeof(OneAndFourDwordRuntimeLaneView) == 0x14, "OneAndFourDwordRuntimeLaneView size must be 0x14");

    struct TwoDwordRuntimeView
    {
      std::uint32_t lane00 = 0; // +0x00
      std::uint32_t lane04 = 0; // +0x04
    };
    static_assert(sizeof(TwoDwordRuntimeView) == 0x08, "TwoDwordRuntimeView size must be 0x08");

    struct ByteRuntimeView
    {
      std::uint8_t lane00 = 0; // +0x00
    };

    struct TwoDwordAndByteRuntimeView
    {
      std::uint32_t lane00 = 0; // +0x00
      std::uint32_t lane04 = 0; // +0x04
      std::uint8_t lane08 = 0;  // +0x08
      std::uint8_t reserved09_0B[0x03]{};
    };
    static_assert(offsetof(TwoDwordAndByteRuntimeView, lane08) == 0x08, "TwoDwordAndByteRuntimeView::lane08 offset must be 0x08");

    [[nodiscard]] RuntimeStride12EntryView* ResolveRuntimeStride12From24Entry(
      RuntimeStride12From24OwnerView* const runtime,
      const std::int32_t index
    ) noexcept
    {
      return &runtime->firstEntry + index;
    }

    [[nodiscard]] RuntimeStride24EntryView* ResolveRuntimeStride24From40Entry(
      RuntimeStride24From40OwnerView* const runtime,
      const std::int32_t index
    ) noexcept
    {
      return &runtime->firstEntry + index;
    }

    [[nodiscard]] RuntimeStride24EntryView* ResolveRuntimeStride24From48Entry(
      RuntimeStride24From48OwnerView* const runtime,
      const std::int32_t index
    ) noexcept
    {
      return &runtime->firstEntry + index;
    }

    [[nodiscard]] FourDwordRuntimeLaneView* InitializeFourDwordRuntimeLane(
      FourDwordRuntimeLaneView* const runtime,
      const std::uint32_t lane00,
      const std::uint32_t lane04,
      const std::uint32_t lane08,
      const std::uint32_t lane0C
    ) noexcept
    {
      runtime->lane00 = lane00;
      runtime->lane04 = lane04;
      runtime->lane08 = lane08;
      runtime->lane0C = lane0C;
      return runtime;
    }

    [[nodiscard]] TwoDwordAndByteRuntimeView* InitializeTwoDwordAndByteRuntimeLane(
      TwoDwordAndByteRuntimeView* const runtime,
      const TwoDwordRuntimeView* const sourcePair,
      const ByteRuntimeView* const sourceByte
    ) noexcept
    {
      runtime->lane00 = sourcePair->lane00;
      runtime->lane04 = sourcePair->lane04;
      runtime->lane08 = sourceByte->lane00;
      return runtime;
    }

    [[nodiscard]] OneAndFourDwordRuntimeLaneView* InitializeOneAndFourDwordRuntimeLane(
      OneAndFourDwordRuntimeLaneView* const runtime,
      const SingleDwordRuntimeView* const sourceLane00,
      const FourDwordRuntimeInputView* const sourceLane04To10
    ) noexcept
    {
      runtime->lane00 = sourceLane00->lane00;
      runtime->lane04 = sourceLane04To10->lane00;
      runtime->lane08 = sourceLane04To10->lane04;
      runtime->lane0C = sourceLane04To10->lane08;
      runtime->lane10 = sourceLane04To10->lane0C;
      return runtime;
    }
  } // namespace

  /**
   * Address: 0x00A45550 (FUN_00A45550)
   *
   * What it does:
   * Loads one single-precision runtime lane at `+0x04` and returns it as a
   * double-precision value.
   */
  [[maybe_unused]] double LoadRuntimeFloatOffset04AsDoubleLaneA(
    const RuntimeFloatLane04View* const runtime
  ) noexcept
  {
    return static_cast<double>(runtime->lane04);
  }

  /**
   * Address: 0x00A45760 (FUN_00A45760)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x34`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset34LaneA(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane34;
  }

  /**
   * Address: 0x00A45770 (FUN_00A45770)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x38`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset38LaneA(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane38;
  }

  /**
   * Address: 0x00A457B0 (FUN_00A457B0)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x68`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset68LaneA(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane68;
  }

  /**
   * Address: 0x00A457C0 (FUN_00A457C0)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset6CLaneA(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane6C;
  }

  /**
   * Address: 0x00A46370 (FUN_00A46370)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x24`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset24LaneA(
    const RuntimeDwordLane24_28View* const runtime
  ) noexcept
  {
    return runtime->lane24;
  }

  /**
   * Address: 0x00A46380 (FUN_00A46380)
   *
   * What it does:
   * Returns one indexed runtime entry lane at `this + 0x28 + index*0x18`.
   */
  [[maybe_unused]] RuntimeStride24EntryView* ResolveRuntimeEntryOffset40Stride24LaneA(
    RuntimeStride24From40OwnerView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return ResolveRuntimeStride24From40Entry(runtime, index);
  }

  /**
   * Address: 0x00A46970 (FUN_00A46970)
   *
   * What it does:
   * Alternate lane that loads one dword runtime value at owner offset `+0x24`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset24LaneB(
    const RuntimeDwordLane24_28View* const runtime
  ) noexcept
  {
    return runtime->lane24;
  }

  /**
   * Address: 0x00A46980 (FUN_00A46980)
   *
   * What it does:
   * Loads one dword runtime lane at owner offset `+0x28`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset28LaneA(
    const RuntimeDwordLane24_28View* const runtime
  ) noexcept
  {
    return runtime->lane28;
  }

  /**
   * Address: 0x00A46990 (FUN_00A46990)
   *
   * What it does:
   * Returns one indexed runtime entry lane at `this + 0x30 + index*0x18`.
   */
  [[maybe_unused]] RuntimeStride24EntryView* ResolveRuntimeEntryOffset48Stride24LaneA(
    RuntimeStride24From48OwnerView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return ResolveRuntimeStride24From48Entry(runtime, index);
  }

  /**
   * Address: 0x00A48060 (FUN_00A48060)
   *
   * What it does:
   * Alternate lane that loads one dword runtime value at owner offset `+0x34`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset34LaneB(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane34;
  }

  /**
   * Address: 0x00A48070 (FUN_00A48070)
   *
   * What it does:
   * Alternate lane that loads one dword runtime value at owner offset `+0x38`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset38LaneB(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane38;
  }

  /**
   * Address: 0x00A480B0 (FUN_00A480B0)
   *
   * What it does:
   * Alternate lane that loads one dword runtime value at owner offset `+0x68`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset68LaneB(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane68;
  }

  /**
   * Address: 0x00A480C0 (FUN_00A480C0)
   *
   * What it does:
   * Alternate lane that loads one dword runtime value at owner offset `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t LoadRuntimeDwordOffset6CLaneB(
    const RuntimeDwordLane34_6CView* const runtime
  ) noexcept
  {
    return runtime->lane6C;
  }

  /**
   * Address: 0x00A48A00 (FUN_00A48A00)
   *
   * What it does:
   * Reverses one contiguous byte span in place and returns the last front-side
   * byte value observed by the swap loop.
   */
  [[maybe_unused]] char ReverseByteSpanInPlaceLaneA(
    const std::int32_t byteCount,
    std::uint8_t* const bytes
  ) noexcept
  {
    const std::int32_t adjustedCount = byteCount - (byteCount >> 31);
    std::uint8_t returnByte = static_cast<std::uint8_t>(adjustedCount);
    const std::int32_t halfCount = adjustedCount >> 1;
    if (halfCount > 0) {
      std::uint8_t* tail = bytes + byteCount - 1;
      for (std::int32_t index = 0; index < halfCount; ++index, --tail) {
        returnByte = bytes[index];
        bytes[index] = *tail;
        *tail = returnByte;
      }
    }
    return static_cast<char>(returnByte);
  }

  /**
   * Address: 0x00A4E570 (FUN_00A4E570)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x14`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset20LaneA(
    RuntimePayloadOffset20View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset20);
  }

  /**
   * Address: 0x00A4E5A0 (FUN_00A4E5A0)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x20`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset32LaneA(
    RuntimePayloadOffset32View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset32);
  }

  /**
   * Address: 0x00A4FCB0 (FUN_00A4FCB0)
   *
   * What it does:
   * Returns one indexed runtime entry lane at `this + 0x18 + index*0x0C`.
   */
  [[maybe_unused]] RuntimeStride12EntryView* ResolveRuntimeEntryOffset24Stride12LaneA(
    RuntimeStride12From24OwnerView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return ResolveRuntimeStride12From24Entry(runtime, index);
  }

  /**
   * Address: 0x00A4FD80 (FUN_00A4FD80)
   *
   * What it does:
   * Alternate lane that returns one indexed runtime entry at
   * `this + 0x28 + index*0x18`.
   */
  [[maybe_unused]] RuntimeStride24EntryView* ResolveRuntimeEntryOffset40Stride24LaneB(
    RuntimeStride24From40OwnerView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    return ResolveRuntimeStride24From40Entry(runtime, index);
  }

  /**
   * Address: 0x00A6D2D0 (FUN_00A6D2D0)
   *
   * What it does:
   * Returns one row-relative payload pointer lane computed as
   * `rowBaseTable[rowIndex] + elementIndex * 4`.
   */
  [[maybe_unused]] std::uintptr_t ResolveRuntimeRowStride4AddressLane(
    const void* const runtimeOwner,
    const std::int32_t rowIndex,
    const std::int32_t elementIndex
  ) noexcept
  {
    struct RuntimeRowPointerArrayOwnerView
    {
      std::uint8_t reserved00_13[0x14]{};
      std::uintptr_t rowBaseTable = 0; // +0x14
    };
    static_assert(
      offsetof(RuntimeRowPointerArrayOwnerView, rowBaseTable) == 0x14,
      "RuntimeRowPointerArrayOwnerView::rowBaseTable offset must be 0x14"
    );

    const auto* const owner = static_cast<const RuntimeRowPointerArrayOwnerView*>(runtimeOwner);
    const auto* const rowBaseTable = reinterpret_cast<const std::uintptr_t*>(owner->rowBaseTable);
    const std::uintptr_t rowBase = rowBaseTable[rowIndex];
    const std::intptr_t elementByteOffset = static_cast<std::intptr_t>(elementIndex) * static_cast<std::intptr_t>(4);
    return static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rowBase) + elementByteOffset);
  }

  /**
   * Address: 0x00A6EDC0 (FUN_00A6EDC0)
   *
   * What it does:
   * Returns one row-relative payload pointer lane computed as
   * `rowBaseTable[rowIndex] + elementIndex * 8`.
   */
  [[maybe_unused]] std::uintptr_t ResolveRuntimeRowStride8AddressLane(
    const void* const runtimeOwner,
    const std::int32_t rowIndex,
    const std::int32_t elementIndex
  ) noexcept
  {
    struct RuntimeRowPointerArrayOwnerView
    {
      std::uint8_t reserved00_13[0x14]{};
      std::uintptr_t rowBaseTable = 0; // +0x14
    };
    static_assert(
      offsetof(RuntimeRowPointerArrayOwnerView, rowBaseTable) == 0x14,
      "RuntimeRowPointerArrayOwnerView::rowBaseTable offset must be 0x14"
    );

    const auto* const owner = static_cast<const RuntimeRowPointerArrayOwnerView*>(runtimeOwner);
    const auto* const rowBaseTable = reinterpret_cast<const std::uintptr_t*>(owner->rowBaseTable);
    const std::uintptr_t rowBase = rowBaseTable[rowIndex];
    const std::intptr_t elementByteOffset = static_cast<std::intptr_t>(elementIndex) * static_cast<std::intptr_t>(8);
    return static_cast<std::uintptr_t>(static_cast<std::intptr_t>(rowBase) + elementByteOffset);
  }

  /**
   * Address: 0x00A51EC0 (FUN_00A51EC0)
   *
   * What it does:
   * Initializes one four-dword runtime lane from four input dword lanes.
   */
  [[maybe_unused]] FourDwordRuntimeLaneView* InitializeFourDwordRuntimeLaneA(
    FourDwordRuntimeLaneView* const runtime,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint32_t lane0C
  ) noexcept
  {
    return InitializeFourDwordRuntimeLane(runtime, lane00, lane04, lane08, lane0C);
  }

  /**
   * Address: 0x00A51EE0 (FUN_00A51EE0)
   *
   * What it does:
   * Alternate lane that initializes one four-dword runtime lane.
   */
  [[maybe_unused]] FourDwordRuntimeLaneView* InitializeFourDwordRuntimeLaneB(
    FourDwordRuntimeLaneView* const runtime,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint32_t lane0C
  ) noexcept
  {
    return InitializeFourDwordRuntimeLane(runtime, lane00, lane04, lane08, lane0C);
  }

  /**
   * Address: 0x00A51F00 (FUN_00A51F00)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x2C`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset44LaneA(
    RuntimePayloadOffset44View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset44);
  }

  /**
   * Address: 0x00A51F10 (FUN_00A51F10)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x38`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset56LaneA(
    RuntimePayloadOffset56View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset56);
  }

  /**
   * Address: 0x00A51F40 (FUN_00A51F40)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x40`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset64LaneA(
    RuntimePayloadOffset64View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset64);
  }

  /**
   * Address: 0x00A51F50 (FUN_00A51F50)
   *
   * What it does:
   * Returns one runtime payload pointer lane at owner offset `+0x58`.
   */
  [[maybe_unused]] char* RuntimePayloadOffset88LaneA(
    RuntimePayloadOffset88View* const runtime
  ) noexcept
  {
    return reinterpret_cast<char*>(&runtime->payloadOffset88);
  }

  /**
   * Address: 0x00A520F0 (FUN_00A520F0)
   *
   * What it does:
   * Initializes one `{dword,dword,byte}` runtime lane from the two input
   * source lanes.
   */
  [[maybe_unused]] TwoDwordAndByteRuntimeView* InitializeTwoDwordAndByteRuntimeLaneA(
    TwoDwordAndByteRuntimeView* const runtime,
    const TwoDwordRuntimeView* const sourcePair,
    const ByteRuntimeView* const sourceByte
  ) noexcept
  {
    return InitializeTwoDwordAndByteRuntimeLane(runtime, sourcePair, sourceByte);
  }

  /**
   * Address: 0x00A521B0 (FUN_00A521B0)
   *
   * What it does:
   * Initializes one `{dword + four-dword}` runtime lane from two source
   * payload lanes.
   */
  [[maybe_unused]] OneAndFourDwordRuntimeLaneView* InitializeOneAndFourDwordRuntimeLaneA(
    OneAndFourDwordRuntimeLaneView* const runtime,
    const SingleDwordRuntimeView* const sourceLane00,
    const FourDwordRuntimeInputView* const sourceLane04To10
  ) noexcept
  {
    return InitializeOneAndFourDwordRuntimeLane(runtime, sourceLane00, sourceLane04To10);
  }

  /**
   * Address: 0x00A521E0 (FUN_00A521E0)
   *
   * What it does:
   * Alternate lane that initializes one `{dword,dword,byte}` runtime lane.
   */
  [[maybe_unused]] TwoDwordAndByteRuntimeView* InitializeTwoDwordAndByteRuntimeLaneB(
    TwoDwordAndByteRuntimeView* const runtime,
    const TwoDwordRuntimeView* const sourcePair,
    const ByteRuntimeView* const sourceByte
  ) noexcept
  {
    return InitializeTwoDwordAndByteRuntimeLane(runtime, sourcePair, sourceByte);
  }

  /**
   * Address: 0x00A522A0 (FUN_00A522A0)
   *
   * What it does:
   * Alternate lane that initializes one `{dword + four-dword}` runtime lane.
   */
  [[maybe_unused]] OneAndFourDwordRuntimeLaneView* InitializeOneAndFourDwordRuntimeLaneB(
    OneAndFourDwordRuntimeLaneView* const runtime,
    const SingleDwordRuntimeView* const sourceLane00,
    const FourDwordRuntimeInputView* const sourceLane04To10
  ) noexcept
  {
    return InitializeOneAndFourDwordRuntimeLane(runtime, sourceLane00, sourceLane04To10);
  }

  /**
   * Address: 0x00A522D0 (FUN_00A522D0)
   *
   * What it does:
   * Clears one single-dword runtime lane and returns that same lane pointer.
   */
  [[maybe_unused]] SingleDwordRuntimeView* ResetSingleDwordRuntimeLaneToZero(
    SingleDwordRuntimeView* const runtime
  ) noexcept
  {
    runtime->lane00 = 0;
    return runtime;
  }
} // namespace Wm3
