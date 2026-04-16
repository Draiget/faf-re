#include "Vector.h"
#include "String.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/ai/SAiReservedTransportBone.h"
#include "moho/ai/SPointVector.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/ui/SDebugScreenText.h"
#include "moho/ui/SDebugWorldText.h"
#include <cstring>
#include <intrin.h>
#include <limits>
#include <new>

extern "C" void __cdecl _invalid_parameter(
  const wchar_t* expression,
  const wchar_t* functionName,
  const wchar_t* fileName,
  unsigned int line,
  std::uintptr_t reserved
);

using namespace msvc8;

namespace msvc8::detail
{
namespace
{
struct VectorVoidStorageView
{
  void* proxy;
  void** first;
  void** last;
  void** end;
};

struct VectorDwordStorageView
{
  void* proxy;
  std::uint32_t* first;
  std::uint32_t* last;
  std::uint32_t* end;
};

struct VectorHeaderedStorageLaneView
{
  std::uint32_t lane00;
  std::uint32_t lane04;
  void* first;
  void* last;
  void* end;
};

struct VectorElement40StringLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  std::uint32_t lane2;
  msvc8::string text;
};

struct VectorElement84StringTripleLane
{
  msvc8::string lane0; // +0x00
  msvc8::string lane1; // +0x1C
  msvc8::string lane2; // +0x38
};

struct VectorElement12DwordTripleLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  std::uint32_t lane2;
};

struct VectorElement8DwordPairLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
};

constexpr std::uint32_t kLegacyVectorStorageGuard352Byte = 0x00BA2E8Bu;
constexpr std::uint32_t kLegacyVectorStorageGuard568Byte = 0x0073615Au;

struct VectorElementDwordBytePairLane
{
  std::uint32_t lane00;
  std::uint8_t lane04;
  std::uint8_t pad05[3];
};

struct VectorElement16DwordQuadLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  std::uint32_t lane2;
  std::uint32_t lane3;
};

struct VectorElement20DwordQuintLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  std::uint32_t lane2;
  std::uint32_t lane3;
  std::uint32_t lane4;
};

struct VectorElement28FloatSeptupleLane
{
  float lane0;
  float lane1;
  float lane2;
  float lane3;
  float lane4;
  float lane5;
  float lane6;
};

struct HeapElement12FloatKeyLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  float key;
};

struct VectorElementFloatTripleLane
{
  float x;
  float y;
  float z;
};

struct VectorElementFloatPairXZLane
{
  float x;
  float z;
};

struct VectorElementCountRuntimeView
{
  void* reservedProxy;
  std::byte* first;
  std::byte* last;
};

struct VectorElement12RefcountedLane
{
  std::uint32_t lane0;
  std::uint32_t lane1;
  volatile long* sharedControl;
};

struct VectorElementIteratorRuntimeView
{
  VectorElementCountRuntimeView* owner;
  std::byte* current;
};

struct VectorElement40DwordDecupleLane
{
  std::uint32_t lanes[10];
};

struct VectorElementStringTailLane
{
  msvc8::string text; // +0x00
  void* tailLane;     // +0x1C
};

struct VectorElementTripleWordStringTailFlagsLane
{
  std::uint32_t lane0; // +0x00
  std::uint32_t lane4; // +0x04
  std::uint32_t lane8; // +0x08
  msvc8::string text;  // +0x0C
  void* tailLane;      // +0x28
  std::uint8_t flag2C; // +0x2C
  std::uint8_t flag2D; // +0x2D
  std::uint8_t pad2E[2];
};

static_assert(sizeof(VectorVoidStorageView) == 0x10, "VectorVoidStorageView size must be 0x10");
static_assert(offsetof(VectorVoidStorageView, first) == 0x04, "VectorVoidStorageView::first offset must be 0x04");
static_assert(offsetof(VectorVoidStorageView, last) == 0x08, "VectorVoidStorageView::last offset must be 0x08");
static_assert(offsetof(VectorVoidStorageView, end) == 0x0C, "VectorVoidStorageView::end offset must be 0x0C");
static_assert(sizeof(VectorDwordStorageView) == 0x10, "VectorDwordStorageView size must be 0x10");
static_assert(offsetof(VectorDwordStorageView, first) == 0x04, "VectorDwordStorageView::first offset must be 0x04");
static_assert(offsetof(VectorDwordStorageView, last) == 0x08, "VectorDwordStorageView::last offset must be 0x08");
static_assert(offsetof(VectorDwordStorageView, end) == 0x0C, "VectorDwordStorageView::end offset must be 0x0C");
static_assert(sizeof(VectorHeaderedStorageLaneView) == 0x14, "VectorHeaderedStorageLaneView size must be 0x14");
static_assert(
  offsetof(VectorHeaderedStorageLaneView, first) == 0x08,
  "VectorHeaderedStorageLaneView::first offset must be 0x08"
);
static_assert(
  offsetof(VectorHeaderedStorageLaneView, last) == 0x0C,
  "VectorHeaderedStorageLaneView::last offset must be 0x0C"
);
static_assert(
  offsetof(VectorHeaderedStorageLaneView, end) == 0x10,
  "VectorHeaderedStorageLaneView::end offset must be 0x10"
);
static_assert(sizeof(VectorElement40StringLane) == 0x28, "VectorElement40StringLane size must be 0x28");
static_assert(sizeof(VectorElement84StringTripleLane) == 0x54, "VectorElement84StringTripleLane size must be 0x54");
static_assert(
  offsetof(VectorElement84StringTripleLane, lane1) == 0x1C,
  "VectorElement84StringTripleLane::lane1 offset must be 0x1C"
);
static_assert(
  offsetof(VectorElement84StringTripleLane, lane2) == 0x38,
  "VectorElement84StringTripleLane::lane2 offset must be 0x38"
);
static_assert(sizeof(VectorElement12DwordTripleLane) == 0x0C, "VectorElement12DwordTripleLane size must be 0x0C");
static_assert(sizeof(VectorElement8DwordPairLane) == 0x08, "VectorElement8DwordPairLane size must be 0x08");
static_assert(sizeof(VectorElementDwordBytePairLane) == 0x08, "VectorElementDwordBytePairLane size must be 0x08");
static_assert(
  offsetof(VectorElementDwordBytePairLane, lane04) == 0x04,
  "VectorElementDwordBytePairLane::lane04 offset must be 0x04"
);
static_assert(sizeof(VectorElement16DwordQuadLane) == 0x10, "VectorElement16DwordQuadLane size must be 0x10");
static_assert(sizeof(VectorElement20DwordQuintLane) == 0x14, "VectorElement20DwordQuintLane size must be 0x14");
static_assert(sizeof(VectorElement28FloatSeptupleLane) == 0x1C, "VectorElement28FloatSeptupleLane size must be 0x1C");
static_assert(sizeof(HeapElement12FloatKeyLane) == 0x0C, "HeapElement12FloatKeyLane size must be 0x0C");
static_assert(sizeof(VectorElementFloatTripleLane) == 0x0C, "VectorElementFloatTripleLane size must be 0x0C");
static_assert(sizeof(VectorElementFloatPairXZLane) == 0x08, "VectorElementFloatPairXZLane size must be 0x08");
static_assert(sizeof(VectorElementCountRuntimeView) == 0x0C, "VectorElementCountRuntimeView size must be 0x0C");
static_assert(offsetof(VectorElementCountRuntimeView, first) == 0x04, "VectorElementCountRuntimeView::first offset must be 0x04");
static_assert(offsetof(VectorElementCountRuntimeView, last) == 0x08, "VectorElementCountRuntimeView::last offset must be 0x08");
static_assert(sizeof(VectorElement12RefcountedLane) == 0x0C, "VectorElement12RefcountedLane size must be 0x0C");
static_assert(sizeof(VectorElementIteratorRuntimeView) == 0x08, "VectorElementIteratorRuntimeView size must be 0x08");
static_assert(sizeof(VectorElement40DwordDecupleLane) == 0x28, "VectorElement40DwordDecupleLane size must be 0x28");
static_assert(sizeof(VectorElementStringTailLane) == 0x20, "VectorElementStringTailLane size must be 0x20");
static_assert(offsetof(VectorElementStringTailLane, tailLane) == 0x1C, "VectorElementStringTailLane::tailLane offset must be 0x1C");
static_assert(
  offsetof(VectorElementTripleWordStringTailFlagsLane, text) == 0x0C,
  "VectorElementTripleWordStringTailFlagsLane::text offset must be 0x0C"
);
static_assert(
  offsetof(VectorElementTripleWordStringTailFlagsLane, tailLane) == 0x28,
  "VectorElementTripleWordStringTailFlagsLane::tailLane offset must be 0x28"
);
static_assert(
  offsetof(VectorElementTripleWordStringTailFlagsLane, flag2C) == 0x2C,
  "VectorElementTripleWordStringTailFlagsLane::flag2C offset must be 0x2C"
);
static_assert(
  offsetof(VectorElementTripleWordStringTailFlagsLane, flag2D) == 0x2D,
  "VectorElementTripleWordStringTailFlagsLane::flag2D offset must be 0x2D"
);
static_assert(
  sizeof(VectorElementTripleWordStringTailFlagsLane) == 0x30,
  "VectorElementTripleWordStringTailFlagsLane size must be 0x30"
);

[[nodiscard]] void* AllocateCheckedElementBlock(const std::uint32_t count, const std::uint32_t elementSize)
{
  if (elementSize == 0u || count > (std::numeric_limits<std::uint32_t>::max() / elementSize)) {
    throw std::bad_alloc{};
  }

  const std::size_t byteCount = static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize);
  return ::operator new(byteCount);
}

inline void ReportVectorInvalidParameter() noexcept
{
  _invalid_parameter(nullptr, nullptr, nullptr, 0u, 0u);
}

[[nodiscard]] int CheckedVectorElementIteratorDistance(
  const VectorElementIteratorRuntimeView* const left,
  const VectorElementIteratorRuntimeView* const right,
  const std::size_t elementSize
) noexcept
{
  if (left->owner == nullptr || left->owner != right->owner) {
    ReportVectorInvalidParameter();
  }

  const std::ptrdiff_t byteDistance = left->current - right->current;
  return static_cast<int>(byteDistance / static_cast<std::ptrdiff_t>(elementSize));
}

[[nodiscard]] std::byte* CheckedVectorElementAtIndex(
  const VectorElementCountRuntimeView* const storage,
  const std::uint32_t index,
  const std::size_t elementSize
) noexcept
{
  std::byte* const begin = storage->first;
  if (begin == nullptr) {
    ReportVectorInvalidParameter();
  }

  const std::uint32_t size = static_cast<std::uint32_t>((storage->last - begin) / static_cast<std::ptrdiff_t>(elementSize));
  if (index >= size) {
    ReportVectorInvalidParameter();
  }

  return begin + (static_cast<std::size_t>(index) * elementSize);
}

[[nodiscard]] VectorElementIteratorRuntimeView* InitializeVectorElementIteratorChecked(
  VectorElementIteratorRuntimeView* const iterator,
  const std::byte* const position,
  VectorElementCountRuntimeView* const owner
) noexcept
{
  iterator->owner = nullptr;
  if (owner == nullptr || owner->first > position || position > owner->last) {
    ReportVectorInvalidParameter();
  }

  iterator->owner = owner;
  iterator->current = const_cast<std::byte*>(position);
  return iterator;
}

[[nodiscard]] VectorElementIteratorRuntimeView* InitializeVectorElementIteratorAtBeginChecked(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  iterator->owner = nullptr;
  if (owner->first > owner->last) {
    ReportVectorInvalidParameter();
  }

  iterator->owner = owner;
  iterator->current = owner->first;
  return iterator;
}

[[nodiscard]] VectorElementIteratorRuntimeView* InitializeVectorElementIteratorAtEndChecked(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  iterator->owner = nullptr;
  if (owner->first > owner->last) {
    ReportVectorInvalidParameter();
  }

  iterator->owner = owner;
  iterator->current = owner->last;
  return iterator;
}
} // namespace

/**
 * Address: 0x004FB510 (FUN_004FB510)
 *
 * What it does:
 * Copies one half-open range of 0x28-byte elements with `{dword,dword,dword,
 * string}` layout and returns one-past-last destination slot.
 */
[[maybe_unused]] [[nodiscard]] VectorElement40StringLane* CopyVectorElement40StringRange(
  VectorElement40StringLane* destinationBegin,
  const VectorElement40StringLane* sourceBegin,
  const VectorElement40StringLane* sourceEnd
)
{
  VectorElement40StringLane* destination = destinationBegin;
  for (const VectorElement40StringLane* source = sourceBegin; source != sourceEnd; ++source, ++destination) {
    destination->lane0 = source->lane0;
    destination->lane1 = source->lane1;
    destination->lane2 = source->lane2;
    destination->text = source->text;
  }

  return destination;
}

/**
 * Address: 0x004FB190 (FUN_004FB190)
 * Address: 0x008A9B10 (FUN_008A9B10)
 *
 * What it does:
 * Adapts one register-lane caller shape into the canonical
 * `CopyVectorElement40StringRange(destination, begin, end)` helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement40StringLane* CopyVectorElement40StringRangeRegisterAdapter(
  const VectorElement40StringLane* const sourceBegin,
  const VectorElement40StringLane* const sourceEnd,
  VectorElement40StringLane* const destinationBegin
)
{
  return CopyVectorElement40StringRange(destinationBegin, sourceBegin, sourceEnd);
}

/**
 * Address: 0x004D5390 (FUN_004D5390)
 *
 * What it does:
 * Fills one half-open 0x54-byte triple-string range `[destinationBegin,
 * destinationEnd)` by assigning all three `msvc8::string` lanes from
 * `sourceTriple`.
 */
[[maybe_unused]] [[nodiscard]] msvc8::string* FillStringTripleRangeFromSingle(
  VectorElement84StringTripleLane* destinationBegin,
  VectorElement84StringTripleLane* const destinationEnd,
  const VectorElement84StringTripleLane* const sourceTriple
)
{
  auto* destination = destinationBegin;
  msvc8::string* result = reinterpret_cast<msvc8::string*>(destinationBegin);
  while (destination != destinationEnd) {
    destination->lane0.assign(sourceTriple->lane0, 0u, msvc8::string::npos);
    destination->lane1.assign(sourceTriple->lane1, 0u, msvc8::string::npos);
    result = &destination->lane2.assign(sourceTriple->lane2, 0u, msvc8::string::npos);
    ++destination;
  }

  return result;
}

/**
 * Address: 0x004D5AD0 (FUN_004D5AD0)
 *
 * What it does:
 * Copies one reverse-walk 0x54-byte triple-string range from
 * `[sourceBegin,sourceEnd)` into the destination tail ending at
 * `destinationEnd` and returns the resulting destination-begin lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement84StringTripleLane* CopyStringTripleRangeBackward(
  const VectorElement84StringTripleLane* sourceBegin,
  const VectorElement84StringTripleLane* sourceEnd,
  VectorElement84StringTripleLane* destinationEnd
)
{
  if (sourceBegin == sourceEnd) {
    return destinationEnd;
  }

  auto* destination = destinationEnd;
  const VectorElement84StringTripleLane* source = sourceEnd;
  do {
    --source;
    --destination;
    destination->lane0.assign(source->lane0, 0u, msvc8::string::npos);
    destination->lane1.assign(source->lane1, 0u, msvc8::string::npos);
    destination->lane2.assign(source->lane2, 0u, msvc8::string::npos);
  } while (source != sourceBegin);

  return destination;
}

/**
 * Address: 0x004D4F60 (FUN_004D4F60)
 * Address: 0x004D5400 (FUN_004D5400)
 *
 * What it does:
 * Bridges legacy masked-register wrapper lanes into the canonical
 * triple-string reverse-copy helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement84StringTripleLane* CopyStringTripleRangeBackwardRegisterAdapter(
  const VectorElement84StringTripleLane* const sourceBegin,
  const VectorElement84StringTripleLane* const sourceEnd,
  const std::uint32_t /*unusedMaskedLane*/,
  VectorElement84StringTripleLane* const destinationEnd
)
{
  return CopyStringTripleRangeBackward(sourceBegin, sourceEnd, destinationEnd);
}

/**
 * Address: 0x00653BC0 (FUN_00653BC0)
 *
 * What it does:
 * Copy-assigns one contiguous `SDebugWorldText` range `[sourceBegin,
 * sourceEnd)` into destination storage and returns the advanced destination
 * cursor.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugWorldText* CopyDebugWorldTextRangeForward(
  moho::SDebugWorldText* destinationBegin,
  const moho::SDebugWorldText* sourceBegin,
  const moho::SDebugWorldText* sourceEnd
) noexcept
{
  moho::SDebugWorldText* destinationCursor = destinationBegin;
  const moho::SDebugWorldText* sourceCursor = sourceBegin;
  while (sourceCursor != sourceEnd) {
    destinationCursor->position.x = sourceCursor->position.x;
    destinationCursor->position.y = sourceCursor->position.y;
    destinationCursor->position.z = sourceCursor->position.z;
    destinationCursor->text.assign(sourceCursor->text, 0u, msvc8::string::npos);
    destinationCursor->style = sourceCursor->style;
    destinationCursor->depth = sourceCursor->depth;
    ++destinationCursor;
    ++sourceCursor;
  }

  return destinationCursor;
}

/**
 * Address: 0x00653A10 (FUN_00653A10)
 *
 * What it does:
 * Forwarding adapter lane into `CopyDebugWorldTextRangeForward`.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugWorldText* CopyDebugWorldTextRangeForwardAdapterA(
  moho::SDebugWorldText* const destinationBegin,
  const moho::SDebugWorldText* const sourceBegin,
  const moho::SDebugWorldText* const sourceEnd
) noexcept
{
  return CopyDebugWorldTextRangeForward(destinationBegin, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00653E80 (FUN_00653E80)
 *
 * What it does:
 * Copy-assigns one contiguous `SDebugWorldText` range in reverse order from
 * `(sourceBegin, sourceEnd]` into `(destinationBegin, destinationEnd]` and
 * returns the rewound destination cursor.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugWorldText* CopyDebugWorldTextRangeBackward(
  moho::SDebugWorldText* destinationEnd,
  const moho::SDebugWorldText* sourceEnd,
  const moho::SDebugWorldText* sourceBegin
) noexcept
{
  moho::SDebugWorldText* destinationCursor = destinationEnd;
  const moho::SDebugWorldText* sourceCursor = sourceEnd;
  while (sourceCursor != sourceBegin) {
    --destinationCursor;
    --sourceCursor;
    destinationCursor->position.x = sourceCursor->position.x;
    destinationCursor->position.y = sourceCursor->position.y;
    destinationCursor->position.z = sourceCursor->position.z;
    destinationCursor->text.assign(sourceCursor->text, 0u, msvc8::string::npos);
    destinationCursor->style = sourceCursor->style;
    destinationCursor->depth = sourceCursor->depth;
  }

  return destinationCursor;
}

/**
 * Address: 0x0064FA40 (FUN_0064FA40)
 *
 * What it does:
 * Copy-assigns one contiguous `SDebugScreenText` range `[sourceBegin,
 * sourceEnd)` into destination storage and returns the advanced destination
 * cursor.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugScreenText* CopyDebugScreenTextRangeForward(
  moho::SDebugScreenText* destinationBegin,
  const moho::SDebugScreenText* sourceBegin,
  const moho::SDebugScreenText* sourceEnd
) noexcept
{
  moho::SDebugScreenText* destinationCursor = destinationBegin;
  const moho::SDebugScreenText* sourceCursor = sourceBegin;
  while (sourceCursor != sourceEnd) {
    destinationCursor->origin.x = sourceCursor->origin.x;
    destinationCursor->origin.y = sourceCursor->origin.y;
    destinationCursor->origin.z = sourceCursor->origin.z;
    destinationCursor->xAxis.x = sourceCursor->xAxis.x;
    destinationCursor->xAxis.y = sourceCursor->xAxis.y;
    destinationCursor->xAxis.z = sourceCursor->xAxis.z;
    destinationCursor->yAxis.x = sourceCursor->yAxis.x;
    destinationCursor->yAxis.y = sourceCursor->yAxis.y;
    destinationCursor->yAxis.z = sourceCursor->yAxis.z;
    destinationCursor->text.assign(sourceCursor->text, 0u, msvc8::string::npos);
    destinationCursor->pointSize = sourceCursor->pointSize;
    destinationCursor->color = sourceCursor->color;
    ++destinationCursor;
    ++sourceCursor;
  }

  return destinationCursor;
}

/**
 * Address: 0x0064F750 (FUN_0064F750)
 *
 * What it does:
 * Forwarding adapter lane into `CopyDebugScreenTextRangeForward`.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugScreenText* CopyDebugScreenTextRangeForwardAdapterA(
  moho::SDebugScreenText* const destinationBegin,
  const moho::SDebugScreenText* const sourceBegin,
  const moho::SDebugScreenText* const sourceEnd
) noexcept
{
  return CopyDebugScreenTextRangeForward(destinationBegin, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0064FFB0 (FUN_0064FFB0)
 *
 * What it does:
 * Copy-assigns one contiguous `SDebugScreenText` range in reverse order from
 * `(sourceBegin, sourceEnd]` into `(destinationBegin, destinationEnd]` and
 * returns the rewound destination cursor.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugScreenText* CopyDebugScreenTextRangeBackward(
  moho::SDebugScreenText* destinationEnd,
  const moho::SDebugScreenText* sourceEnd,
  const moho::SDebugScreenText* sourceBegin
) noexcept
{
  moho::SDebugScreenText* destinationCursor = destinationEnd;
  const moho::SDebugScreenText* sourceCursor = sourceEnd;
  while (sourceCursor != sourceBegin) {
    --destinationCursor;
    --sourceCursor;
    destinationCursor->origin.x = sourceCursor->origin.x;
    destinationCursor->origin.y = sourceCursor->origin.y;
    destinationCursor->origin.z = sourceCursor->origin.z;
    destinationCursor->xAxis.x = sourceCursor->xAxis.x;
    destinationCursor->xAxis.y = sourceCursor->xAxis.y;
    destinationCursor->xAxis.z = sourceCursor->xAxis.z;
    destinationCursor->yAxis.x = sourceCursor->yAxis.x;
    destinationCursor->yAxis.y = sourceCursor->yAxis.y;
    destinationCursor->yAxis.z = sourceCursor->yAxis.z;
    destinationCursor->text.assign(sourceCursor->text, 0u, msvc8::string::npos);
    destinationCursor->pointSize = sourceCursor->pointSize;
    destinationCursor->color = sourceCursor->color;
  }

  return destinationCursor;
}

/**
 * Address: 0x0064FAC0 (FUN_0064FAC0)
 *
 * What it does:
 * Register-order adapter lane that forwards one backward screen-text copy
 * range into `CopyDebugScreenTextRangeBackward`.
 */
[[maybe_unused]] [[nodiscard]] moho::SDebugScreenText* CopyDebugScreenTextRangeBackwardAdapterA(
  const moho::SDebugScreenText* const sourceBegin,
  const moho::SDebugScreenText* const sourceEnd,
  moho::SDebugScreenText* const destinationEnd
) noexcept
{
  return CopyDebugScreenTextRangeBackward(destinationEnd, sourceEnd, sourceBegin);
}

/**
 * Address: 0x004D6750 (FUN_004D6750)
 *
 * What it does:
 * Copies one reverse-walk 0x54-byte triple-string range from
 * `[sourceBegin,sourceEnd)` into the destination tail ending at
 * `destinationEnd`, stores the resulting destination-begin lane in
 * `outDestinationBegin`, and returns the output slot.
 */
[[maybe_unused]] [[nodiscard]] VectorElement84StringTripleLane** CopyStringTripleRangeBackwardAndStoreBegin(
  VectorElement84StringTripleLane** const outDestinationBegin,
  const VectorElement84StringTripleLane* const sourceBegin,
  const VectorElement84StringTripleLane* sourceEnd,
  VectorElement84StringTripleLane* destinationEnd
)
{
  if (sourceBegin == sourceEnd) {
    *outDestinationBegin = destinationEnd;
    return outDestinationBegin;
  }

  auto* destination = destinationEnd;
  const VectorElement84StringTripleLane* source = sourceEnd;
  do {
    --source;
    --destination;
    destination->lane0.assign(source->lane0, 0u, msvc8::string::npos);
    destination->lane1.assign(source->lane1, 0u, msvc8::string::npos);
    destination->lane2.assign(source->lane2, 0u, msvc8::string::npos);
  } while (source != sourceBegin);

  *outDestinationBegin = destination;
  return outDestinationBegin;
}

/**
 * Address: 0x004D4F50 (FUN_004D4F50)
 *
 * What it does:
 * Register-shape adapter for one triple-string fill lane dispatch into
 * `FillStringTripleRangeFromSingle`.
 */
[[maybe_unused]] [[nodiscard]] msvc8::string* FillStringTripleRangeFromSingleRegisterAdapter(
  const VectorElement84StringTripleLane* const sourceTriple,
  VectorElement84StringTripleLane* const destinationBegin,
  VectorElement84StringTripleLane* const destinationEnd
)
{
  return FillStringTripleRangeFromSingle(destinationBegin, destinationEnd, sourceTriple);
}

/**
 * Address: 0x004D6430 (FUN_004D6430)
 *
 * What it does:
 * Register-shape adapter that forwards one triple-string reverse-copy lane and
 * returns the caller output-slot pointer.
 */
[[maybe_unused]] [[nodiscard]] VectorElement84StringTripleLane** CopyStringTripleRangeBackwardAndStoreBeginRegisterAdapter(
  VectorElement84StringTripleLane** const outDestinationBegin,
  const VectorElement84StringTripleLane* const sourceBegin,
  const VectorElement84StringTripleLane* const sourceEnd,
  VectorElement84StringTripleLane* const destinationEnd
)
{
  (void)CopyStringTripleRangeBackwardAndStoreBegin(outDestinationBegin, sourceBegin, sourceEnd, destinationEnd);
  return outDestinationBegin;
}

/**
 * Address: 0x005347F0 (FUN_005347F0)
 * Address: 0x00534820 (FUN_00534820)
 * Address: 0x00534850 (FUN_00534850)
 * Address: 0x00534880 (FUN_00534880)
 * Address: 0x005348B0 (FUN_005348B0)
 * Address: 0x005348E0 (FUN_005348E0)
 * Address: 0x00534910 (FUN_00534910)
 *
 * What it does:
 * Reinitializes one legacy string lane to empty SSO state, copy-assigns text
 * from `sourceText`, and stores one caller-provided tail pointer lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElementStringTailLane* InitializeVectorElementStringTailLane(
  VectorElementStringTailLane* const destination,
  const msvc8::string* const sourceText,
  void* const* const tailLaneSlot
) noexcept
{
  destination->text.mySize = 0u;
  destination->text.myRes = 15u;
  destination->text.bx.buf[0] = '\0';
  destination->text.assign(*sourceText, 0u, msvc8::string::npos);
  destination->tailLane = *tailLaneSlot;
  return destination;
}

/**
 * Address: 0x005366A0 (FUN_005366A0)
 * Address: 0x005366E0 (FUN_005366E0)
 * Address: 0x00536720 (FUN_00536720)
 * Address: 0x00536760 (FUN_00536760)
 * Address: 0x005367A0 (FUN_005367A0)
 * Address: 0x005367E0 (FUN_005367E0)
 *
 * What it does:
 * Initializes one `{3 dword, string, tail, 2 flags}` lane record by copying
 * scalar header lanes, assigning text from `sourceText`, inheriting the source
 * tail lane at `+0x1C`, and zeroing trailing flags.
 */
[[maybe_unused]] [[nodiscard]] VectorElementTripleWordStringTailFlagsLane* InitializeVectorElementTripleWordStringTailFlagsLane(
  const std::uint32_t lane0,
  const std::uint32_t lane8,
  const std::uint32_t lane4,
  VectorElementTripleWordStringTailFlagsLane* const destination,
  const msvc8::string* const sourceText
) noexcept
{
  destination->lane4 = lane4;
  destination->lane0 = lane0;
  destination->lane8 = lane8;
  destination->text.mySize = 0u;
  destination->text.myRes = 15u;
  destination->text.bx.buf[0] = '\0';
  destination->text.assign(*sourceText, 0u, msvc8::string::npos);
  destination->tailLane = reinterpret_cast<const VectorElementStringTailLane*>(sourceText)->tailLane;
  destination->flag2C = 0u;
  destination->flag2D = 0u;
  return destination;
}

/**
 * Address: 0x005459D0 (FUN_005459D0)
 *
 * What it does:
 * Initializes one 20-byte `{dword x5}` lane by copying four source dwords and
 * writing one explicit caller-provided tail dword.
 */
[[maybe_unused]] [[nodiscard]] VectorElement20DwordQuintLane* InitializeDwordQuintLaneWithTailWord(
  VectorElement20DwordQuintLane* const destination,
  const VectorElement16DwordQuadLane* const sourceHead,
  const std::uint32_t tailWord
) noexcept
{
  destination->lane0 = sourceHead->lane0;
  destination->lane1 = sourceHead->lane1;
  destination->lane2 = sourceHead->lane2;
  destination->lane3 = sourceHead->lane3;
  destination->lane4 = tailWord;
  return destination;
}

/**
 * Address: 0x00545A30 (FUN_00545A30)
 *
 * What it does:
 * Copies one source float triple lane into an `{x,z}` destination pair lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElementFloatPairXZLane* CopyFloatPairXZLane(
  VectorElementFloatPairXZLane* const destination,
  const VectorElementFloatTripleLane* const source
) noexcept
{
  destination->x = source->x;
  destination->z = source->z;
  return destination;
}

/**
 * Address: 0x004FD660 (FUN_004FD660)
 *
 * What it does:
 * Appends one pointer lane from `valueSlot` to `destination`, using the
 * existing vector growth path when capacity is exhausted.
 */
[[maybe_unused]] [[nodiscard]] int* PushBackPointerLaneWithGrowth(
  int* const* const valueSlot,
  msvc8::vector<int*>& destination
)
{
  int* const value = (valueSlot != nullptr) ? *valueSlot : nullptr;
  destination.push_back(value);
  return value;
}

/**
 * Address: 0x004FD750 (FUN_004FD750)
 * Address: 0x00504ED0 (FUN_00504ED0)
 *
 * What it does:
 * Stores one vector `_Mylast` lane pointer into caller output storage.
 */
[[maybe_unused]] [[nodiscard]] std::byte** StoreVectorLastPointerLane(
  std::byte** const outPointer,
  const VectorElementCountRuntimeView* const storage
) noexcept
{
  *outPointer = storage->last;
  return outPointer;
}

/**
 * Address: 0x004FD980 (FUN_004FD980)
 * Address: 0x00504EC0 (FUN_00504EC0)
 *
 * What it does:
 * Stores one vector `_Myfirst` lane pointer into caller output storage.
 */
[[maybe_unused]] [[nodiscard]] std::byte** StoreVectorFirstPointerLane(
  std::byte** const outPointer,
  const VectorElementCountRuntimeView* const storage
) noexcept
{
  *outPointer = storage->first;
  return outPointer;
}

/**
 * Address: 0x00505CA0 (FUN_00505CA0)
 * Address: 0x00582670 (FUN_00582670)
 *
 * What it does:
 * Initializes one `[dword,byte]` pair lane from source scalar lanes.
 */
[[maybe_unused]] [[nodiscard]] VectorElementDwordBytePairLane* InitializeDwordBytePairLane(
  VectorElementDwordBytePairLane* const outPair,
  const std::uint32_t* const dwordLane,
  const std::uint8_t* const byteLane
) noexcept
{
  outPair->lane00 = *dwordLane;
  outPair->lane04 = *byteLane;
  return outPair;
}

/**
 * Address: 0x00581D50 (FUN_00581D50)
 * Address: 0x005C99D0 (FUN_005C99D0)
 *
 * What it does:
 * Initializes one `[dword,byte]` pair lane from caller-provided scalar
 * value lanes.
 */
[[maybe_unused]] [[nodiscard]] VectorElementDwordBytePairLane* InitializeDwordBytePairLaneFromValues(
  VectorElementDwordBytePairLane* const outPair,
  const std::uint32_t dwordLane,
  const std::uint8_t byteLane
) noexcept
{
  outPair->lane00 = dwordLane;
  outPair->lane04 = byteLane;
  return outPair;
}

/**
 * Address: 0x004FDD50 (FUN_004FDD50)
 * Address: 0x005440B0 (FUN_005440B0)
 * Address: 0x00544120 (FUN_00544120)
 * Address: 0x005485B0 (FUN_005485B0)
 * Address: 0x00548650 (FUN_00548650)
 *
 * What it does:
 * Pass-through adapter that stores one caller pointer lane into output
 * storage.
 */
[[maybe_unused]] [[nodiscard]] void** StorePointerLanePassthroughA(
  void** const outPointer,
  void* const value
) noexcept
{
  *outPointer = value;
  return outPointer;
}

struct VectorDwordBeginLaneRuntimeView
{
  std::uint32_t* begin = nullptr; // +0x00
};
static_assert(sizeof(VectorDwordBeginLaneRuntimeView) == 0x04, "VectorDwordBeginLaneRuntimeView size must be 0x04");

/**
 * Address: 0x004FDD60 (FUN_004FDD60)
 *
 * What it does:
 * Stores one dword-lane pointer computed as `begin + index` into caller output
 * storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t** StoreDwordPointerAtIndexLane(
  std::uint32_t** const outPointer,
  const VectorDwordBeginLaneRuntimeView* const lane,
  const std::int32_t index
) noexcept
{
  const std::intptr_t base = static_cast<std::intptr_t>(reinterpret_cast<std::uintptr_t>(lane->begin));
  const std::intptr_t offset = static_cast<std::intptr_t>(index) * static_cast<std::intptr_t>(sizeof(std::uint32_t));
  *outPointer = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(base + offset));
  return outPointer;
}

/**
 * Address: 0x00547730 (FUN_00547730)
 * Address: 0x00547740 (FUN_00547740)
 *
 * What it does:
 * Computes one 20-byte-stride element address from vector `_Myfirst` and
 * returns the resulting x86 dword lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeVectorFirstWordAddressAtIndexStride20(
  const int index,
  const VectorDwordStorageView* const storage
) noexcept
{
  return static_cast<std::uint32_t>(
    reinterpret_cast<std::uintptr_t>(storage->first) + (static_cast<std::uint32_t>(index) * 20u)
  );
}

/**
 * Address: 0x0053FE90 (FUN_0053FE90)
 *
 * What it does:
 * Computes one 8-byte-stride lane address from a base dword lane and index,
 * then stores the resulting dword lane into caller-provided output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreDwordLaneAddressAtIndexStride8(
  std::uint32_t* const outWord,
  const std::uint32_t* const baseWord,
  const int index
) noexcept
{
  *outWord = *baseWord + (static_cast<std::uint32_t>(index) * 8u);
  return outWord;
}

/**
 * Address: 0x004FDDA0 (FUN_004FDDA0)
 *
 * What it does:
 * Secondary pass-through adapter that stores one caller pointer lane into
 * output storage.
 */
[[maybe_unused]] [[nodiscard]] void** StorePointerLanePassthroughB(
  void** const outPointer,
  void* const value
) noexcept
{
  return StorePointerLanePassthroughA(outPointer, value);
}

/**
 * Address: 0x0053FD40 (FUN_0053FD40)
 *
 * What it does:
 * Moves one dword lane from source to destination and clears the source slot.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* MoveDwordLaneAndClearSource(
  std::uint32_t* const outWord,
  std::uint32_t* const sourceLane
) noexcept
{
  const std::uint32_t value = *sourceLane;
  *sourceLane = 0u;
  *outWord = value;
  return outWord;
}

struct VtableWordPairAccessorView
{
  std::uint32_t vtableLane; // +0x00
  std::uint32_t lane04;     // +0x04
  std::uint32_t lane08;     // +0x08
};
static_assert(sizeof(VtableWordPairAccessorView) == 0x0C, "VtableWordPairAccessorView size must be 0x0C");

struct VtableTripleWordSwapView
{
  std::uint32_t vtableLane; // +0x00
  std::uint32_t lane04;     // +0x04
  std::uint32_t lane08;     // +0x08
  std::uint32_t lane0C;     // +0x0C
};
static_assert(sizeof(VtableTripleWordSwapView) == 0x10, "VtableTripleWordSwapView size must be 0x10");

struct LaneWordSeedView
{
  std::uint32_t lane00; // +0x00
};
static_assert(sizeof(LaneWordSeedView) == 0x04, "LaneWordSeedView size must be 0x04");

struct TreeBootstrapWordHeaderView
{
  std::uint32_t seedLane00;      // +0x00
  std::uint32_t reserved04;      // +0x04
  std::uint32_t elementCount;    // +0x08
  std::uint32_t reserved0C;      // +0x0C
  std::uint32_t rootLane;        // +0x10
  std::uint32_t leftLane;        // +0x14
  std::uint32_t rightLane;       // +0x18
  std::uint32_t parentLane;      // +0x1C
  std::uint32_t sentinelLane00;  // +0x20
  std::uint32_t sentinelLane04;  // +0x24
  std::uint32_t sentinelLane08;  // +0x28
};
static_assert(sizeof(TreeBootstrapWordHeaderView) == 0x2C, "TreeBootstrapWordHeaderView size must be 0x2C");
static_assert(offsetof(TreeBootstrapWordHeaderView, sentinelLane00) == 0x20, "sentinelLane00 offset must be 0x20");
static_assert(offsetof(TreeBootstrapWordHeaderView, sentinelLane08) == 0x28, "sentinelLane08 offset must be 0x28");

/**
 * Address: 0x00522FC0 (FUN_00522FC0)
 *
 * What it does:
 * Initializes one legacy tree-header lane with copied seed word, zero count,
 * and self-linked sentinel/root pointers.
 */
[[maybe_unused]] [[nodiscard]] TreeBootstrapWordHeaderView* InitializeTreeBootstrapWordHeader(
  TreeBootstrapWordHeaderView* const outHeader,
  const LaneWordSeedView* const source
) noexcept
{
  outHeader->seedLane00 = source->lane00;
  outHeader->elementCount = 0u;

  const std::uint32_t sentinelAddress =
    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&outHeader->sentinelLane00));
  const std::uint32_t rightLaneAddress =
    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&outHeader->sentinelLane08));

  outHeader->rootLane = sentinelAddress;
  outHeader->leftLane = sentinelAddress;
  outHeader->rightLane = rightLaneAddress;
  outHeader->parentLane = sentinelAddress;
  return outHeader;
}

/**
 * Address: 0x00523060 (FUN_00523060)
 * Address: 0x005783C0 (FUN_005783C0)
 *
 * What it does:
 * Zeros one two-dword output lane and returns the destination.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* ZeroTwoWordOutputLane(std::uint32_t* const outWords) noexcept
{
  outWords[0] = 0u;
  outWords[1] = 0u;
  return outWords;
}

/**
 * Address: 0x00523890 (FUN_00523890)
 * Address: 0x005249F0 (FUN_005249F0)
 * Address: 0x005438F0 (FUN_005438F0)
 * Address: 0x005449D0 (FUN_005449D0)
 * Address: 0x00547F10 (FUN_00547F10)
 * Address: 0x00549040 (FUN_00549040)
 *
 * What it does:
 * Stores source lane `+0x04` into one caller-provided output dword slot.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreVtableAccessorLane04Word(
  std::uint32_t* const outWord,
  const VtableWordPairAccessorView* const source
) noexcept
{
  *outWord = source->lane04;
  return outWord;
}

/**
 * Address: 0x005238A0 (FUN_005238A0)
 * Address: 0x00524A00 (FUN_00524A00)
 * Address: 0x00543900 (FUN_00543900)
 * Address: 0x005449E0 (FUN_005449E0)
 * Address: 0x00547AF0 (FUN_00547AF0)
 * Address: 0x00549050 (FUN_00549050)
 *
 * What it does:
 * Stores source lane `+0x08` into one caller-provided output dword slot.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreVtableAccessorLane08Word(
  std::uint32_t* const outWord,
  const VtableWordPairAccessorView* const source
) noexcept
{
  *outWord = source->lane08;
  return outWord;
}

/**
 * Address: 0x00524700 (FUN_00524700)
 * Address: 0x00524E20 (FUN_00524E20)
 * Address: 0x005251E0 (FUN_005251E0)
 * Address: 0x00525250 (FUN_00525250)
 *
 * What it does:
 * Stores one raw pointer lane (truncated to x86 dword width) into caller
 * output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreRawPointerLaneAsWord(
  std::uint32_t* const outWord,
  const void* const value
) noexcept
{
  *outWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(value));
  return outWord;
}

/**
 * Address: 0x0053FC40 (FUN_0053FC40)
 * Address: 0x005612C0 (FUN_005612C0)
 * Address: 0x00561560 (FUN_00561560)
 * Address: 0x00561670 (FUN_00561670)
 * Address: 0x00561790 (FUN_00561790)
 * Address: 0x005618B0 (FUN_005618B0)
 * Address: 0x00591C40 (FUN_00591C40)
 * Address: 0x00591DC0 (FUN_00591DC0)
 * Address: 0x00591E90 (FUN_00591E90)
 * Address: 0x00578940 (FUN_00578940)
 *
 * What it does:
 * Stores the dword at source lane `+0x04` into caller-provided output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreDwordLaneOffset4(
  std::uint32_t* const outWord,
  const std::uint32_t* const sourceLane
) noexcept
{
  *outWord = sourceLane[1];
  return outWord;
}

/**
 * Address: 0x0053FF90 (FUN_0053FF90)
 * Address: 0x005815F0 (FUN_005815F0)
 * Address: 0x005612D0 (FUN_005612D0)
 * Address: 0x00561570 (FUN_00561570)
 * Address: 0x00561680 (FUN_00561680)
 * Address: 0x005617A0 (FUN_005617A0)
 * Address: 0x005618C0 (FUN_005618C0)
 * Address: 0x00591C50 (FUN_00591C50)
 * Address: 0x00591DD0 (FUN_00591DD0)
 * Address: 0x005786E0 (FUN_005786E0)
 * Address: 0x005787C0 (FUN_005787C0)
 *
 * What it does:
 * Stores the dword at source lane `+0x08` into caller-provided output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreDwordLaneOffset8(
  std::uint32_t* const outWord,
  const std::uint32_t* const sourceLane
) noexcept
{
  *outWord = sourceLane[2];
  return outWord;
}

/**
 * Address: 0x00592220 (FUN_00592220)
 * Address: 0x00592410 (FUN_00592410)
 *
 * What it does:
 * Stores one dword loaded from `*sourceLane[1]` into caller-provided output
 * storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreDwordFromIndirectOffset4(
  std::uint32_t* const outWord,
  const std::uint32_t* const sourceLane
) noexcept
{
  const auto* const indirectLane =
    reinterpret_cast<const std::uint32_t*>(static_cast<std::uintptr_t>(sourceLane[1]));
  *outWord = *indirectLane;
  return outWord;
}

/**
 * Address: 0x00524E10 (FUN_00524E10)
 *
 * What it does:
 * Writes one base dword lane plus `index * 4` byte-stride contribution into
 * caller output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreWordOffsetByIndexStride4(
  std::uint32_t* const outWord,
  const std::uint32_t* const baseWord,
  const int index
) noexcept
{
  *outWord = *baseWord + (static_cast<std::uint32_t>(index) * sizeof(std::uint32_t));
  return outWord;
}

/**
 * Address: 0x00585980 (FUN_00585980)
 *
 * What it does:
 * Returns one dword lane offset by `index * 4` bytes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeWordOffsetByIndexStride4(
  const std::uint32_t baseWord,
  const int index
) noexcept
{
  return baseWord + (static_cast<std::uint32_t>(index) * sizeof(std::uint32_t));
}

/**
 * Address: 0x00591C80 (FUN_00591C80)
 *
 * What it does:
 * Returns source lane `+0x04` plus `index * 12` byte-stride contribution.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeWordOffsetByIndexStride12FromOffset4(
  const int index,
  const VtableWordPairAccessorView* const source
) noexcept
{
  return source->lane04 + (static_cast<std::uint32_t>(index) * 12u);
}

/**
 * Address: 0x005485C0 (FUN_005485C0)
 * Address: 0x00578D30 (FUN_00578D30)
 *
 * What it does:
 * Writes one base dword lane plus `index * 20` byte-stride contribution into
 * caller output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreWordOffsetByIndexStride20(
  std::uint32_t* const outWord,
  const std::uint32_t* const baseWord,
  const int index
) noexcept
{
  *outWord = *baseWord + (static_cast<std::uint32_t>(index) * 20u);
  return outWord;
}

/**
 * Address: 0x005784F0 (FUN_005784F0)
 *
 * What it does:
 * Returns the dword lane at `baseWord[0]` plus `index * 20` bytes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeWordOffsetByIndexStride20(
  const std::uint32_t* const baseWord,
  const int index
) noexcept
{
  return *baseWord + (static_cast<std::uint32_t>(index) * 20u);
}

/**
 * Address: 0x00578640 (FUN_00578640)
 *
 * What it does:
 * Returns the dword lane at `baseWord[1]` plus `index * 20` bytes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeWordOffsetByIndexStride20FromOffset4(
  const std::uint32_t* const baseWord,
  const int index
) noexcept
{
  return baseWord[1] + (static_cast<std::uint32_t>(index) * 20u);
}

struct VectorElement20WordLane
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
  std::uint32_t lane0C; // +0x0C
};
static_assert(sizeof(VectorElement20WordLane) == 0x10, "VectorElement20WordLane size must be 0x10");

struct SparseWordByteAccessorRuntimeView
{
  std::uint8_t pad_0000_0034[0x34];
  std::uint32_t lane34; // +0x34
  std::uint32_t lane38; // +0x38
  std::uint32_t lane3C; // +0x3C
  std::uint8_t pad_0040_0054[0x14];
  std::uint8_t lane54; // +0x54
  std::uint8_t pad_0055_00A4[0x4F];
  std::uint32_t laneA4; // +0xA4
  std::uint8_t pad_00A8_016C[0xC4];
  std::uint32_t lane16C; // +0x16C
  std::uint8_t pad_0170_01C4[0x54];
  std::uint32_t lane1C4; // +0x1C4
};
static_assert(sizeof(SparseWordByteAccessorRuntimeView) == 0x1C8, "SparseWordByteAccessorRuntimeView size must be 0x1C8");
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane34) == 0x34,
  "SparseWordByteAccessorRuntimeView::lane34 offset must be 0x34"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane38) == 0x38,
  "SparseWordByteAccessorRuntimeView::lane38 offset must be 0x38"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane3C) == 0x3C,
  "SparseWordByteAccessorRuntimeView::lane3C offset must be 0x3C"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane54) == 0x54,
  "SparseWordByteAccessorRuntimeView::lane54 offset must be 0x54"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, laneA4) == 0xA4,
  "SparseWordByteAccessorRuntimeView::laneA4 offset must be 0xA4"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane16C) == 0x16C,
  "SparseWordByteAccessorRuntimeView::lane16C offset must be 0x16C"
);
static_assert(
  offsetof(SparseWordByteAccessorRuntimeView, lane1C4) == 0x1C4,
  "SparseWordByteAccessorRuntimeView::lane1C4 offset must be 0x1C4"
);

/**
 * Address: 0x00585990 (FUN_00585990)
 *
 * What it does:
 * Returns one dword loaded from lane `+0x16C`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLane16C(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->lane16C;
}

/**
 * Address: 0x005859A0 (FUN_005859A0)
 *
 * What it does:
 * Returns one dword loaded from lane `+0x1C4`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLane1C4(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->lane1C4;
}

/**
 * Address: 0x00585A00 (FUN_00585A00)
 *
 * What it does:
 * Stores one dword value into lane `+0x38` and returns the destination view.
 */
[[maybe_unused]] [[nodiscard]] SparseWordByteAccessorRuntimeView* WriteSparseLane38(
  SparseWordByteAccessorRuntimeView* const value,
  const std::uint32_t laneValue
) noexcept
{
  value->lane38 = laneValue;
  return value;
}

/**
 * Address: 0x00585A10 (FUN_00585A10)
 *
 * What it does:
 * Returns one dword loaded from lane `+0x38`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLane38(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->lane38;
}

/**
 * Address: 0x00585A20 (FUN_00585A20)
 *
 * What it does:
 * Returns one dword loaded from lane `+0x34`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLane34(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->lane34;
}

/**
 * Address: 0x00585A30 (FUN_00585A30)
 *
 * What it does:
 * Returns one dword loaded from lane `+0x3C`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLane3C(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->lane3C;
}

/**
 * Address: 0x00585A80 (FUN_00585A80)
 *
 * What it does:
 * Returns one dword loaded from lane `+0xA4`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseLaneA4(
  const SparseWordByteAccessorRuntimeView* const value
) noexcept
{
  return value->laneA4;
}

/**
 * Address: 0x00585AA0 (FUN_00585AA0)
 *
 * What it does:
 * Stores one byte value into lane `+0x54` and returns the destination view.
 */
[[maybe_unused]] [[nodiscard]] SparseWordByteAccessorRuntimeView* WriteSparseLane54Byte(
  SparseWordByteAccessorRuntimeView* const value,
  const std::uint8_t laneValue
) noexcept
{
  value->lane54 = laneValue;
  return value;
}

struct Span560PointerQuadRuntimeView
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
  std::uint32_t lane0C; // +0x0C
};
static_assert(sizeof(Span560PointerQuadRuntimeView) == 0x10, "Span560PointerQuadRuntimeView size must be 0x10");

struct VectorElement6WordLane
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
  std::uint32_t lane0C; // +0x0C
  std::uint32_t lane10; // +0x10
  std::uint32_t lane14; // +0x14
};
static_assert(sizeof(VectorElement6WordLane) == 0x18, "VectorElement6WordLane size must be 0x18");

struct DualEmbeddedLegacyStringRuntimeView
{
  std::uint32_t lane00;       // +0x00
  msvc8::string primaryText;  // +0x04
  msvc8::string secondaryText; // +0x20
};
static_assert(sizeof(DualEmbeddedLegacyStringRuntimeView) == 0x3C, "DualEmbeddedLegacyStringRuntimeView size must be 0x3C");
static_assert(
  offsetof(DualEmbeddedLegacyStringRuntimeView, primaryText) == 0x04,
  "DualEmbeddedLegacyStringRuntimeView::primaryText offset must be 0x04"
);
static_assert(
  offsetof(DualEmbeddedLegacyStringRuntimeView, secondaryText) == 0x20,
  "DualEmbeddedLegacyStringRuntimeView::secondaryText offset must be 0x20"
);

struct WordSharedControlPairRuntimeView
{
  std::uint32_t lane00;        // +0x00
  volatile long* sharedControl; // +0x04
};
static_assert(sizeof(WordSharedControlPairRuntimeView) == 0x08, "WordSharedControlPairRuntimeView size must be 0x08");
static_assert(
  offsetof(WordSharedControlPairRuntimeView, sharedControl) == 0x04,
  "WordSharedControlPairRuntimeView::sharedControl offset must be 0x04"
);

struct FlaggedSharedControlSourceRuntimeView
{
  std::uint8_t lane00;  // +0x00
  std::uint8_t pad01[3];
  std::uint32_t lane04;        // +0x04
  volatile long* sharedControl; // +0x08
  std::uint8_t lane0C;         // +0x0C
  std::uint8_t pad0D[3];
};
static_assert(sizeof(FlaggedSharedControlSourceRuntimeView) == 0x10, "FlaggedSharedControlSourceRuntimeView size must be 0x10");
static_assert(
  offsetof(FlaggedSharedControlSourceRuntimeView, lane04) == 0x04,
  "FlaggedSharedControlSourceRuntimeView::lane04 offset must be 0x04"
);
static_assert(
  offsetof(FlaggedSharedControlSourceRuntimeView, sharedControl) == 0x08,
  "FlaggedSharedControlSourceRuntimeView::sharedControl offset must be 0x08"
);
static_assert(
  offsetof(FlaggedSharedControlSourceRuntimeView, lane0C) == 0x0C,
  "FlaggedSharedControlSourceRuntimeView::lane0C offset must be 0x0C"
);

struct TripleWordFlaggedSharedControlRuntimeView
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
  std::uint8_t lane0C;  // +0x0C
  std::uint8_t pad0D[3];
  std::uint32_t lane10;         // +0x10
  volatile long* sharedControl; // +0x14
  std::uint8_t lane18;          // +0x18
  std::uint8_t pad19[3];
};
static_assert(
  sizeof(TripleWordFlaggedSharedControlRuntimeView) == 0x1C,
  "TripleWordFlaggedSharedControlRuntimeView size must be 0x1C"
);
static_assert(
  offsetof(TripleWordFlaggedSharedControlRuntimeView, lane0C) == 0x0C,
  "TripleWordFlaggedSharedControlRuntimeView::lane0C offset must be 0x0C"
);
static_assert(
  offsetof(TripleWordFlaggedSharedControlRuntimeView, lane10) == 0x10,
  "TripleWordFlaggedSharedControlRuntimeView::lane10 offset must be 0x10"
);
static_assert(
  offsetof(TripleWordFlaggedSharedControlRuntimeView, sharedControl) == 0x14,
  "TripleWordFlaggedSharedControlRuntimeView::sharedControl offset must be 0x14"
);
static_assert(
  offsetof(TripleWordFlaggedSharedControlRuntimeView, lane18) == 0x18,
  "TripleWordFlaggedSharedControlRuntimeView::lane18 offset must be 0x18"
);

struct SparseIndexedWordTableRuntimeView
{
  std::uint8_t pad0000_0910[0x910];
  std::uint32_t* lane910; // +0x910
  std::uint32_t* lane914; // +0x914
};
static_assert(sizeof(SparseIndexedWordTableRuntimeView) == 0x918, "SparseIndexedWordTableRuntimeView size must be 0x918");
static_assert(
  offsetof(SparseIndexedWordTableRuntimeView, lane910) == 0x910,
  "SparseIndexedWordTableRuntimeView::lane910 offset must be 0x910"
);
static_assert(
  offsetof(SparseIndexedWordTableRuntimeView, lane914) == 0x914,
  "SparseIndexedWordTableRuntimeView::lane914 offset must be 0x914"
);

struct SparseScalarAccessorRuntimeView
{
  std::uint8_t pad0000_0080[0x80];
  std::uint32_t lane80; // +0x80
  std::uint8_t pad0084_0090[0x0C];
  float lane90; // +0x90
  float lane94; // +0x94
  std::uint8_t pad0098_00D8[0x40];
  float laneD8; // +0xD8
  std::uint8_t pad00DC_029C[0x1C0];
  std::uint32_t lane29C; // +0x29C
  std::uint8_t pad02A0_0540[0x2A0];
  std::uint32_t lane540; // +0x540
  std::uint8_t pad0544_0984[0x440];
  std::uint32_t lane984; // +0x984
  std::uint8_t pad0988_0A88[0x100];
  std::uint32_t laneA88; // +0xA88
};
static_assert(sizeof(SparseScalarAccessorRuntimeView) == 0xA8C, "SparseScalarAccessorRuntimeView size must be 0xA8C");
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane80) == 0x80,
  "SparseScalarAccessorRuntimeView::lane80 offset must be 0x80"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane90) == 0x90,
  "SparseScalarAccessorRuntimeView::lane90 offset must be 0x90"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane94) == 0x94,
  "SparseScalarAccessorRuntimeView::lane94 offset must be 0x94"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, laneD8) == 0xD8,
  "SparseScalarAccessorRuntimeView::laneD8 offset must be 0xD8"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane29C) == 0x29C,
  "SparseScalarAccessorRuntimeView::lane29C offset must be 0x29C"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane540) == 0x540,
  "SparseScalarAccessorRuntimeView::lane540 offset must be 0x540"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, lane984) == 0x984,
  "SparseScalarAccessorRuntimeView::lane984 offset must be 0x984"
);
static_assert(
  offsetof(SparseScalarAccessorRuntimeView, laneA88) == 0xA88,
  "SparseScalarAccessorRuntimeView::laneA88 offset must be 0xA88"
);

struct VectorElementWordByteWordLane
{
  std::uint32_t lane00; // +0x00
  std::uint8_t lane04;  // +0x04
  std::uint8_t pad05[3];
  std::uint32_t lane08; // +0x08
};
static_assert(sizeof(VectorElementWordByteWordLane) == 0x0C, "VectorElementWordByteWordLane size must be 0x0C");
static_assert(
  offsetof(VectorElementWordByteWordLane, lane04) == 0x04,
  "VectorElementWordByteWordLane::lane04 offset must be 0x04"
);
static_assert(
  offsetof(VectorElementWordByteWordLane, lane08) == 0x08,
  "VectorElementWordByteWordLane::lane08 offset must be 0x08"
);

struct BacklinkedNodeRuntimeView
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
};
static_assert(sizeof(BacklinkedNodeRuntimeView) == 0x0C, "BacklinkedNodeRuntimeView size must be 0x0C");
static_assert(
  offsetof(BacklinkedNodeRuntimeView, lane08) == 0x08,
  "BacklinkedNodeRuntimeView::lane08 offset must be 0x08"
);

struct PointerSentinelLaneBlockRuntimeView
{
  std::uint32_t lane00; // +0x00
  std::uint32_t lane04; // +0x04
  std::uint32_t lane08; // +0x08
  std::uint32_t lane0C; // +0x0C
  std::uint32_t lane10; // +0x10
  std::uint32_t lane14; // +0x14
};
static_assert(sizeof(PointerSentinelLaneBlockRuntimeView) == 0x18, "PointerSentinelLaneBlockRuntimeView size must be 0x18");

struct ThresholdTreeNodeRuntimeView
{
  ThresholdTreeNodeRuntimeView* lane00; // +0x00
  ThresholdTreeNodeRuntimeView* lane04; // +0x04
  ThresholdTreeNodeRuntimeView* lane08; // +0x08
  std::uint32_t keyLane0C; // +0x0C
  std::uint8_t pad10[5];
  std::uint8_t isSentinelLane15; // +0x15
  std::uint8_t pad16[2];
};
static_assert(sizeof(ThresholdTreeNodeRuntimeView) == 0x18, "ThresholdTreeNodeRuntimeView size must be 0x18");
static_assert(
  offsetof(ThresholdTreeNodeRuntimeView, lane04) == 0x04,
  "ThresholdTreeNodeRuntimeView::lane04 offset must be 0x04"
);
static_assert(
  offsetof(ThresholdTreeNodeRuntimeView, lane08) == 0x08,
  "ThresholdTreeNodeRuntimeView::lane08 offset must be 0x08"
);
static_assert(
  offsetof(ThresholdTreeNodeRuntimeView, keyLane0C) == 0x0C,
  "ThresholdTreeNodeRuntimeView::keyLane0C offset must be 0x0C"
);
static_assert(
  offsetof(ThresholdTreeNodeRuntimeView, isSentinelLane15) == 0x15,
  "ThresholdTreeNodeRuntimeView::isSentinelLane15 offset must be 0x15"
);

struct ThresholdTreeAccessorRuntimeView
{
  std::uint32_t lane00; // +0x00
  ThresholdTreeNodeRuntimeView* treeHeadLane04; // +0x04
};
static_assert(sizeof(ThresholdTreeAccessorRuntimeView) == 0x08, "ThresholdTreeAccessorRuntimeView size must be 0x08");
static_assert(
  offsetof(ThresholdTreeAccessorRuntimeView, treeHeadLane04) == 0x04,
  "ThresholdTreeAccessorRuntimeView::treeHeadLane04 offset must be 0x04"
);

/**
 * Address: 0x005B1D10 (FUN_005B1D10)
 *
 * What it does:
 * Projects one input float-pair lane onto one basis float-pair lane and
 * stores the projected lane in `outLane`.
 */
[[maybe_unused]] [[nodiscard]] VectorElementFloatPairXZLane* ProjectFloatPairOntoBasisLane(
  VectorElementFloatPairXZLane* const outLane,
  const VectorElementFloatPairXZLane* const inputLane,
  const VectorElementFloatPairXZLane* const basisLane
) noexcept
{
  const float basisMagnitudeSq = (basisLane->x * basisLane->x) + (basisLane->z * basisLane->z);
  if (basisMagnitudeSq <= 0.0f) {
    outLane->x = 0.0f;
    outLane->z = 0.0f;
    return outLane;
  }

  const float scale = ((inputLane->x * basisLane->x) + (inputLane->z * basisLane->z)) / basisMagnitudeSq;
  outLane->x = basisLane->x * scale;
  outLane->z = basisLane->z * scale;
  return outLane;
}

/**
 * Address: 0x005B1DA0 (FUN_005B1DA0)
 *
 * What it does:
 * Removes the basis-parallel component from one input float-pair lane and
 * stores the rejection lane in `outLane`.
 */
[[maybe_unused]] [[nodiscard]] VectorElementFloatPairXZLane* RejectFloatPairFromBasisLane(
  VectorElementFloatPairXZLane* const outLane,
  const VectorElementFloatPairXZLane* const basisLane,
  const VectorElementFloatPairXZLane* const inputLane
) noexcept
{
  VectorElementFloatPairXZLane projected{};
  ProjectFloatPairOntoBasisLane(&projected, inputLane, basisLane);
  outLane->x = inputLane->x - projected.x;
  outLane->z = inputLane->z - projected.z;
  return outLane;
}

/**
 * Address: 0x005B4680 (FUN_005B4680)
 *
 * What it does:
 * Initializes one 4-lane pointer window from the destination object's
 * `+0x10` embedded base lane and fixed `+0x230` span.
 */
[[maybe_unused]] [[nodiscard]] Span560PointerQuadRuntimeView* InitializeSpan560PointerQuadFromSelfOffset10(
  Span560PointerQuadRuntimeView* const outLane
) noexcept
{
  const std::uint32_t baseLane = static_cast<std::uint32_t>(
    reinterpret_cast<std::uintptr_t>(reinterpret_cast<std::byte*>(outLane) + 0x10)
  );

  outLane->lane00 = baseLane;
  outLane->lane04 = baseLane;
  outLane->lane08 = baseLane + 0x230u;
  outLane->lane0C = baseLane;
  return outLane;
}

/**
 * Address: 0x005B4E30 (FUN_005B4E30)
 *
 * What it does:
 * Initializes one 4-lane pointer window from one explicit base lane and fixed
 * `+0x230` span.
 */
[[maybe_unused]] [[nodiscard]] Span560PointerQuadRuntimeView* InitializeSpan560PointerQuadFromBaseLane(
  Span560PointerQuadRuntimeView* const outLane,
  const std::uint32_t baseLane
) noexcept
{
  outLane->lane00 = baseLane;
  outLane->lane04 = baseLane;
  outLane->lane08 = baseLane + 0x230u;
  outLane->lane0C = baseLane;
  return outLane;
}

/**
 * Address: 0x005BD3F0 (FUN_005BD3F0)
 *
 * What it does:
 * Clears one 24-byte six-word lane record to zero.
 */
[[maybe_unused]] [[nodiscard]] VectorElement6WordLane* ZeroSixWordLane(
  VectorElement6WordLane* const outLane
) noexcept
{
  outLane->lane00 = 0u;
  outLane->lane04 = 0u;
  outLane->lane08 = 0u;
  outLane->lane0C = 0u;
  outLane->lane10 = 0u;
  outLane->lane14 = 0u;
  return outLane;
}

/**
 * Address: 0x005BD450 (FUN_005BD450)
 *
 * What it does:
 * Stores one scalar dword lane into caller output storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreSingleWordLaneValue(
  std::uint32_t* const outWord,
  const std::uint32_t value
) noexcept
{
  *outWord = value;
  return outWord;
}

/**
 * Address: 0x005BD5C0 (FUN_005BD5C0)
 *
 * What it does:
 * Copies one 12-byte `{dword,dword,dword}` lane record.
 */
[[maybe_unused]] [[nodiscard]] VectorElement12DwordTripleLane* CopyDwordTripleLane(
  VectorElement12DwordTripleLane* const destination,
  const VectorElement12DwordTripleLane* const source
) noexcept
{
  destination->lane0 = source->lane0;
  destination->lane1 = source->lane1;
  destination->lane2 = source->lane2;
  return destination;
}

/**
 * Address: 0x005BD620 (FUN_005BD620)
 *
 * What it does:
 * Clears one two-word lane record to zero.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* ZeroTwoWordLane(
  std::uint32_t* const outWords
) noexcept
{
  outWords[0] = 0u;
  outWords[1] = 0u;
  return outWords;
}

/**
 * Address: 0x005BD680 (FUN_005BD680)
 *
 * What it does:
 * Returns the character-data pointer for the first embedded legacy string
 * lane.
 */
[[maybe_unused]] [[nodiscard]] const char* GetPrimaryEmbeddedLegacyStringDataPointer(
  const DualEmbeddedLegacyStringRuntimeView* const value
) noexcept
{
  return value->primaryText.raw_data_unsafe();
}

/**
 * Address: 0x005BD690 (FUN_005BD690)
 *
 * What it does:
 * Returns the character-data pointer for the second embedded legacy string
 * lane.
 */
[[maybe_unused]] [[nodiscard]] const char* GetSecondaryEmbeddedLegacyStringDataPointer(
  const DualEmbeddedLegacyStringRuntimeView* const value
) noexcept
{
  return value->secondaryText.raw_data_unsafe();
}

/**
 * Address: 0x005BD9B0 (FUN_005BD9B0)
 *
 * What it does:
 * Initializes one 28-byte `{triple-word,flags,shared-control}` lane by copying
 * payload lanes and retaining one shared-control reference when present.
 */
[[maybe_unused]] [[nodiscard]] TripleWordFlaggedSharedControlRuntimeView* InitializeTripleWordFlaggedSharedControlLane(
  TripleWordFlaggedSharedControlRuntimeView* const destination,
  const VectorElement12DwordTripleLane* const tripleSource,
  const FlaggedSharedControlSourceRuntimeView* const sharedSource
) noexcept
{
  destination->lane00 = tripleSource->lane0;
  destination->lane04 = tripleSource->lane1;
  destination->lane08 = tripleSource->lane2;
  destination->lane0C = sharedSource->lane00;
  destination->lane10 = sharedSource->lane04;
  destination->sharedControl = sharedSource->sharedControl;
  if (destination->sharedControl != nullptr) {
    (void)_InterlockedExchangeAdd(destination->sharedControl + 1, 1L);
  }
  destination->lane18 = sharedSource->lane0C;
  return destination;
}

/**
 * Address: 0x005BDA60 (FUN_005BDA60)
 * Address: 0x005BE290 (FUN_005BE290)
 *
 * What it does:
 * Copies one `{word,shared-control}` lane and retains the shared-control
 * reference when present.
 */
[[maybe_unused]] [[nodiscard]] WordSharedControlPairRuntimeView* CopyWordSharedControlPairRetain(
  WordSharedControlPairRuntimeView* const destination,
  const WordSharedControlPairRuntimeView* const source
) noexcept
{
  destination->lane00 = source->lane00;
  destination->sharedControl = source->sharedControl;
  if (destination->sharedControl != nullptr) {
    (void)_InterlockedExchangeAdd(destination->sharedControl + 1, 1L);
  }
  return destination;
}

/**
 * Address: 0x005BDAB0 (FUN_005BDAB0)
 *
 * What it does:
 * Returns one indexed dword from sparse table lanes `+0x910/+0x914`, or zero
 * when the table is absent/out-of-range.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadIndexedSparseWordTableLane910(
  const SparseIndexedWordTableRuntimeView* const table,
  const std::uint32_t index
) noexcept
{
  const std::uint32_t* const begin = table->lane910;
  if (begin == nullptr) {
    return 0u;
  }

  const auto spanBytes = static_cast<std::int32_t>(
    static_cast<std::intptr_t>(reinterpret_cast<std::uintptr_t>(table->lane914)) -
    static_cast<std::intptr_t>(reinterpret_cast<std::uintptr_t>(begin))
  );
  const std::uint32_t count = static_cast<std::uint32_t>(spanBytes >> 2);
  if (index >= count) {
    return 0u;
  }

  return begin[index];
}

/**
 * Address: 0x005BDAF0 (FUN_005BDAF0)
 *
 * What it does:
 * Returns one dword lane loaded from offset `+0x984`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseWord984(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane984;
}

/**
 * Address: 0x005BDB00 (FUN_005BDB00)
 *
 * What it does:
 * Returns one dword lane loaded from offset `+0xA88`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseWordA88(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->laneA88;
}

/**
 * Address: 0x005BDB80 (FUN_005BDB80)
 *
 * What it does:
 * Returns one dword lane loaded from offset `+0x80`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseWord80(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane80;
}

/**
 * Address: 0x005BDC30 (FUN_005BDC30)
 *
 * What it does:
 * Returns one float lane loaded from offset `+0xD8`.
 */
[[maybe_unused]] [[nodiscard]] float ReadSparseFloatD8(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->laneD8;
}

/**
 * Address: 0x005BDC40 (FUN_005BDC40)
 *
 * What it does:
 * Returns one float lane loaded from offset `+0x90`.
 */
[[maybe_unused]] [[nodiscard]] float ReadSparseFloat90(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane90;
}

/**
 * Address: 0x005BDC50 (FUN_005BDC50)
 *
 * What it does:
 * Returns one float lane loaded from offset `+0x94`.
 */
[[maybe_unused]] [[nodiscard]] float ReadSparseFloat94(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane94;
}

/**
 * Address: 0x005BDD90 (FUN_005BDD90)
 *
 * What it does:
 * Returns true when sparse dword lane `+0x29C` is non-zero.
 */
[[maybe_unused]] [[nodiscard]] bool HasSparseWord29C(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane29C != 0u;
}

/**
 * Address: 0x005BDDA0 (FUN_005BDDA0)
 *
 * What it does:
 * Returns one dword lane loaded from offset `+0x540`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadSparseWord540(
  const SparseScalarAccessorRuntimeView* const value
) noexcept
{
  return value->lane540;
}

[[nodiscard]] ThresholdTreeNodeRuntimeView* FindLowerBoundThresholdTreeNode(
  const ThresholdTreeAccessorRuntimeView* const treeAccessor,
  const std::uint32_t threshold
) noexcept
{
  ThresholdTreeNodeRuntimeView* candidate = treeAccessor->treeHeadLane04;
  ThresholdTreeNodeRuntimeView* node = candidate->lane04;
  while (node->isSentinelLane15 == 0u) {
    if (node->keyLane0C >= threshold) {
      candidate = node;
      node = node->lane00;
    } else {
      node = node->lane08;
    }
  }

  return candidate;
}

/**
 * Address: 0x005BE2D0 (FUN_005BE2D0)
 *
 * What it does:
 * Stores one lower-bound tree-node candidate for threshold `0x30000000`.
 */
[[maybe_unused]] [[nodiscard]] ThresholdTreeNodeRuntimeView** StoreLowerBoundThresholdNode30000000(
  ThresholdTreeNodeRuntimeView** const outNode,
  const ThresholdTreeAccessorRuntimeView* const treeAccessor
) noexcept
{
  *outNode = FindLowerBoundThresholdTreeNode(treeAccessor, 0x30000000u);
  return outNode;
}

/**
 * Address: 0x005BE300 (FUN_005BE300)
 *
 * What it does:
 * Stores one lower-bound tree-node candidate for threshold `0x40000000`.
 */
[[maybe_unused]] [[nodiscard]] ThresholdTreeNodeRuntimeView** StoreLowerBoundThresholdNode40000000(
  ThresholdTreeNodeRuntimeView** const outNode,
  const ThresholdTreeAccessorRuntimeView* const treeAccessor
) noexcept
{
  *outNode = FindLowerBoundThresholdTreeNode(treeAccessor, 0x40000000u);
  return outNode;
}

/**
 * Address: 0x005BFF80 (FUN_005BFF80)
 *
 * What it does:
 * Initializes one `{dword,byte,dword}` lane record from scalar input lanes.
 */
[[maybe_unused]] [[nodiscard]] VectorElementWordByteWordLane* InitializeWordByteWordLane(
  VectorElementWordByteWordLane* const outLane,
  const std::uint32_t lane00,
  const std::uint8_t lane04,
  const std::uint32_t lane08
) noexcept
{
  outLane->lane00 = lane00;
  outLane->lane04 = lane04;
  outLane->lane08 = lane08;
  return outLane;
}

/**
 * Address: 0x005C3980 (FUN_005C3980)
 *
 * What it does:
 * Returns lane `+0x08` adjusted back by `0xD8` bytes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeBaseLaneFromBacklinkMinusD8(
  const BacklinkedNodeRuntimeView* const value
) noexcept
{
  return value->lane08 - 0xD8u;
}

/**
 * Address: 0x005C3990 (FUN_005C3990)
 *
 * What it does:
 * Returns lane `+0x08` adjusted back by `0x238` bytes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ComputeBaseLaneFromBacklinkMinus238(
  const BacklinkedNodeRuntimeView* const value
) noexcept
{
  return value->lane08 - 0x238u;
}

/**
 * Address: 0x005C3A70 (FUN_005C3A70)
 *
 * What it does:
 * Initializes one 6-lane pointer-sentinel block with self and two embedded
 * sentinel anchors.
 */
[[maybe_unused]] [[nodiscard]] PointerSentinelLaneBlockRuntimeView* InitializePointerSentinelLaneBlock(
  PointerSentinelLaneBlockRuntimeView* const outBlock
) noexcept
{
  const std::uint32_t selfLane = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outBlock));
  const std::uint32_t sentinelLane = selfLane + 0x18u;

  outBlock->lane00 = selfLane;
  outBlock->lane04 = selfLane;
  outBlock->lane08 = sentinelLane;
  outBlock->lane0C = sentinelLane;
  outBlock->lane10 = sentinelLane + 0x10u;
  outBlock->lane14 = sentinelLane;
  return outBlock;
}

/**
 * Address: 0x005B1A10 (FUN_005B1A10)
 *
 * What it does:
 * Swaps one dword payload lane between two caller-provided storage lanes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLaneLegacyAdapterA(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  const std::uint32_t temp = *right;
  *right = *left;
  *left = temp;
  return left;
}

/**
 * Address: 0x00578750 (FUN_00578750)
 *
 * What it does:
 * Initializes a four-lane word record from a base pointer and element count.
 */
[[maybe_unused]] [[nodiscard]] VectorElement20WordLane* InitializeVectorElement20WordLane(
  VectorElement20WordLane* const outLane,
  const int count,
  const std::uint32_t* const baseWord
) noexcept
{
  const std::uint32_t baseAddress =
    static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(baseWord));
  outLane->lane00 = baseAddress;
  outLane->lane04 = baseAddress;
  outLane->lane08 = baseAddress + (static_cast<std::uint32_t>(count) * 20u);
  outLane->lane0C = baseAddress;
  return outLane;
}

/**
 * Address: 0x00549090 (FUN_00549090)
 *
 * What it does:
 * Returns one dword lane loaded from `baseLane[index]`.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t ReadIndexedDwordLane(
  const std::uint32_t* const baseLane,
  const int index
) noexcept
{
  return baseLane[index];
}

/**
 * Address: 0x0054DD80 (FUN_0054DD80)
 *
 * What it does:
 * Adds one `index * 8` byte-stride contribution into an existing dword lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* AccumulateWordOffsetByIndexStride8(
  std::uint32_t* const inOutWord,
  const int index
) noexcept
{
  *inOutWord += static_cast<std::uint32_t>(index) * static_cast<std::uint32_t>(sizeof(VectorElement8DwordPairLane));
  return inOutWord;
}

/**
 * Address: 0x0054DDA0 (FUN_0054DDA0)
 * Address: 0x00561EF0 (FUN_00561EF0)
 * Address: 0x00561F00 (FUN_00561F00)
 * Address: 0x00561F10 (FUN_00561F10)
 * Address: 0x00561F20 (FUN_00561F20)
 * Address: 0x00592070 (FUN_00592070)
 * Address: 0x00592160 (FUN_00592160)
 * Address: 0x00578D20 (FUN_00578D20)
 * Address: 0x00578D80 (FUN_00578D80)
 *
 * What it does:
 * Stores one signed scalar index lane into caller-provided dword storage.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* StoreIndexScalarLane(
  std::uint32_t* const outWord,
  const int index
) noexcept
{
  *outWord = static_cast<std::uint32_t>(index);
  return outWord;
}

/**
 * Address: 0x0054DDB0 (FUN_0054DDB0)
 *
 * What it does:
 * Adds one `index * 0x58` byte-stride contribution into an existing dword
 * lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* AccumulateWordOffsetByIndexStride88(
  std::uint32_t* const inOutWord,
  const int index
) noexcept
{
  *inOutWord += static_cast<std::uint32_t>(index) * 0x58u;
  return inOutWord;
}

/**
 * Address: 0x0054E110 (FUN_0054E110)
 *
 * What it does:
 * Copies one half-open 8-byte lane range `[sourceBegin, sourceEnd)` into
 * destination storage and returns one-past-last destination lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* CopyDwordPairRangeForward(
  VectorElement8DwordPairLane* destinationBegin,
  const VectorElement8DwordPairLane* const sourceEnd,
  const VectorElement8DwordPairLane* sourceBegin
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destinationBegin = *sourceBegin;
    ++sourceBegin;
    ++destinationBegin;
  }
  return destinationBegin;
}

/**
 * Address: 0x0054F850 (FUN_0054F850)
 * Address: 0x00574820 (FUN_00574820)
 *
 * What it does:
 * Initializes one 8-byte dword-pair lane from two scalar source-word slots.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* InitializeDwordPairLaneFromWordSlots(
  VectorElement8DwordPairLane* const outLane,
  const std::uint32_t* const lane0Source,
  const std::uint32_t* const lane1Source
) noexcept
{
  outLane->lane0 = *lane0Source;
  outLane->lane1 = *lane1Source;
  return outLane;
}

/**
 * Address: 0x005EF950 (FUN_005EF950)
 *
 * What it does:
 * Initializes one 8-byte dword-pair lane from two independent scalar source
 * slots.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* InitializeDwordPairLaneFromSplitScalarSlots(
  VectorElement8DwordPairLane* const outLane,
  const std::uint32_t* const lane0Source,
  const std::uint32_t* const lane1Source
) noexcept
{
  return InitializeDwordPairLaneFromWordSlots(outLane, lane0Source, lane1Source);
}

/**
 * Address: 0x0054F950 (FUN_0054F950)
 * Address: 0x0055AB10 (FUN_0055AB10)
 * Address: 0x0055FCE0 (FUN_0055FCE0)
 * Address: 0x0055FD00 (FUN_0055FD00)
 * Address: 0x00578F70 (FUN_00578F70)
 * Address: 0x005CA4F0 (FUN_005CA4F0)
 *
 * What it does:
 * Swaps both dword payload lanes between two 8-byte lane records.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* SwapDwordPairPayloadLanes(
  VectorElement8DwordPairLane* const left,
  VectorElement8DwordPairLane* const right
) noexcept
{
  std::uint32_t lane = left->lane0;
  left->lane0 = right->lane0;
  right->lane0 = lane;

  lane = left->lane1;
  left->lane1 = right->lane1;
  right->lane1 = lane;
  return left;
}

/**
 * Address: 0x0054FD70 (FUN_0054FD70)
 *
 * What it does:
 * Register-shape swap adapter for one 8-byte dword-pair lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* SwapDwordPairPayloadLanesRegisterAdapterA(
  VectorElement8DwordPairLane* const left,
  VectorElement8DwordPairLane* const right
) noexcept
{
  return SwapDwordPairPayloadLanes(left, right);
}

/**
 * Address: 0x00550180 (FUN_00550180)
 *
 * What it does:
 * Secondary register-shape swap adapter for one 8-byte dword-pair lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* SwapDwordPairPayloadLanesRegisterAdapterB(
  VectorElement8DwordPairLane* const left,
  VectorElement8DwordPairLane* const right
) noexcept
{
  return SwapDwordPairPayloadLanes(left, right);
}

/**
 * Address: 0x005501C0 (FUN_005501C0)
 *
 * What it does:
 * Tertiary register-shape swap adapter for one 8-byte dword-pair lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* SwapDwordPairPayloadLanesRegisterAdapterC(
  VectorElement8DwordPairLane* const left,
  VectorElement8DwordPairLane* const right
) noexcept
{
  return SwapDwordPairPayloadLanes(left, right);
}

/**
 * Address: 0x00551F80 (FUN_00551F80)
 *
 * What it does:
 * Quaternary register-shape swap adapter for one 8-byte dword-pair lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* SwapDwordPairPayloadLanesRegisterAdapterD(
  VectorElement8DwordPairLane* const left,
  VectorElement8DwordPairLane* const right
) noexcept
{
  return SwapDwordPairPayloadLanes(left, right);
}

/**
 * Address: 0x00550420 (FUN_00550420)
 * Address: 0x005EE680 (FUN_005EE680)
 * Address: 0x005EE6A0 (FUN_005EE6A0)
 * Address: 0x008A88D0 (FUN_008A88D0)
 * Address: 0x008A88E0 (FUN_008A88E0)
 * Address: 0x008A88F0 (FUN_008A88F0)
 * Address: 0x008B98B0 (FUN_008B98B0)
 *
 * What it does:
 * Swaps one dword payload lane between two caller-provided lanes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLaneRegisterAdapterA(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  const std::uint32_t lane = *right;
  *right = *left;
  *left = lane;
  return left;
}

/**
 * Address: 0x00550430 (FUN_00550430)
 *
 * What it does:
 * Secondary register-shape swap adapter for one dword payload lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLaneRegisterAdapterB(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  return SwapSingleDwordPayloadLaneRegisterAdapterA(left, right);
}

/**
 * Address: 0x00550440 (FUN_00550440)
 *
 * What it does:
 * Tertiary register-shape swap adapter for one dword payload lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLaneRegisterAdapterC(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  return SwapSingleDwordPayloadLaneRegisterAdapterA(left, right);
}

/**
 * Address: 0x00552010 (FUN_00552010)
 *
 * What it does:
 * Quaternary register-shape swap adapter for one dword payload lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLaneRegisterAdapterD(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  return SwapSingleDwordPayloadLaneRegisterAdapterA(left, right);
}

/**
 * Address: 0x00550CB0 (FUN_00550CB0)
 * Address: 0x0055C820 (FUN_0055C820)
 * Address: 0x0055FCD0 (FUN_0055FCD0)
 *
 * What it does:
 * Clears one 8-byte dword-pair lane to zero.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* ZeroDwordPairLane(
  VectorElement8DwordPairLane* const outLane
) noexcept
{
  outLane->lane0 = 0u;
  outLane->lane1 = 0u;
  return outLane;
}

/**
 * Address: 0x0051A6A0 (FUN_0051A6A0)
 * Address: 0x005262E0 (FUN_005262E0)
 * Address: 0x00526310 (FUN_00526310)
 * Address: 0x00544570 (FUN_00544570)
 * Address: 0x005447D0 (FUN_005447D0)
 * Address: 0x005489C0 (FUN_005489C0)
 * Address: 0x00548CE0 (FUN_00548CE0)
 * Address: 0x00581EA0 (FUN_00581EA0)
 * Address: 0x00582570 (FUN_00582570)
 * Address: 0x005845F0 (FUN_005845F0)
 * Address: 0x005C9B90 (FUN_005C9B90)
 * Address: 0x005C9C10 (FUN_005C9C10)
 * Address: 0x005CA4C0 (FUN_005CA4C0)
 * Address: 0x005CA5F0 (FUN_005CA5F0)
 *
 * What it does:
 * Swaps three payload dword lanes (`+0x04,+0x08,+0x0C`) between two
 * vtable-backed runtime views.
 */
[[maybe_unused]] [[nodiscard]] VtableTripleWordSwapView* SwapVtableTripleWordPayloadLanes(
  VtableTripleWordSwapView* const left,
  VtableTripleWordSwapView* const right
) noexcept
{
  std::uint32_t temp = right->lane04;
  right->lane04 = left->lane04;
  left->lane04 = temp;

  temp = right->lane08;
  right->lane08 = left->lane08;
  left->lane08 = temp;

  temp = right->lane0C;
  right->lane0C = left->lane0C;
  left->lane0C = temp;
  return left;
}

/**
 * Address: 0x0051B010 (FUN_0051B010)
 * Address: 0x0055ADA0 (FUN_0055ADA0)
 * Address: 0x0055FDF0 (FUN_0055FDF0)
 * Address: 0x0055FE00 (FUN_0055FE00)
 * Address: 0x00527450 (FUN_00527450)
 * Address: 0x00527470 (FUN_00527470)
 * Address: 0x005451F0 (FUN_005451F0)
 * Address: 0x00549740 (FUN_00549740)
 * Address: 0x00583950 (FUN_00583950)
 * Address: 0x005849B0 (FUN_005849B0)
 * Address: 0x005849D0 (FUN_005849D0)
 * Address: 0x00584C70 (FUN_00584C70)
 * Address: 0x00584C80 (FUN_00584C80)
 * Address: 0x005790B0 (FUN_005790B0)
 * Address: 0x005CC330 (FUN_005CC330)
 * Address: 0x005CC340 (FUN_005CC340)
 * Address: 0x005CC360 (FUN_005CC360)
 * Address: 0x005CFFA0 (FUN_005CFFA0)
 *
 * What it does:
 * Swaps one dword payload lane between two caller-provided storage lanes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* SwapSingleDwordPayloadLane(
  std::uint32_t* const left,
  std::uint32_t* const right
) noexcept
{
  const std::uint32_t temp = *right;
  *right = *left;
  *left = temp;
  return left;
}

/**
 * Address: 0x004DC780 (FUN_004DC780)
 * Address: 0x00504DE0 (FUN_00504DE0)
 * Address: 0x00504F50 (FUN_00504F50)
 * Address: 0x005238F0 (FUN_005238F0)
 * Address: 0x00537C10 (FUN_00537C10)
 * Address: 0x00652220 (FUN_00652220)
 * Address: 0x0074F880 (FUN_0074F880)
 *
 * What it does:
 * Relocates one contiguous `void*` vector segment from `sourceBegin` to
 * `destinationBegin`, updates `_Mylast` by the copied element count, and
 * returns the destination-begin output slot.
 */
[[maybe_unused]] static void*** RelocateVectorVoidSegment(
  VectorVoidStorageView& storage,
  void*** const outDestinationBegin,
  void** const destinationBegin,
  void** const sourceBegin
) noexcept
{
  if (destinationBegin != sourceBegin) {
    const std::ptrdiff_t elementCount = storage.last - sourceBegin;
    if (elementCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(elementCount) * sizeof(void*);
      (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
    }
    storage.last = destinationBegin + elementCount;
  }

  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x00523020 (FUN_00523020)
 * Address: 0x005C4B30 (FUN_005C4B30)
 * Address: 0x00753530 (FUN_00753530)
 *
 * What it does:
 * Rewinds one vector storage lane to empty by setting `_Mylast` to `_Myfirst`
 * without touching allocation ownership.
 */
[[maybe_unused]] void ResetVectorWordStorageLogicalEnd(VectorVoidStorageView& storage) noexcept
{
  if (storage.first != storage.last) {
    storage.last = storage.first;
  }
}

/**
 * Address: 0x008D79D0 (FUN_008D79D0)
 *
 * What it does:
 * Alias lane of `ResetVectorWordStorageLogicalEnd` used by one vector
 * assignment fast-path when the source range is empty.
 */
[[maybe_unused]] void ResetVectorWordStorageLogicalEndAliasA(VectorVoidStorageView& storage) noexcept
{
  ResetVectorWordStorageLogicalEnd(storage);
}

/**
 * Address: 0x008D7A20 (FUN_008D7A20)
 *
 * What it does:
 * Alias lane of `ResetVectorWordStorageLogicalEnd` used by one adjacent
 * vector assignment fast-path when the source range is empty.
 */
[[maybe_unused]] void ResetVectorWordStorageLogicalEndAliasB(VectorVoidStorageView& storage) noexcept
{
  ResetVectorWordStorageLogicalEnd(storage);
}

/**
 * Address: 0x00523980 (FUN_00523980)
 * Address: 0x0053FF20 (FUN_0053FF20)
 * Address: 0x00767710 (FUN_00767710)
 * Address: 0x007C9310 (FUN_007C9310)
 *
 * What it does:
 * Releases one vector backing allocation and clears begin/end/capacity lanes.
 */
[[maybe_unused]] void ReleaseVectorWordStorageAndNullAllLanes(VectorVoidStorageView& storage) noexcept
{
  if (storage.first != nullptr) {
    ::operator delete(storage.first);
  }

  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;
}

/**
 * Address: 0x00583B40 (FUN_00583B40)
 *
 * What it does:
 * Clears one header dword lane, releases the owned storage pointer at `+0x08`
 * when present, and nulls the `{first,last,end}` lanes.
 */
[[maybe_unused]] void ReleaseHeaderedVectorStorageAndReset(VectorHeaderedStorageLaneView& storage) noexcept
{
  storage.lane00 = 0u;
  if (storage.first != nullptr) {
    ::operator delete(storage.first);
  }

  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;
}

/**
 * Address: 0x00537F70 (FUN_00537F70)
 *
 * What it does:
 * Deletes one heap allocation lane through global `operator delete`.
 */
[[maybe_unused]] void DeleteAllocationLane(void* const allocation) noexcept
{
  ::operator delete(allocation);
}

/**
 * Address: 0x0075F2B0 (FUN_0075F2B0)
 * Address: 0x00769D70 (FUN_00769D70)
 *
 * What it does:
 * Fills `tripleCount` contiguous 12-byte lanes with zero dwords and returns
 * one-past the last written lane.
 */
[[maybe_unused]] std::uint32_t* FillZeroDwordTripleLanesAndReturnEnd(
  std::uint32_t* const destinationBegin,
  const std::uint32_t tripleCount
) noexcept
{
  auto* const begin = reinterpret_cast<VectorElement12DwordTripleLane*>(destinationBegin);
  for (std::uint32_t index = 0u; index < tripleCount; ++index) {
    begin[index].lane0 = 0u;
    begin[index].lane1 = 0u;
    begin[index].lane2 = 0u;
  }

  return destinationBegin + (tripleCount * 3u);
}

/**
 * Address: 0x00594120 (FUN_00594120)
 * Address: 0x005CA0D0 (FUN_005CA0D0)
 *
 * What it does:
 * Fills one half-open 12-byte `{dword,dword,dword}` lane range
 * `[destinationBegin, destinationEnd)` from `*valuePtr` and returns
 * one-past-last destination lane.
 */
[[maybe_unused]] VectorElement12DwordTripleLane* FillDwordTripleRangeFromValueLane(
  VectorElement12DwordTripleLane* destinationBegin,
  const VectorElement12DwordTripleLane* const destinationEnd,
  const VectorElement12DwordTripleLane* const valuePtr
) noexcept
{
  while (destinationBegin != destinationEnd) {
    *destinationBegin = *valuePtr;
    ++destinationBegin;
  }

  return destinationBegin;
}

/**
 * What it does:
 * Returns element count from one legacy vector lane using the caller-provided
 * element stride (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[nodiscard]] int CountElementVectorLanesByStride(
  const VectorElementCountRuntimeView* const view,
  const int strideBytes
) noexcept
{
  const std::byte* const first = view->first;
  if (first == nullptr) {
    return 0;
  }

  return static_cast<int>((view->last - first) / strideBytes);
}

/**
 * Address: 0x00507F50 (FUN_00507F50)
 * Address: 0x00547710 (FUN_00547710)
 * Address: 0x0053FBC0 (FUN_0053FBC0)
 * Address: 0x00578620 (FUN_00578620)
 * Address: 0x0057F9D0 (FUN_0057F9D0)
 * Address: 0x00686890 (FUN_00686890)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 20 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count20ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 20);
}

/**
 * Address: 0x005191E0 (FUN_005191E0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 204 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count204ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 204);
}

/**
 * Address: 0x0057ED80 (FUN_0057ED80)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 24 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count24ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 24);
}

/**
 * Address: 0x005C3C70 (FUN_005C3C70)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 52 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count52ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 52);
}

/**
 * Address: 0x005C4C70 (FUN_005C4C70)
 * Address: 0x00591C60 (FUN_00591C60)
 * Address: 0x00627310 (FUN_00627310)
 * Address: 0x0069ED20 (FUN_0069ED20)
 * Address: 0x006DBCD0 (FUN_006DBCD0)
 * Address: 0x0067C6A0 (FUN_0067C6A0)
 * Address: 0x0074D8A0 (FUN_0074D8A0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 12 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count12ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 12);
}

/**
 * Address: 0x00692840 (FUN_00692840)
 * Address: 0x005C50E0 (FUN_005C50E0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 28 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count28ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 28);
}

/**
 * Address: 0x00702570 (FUN_00702570)
 * Address: 0x0074D9E0 (FUN_0074D9E0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 40 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count40ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 40);
}

/**
 * Address: 0x007198B0 (FUN_007198B0)
 * Address: 0x008A8A60 (FUN_008A8A60)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 56 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count56ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 56);
}

/**
 * Address: 0x0074C5C0 (FUN_0074C5C0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 36 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count36ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 36);
}

/**
 * Address: 0x00523090 (FUN_00523090)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 388 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count388ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 388);
}

/**
 * Address: 0x0054C0F0 (FUN_0054C0F0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 88 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count88ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 88);
}

/**
 * Address: 0x00560E90 (FUN_00560E90)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 352 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count352ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 352);
}

/**
 * Address: 0x00560FE0 (FUN_00560FE0)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 216 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count216ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 216);
}

/**
 * Address: 0x00561130 (FUN_00561130)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 568 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count568ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 568);
}

/**
 * Address: 0x00561290 (FUN_00561290)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 120 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count120ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 120);
}

/**
 * Address: 0x00836E60 (FUN_00836E60)
 *
 * What it does:
 * Returns element count from one legacy vector lane whose element stride is
 * 48 bytes (`_Mylast - _Myfirst`), or zero when uninitialized.
 */
[[maybe_unused]] int Count48ByteElementVectorLanes(const VectorElementCountRuntimeView* const view) noexcept
{
  return CountElementVectorLanesByStride(view, 48);
}

/**
 * Address: 0x00540F40 (FUN_00540F40, func_ArraySet)
 * Address: 0x00680A10 (FUN_00680A10)
 * Address: 0x006E3490 (FUN_006E3490)
 * Address: 0x00540BB0 (FUN_00540BB0)
 * Address: 0x00765630 (FUN_00765630)
 *
 * What it does:
 * Writes one dword value from `valuePtr` into `count` consecutive destination
 * dword lanes, preserving the original null-destination guard semantics.
 */
std::uint32_t FillDwordArrayFromValuePointerNullable(
  std::uint32_t count,
  const std::uint32_t* const valuePtr,
  std::uint32_t* destination
) noexcept
{
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (count != 0u) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<std::uint32_t*>(destinationAddress) = *valuePtr;
    }

    --count;
    destinationAddress += sizeof(std::uint32_t);
  }

  return count;
}

/**
 * Address: 0x0067F770 (FUN_0067F770)
 *
 * What it does:
 * Register-lane adapter that forwards one dword-span fill into the canonical
 * nullable-destination helper.
 */
[[maybe_unused]] std::uint32_t FillDwordArrayFromValuePointerNullableRegisterAdapter(
  const std::uint32_t* const valuePtr,
  std::uint32_t* const destination,
  const std::uint32_t count
) noexcept
{
  return FillDwordArrayFromValuePointerNullable(count, valuePtr, destination);
}

/**
 * Address: 0x00A72140 (FUN_00A72140)
 *
 * What it does:
 * Returns checked iterator-distance in 8-byte element lanes after validating
 * that both iterators belong to the same owner vector.
 */
[[maybe_unused]] int Distance8ByteVectorIteratorsCheckedLaneA(
  const VectorElementIteratorRuntimeView* const left,
  const VectorElementIteratorRuntimeView* const right
) noexcept
{
  return CheckedVectorElementIteratorDistance(left, right, sizeof(VectorElement8DwordPairLane));
}

/**
 * Address: 0x00A72170 (FUN_00A72170)
 *
 * What it does:
 * Returns checked iterator-distance in 16-byte element lanes after validating
 * that both iterators belong to the same owner vector.
 */
[[maybe_unused]] int Distance16ByteVectorIteratorsCheckedLaneA(
  const VectorElementIteratorRuntimeView* const left,
  const VectorElementIteratorRuntimeView* const right
) noexcept
{
  return CheckedVectorElementIteratorDistance(left, right, sizeof(VectorElement16DwordQuadLane));
}

/**
 * Address: 0x00A724E0 (FUN_00A724E0)
 *
 * What it does:
 * Resolves one checked element pointer for an 8-byte element vector by index.
 */
[[maybe_unused]] VectorElement8DwordPairLane* Resolve8ByteVectorElementAtChecked(
  const VectorElementCountRuntimeView* const storage,
  const std::uint32_t index
) noexcept
{
  return reinterpret_cast<VectorElement8DwordPairLane*>(
    CheckedVectorElementAtIndex(storage, index, sizeof(VectorElement8DwordPairLane))
  );
}

/**
 * Address: 0x00A72510 (FUN_00A72510)
 *
 * What it does:
 * Resolves one checked element pointer for a 16-byte element vector by index.
 */
[[maybe_unused]] VectorElement16DwordQuadLane* Resolve16ByteVectorElementAtChecked(
  const VectorElementCountRuntimeView* const storage,
  const std::uint32_t index
) noexcept
{
  return reinterpret_cast<VectorElement16DwordQuadLane*>(
    CheckedVectorElementAtIndex(storage, index, sizeof(VectorElement16DwordQuadLane))
  );
}

/**
 * Address: 0x00A72560 (FUN_00A72560)
 *
 * What it does:
 * Initializes one checked iterator for an 8-byte element vector at `position`.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* Initialize8ByteVectorIteratorCheckedLaneA(
  VectorElementIteratorRuntimeView* const iterator,
  const VectorElement8DwordPairLane* const position,
  VectorElementCountRuntimeView* const owner
) noexcept
{
  return InitializeVectorElementIteratorChecked(
    iterator,
    reinterpret_cast<const std::byte*>(position),
    owner
  );
}

/**
 * Address: 0x00A725A0 (FUN_00A725A0)
 *
 * What it does:
 * Initializes one checked iterator for a 16-byte element vector at `position`.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* Initialize16ByteVectorIteratorCheckedLaneA(
  VectorElementIteratorRuntimeView* const iterator,
  const VectorElement16DwordQuadLane* const position,
  VectorElementCountRuntimeView* const owner
) noexcept
{
  return InitializeVectorElementIteratorChecked(
    iterator,
    reinterpret_cast<const std::byte*>(position),
    owner
  );
}

/**
 * Address: 0x00A72640 (FUN_00A72640)
 *
 * What it does:
 * Returns checked iterator-distance in 8-byte element lanes after validating
 * that both iterators belong to the same owner vector.
 */
[[maybe_unused]] int Distance8ByteVectorIteratorsCheckedLaneB(
  const VectorElementIteratorRuntimeView* const left,
  const VectorElementIteratorRuntimeView* const right
) noexcept
{
  return CheckedVectorElementIteratorDistance(left, right, sizeof(VectorElement8DwordPairLane));
}

/**
 * Address: 0x00A72670 (FUN_00A72670)
 *
 * What it does:
 * Returns checked iterator-distance in 16-byte element lanes after validating
 * that both iterators belong to the same owner vector.
 */
[[maybe_unused]] int Distance16ByteVectorIteratorsCheckedLaneB(
  const VectorElementIteratorRuntimeView* const left,
  const VectorElementIteratorRuntimeView* const right
) noexcept
{
  return CheckedVectorElementIteratorDistance(left, right, sizeof(VectorElement16DwordQuadLane));
}

/**
 * Address: 0x00A72B80 (FUN_00A72B80)
 *
 * What it does:
 * Secondary lane that initializes one checked iterator for an 8-byte element
 * vector at `position`.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* Initialize8ByteVectorIteratorCheckedLaneB(
  VectorElementIteratorRuntimeView* const iterator,
  const VectorElement8DwordPairLane* const position,
  VectorElementCountRuntimeView* const owner
) noexcept
{
  return InitializeVectorElementIteratorChecked(
    iterator,
    reinterpret_cast<const std::byte*>(position),
    owner
  );
}

/**
 * Address: 0x00A72BC0 (FUN_00A72BC0)
 *
 * What it does:
 * Secondary lane that initializes one checked iterator for a 16-byte element
 * vector at `position`.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* Initialize16ByteVectorIteratorCheckedLaneB(
  VectorElementIteratorRuntimeView* const iterator,
  const VectorElement16DwordQuadLane* const position,
  VectorElementCountRuntimeView* const owner
) noexcept
{
  return InitializeVectorElementIteratorChecked(
    iterator,
    reinterpret_cast<const std::byte*>(position),
    owner
  );
}

/**
 * Address: 0x00A72F90 (FUN_00A72F90)
 *
 * What it does:
 * Initializes one checked iterator to the begin lane of the owner vector.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* InitializeVectorIteratorAtBeginCheckedLane(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  return InitializeVectorElementIteratorAtBeginChecked(owner, iterator);
}

/**
 * Address: 0x00A72FC0 (FUN_00A72FC0)
 *
 * What it does:
 * Initializes one checked iterator to the end lane of the owner vector.
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* InitializeVectorIteratorAtEndCheckedLane(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  return InitializeVectorElementIteratorAtEndChecked(owner, iterator);
}

/**
 * Address: 0x00A72FF0 (FUN_00A72FF0)
 *
 * What it does:
 * Initializes one checked iterator to the begin lane of the owner vector
 * (alias lane with explicit iterator-zeroing before validation).
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* InitializeVectorIteratorAtBeginCheckedLaneAlias(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  iterator->owner = nullptr;
  return InitializeVectorElementIteratorAtBeginChecked(owner, iterator);
}

/**
 * Address: 0x00A73020 (FUN_00A73020)
 *
 * What it does:
 * Initializes one checked iterator to the end lane of the owner vector
 * (alias lane with explicit iterator-zeroing before validation).
 */
[[maybe_unused]] VectorElementIteratorRuntimeView* InitializeVectorIteratorAtEndCheckedLaneAlias(
  VectorElementCountRuntimeView* const owner,
  VectorElementIteratorRuntimeView* const iterator
) noexcept
{
  iterator->owner = nullptr;
  return InitializeVectorElementIteratorAtEndChecked(owner, iterator);
}

/**
 * Address: 0x00A72A90 (FUN_00A72A90)
 * Address: 0x0059DC90 (FUN_0059DC90)
 *
 * What it does:
 * Copies one half-open range of 16-byte `{dword,dword,dword,dword}` lanes
 * into destination storage using backwards iteration and returns the
 * destination-begin lane.
 */
[[maybe_unused]] VectorElement16DwordQuadLane* CopyDwordQuadRangeBackward(
  const VectorElement16DwordQuadLane* const sourceBegin,
  const VectorElement16DwordQuadLane* const sourceEnd,
  VectorElement16DwordQuadLane* const destinationEnd
) noexcept
{
  VectorElement16DwordQuadLane* const destinationBegin = destinationEnd - (sourceEnd - sourceBegin);
  const VectorElement16DwordQuadLane* source = sourceEnd;
  VectorElement16DwordQuadLane* destination = destinationEnd;
  while (source != sourceBegin) {
    --source;
    --destination;
    *destination = *source;
  }

  return destinationBegin;
}

/**
 * Address: 0x00A72EC0 (FUN_00A72EC0)
 *
 * What it does:
 * Register-shape adapter lane that forwards to
 * `CopyDwordQuadRangeBackward(begin, end, destinationEnd)`.
 */
[[maybe_unused]] VectorElement16DwordQuadLane* CopyDwordQuadRangeBackwardRegisterAdapterLane(
  const VectorElement16DwordQuadLane* const sourceBegin,
  const VectorElement16DwordQuadLane* const sourceEnd,
  VectorElement16DwordQuadLane* const destinationEnd
) noexcept
{
  return CopyDwordQuadRangeBackward(sourceBegin, sourceEnd, destinationEnd);
}

/**
 * Address: 0x00594140 (FUN_00594140)
 * Address: 0x005CA0F0 (FUN_005CA0F0)
 *
 * What it does:
 * Copies one half-open 12-byte `{dword,dword,dword}` lane range backwards
 * from `[sourceBegin, sourceEnd)` into storage ending at `destinationEnd`,
 * and returns the resulting destination-begin lane.
 */
[[maybe_unused]] VectorElement12DwordTripleLane* CopyDwordTripleRangeBackward(
  const VectorElement12DwordTripleLane* const sourceBegin,
  const VectorElement12DwordTripleLane* sourceEnd,
  VectorElement12DwordTripleLane* destinationEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    *destinationEnd = *sourceEnd;
  }

  return destinationEnd;
}

/**
 * Address: 0x008DA320 (FUN_008DA320)
 *
 * What it does:
 * Copies one half-open 8-byte `{dword,dword}` lane range backward from
 * `[sourceBegin, sourceEnd)` into storage ending at `destinationEnd`.
 */
[[maybe_unused]] VectorElement8DwordPairLane* CopyDwordPairRangeBackward(
  const VectorElement8DwordPairLane* const sourceBegin,
  const VectorElement8DwordPairLane* sourceEnd,
  VectorElement8DwordPairLane* destinationEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    *destinationEnd = *sourceEnd;
  }

  return destinationEnd;
}

/**
 * Address: 0x006E3510 (FUN_006E3510)
 *
 * What it does:
 * Copies one half-open dword lane range backward from `[sourceBegin, sourceEnd)`
 * into storage ending at `destinationEnd`.
 */
[[maybe_unused]] std::uint32_t* CopyDwordRangeBackward(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* sourceEnd,
  std::uint32_t* destinationEnd
) noexcept
{
  while (sourceEnd != sourceBegin) {
    --sourceEnd;
    --destinationEnd;
    *destinationEnd = *sourceEnd;
  }

  return destinationEnd;
}

struct HeapElement72FloatKeyFastVectorN2Lane
{
  float lane00 = 0.0f;                     // +0x00
  float lane04 = 0.0f;                     // +0x04
  float lane08 = 0.0f;                     // +0x08
  float lane0C = 0.0f;                     // +0x0C
  float lane10 = 0.0f;                     // +0x10
  float lane14 = 0.0f;                     // +0x14
  float lane18 = 0.0f;                     // +0x18
  float lane1C = 0.0f;                     // +0x1C
  std::uint32_t lane20 = 0u;               // +0x20
  std::uint32_t lane24 = 0u;               // +0x24
  std::uint32_t lane28 = 0u;               // +0x28
  std::uint32_t lane2C = 0u;               // +0x2C
  gpg::fastvector_n<std::uint32_t, 2> lane30{}; // +0x30
};
static_assert(sizeof(HeapElement72FloatKeyFastVectorN2Lane) == 0x48, "HeapElement72FloatKeyFastVectorN2Lane size must be 0x48");
static_assert(
  offsetof(HeapElement72FloatKeyFastVectorN2Lane, lane18) == 0x18,
  "HeapElement72FloatKeyFastVectorN2Lane::lane18 offset must be 0x18"
);
static_assert(
  offsetof(HeapElement72FloatKeyFastVectorN2Lane, lane30) == 0x30,
  "HeapElement72FloatKeyFastVectorN2Lane::lane30 offset must be 0x30"
);

struct HeapElement72PartialSnapshot
{
  float lane00 = 0.0f;
  float lane04 = 0.0f;
  float lane08 = 0.0f;
  float lane0C = 0.0f;
  float lane10 = 0.0f;
  float lane14 = 0.0f;
  float lane18 = 0.0f;
  float lane1C = 0.0f;
  std::uint32_t lane20 = 0u;
  std::uint32_t lane28 = 0u;
  gpg::fastvector_n<std::uint32_t, 2> lane30{};

  HeapElement72PartialSnapshot() = default;

  HeapElement72PartialSnapshot(const HeapElement72PartialSnapshot& other)
    : lane00(other.lane00)
    , lane04(other.lane04)
    , lane08(other.lane08)
    , lane0C(other.lane0C)
    , lane10(other.lane10)
    , lane14(other.lane14)
    , lane18(other.lane18)
    , lane1C(other.lane1C)
    , lane20(other.lane20)
    , lane28(other.lane28)
    , lane30{}
  {
    (void)gpg::FastVectorN2RebindAndCopy(&lane30, &other.lane30);
  }

  HeapElement72PartialSnapshot& operator=(const HeapElement72PartialSnapshot& other)
  {
    if (this == &other) {
      return *this;
    }

    lane00 = other.lane00;
    lane04 = other.lane04;
    lane08 = other.lane08;
    lane0C = other.lane0C;
    lane10 = other.lane10;
    lane14 = other.lane14;
    lane18 = other.lane18;
    lane1C = other.lane1C;
    lane20 = other.lane20;
    lane28 = other.lane28;
    (void)gpg::FastVectorN2RebindAndCopy(&lane30, &other.lane30);
    return *this;
  }
};
static_assert(sizeof(HeapElement72PartialSnapshot) == 0x40, "HeapElement72PartialSnapshot size must be 0x40");

void CopyFastVectorN2UIntLaneWithRuntimeAssign(
  gpg::fastvector_n<std::uint32_t, 2>& destination,
  const gpg::fastvector_n<std::uint32_t, 2>& source
)
{
  auto& destinationView = gpg::AsFastVectorRuntimeView<std::uint32_t>(&destination);
  const auto& sourceView = gpg::AsFastVectorRuntimeView<std::uint32_t>(&source);
  (void)gpg::FastVectorRuntimeCopyAssignAlias(destinationView, sourceView);
}

[[nodiscard]] HeapElement72PartialSnapshot CaptureHeapElement72Partial(
  const HeapElement72FloatKeyFastVectorN2Lane& source
)
{
  HeapElement72PartialSnapshot snapshot{};
  snapshot.lane00 = source.lane00;
  snapshot.lane04 = source.lane04;
  snapshot.lane08 = source.lane08;
  snapshot.lane0C = source.lane0C;
  snapshot.lane10 = source.lane10;
  snapshot.lane14 = source.lane14;
  snapshot.lane18 = source.lane18;
  snapshot.lane1C = source.lane1C;
  snapshot.lane20 = source.lane20;
  snapshot.lane28 = source.lane28;
  (void)gpg::FastVectorN2RebindAndCopy(&snapshot.lane30, &source.lane30);
  return snapshot;
}

void CopyHeapElement72Partial(
  HeapElement72FloatKeyFastVectorN2Lane& destination,
  const HeapElement72FloatKeyFastVectorN2Lane& source
)
{
  // Keep binary-accurate partial-copy semantics: lane24/lane2C are intentionally not written.
  destination.lane00 = source.lane00;
  destination.lane04 = source.lane04;
  destination.lane08 = source.lane08;
  destination.lane0C = source.lane0C;
  destination.lane10 = source.lane10;
  destination.lane14 = source.lane14;
  destination.lane18 = source.lane18;
  destination.lane1C = source.lane1C;
  destination.lane20 = source.lane20;
  destination.lane28 = source.lane28;
  CopyFastVectorN2UIntLaneWithRuntimeAssign(destination.lane30, source.lane30);
}

void RestoreHeapElement72Partial(
  HeapElement72FloatKeyFastVectorN2Lane& destination,
  const HeapElement72PartialSnapshot& snapshot
)
{
  // Keep binary-accurate partial-copy semantics: lane24/lane2C are intentionally not written.
  destination.lane00 = snapshot.lane00;
  destination.lane04 = snapshot.lane04;
  destination.lane08 = snapshot.lane08;
  destination.lane0C = snapshot.lane0C;
  destination.lane10 = snapshot.lane10;
  destination.lane14 = snapshot.lane14;
  destination.lane18 = snapshot.lane18;
  destination.lane1C = snapshot.lane1C;
  destination.lane20 = snapshot.lane20;
  destination.lane28 = snapshot.lane28;
  CopyFastVectorN2UIntLaneWithRuntimeAssign(destination.lane30, snapshot.lane30);
}

/**
 * Address: 0x00573340 (FUN_00573340)
 *
 * What it does:
 * Copies one 72-byte heap lane into destination using the binary's partial
 * write profile and fastvector_n2 copy lane.
 */
[[maybe_unused]] [[nodiscard]] HeapElement72FloatKeyFastVectorN2Lane* CopyHeapElement72PartialLane(
  const HeapElement72FloatKeyFastVectorN2Lane* const source,
  HeapElement72FloatKeyFastVectorN2Lane* const destination
)
{
  CopyHeapElement72Partial(*destination, *source);
  return destination;
}

/**
 * Address: 0x0056CB60 (FUN_0056CB60)
 *
 * What it does:
 * Copies one lane72 payload from source to destination and applies the
 * fastvector-n2 rebind+copy lane (`0x00402220`) for the trailing vector data.
 */
[[maybe_unused]] [[nodiscard]] HeapElement72FloatKeyFastVectorN2Lane* CopyHeapElement72WithResizeLane(
  const HeapElement72FloatKeyFastVectorN2Lane* const source,
  HeapElement72FloatKeyFastVectorN2Lane* const destination
)
{
  destination->lane00 = source->lane00;
  destination->lane04 = source->lane04;
  destination->lane08 = source->lane08;
  destination->lane0C = source->lane0C;
  destination->lane10 = source->lane10;
  destination->lane14 = source->lane14;
  destination->lane18 = source->lane18;
  destination->lane1C = source->lane1C;
  destination->lane20 = source->lane20;
  destination->lane28 = source->lane28;
  (void)gpg::core::legacy::RebindInlineAndCopy(destination->lane30, static_cast<const gpg::fastvector<std::uint32_t>&>(source->lane30));
  return destination;
}

/**
 * Address: 0x00575210 (FUN_00575210)
 *
 * What it does:
 * Swaps two lane72 entries through one stack temporary: copies `left` into
 * temporary storage, moves `right` into `left`, then restores temporary into
 * `right`.
 */
[[maybe_unused]] void SwapHeapElement72WithTemporary(
  HeapElement72FloatKeyFastVectorN2Lane* const left,
  HeapElement72FloatKeyFastVectorN2Lane* const right
)
{
  HeapElement72FloatKeyFastVectorN2Lane temporary{};
  (void)CopyHeapElement72WithResizeLane(left, &temporary);
  (void)CopyHeapElement72PartialLane(right, left);
  (void)CopyHeapElement72PartialLane(&temporary, right);
}

void SwapHeapElement72IfLeftKeyGreater(
  HeapElement72FloatKeyFastVectorN2Lane* const left,
  HeapElement72FloatKeyFastVectorN2Lane* const right
)
{
  if (left->lane18 > right->lane18) {
    SwapHeapElement72WithTemporary(left, right);
  }
}

/**
 * Address: 0x005751C0 (FUN_005751C0)
 *
 * What it does:
 * Applies the recovered three-lane compare/swap network over
 * `(first, second, third)` using `lane18` as key.
 */
[[maybe_unused]] void CompareSwapLane72Triple(
  HeapElement72FloatKeyFastVectorN2Lane* const first,
  HeapElement72FloatKeyFastVectorN2Lane* const second,
  HeapElement72FloatKeyFastVectorN2Lane* const third
)
{
  SwapHeapElement72IfLeftKeyGreater(first, second);
  SwapHeapElement72IfLeftKeyGreater(third, first);
  SwapHeapElement72IfLeftKeyGreater(first, second);
}

/**
 * Address: 0x00574830 (FUN_00574830)
 *
 * What it does:
 * Applies the recovered small/large compare-swap sampling network for lane72
 * entries around `begin`, `middle`, and `end`.
 */
[[maybe_unused]] void CompareSwapLane72PivotNetwork(
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  HeapElement72FloatKeyFastVectorN2Lane* const middle,
  HeapElement72FloatKeyFastVectorN2Lane* const end
)
{
  const int count = static_cast<int>(end - begin);
  if (count <= 40) {
    SwapHeapElement72IfLeftKeyGreater(middle, begin);
    SwapHeapElement72IfLeftKeyGreater(end, middle);
    SwapHeapElement72IfLeftKeyGreater(middle, begin);
    return;
  }

  const int sampleStep = (count + 1) / 8;
  HeapElement72FloatKeyFastVectorN2Lane* const beginPlusStep = begin + sampleStep;
  HeapElement72FloatKeyFastVectorN2Lane* const beginPlusDoubleStep = begin + (sampleStep * 2);
  SwapHeapElement72IfLeftKeyGreater(beginPlusStep, begin);
  SwapHeapElement72IfLeftKeyGreater(beginPlusDoubleStep, beginPlusStep);
  SwapHeapElement72IfLeftKeyGreater(beginPlusStep, begin);

  HeapElement72FloatKeyFastVectorN2Lane* const middleMinusStep = middle - sampleStep;
  HeapElement72FloatKeyFastVectorN2Lane* const middlePlusStep = middle + sampleStep;
  SwapHeapElement72IfLeftKeyGreater(middle, middleMinusStep);
  SwapHeapElement72IfLeftKeyGreater(middlePlusStep, middle);
  SwapHeapElement72IfLeftKeyGreater(middle, middleMinusStep);

  HeapElement72FloatKeyFastVectorN2Lane* const endMinusStep = end - sampleStep;
  HeapElement72FloatKeyFastVectorN2Lane* const endMinusDoubleStep = end - (sampleStep * 2);
  SwapHeapElement72IfLeftKeyGreater(endMinusStep, endMinusDoubleStep);
  SwapHeapElement72IfLeftKeyGreater(end, endMinusStep);
  SwapHeapElement72IfLeftKeyGreater(endMinusStep, endMinusDoubleStep);

  SwapHeapElement72IfLeftKeyGreater(middle, beginPlusStep);
  SwapHeapElement72IfLeftKeyGreater(endMinusStep, middle);
  SwapHeapElement72IfLeftKeyGreater(middle, beginPlusStep);
}

/**
 * Address: 0x00575690 (FUN_00575690)
 *
 * What it does:
 * Rotates one 72-byte heap-lane range left around `middle` using the original
 * gcd-cycle move strategy and preserving binary partial-copy semantics.
 */
[[maybe_unused]] int RotateHeapElement72RangeByGcdCycles(
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  HeapElement72FloatKeyFastVectorN2Lane* const middle,
  HeapElement72FloatKeyFastVectorN2Lane* const end
)
{
  const int leftCount = static_cast<int>(middle - begin);
  int result = static_cast<int>(end - begin);
  const int leftCountSnapshot = leftCount;

  int divisor = leftCount;
  int remainingCycles = result;
  if (leftCount != 0) {
    do {
      const int remainder = result % divisor;
      remainingCycles = divisor;
      result = divisor;
      divisor = remainder;
    } while (divisor != 0);
  }

  const int totalCount = static_cast<int>(end - begin);
  if (result < totalCount && result > 0) {
    HeapElement72FloatKeyFastVectorN2Lane* cycleStart = begin + result;
    while (true) {
      const HeapElement72PartialSnapshot saved = CaptureHeapElement72Partial(*cycleStart);

      HeapElement72FloatKeyFastVectorN2Lane* source = begin;
      HeapElement72FloatKeyFastVectorN2Lane* destination = cycleStart;
      HeapElement72FloatKeyFastVectorN2Lane* const cycleCandidate = cycleStart + leftCount;
      if (cycleCandidate != end) {
        source = cycleCandidate;
      }

      while (source != cycleStart) {
        CopyHeapElement72Partial(*destination, *source);
        const int remainingToEnd = static_cast<int>(end - source);
        destination = source;
        if (leftCountSnapshot >= remainingToEnd) {
          source = begin + (leftCountSnapshot - remainingToEnd);
        } else {
          source += leftCountSnapshot;
        }
      }

      RestoreHeapElement72Partial(*destination, saved);
      result = remainingCycles - 1;
      --cycleStart;
      if (--remainingCycles <= 0) {
        break;
      }
    }
  }

  return result;
}

/**
 * Address: 0x005754F0 (FUN_005754F0)
 *
 * What it does:
 * Register-shape adapter that forwards one heap-lane rotation into
 * `RotateHeapElement72RangeByGcdCycles`.
 */
[[maybe_unused]] int RotateHeapElement72RangeRegisterAdapter(
  HeapElement72FloatKeyFastVectorN2Lane* const end,
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  HeapElement72FloatKeyFastVectorN2Lane* const middle
)
{
  return RotateHeapElement72RangeByGcdCycles(begin, middle, end);
}

/**
 * Address: 0x00574170 (FUN_00574170)
 *
 * What it does:
 * Performs insertion-style key ordering over one contiguous 72-byte heap-lane
 * range by rotating each out-of-order lane into its insertion window.
 */
[[maybe_unused]] void StableInsertSortHeapElement72ByKey(
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  HeapElement72FloatKeyFastVectorN2Lane* const end
)
{
  if (begin == end) {
    return;
  }

  HeapElement72FloatKeyFastVectorN2Lane* cursor = begin + 1;
  if (cursor == end) {
    return;
  }

  HeapElement72FloatKeyFastVectorN2Lane* trailing = begin + 2;
  do {
    const float key = cursor->lane18;
    if (key <= begin->lane18) {
      HeapElement72FloatKeyFastVectorN2Lane* insertPosition = cursor;
      HeapElement72FloatKeyFastVectorN2Lane* scan = cursor;
      while (true) {
        --scan;
        if (key <= scan->lane18) {
          break;
        }
        insertPosition = scan;
      }

      if (insertPosition != cursor && cursor != trailing) {
        (void)RotateHeapElement72RangeByGcdCycles(insertPosition, cursor, trailing);
      }
    } else if (begin != cursor && cursor != trailing) {
      (void)RotateHeapElement72RangeByGcdCycles(begin, cursor, trailing);
    }

    ++cursor;
    ++trailing;
  } while (cursor != end);
}

[[nodiscard]] int LegacyHeapParentIndex(const int childIndex) noexcept
{
  const int adjusted = childIndex - 1;
  const int sign = adjusted >> 31;
  return (adjusted - sign) / 2;
}

/**
 * Address: 0x00575500 (FUN_00575500)
 *
 * What it does:
 * Sifts one 72-byte heap lane up within `[rootFloorIndex, insertIndex]` using
 * ascending key order (`lane18`), then writes the displaced partial lane into
 * the final heap hole.
 */
[[maybe_unused]] void SiftUpHeapElement72ByKeyWithDisplacedPartialLane(
  HeapElement72FloatKeyFastVectorN2Lane* const heapBase,
  const int rootFloorIndex,
  const int insertIndex,
  const float lane00,
  const float lane04,
  const float lane08,
  const float lane0C,
  const float lane10,
  const float lane14,
  const float lane18,
  const float lane1C,
  const std::uint32_t lane20,
  const std::uint32_t lane28,
  const gpg::fastvector_n<std::uint32_t, 2>& lane30
)
{
  int writeIndex = insertIndex;
  int parentIndex = LegacyHeapParentIndex(writeIndex);
  while (rootFloorIndex < writeIndex) {
    HeapElement72FloatKeyFastVectorN2Lane& parentLane = heapBase[parentIndex];
    if (parentLane.lane18 <= lane18) {
      break;
    }

    CopyHeapElement72Partial(heapBase[writeIndex], parentLane);
    writeIndex = parentIndex;
    parentIndex = LegacyHeapParentIndex(parentIndex);
  }

  HeapElement72FloatKeyFastVectorN2Lane& destination = heapBase[writeIndex];
  destination.lane00 = lane00;
  destination.lane04 = lane04;
  destination.lane08 = lane08;
  destination.lane0C = lane0C;
  destination.lane10 = lane10;
  destination.lane14 = lane14;
  destination.lane18 = lane18;
  destination.lane1C = lane1C;
  destination.lane20 = lane20;
  destination.lane28 = lane28;
  (void)gpg::FastVectorN2RebindAndCopy(&destination.lane30, &lane30);
}

/**
 * Address: 0x00575280 (FUN_00575280)
 *
 * What it does:
 * Performs the recovered lane72 heap hole percolation: pushes the root hole
 * down by promoting the preferred child lane, handles the single-child tail
 * case, then reinserts the displaced partial lane with the recovered sift-up
 * helper.
 */
[[maybe_unused]] void SiftDownThenInsertHeapElement72ByKey(
  HeapElement72FloatKeyFastVectorN2Lane* const heapBase,
  const int rootFloorIndex,
  const int heapCount,
  const HeapElement72PartialSnapshot& displaced
)
{
  int writeIndex = rootFloorIndex;
  int childIndex = (rootFloorIndex * 2) + 2;
  if (childIndex < heapCount) {
    do {
      if (heapBase[childIndex].lane18 > heapBase[childIndex - 1].lane18) {
        --childIndex;
      }

      CopyHeapElement72Partial(heapBase[writeIndex], heapBase[childIndex]);
      writeIndex = childIndex;
      childIndex = (childIndex * 2) + 2;
    } while (childIndex < heapCount);

    if (childIndex == heapCount) {
      CopyHeapElement72Partial(heapBase[writeIndex], heapBase[heapCount - 1]);
    }
  }

  SiftUpHeapElement72ByKeyWithDisplacedPartialLane(
    heapBase,
    rootFloorIndex,
    writeIndex,
    displaced.lane00,
    displaced.lane04,
    displaced.lane08,
    displaced.lane0C,
    displaced.lane10,
    displaced.lane14,
    displaced.lane18,
    displaced.lane1C,
    displaced.lane20,
    displaced.lane28,
    displaced.lane30
  );
}

/**
 * Address: 0x00575950 (FUN_00575950)
 *
 * What it does:
 * Copies the current heap root into `destinationSlot`, then restores heap
 * order for `[heapBegin, destinationSlot)` using one prepared displaced lane.
 */
[[maybe_unused]] void PromoteHeapElement72RootAndRepairPrefix(
  HeapElement72FloatKeyFastVectorN2Lane* const destinationSlot,
  HeapElement72FloatKeyFastVectorN2Lane* const heapBegin,
  const HeapElement72FloatKeyFastVectorN2Lane& displacedLane
)
{
  (void)CopyHeapElement72PartialLane(heapBegin, destinationSlot);

  HeapElement72FloatKeyFastVectorN2Lane displacedCopy{};
  (void)CopyHeapElement72WithResizeLane(&displacedLane, &displacedCopy);
  const HeapElement72PartialSnapshot displacedSnapshot = CaptureHeapElement72Partial(displacedCopy);
  const int heapCount = static_cast<int>(destinationSlot - heapBegin);
  SiftDownThenInsertHeapElement72ByKey(heapBegin, 0, heapCount, displacedSnapshot);
}

/**
 * Address: 0x00575490 (FUN_00575490)
 *
 * What it does:
 * Performs one lane72 heap-pop pass for `[begin, end)`: captures the
 * predecessor lane as displaced payload and repairs the remaining heap prefix.
 */
[[maybe_unused]] int PopHeapElement72RootFromRange(
  HeapElement72FloatKeyFastVectorN2Lane* const end,
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  const std::uint32_t
)
{
  const int heapCount = static_cast<int>(end - begin);
  if (heapCount > 1) {
    HeapElement72FloatKeyFastVectorN2Lane* const predecessor = end - 1;
    HeapElement72FloatKeyFastVectorN2Lane displaced{};
    (void)CopyHeapElement72WithResizeLane(predecessor, &displaced);
    PromoteHeapElement72RootAndRepairPrefix(predecessor, begin, displaced);
  }
  return heapCount;
}

/**
 * Address: 0x00575660 (FUN_00575660)
 *
 * What it does:
 * Register-shape adapter that forwards one lane72 root-pop repair using
 * `cursorAfterPredecessor - 1` as displaced lane source.
 */
[[maybe_unused]] int PopHeapElement72RootRegisterAdapter(
  HeapElement72FloatKeyFastVectorN2Lane* const cursorAfterPredecessor,
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  const std::uint32_t
)
{
  HeapElement72FloatKeyFastVectorN2Lane* const predecessor = cursorAfterPredecessor - 1;
  HeapElement72FloatKeyFastVectorN2Lane displaced{};
  (void)CopyHeapElement72WithResizeLane(predecessor, &displaced);
  PromoteHeapElement72RootAndRepairPrefix(predecessor, begin, displaced);
  return static_cast<int>(predecessor - begin);
}

/**
 * Address: 0x00574A30 (FUN_00574A30)
 *
 * What it does:
 * Builds one lane72 min-heap over `[begin, end)` by walking parent roots from
 * the last internal node to root and applying recovered sift-down insertion.
 */
[[maybe_unused]] int BuildHeapElement72RangeByKey(
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  HeapElement72FloatKeyFastVectorN2Lane* const end,
  const std::uint32_t
)
{
  int result = static_cast<int>(end - begin);
  result -= (result >> 31);

  int rootIndex = result / 2;
  if (rootIndex > 0) {
    do {
      --rootIndex;
      HeapElement72FloatKeyFastVectorN2Lane displaced{};
      CopyHeapElement72Partial(displaced, begin[rootIndex]);
      const HeapElement72PartialSnapshot displacedSnapshot = CaptureHeapElement72Partial(displaced);
      SiftDownThenInsertHeapElement72ByKey(begin, rootIndex, result, displacedSnapshot);
    } while (rootIndex > 0);
  }

  return result;
}

/**
 * Address: 0x00574B40 (FUN_00574B40)
 *
 * What it does:
 * Repeatedly pops one lane72 heap root into the tail lane and repairs the
 * remaining prefix until the heap window shrinks to one element.
 */
[[maybe_unused]] int SortHeapElement72RangeByKey(
  HeapElement72FloatKeyFastVectorN2Lane* const end,
  HeapElement72FloatKeyFastVectorN2Lane* const begin,
  const std::uint32_t
)
{
  int result = static_cast<int>(end - begin);
  if (result > 1) {
    HeapElement72FloatKeyFastVectorN2Lane* predecessor = end - 1;
    do {
      HeapElement72FloatKeyFastVectorN2Lane displaced{};
      CopyHeapElement72Partial(displaced, *predecessor);
      PromoteHeapElement72RootAndRepairPrefix(predecessor, begin, displaced);
      --predecessor;
      result = static_cast<int>((predecessor + 1) - begin);
    } while (result > 1);
  }
  return result;
}

struct FloatDwordPairSortLane
{
  float key = 0.0f;
  std::uint32_t payload = 0;
};
static_assert(sizeof(FloatDwordPairSortLane) == 0x08, "FloatDwordPairSortLane size must be 0x08");

/**
 * Address: 0x00A73B30 (FUN_00A73B30)
 *
 * What it does:
 * Performs in-place insertion sort over one contiguous `[begin, end)` range
 * of `{float key, dword payload}` records using ascending key order.
 */
[[maybe_unused]] void SortFloatDwordPairRangeByKey(
  FloatDwordPairSortLane* const begin,
  FloatDwordPairSortLane* const end
) noexcept
{
  if (begin == nullptr || end == nullptr || begin == end) {
    return;
  }

  for (FloatDwordPairSortLane* current = begin + 1; current != end; ++current) {
    const FloatDwordPairSortLane value = *current;
    FloatDwordPairSortLane* insertion = current;
    while (insertion != begin && (insertion - 1)->key > value.key) {
      *insertion = *(insertion - 1);
      --insertion;
    }
    *insertion = value;
  }
}

struct StringIntHeapLane
{
  const char* key = nullptr;
  std::int32_t value = 0;
};
static_assert(sizeof(StringIntHeapLane) == 0x08, "StringIntHeapLane size must be 0x08");

struct StringPointerQuintHeapLane
{
  const char* key = nullptr;   // +0x00
  const char* lane04 = nullptr;// +0x04
  const char* lane08 = nullptr;// +0x08
  const char* lane0C = nullptr;// +0x0C
  const char* lane10 = nullptr;// +0x10
};
static_assert(sizeof(StringPointerQuintHeapLane) == 0x14, "StringPointerQuintHeapLane size must be 0x14");

/**
 * Address: 0x005501E0 (FUN_005501E0)
 *
 * What it does:
 * Sifts one `{const char* key, int value}` lane up a binary max-heap ordered
 * by `(key, value)` and stores the insertion lane at its final position.
 */
[[maybe_unused]] const char* SiftUpStringIntHeapLane(
  StringIntHeapLane* const heapBase,
  const std::int32_t insertIndex,
  const std::int32_t rootFloorIndex,
  const char* const key,
  const std::int32_t value
) noexcept
{
  std::int32_t writeIndex = insertIndex;
  std::int32_t parentIndex = (insertIndex - 1) / 2;
  while (rootFloorIndex < writeIndex) {
    const StringIntHeapLane& parent = heapBase[parentIndex];
    const std::int32_t keyCompare = std::strcmp(parent.key ? parent.key : "", key ? key : "");
    const bool parentStrictlyLess = (keyCompare < 0) || (keyCompare == 0 && parent.value < value);
    if (!parentStrictlyLess) {
      break;
    }

    heapBase[writeIndex] = parent;
    writeIndex = parentIndex;
    parentIndex = (parentIndex - 1) / 2;
  }

  heapBase[writeIndex].key = key;
  heapBase[writeIndex].value = value;
  return key;
}

/**
 * Address: 0x0054FD90 (FUN_0054FD90)
 *
 * What it does:
 * Sifts one string/int heap hole down through the max-heap child lanes, then
 * reinserts the displaced lane with the standard sift-up step.
 */
[[maybe_unused]] const char* SiftDownThenInsertStringIntHeapLane(
  StringIntHeapLane* const heapBase,
  const std::int32_t rootFloorIndex,
  const std::int32_t heapCount,
  const char* const displacedKey,
  const std::int32_t displacedValue
) noexcept
{
  std::int32_t writeIndex = rootFloorIndex;
  std::int32_t childIndex = (2 * writeIndex) + 2;
  while (childIndex < heapCount) {
    const StringIntHeapLane& rightChild = heapBase[childIndex];
    const StringIntHeapLane& leftChild = heapBase[childIndex - 1];
    const std::int32_t keyCompare =
      std::strcmp(rightChild.key ? rightChild.key : "", leftChild.key ? leftChild.key : "");
    const bool chooseLeftChild = (keyCompare < 0) || (keyCompare == 0 && rightChild.value < leftChild.value);
    if (chooseLeftChild) {
      --childIndex;
    }

    heapBase[writeIndex] = heapBase[childIndex];
    writeIndex = childIndex;
    childIndex = (2 * childIndex) + 2;
  }

  if (childIndex == heapCount && heapCount > 0) {
    heapBase[writeIndex] = heapBase[heapCount - 1];
    writeIndex = heapCount - 1;
  }

  return SiftUpStringIntHeapLane(heapBase, writeIndex, rootFloorIndex, displacedKey, displacedValue);
}

/**
 * Address: 0x005502C0 (FUN_005502C0)
 *
 * What it does:
 * Rotates one contiguous string/int heap lane range left around `middle`
 * using the binary's gcd-cycle move strategy.
 */
[[maybe_unused]] int RotateStringIntHeapRangeByGcdCycles(
  StringIntHeapLane* const begin,
  StringIntHeapLane* const middle,
  StringIntHeapLane* const end
) noexcept
{
  const std::int32_t leftCount = static_cast<std::int32_t>(middle - begin);
  const std::int32_t totalCount = static_cast<std::int32_t>(end - begin);
  std::int32_t cycleCount = leftCount;
  std::int32_t remainder = totalCount;
  while (cycleCount != 0) {
    const std::int32_t next = remainder % cycleCount;
    remainder = cycleCount;
    cycleCount = next;
  }

  const std::int32_t gcdCycles = remainder;
  if (gcdCycles <= 0 || gcdCycles >= totalCount) {
    return gcdCycles;
  }

  for (std::int32_t cycle = 0; cycle < gcdCycles; ++cycle) {
    const StringIntHeapLane saved = begin[cycle];
    std::int32_t write = cycle;
    while (true) {
      std::int32_t read = write + leftCount;
      if (read >= totalCount) {
        read -= totalCount;
      }
      if (read == cycle) {
        break;
      }
      begin[write] = begin[read];
      write = read;
    }
    begin[write] = saved;
  }

  return gcdCycles;
}

/**
 * Address: 0x0054FEB0 (FUN_0054FEB0)
 *
 * What it does:
 * Register-shape adapter for string/int heap range rotation.
 */
[[maybe_unused]] int RotateStringIntHeapRangeRegisterAdapter(
  StringIntHeapLane* const begin,
  StringIntHeapLane* const middle,
  StringIntHeapLane* const end
) noexcept
{
  return RotateStringIntHeapRangeByGcdCycles(begin, middle, end);
}

/**
 * Address: 0x00550280 (FUN_00550280)
 *
 * What it does:
 * Promotes one predecessor lane into the root hole and restores heap order
 * through the binary sift-down/sift-up lane.
 */
[[maybe_unused]] const char* PromoteStringIntHeapRootFromPreviousLane(
  StringIntHeapLane* const heapBase,
  StringIntHeapLane* const cursorAfterPredecessor,
  const std::int32_t
) noexcept
{
  StringIntHeapLane* const predecessor = cursorAfterPredecessor - 1;
  const StringIntHeapLane displaced = *predecessor;
  *predecessor = *heapBase;
  const std::int32_t heapCount = static_cast<std::int32_t>(predecessor - heapBase);
  return SiftDownThenInsertStringIntHeapLane(heapBase, 0, heapCount, displaced.key, displaced.value);
}

/**
 * Address: 0x00550450 (FUN_00550450)
 *
 * What it does:
 * Writes one source lane to `destination`, then reorders the leading heap
 * range with one displaced `(key,value)` lane.
 */
[[maybe_unused]] const char* PromoteStringIntHeapRootWithExplicitDisplacedLane(
  const StringIntHeapLane* const heapBase,
  const StringIntHeapLane* const heapCursor,
  StringIntHeapLane* const destination,
  const std::int32_t,
  const char* const displacedKey,
  const std::int32_t displacedValue
) noexcept
{
  *destination = *heapBase;
  const std::int32_t heapCount = static_cast<std::int32_t>(heapCursor - heapBase);
  return SiftDownThenInsertStringIntHeapLane(
    const_cast<StringIntHeapLane*>(heapBase),
    0,
    heapCount,
    displacedKey,
    displacedValue
  );
}

/**
 * Address: 0x008DA500 (FUN_008DA500)
 *
 * What it does:
 * Sifts one 20-byte `{const char* x5}` lane up a binary max-heap ordered by
 * lexical `key` and stores that lane at its final heap position.
 */
[[maybe_unused]] StringPointerQuintHeapLane* SiftUpStringPointerQuintHeapLane(
  StringPointerQuintHeapLane* const heapBase,
  const std::int32_t insertIndex,
  const std::int32_t rootFloorIndex,
  const char* const key,
  const char* const lane04,
  const char* const lane08,
  const char* const lane0C,
  const char* const lane10
) noexcept
{
  std::int32_t writeIndex = insertIndex;
  std::int32_t parentIndex = (insertIndex - 1) / 2;
  while (rootFloorIndex < writeIndex) {
    const StringPointerQuintHeapLane& parent = heapBase[parentIndex];
    if (std::strcmp(parent.key, key) >= 0) {
      break;
    }

    heapBase[writeIndex] = parent;
    writeIndex = parentIndex;
    parentIndex = (parentIndex - 1) / 2;
  }

  StringPointerQuintHeapLane& destination = heapBase[writeIndex];
  destination.key = key;
  destination.lane04 = lane04;
  destination.lane08 = lane08;
  destination.lane0C = lane0C;
  destination.lane10 = lane10;
  return &destination;
}

/**
 * Address: 0x00595F40 (FUN_00595F40)
 *
 * What it does:
 * Sifts one 12-byte `{dword,dword,float key}` lane up a binary max-heap
 * ordered by floating-point key and stores the insertion lane at its final
 * position.
 */
[[maybe_unused]] HeapElement12FloatKeyLane* SiftUpFloatKeyHeapElement12Lane(
  HeapElement12FloatKeyLane* const heapBase,
  const std::int32_t insertIndex,
  const std::int32_t rootFloorIndex,
  const std::uint32_t lane0,
  const std::uint32_t lane1,
  const float key
) noexcept
{
  std::int32_t writeIndex = insertIndex;
  std::int32_t parentIndex = (writeIndex - 1) / 2;
  while (rootFloorIndex < writeIndex) {
    const HeapElement12FloatKeyLane& parent = heapBase[parentIndex];
    if (!(key > parent.key)) {
      break;
    }

    heapBase[writeIndex] = parent;
    writeIndex = parentIndex;
    parentIndex = (parentIndex - 1) / 2;
  }

  HeapElement12FloatKeyLane& destination = heapBase[writeIndex];
  destination.lane0 = lane0;
  destination.lane1 = lane1;
  destination.key = key;
  return &destination;
}

/**
 * Address: 0x0054EC30 (FUN_0054EC30)
 * Address: 0x00A72C30 (FUN_00A72C30)
 *
 * What it does:
 * Writes one 8-byte `{dword,dword}` value from `valuePtr` into `count`
 * consecutive destination lanes and returns one-past-last destination lane,
 * preserving legacy null-destination guard semantics.
 */
[[maybe_unused]] VectorElement8DwordPairLane* FillDwordPairArrayFromValuePointerNullable(
  std::uint32_t count,
  const VectorElement8DwordPairLane* const valuePtr,
  VectorElement8DwordPairLane* destination
) noexcept
{
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (count != 0u) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<VectorElement8DwordPairLane*>(destinationAddress) = *valuePtr;
    }

    --count;
    destinationAddress += sizeof(VectorElement8DwordPairLane);
  }

  return reinterpret_cast<VectorElement8DwordPairLane*>(destinationAddress);
}

/**
 * Address: 0x0054DCC0 (FUN_0054DCC0)
 *
 * What it does:
 * Register-shape adapter that fills one dword-pair lane range from a single
 * source value and returns the destination end lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* FillDwordPairArrayFromValueRegisterAdapterLaneA(
  const VectorElement8DwordPairLane* const valuePtr,
  VectorElement8DwordPairLane* const destination,
  const std::uint32_t count
) noexcept
{
  return FillDwordPairArrayFromValuePointerNullable(count, valuePtr, destination);
}

/**
 * Address: 0x0054E2F0 (FUN_0054E2F0)
 *
 * What it does:
 * Secondary register-shape adapter for the same dword-pair range fill helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane* FillDwordPairArrayFromValueRegisterAdapterLaneB(
  const VectorElement8DwordPairLane* const valuePtr,
  VectorElement8DwordPairLane* const destination,
  const std::uint32_t count
) noexcept
{
  return FillDwordPairArrayFromValuePointerNullable(count, valuePtr, destination);
}

/**
 * Address: 0x00A72C70 (FUN_00A72C70)
 *
 * What it does:
 * Writes one 16-byte `{dword,dword,dword,dword}` value from `valuePtr` into
 * `count` consecutive destination lanes and returns one-past-last destination
 * lane, preserving legacy null-destination guard semantics.
 */
[[maybe_unused]] VectorElement16DwordQuadLane* FillDwordQuadArrayFromValuePointerNullable(
  std::uint32_t count,
  const VectorElement16DwordQuadLane* const valuePtr,
  VectorElement16DwordQuadLane* destination
) noexcept
{
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (count != 0u) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<VectorElement16DwordQuadLane*>(destinationAddress) = *valuePtr;
    }

    --count;
    destinationAddress += sizeof(VectorElement16DwordQuadLane);
  }

  return reinterpret_cast<VectorElement16DwordQuadLane*>(destinationAddress);
}

/**
 * Address: 0x00A73060 (FUN_00A73060)
 *
 * What it does:
 * Cdecl-lane adapter that forwards one dword-pair range fill request to the
 * canonical nullable destination helper.
 */
[[maybe_unused]] int FillDwordPairArrayFromValuePointerNullableCdeclAdapterLaneA(
  const int destinationAddress,
  const int count,
  const int valueAddress
) noexcept
{
  return static_cast<int>(reinterpret_cast<std::uintptr_t>(
    FillDwordPairArrayFromValuePointerNullable(
      static_cast<std::uint32_t>(count),
      reinterpret_cast<const VectorElement8DwordPairLane*>(static_cast<std::uintptr_t>(valueAddress)),
      reinterpret_cast<VectorElement8DwordPairLane*>(static_cast<std::uintptr_t>(destinationAddress))
    )
  ));
}

/**
 * Address: 0x00A730A0 (FUN_00A730A0)
 *
 * What it does:
 * Cdecl-lane adapter that forwards one dword-quad range fill request to the
 * canonical nullable destination helper.
 */
[[maybe_unused]] int FillDwordQuadArrayFromValuePointerNullableCdeclAdapterLaneA(
  const int destinationAddress,
  const int count,
  const int valueAddress
) noexcept
{
  return static_cast<int>(reinterpret_cast<std::uintptr_t>(
    FillDwordQuadArrayFromValuePointerNullable(
      static_cast<std::uint32_t>(count),
      reinterpret_cast<const VectorElement16DwordQuadLane*>(static_cast<std::uintptr_t>(valueAddress)),
      reinterpret_cast<VectorElement16DwordQuadLane*>(static_cast<std::uintptr_t>(destinationAddress))
    )
  ));
}

/**
 * Address: 0x00A73D50 (FUN_00A73D50)
 *
 * What it does:
 * Stdcall-lane adapter that fills one dword-pair range and returns the
 * destination end-address lane.
 */
[[maybe_unused]] int FillDwordPairArrayFromValuePointerNullableStdcallAdapterLaneA(
  const int destinationAddress,
  const int count,
  const int valueAddress
) noexcept
{
  (void)FillDwordPairArrayFromValuePointerNullable(
    static_cast<std::uint32_t>(count),
    reinterpret_cast<const VectorElement8DwordPairLane*>(static_cast<std::uintptr_t>(valueAddress)),
    reinterpret_cast<VectorElement8DwordPairLane*>(static_cast<std::uintptr_t>(destinationAddress))
  );
  return destinationAddress + (static_cast<int>(sizeof(VectorElement8DwordPairLane)) * count);
}

/**
 * Address: 0x00A73DA0 (FUN_00A73DA0)
 *
 * What it does:
 * Stdcall-lane adapter that fills one dword-quad range and returns the
 * destination end-address lane.
 */
[[maybe_unused]] int FillDwordQuadArrayFromValuePointerNullableStdcallAdapterLaneA(
  const int destinationAddress,
  const int count,
  const int valueAddress
) noexcept
{
  (void)FillDwordQuadArrayFromValuePointerNullable(
    static_cast<std::uint32_t>(count),
    reinterpret_cast<const VectorElement16DwordQuadLane*>(static_cast<std::uintptr_t>(valueAddress)),
    reinterpret_cast<VectorElement16DwordQuadLane*>(static_cast<std::uintptr_t>(destinationAddress))
  );
  return destinationAddress + (static_cast<int>(sizeof(VectorElement16DwordQuadLane)) * count);
}

namespace
{
struct HeapEntryFloatPayloadLane
{
  float key = 0.0f;          // +0x00
  std::uint32_t payload = 0; // +0x04
};
static_assert(sizeof(HeapEntryFloatPayloadLane) == 0x08, "HeapEntryFloatPayloadLane size must be 0x08");

struct HeapEntryDoublePayloadLane
{
  double key = 0.0;          // +0x00
  std::uint32_t lane08 = 0;  // +0x08
  std::uint32_t lane0C = 0;  // +0x0C
};
static_assert(sizeof(HeapEntryDoublePayloadLane) == 0x10, "HeapEntryDoublePayloadLane size must be 0x10");

[[nodiscard]] std::uint32_t SiftUpHeapEntryFloatPayloadLaneLocal(
  HeapEntryFloatPayloadLane* const heapEntries,
  int insertIndex,
  const int heapFloorIndex,
  const float key,
  const std::uint32_t payload
) noexcept
{
  while (heapFloorIndex < insertIndex) {
    const int parentIndex = (insertIndex - 1) / 2;
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

[[nodiscard]] int SiftDownThenSiftUpHeapEntryFloatPayloadLaneLocal(
  HeapEntryFloatPayloadLane* const heapEntries,
  const int rootIndex,
  const int tailIndex,
  const float key,
  const std::uint32_t payload
) noexcept
{
  int writeIndex = rootIndex;
  int childIndex = (2 * rootIndex) + 2;
  bool childEqualsTail = (childIndex == tailIndex);
  while (childIndex < tailIndex) {
    if (heapEntries[childIndex - 1].key > heapEntries[childIndex].key) {
      --childIndex;
    }

    heapEntries[writeIndex] = heapEntries[childIndex];
    writeIndex = childIndex;
    childIndex = (2 * childIndex) + 2;
    childEqualsTail = (childIndex == tailIndex);
  }

  if (childEqualsTail) {
    heapEntries[writeIndex] = heapEntries[tailIndex - 1];
    writeIndex = tailIndex - 1;
  }

  return static_cast<int>(SiftUpHeapEntryFloatPayloadLaneLocal(heapEntries, writeIndex, rootIndex, key, payload));
}

[[nodiscard]] std::uint32_t SiftUpHeapEntryDoublePayloadLaneLocal(
  HeapEntryDoublePayloadLane* const heapEntries,
  int insertIndex,
  const int heapFloorIndex,
  const double key,
  const std::uint32_t lane08,
  const std::uint32_t lane0C
) noexcept
{
  while (heapFloorIndex < insertIndex) {
    const int parentIndex = (insertIndex - 1) / 2;
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
  return static_cast<std::uint32_t>(keyBits >> 32u);
}

[[nodiscard]] int SiftDownThenSiftUpHeapEntryDoublePayloadLaneLocal(
  HeapEntryDoublePayloadLane* const heapEntries,
  const int rootIndex,
  const int tailIndex,
  const double key,
  const std::uint32_t lane08,
  const std::uint32_t lane0C
) noexcept
{
  int writeIndex = rootIndex;
  int childIndex = (2 * rootIndex) + 2;
  bool childEqualsTail = (childIndex == tailIndex);
  while (childIndex < tailIndex) {
    if (heapEntries[childIndex - 1].key > heapEntries[childIndex].key) {
      --childIndex;
    }

    heapEntries[writeIndex] = heapEntries[childIndex];
    writeIndex = childIndex;
    childIndex = (2 * childIndex) + 2;
    childEqualsTail = (childIndex == tailIndex);
  }

  if (childEqualsTail) {
    heapEntries[writeIndex] = heapEntries[tailIndex - 1];
    writeIndex = tailIndex - 1;
  }

  return static_cast<int>(SiftUpHeapEntryDoublePayloadLaneLocal(heapEntries, writeIndex, rootIndex, key, lane08, lane0C));
}
} // namespace

/**
 * Address: 0x00A73E20 (FUN_00A73E20)
 *
 * What it does:
 * Repeatedly removes one max-heap root from a `{float key, dword payload}`
 * lane range and repairs heap order for the remaining prefix.
 */
[[maybe_unused]] int PopHeapRootFloatPayloadRange(
  VectorElement8DwordPairLane* const begin,
  VectorElement8DwordPairLane* const end
) noexcept
{
  int byteSpan =
    static_cast<int>(reinterpret_cast<std::uintptr_t>(end) - reinterpret_cast<std::uintptr_t>(begin));
  int result = byteSpan >> 3;
  if (result > 1) {
    do {
      auto* const heapEntries = reinterpret_cast<HeapEntryFloatPayloadLane*>(begin);
      const HeapEntryFloatPayloadLane displaced = heapEntries[(byteSpan >> 3) - 1];
      heapEntries[(byteSpan >> 3) - 1] = heapEntries[0];
      (void)SiftDownThenSiftUpHeapEntryFloatPayloadLaneLocal(
        heapEntries,
        0,
        (byteSpan - 8) >> 3,
        displaced.key,
        displaced.payload
      );
      byteSpan -= 8;
      result = byteSpan >> 3;
    } while ((byteSpan >> 3) > 1);
  }
  return result;
}

/**
 * Address: 0x00A73E70 (FUN_00A73E70)
 *
 * What it does:
 * Repeatedly removes one max-heap root from a
 * `{double key, dword, dword}` lane range and repairs heap order for the
 * remaining prefix.
 */
[[maybe_unused]] int PopHeapRootDoublePayloadRange(
  VectorElement16DwordQuadLane* const begin,
  VectorElement16DwordQuadLane* const end
) noexcept
{
  int byteSpan =
    static_cast<int>(reinterpret_cast<std::uintptr_t>(end) - reinterpret_cast<std::uintptr_t>(begin));
  int result = byteSpan >> 4;
  if (result > 1) {
    do {
      auto* const heapEntries = reinterpret_cast<HeapEntryDoublePayloadLane*>(begin);
      const HeapEntryDoublePayloadLane displaced = heapEntries[(byteSpan >> 4) - 1];
      heapEntries[(byteSpan >> 4) - 1] = heapEntries[0];
      (void)SiftDownThenSiftUpHeapEntryDoublePayloadLaneLocal(
        heapEntries,
        0,
        (byteSpan - 16) >> 4,
        displaced.key,
        displaced.lane08,
        displaced.lane0C
      );
      byteSpan -= 16;
      result = byteSpan >> 4;
    } while ((byteSpan >> 4) > 1);
  }
  return result;
}

/**
 * Address: 0x00A73F50 (FUN_00A73F50)
 * Address: 0x004FBC10 (FUN_004FBC10)
 *
 * What it does:
 * Thunk lane that forwards one 8-byte heap pop/repair pass to the canonical
 * helper.
 */
[[maybe_unused]] int PopHeapRootFloatPayloadRangeThunk(
  std::uint32_t* const begin,
  const int endAddress
) noexcept
{
  return PopHeapRootFloatPayloadRange(
    reinterpret_cast<VectorElement8DwordPairLane*>(begin),
    reinterpret_cast<VectorElement8DwordPairLane*>(static_cast<std::uintptr_t>(endAddress))
  );
}

/**
 * Address: 0x00A73F60 (FUN_00A73F60)
 *
 * What it does:
 * Thunk lane that forwards one 16-byte heap pop/repair pass to the canonical
 * helper.
 */
[[maybe_unused]] int PopHeapRootDoublePayloadRangeThunk(
  std::uint32_t* const begin,
  const int endAddress
) noexcept
{
  return PopHeapRootDoublePayloadRange(
    reinterpret_cast<VectorElement16DwordQuadLane*>(begin),
    reinterpret_cast<VectorElement16DwordQuadLane*>(static_cast<std::uintptr_t>(endAddress))
  );
}

struct VectorElement8StorageRuntimeView
{
  void* reservedProxy = nullptr;                // +0x00
  VectorElement8DwordPairLane* first = nullptr; // +0x04
  VectorElement8DwordPairLane* last = nullptr;  // +0x08
  VectorElement8DwordPairLane* end = nullptr;   // +0x0C
};
static_assert(sizeof(VectorElement8StorageRuntimeView) == 0x10, "VectorElement8StorageRuntimeView size must be 0x10");
static_assert(offsetof(VectorElement8StorageRuntimeView, first) == 0x04, "VectorElement8StorageRuntimeView::first offset must be 0x04");
static_assert(offsetof(VectorElement8StorageRuntimeView, last) == 0x08, "VectorElement8StorageRuntimeView::last offset must be 0x08");
static_assert(offsetof(VectorElement8StorageRuntimeView, end) == 0x0C, "VectorElement8StorageRuntimeView::end offset must be 0x0C");

struct VectorElement16StorageRuntimeView
{
  void* reservedProxy = nullptr;                 // +0x00
  VectorElement16DwordQuadLane* first = nullptr; // +0x04
  VectorElement16DwordQuadLane* last = nullptr;  // +0x08
  VectorElement16DwordQuadLane* end = nullptr;   // +0x0C
};
static_assert(sizeof(VectorElement16StorageRuntimeView) == 0x10, "VectorElement16StorageRuntimeView size must be 0x10");
static_assert(
  offsetof(VectorElement16StorageRuntimeView, first) == 0x04,
  "VectorElement16StorageRuntimeView::first offset must be 0x04"
);
static_assert(
  offsetof(VectorElement16StorageRuntimeView, last) == 0x08,
  "VectorElement16StorageRuntimeView::last offset must be 0x08"
);
static_assert(
  offsetof(VectorElement16StorageRuntimeView, end) == 0x0C,
  "VectorElement16StorageRuntimeView::end offset must be 0x0C"
);

/**
 * Address: 0x005EC680 (FUN_005EC680)
 * Address: 0x005EC6F0 (FUN_005EC6F0)
 * Address: 0x005EC7A0 (FUN_005EC7A0)
 * Address: 0x005ECC10 (FUN_005ECC10)
 * Address: 0x005ECE50 (FUN_005ECE50)
 * Address: 0x005ECE80 (FUN_005ECE80)
 *
 * What it does:
 * Swaps the three active storage lanes (`first/last/end`) between two 16-byte
 * vector storage views while preserving each side's reserved proxy lane.
 */
[[maybe_unused]] [[nodiscard]] VectorElement16StorageRuntimeView* SwapVectorElement16StorageTailLanes(
  VectorElement16StorageRuntimeView* const left,
  VectorElement16StorageRuntimeView* const right
) noexcept
{
  auto* lane = right->first;
  right->first = left->first;
  left->first = lane;

  lane = right->last;
  right->last = left->last;
  left->last = lane;

  lane = right->end;
  right->end = left->end;
  left->end = lane;
  return left;
}

template <std::size_t kInlineDwordCount>
struct EmbeddedInlineDwordSpanRuntimeView
{
  std::uint32_t* lane00; // +0x00
  std::uint32_t* lane04; // +0x04
  std::uint32_t* lane08; // +0x08
  std::uint32_t* lane0C; // +0x0C
  std::uint32_t inlineStorage[kInlineDwordCount]; // +0x10
};

using EmbeddedInlineDwordSpan5RuntimeView = EmbeddedInlineDwordSpanRuntimeView<5u>;
using EmbeddedInlineDwordSpan15RuntimeView = EmbeddedInlineDwordSpanRuntimeView<15u>;

static_assert(sizeof(EmbeddedInlineDwordSpan5RuntimeView) == 0x24, "EmbeddedInlineDwordSpan5RuntimeView size must be 0x24");
static_assert(
  sizeof(EmbeddedInlineDwordSpan15RuntimeView) == 0x4C,
  "EmbeddedInlineDwordSpan15RuntimeView size must be 0x4C"
);
static_assert(
  offsetof(EmbeddedInlineDwordSpan5RuntimeView, inlineStorage) == 0x10,
  "EmbeddedInlineDwordSpan5RuntimeView::inlineStorage offset must be 0x10"
);
static_assert(
  offsetof(EmbeddedInlineDwordSpan15RuntimeView, inlineStorage) == 0x10,
  "EmbeddedInlineDwordSpan15RuntimeView::inlineStorage offset must be 0x10"
);

template <std::size_t kInlineDwordCount>
[[nodiscard]] EmbeddedInlineDwordSpanRuntimeView<kInlineDwordCount>* InitializeEmbeddedInlineDwordSpan(
  EmbeddedInlineDwordSpanRuntimeView<kInlineDwordCount>* const span
) noexcept
{
  std::uint32_t* const inlineBegin = span->inlineStorage;
  span->lane00 = inlineBegin;
  span->lane04 = inlineBegin;
  span->lane08 = inlineBegin + kInlineDwordCount;
  span->lane0C = inlineBegin;
  return span;
}

/**
 * Address: 0x005FBC10 (FUN_005FBC10)
 *
 * What it does:
 * Initializes one 5-dword embedded inline span lane to empty begin/cursor
 * with `end` pointed at the inline-storage limit.
 */
[[maybe_unused]] [[nodiscard]] EmbeddedInlineDwordSpan5RuntimeView* InitializeEmbeddedInlineDwordSpan5(
  EmbeddedInlineDwordSpan5RuntimeView* const span
) noexcept
{
  return InitializeEmbeddedInlineDwordSpan(span);
}

/**
 * Address: 0x00605390 (FUN_00605390)
 *
 * What it does:
 * Initializes one 15-dword embedded inline span lane to empty begin/cursor
 * with `end` pointed at the inline-storage limit.
 */
[[maybe_unused]] [[nodiscard]] EmbeddedInlineDwordSpan15RuntimeView* InitializeEmbeddedInlineDwordSpan15(
  EmbeddedInlineDwordSpan15RuntimeView* const span
) noexcept
{
  return InitializeEmbeddedInlineDwordSpan(span);
}

/**
 * Address: 0x00A74370 (FUN_00A74370)
 *
 * What it does:
 * Initializes one 8-byte vector storage lane to `count` elements filled from
 * `*fillValue`, throwing the VC8 vector-overflow diagnostic on oversize
 * counts.
 */
[[maybe_unused]] int InitializeFilled8ByteVectorStorageLane(
  VectorElement8StorageRuntimeView* const storage,
  const unsigned int count,
  const VectorElement8DwordPairLane* const fillValue
)
{
  int result = 0;
  storage->first = nullptr;
  storage->last = nullptr;
  storage->end = nullptr;
  if (count != 0u) {
    if (count > 0x1FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    auto* const begin = static_cast<VectorElement8DwordPairLane*>(
      AllocateCheckedElementBlock(count, static_cast<std::uint32_t>(sizeof(VectorElement8DwordPairLane)))
    );
    storage->end = begin + count;
    storage->first = begin;
    storage->last = begin;

    result = static_cast<int>(reinterpret_cast<std::uintptr_t>(
      FillDwordPairArrayFromValuePointerNullable(count, fillValue, begin)
    ));
    storage->last = begin + count;
  }
  return result;
}

/**
 * Address: 0x00A74430 (FUN_00A74430)
 *
 * What it does:
 * Initializes one 16-byte vector storage lane to `count` elements filled from
 * `*fillValue`, throwing the VC8 vector-overflow diagnostic on oversize
 * counts.
 */
[[maybe_unused]] int InitializeFilled16ByteVectorStorageLane(
  VectorElement16StorageRuntimeView* const storage,
  const unsigned int count,
  const VectorElement16DwordQuadLane* const fillValue
)
{
  int result = 0;
  storage->first = nullptr;
  storage->last = nullptr;
  storage->end = nullptr;
  if (count != 0u) {
    if (count > 0x0FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    auto* const begin = static_cast<VectorElement16DwordQuadLane*>(
      AllocateCheckedElementBlock(count, static_cast<std::uint32_t>(sizeof(VectorElement16DwordQuadLane)))
    );
    storage->end = begin + count;
    storage->first = begin;
    storage->last = begin;

    result = static_cast<int>(reinterpret_cast<std::uintptr_t>(
      FillDwordQuadArrayFromValuePointerNullable(count, fillValue, begin)
    ));
    storage->last = begin + count;
  }
  return result;
}

/**
 * Address: 0x00A744F0 (FUN_00A744F0)
 *
 * What it does:
 * Initializes one 8-byte vector storage lane to `count` zeroed elements.
 */
[[maybe_unused]] VectorElement8StorageRuntimeView* InitializeZeroFilled8ByteVectorStorageLane(
  VectorElement8StorageRuntimeView* const storage,
  const unsigned int count
)
{
  const VectorElement8DwordPairLane zeroFill{};
  (void)InitializeFilled8ByteVectorStorageLane(storage, count, &zeroFill);
  return storage;
}

/**
 * Address: 0x00A74520 (FUN_00A74520)
 *
 * What it does:
 * Initializes one 16-byte vector storage lane to `count` zeroed elements.
 */
[[maybe_unused]] VectorElement16StorageRuntimeView* InitializeZeroFilled16ByteVectorStorageLane(
  VectorElement16StorageRuntimeView* const storage,
  const unsigned int count
)
{
  const VectorElement16DwordQuadLane zeroFill{};
  (void)InitializeFilled16ByteVectorStorageLane(storage, count, &zeroFill);
  return storage;
}

/**
 * Address: 0x0054F6B0 (FUN_0054F6B0, func_intp_memcpy)
 *
 * What it does:
 * Copies one half-open dword range `[sourceBegin, sourceEnd)` into
 * destination storage and returns one-past the last written destination lane,
 * preserving the original null-destination guard semantics.
 */
std::uint32_t* CopyDwordRangeNullable(
  std::uint32_t* destination,
  const std::uint32_t* sourceBegin,
  const std::uint32_t* sourceEnd
) noexcept
{
  const std::uint32_t* source = sourceBegin;
  std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
  while (source != sourceEnd) {
    if (destinationAddress != 0u) {
      *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
    }

    ++source;
    destinationAddress += sizeof(std::uint32_t);
  }

  return reinterpret_cast<std::uint32_t*>(destinationAddress);
}

/**
 * Address: 0x0054DEF0 (FUN_0054DEF0)
 *
 * What it does:
 * Stdcall-lane adapter for nullable dword range copy.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableStdcallAdapter(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destination
) noexcept
{
  return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0054E660 (FUN_0054E660)
 *
 * What it does:
 * Cdecl-lane adapter for nullable dword range copy.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableCdeclAdapter(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destination
) noexcept
{
  return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0054D3F0 (FUN_0054D3F0)
 *
 * What it does:
 * Copies one trailing 8-byte lane range from `sourceBegin` through
 * `storage._Mylast`, writes the new `_Mylast`, and stores `destinationBegin`
 * into `*outDestinationBegin`.
 */
[[maybe_unused]] VectorElement8DwordPairLane** CopyDwordPairTailRangeAndUpdateLast(
  VectorElement8DwordPairLane** const outDestinationBegin,
  VectorVoidStorageView& storage,
  VectorElement8DwordPairLane* const destinationBegin,
  const VectorElement8DwordPairLane* const sourceBegin
) noexcept
{
  if (destinationBegin != sourceBegin) {
    VectorElement8DwordPairLane* destination = destinationBegin;
    const VectorElement8DwordPairLane* source = sourceBegin;
    const auto* const sourceEnd = reinterpret_cast<const VectorElement8DwordPairLane*>(storage.last);
    while (source != sourceEnd) {
      *destination = *source;
      ++source;
      ++destination;
    }
    storage.last = reinterpret_cast<void**>(destination);
  }

  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x0053FD00 (FUN_0053FD00)
 *
 * What it does:
 * Copies one 8-byte pair tail left by one slot, shrinks `_Mylast` by one
 * element, and returns the erased destination-begin slot.
 */
[[maybe_unused]] [[nodiscard]] VectorElement8DwordPairLane** EraseDwordPairTailAndReturnBegin(
  VectorElement8DwordPairLane** const outDestinationBegin,
  VectorVoidStorageView& storage,
  VectorElement8DwordPairLane* const destinationBegin
) noexcept
{
  const VectorElement8DwordPairLane* const sourceBegin = destinationBegin + 1;
  const auto* const sourceEnd = reinterpret_cast<const VectorElement8DwordPairLane*>(storage.last);
  if (destinationBegin != sourceBegin) {
    VectorElement8DwordPairLane* destination = destinationBegin;
    const VectorElement8DwordPairLane* source = sourceBegin;
    while (source != sourceEnd) {
      *destination = *source;
      ++source;
      ++destination;
    }
  }

  storage.last = reinterpret_cast<void**>(reinterpret_cast<VectorElement8DwordPairLane*>(storage.last) - 1);
  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x008D7D60 (FUN_008D7D60)
 *
 * What it does:
 * Copies one half-open range of 12-byte `{dword,dword,dword}` lanes from
 * `[sourceBegin, sourceEnd)` into `destinationBegin` and returns one-past-last
 * written destination lane.
 */
[[maybe_unused]] VectorElement12DwordTripleLane* CopyDwordTripleRangeAndReturnEnd(
  const VectorElement12DwordTripleLane* sourceBegin,
  const VectorElement12DwordTripleLane* const sourceEnd,
  VectorElement12DwordTripleLane* destinationBegin
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destinationBegin = *sourceBegin;
    ++sourceBegin;
    ++destinationBegin;
  }

  return destinationBegin;
}

/**
 * Address: 0x008D7AF0 (FUN_008D7AF0)
 *
 * What it does:
 * Relocates one 12-byte lane tail range from `sourceBegin` to `destinationBegin`,
 * updates `_Mylast`, and returns `outDestinationBegin`.
 */
[[maybe_unused]] VectorElement12DwordTripleLane** RelocateDwordTripleTailAndReturnBegin(
  VectorElementCountRuntimeView& storage,
  VectorElement12DwordTripleLane** const outDestinationBegin,
  VectorElement12DwordTripleLane* const destinationBegin,
  const VectorElement12DwordTripleLane* const sourceBegin
) noexcept
{
  if (destinationBegin != sourceBegin) {
    const auto* const sourceEnd = reinterpret_cast<const VectorElement12DwordTripleLane*>(storage.last);
    auto* const destinationEnd = CopyDwordTripleRangeAndReturnEnd(sourceBegin, sourceEnd, destinationBegin);
    storage.last = reinterpret_cast<std::byte*>(destinationEnd);
  }

  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x005838B0 (FUN_005838B0)
 *
 * What it does:
 * Swaps one reverse-walk range of 20-byte `{dword x5}` lanes with another
 * reverse-walk range and returns the resulting left-range begin lane.
 */
[[maybe_unused]] VectorElement20DwordQuintLane* SwapDwordQuintLaneReverseRanges(
  VectorElement20DwordQuintLane* leftRangeEnd,
  VectorElement20DwordQuintLane* rightRangeEnd,
  VectorElement20DwordQuintLane* const rightRangeBegin
) noexcept
{
  while (rightRangeEnd != rightRangeBegin) {
    --leftRangeEnd;
    --rightRangeEnd;
    const VectorElement20DwordQuintLane swapLane = *leftRangeEnd;
    *leftRangeEnd = *rightRangeEnd;
    *rightRangeEnd = swapLane;
  }

  return leftRangeEnd;
}

/**
 * Address: 0x00582390 (FUN_00582390)
 *
 * What it does:
 * Bridges one legacy register/stack wrapper lane into
 * `SwapDwordQuintLaneReverseRanges`.
 */
[[maybe_unused]] [[nodiscard]] VectorElement20DwordQuintLane* SwapDwordQuintLaneReverseRangesRegisterAdapter(
  VectorElement20DwordQuintLane* const leftRangeEnd,
  VectorElement20DwordQuintLane* const rightRangeEnd,
  VectorElement20DwordQuintLane* const rightRangeBegin
) noexcept
{
  return SwapDwordQuintLaneReverseRanges(leftRangeEnd, rightRangeEnd, rightRangeBegin);
}

/**
 * Address: 0x00525FE0 (FUN_00525FE0)
 * Address: 0x005628C0 (FUN_005628C0)
 * Address: 0x005822E0 (FUN_005822E0)
 * Address: 0x006E2CB0 (FUN_006E2CB0)
 * Address: 0x00768EB0 (FUN_00768EB0)
 *
 * What it does:
 * Allocates one checked raw block for 4-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked4ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 4u);
}

/**
 * Address: 0x006E2480 (FUN_006E2480)
 *
 * What it does:
 * Allocates one checked 4-byte-element block for non-zero `count` and
 * preserves VC8 zero-count behavior by returning `operator new(0)`.
 */
[[maybe_unused]] void* AllocateChecked4ByteElementsZeroAware(const std::uint32_t count)
{
  return count != 0u ? AllocateChecked4ByteElements(count) : ::operator new(0);
}

/**
 * Address: 0x006D25B0 (FUN_006D25B0)
 *
 * What it does:
 * Allocates one checked raw block for 8-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked8ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 8u);
}

/**
 * Address: 0x006D1DB0 (FUN_006D1DB0)
 *
 * What it does:
 * Allocates one checked 8-byte-element block for non-zero `count` and
 * preserves VC8 zero-count behavior by returning `operator new(0)`.
 */
[[maybe_unused]] void* AllocateChecked8ByteElementsZeroAware(const std::uint32_t count)
{
  return count != 0u ? AllocateChecked8ByteElements(count) : ::operator new(0);
}

/**
 * Address: 0x00628260 (FUN_00628260)
 * Address: 0x006DDD70 (FUN_006DDD70)
 *
 * What it does:
 * Allocates one checked raw block for 12-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked12ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 12u);
}

/**
 * Address: 0x00627BC0 (FUN_00627BC0)
 *
 * What it does:
 * Preserves VC8 zero-count allocation semantics for 12-byte vector storage
 * lanes by returning `operator new(0)` when `count == 0`.
 */
[[maybe_unused]] void* AllocateChecked12ByteElementsZeroAware(const std::uint32_t count)
{
  return count != 0u ? AllocateChecked12ByteElements(count) : ::operator new(0);
}

/**
 * Address: 0x005111C0 (FUN_005111C0)
 *
 * What it does:
 * Allocates one checked raw block for 16-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked16ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 16u);
}

/**
 * Address: 0x00548B80 (FUN_00548B80)
 *
 * What it does:
 * Allocates one checked raw block for 20-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked20ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 20u);
}

/**
 * Address: 0x005821F0 (FUN_005821F0)
 *
 * What it does:
 * Allocates one checked raw block for 24-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked24ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 24u);
}

/**
 * Address: 0x00693190 (FUN_00693190)
 *
 * What it does:
 * Allocates one checked raw block for 28-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked28ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 28u);
}

/**
 * Address: 0x00692D30 (FUN_00692D30)
 *
 * What it does:
 * Preserves VC8 zero-count allocation semantics for 28-byte vector storage
 * lanes by returning `operator new(0)` when `count == 0`.
 */
[[maybe_unused]] void* AllocateChecked28ByteElementsZeroAware(const std::uint32_t count)
{
  return count != 0u ? AllocateChecked28ByteElements(count) : ::operator new(0);
}

/**
 * Address: 0x00544610 (FUN_00544610)
 * Address: 0x005EC960 (FUN_005EC960)
 *
 * What it does:
 * Allocates one checked raw block for 32-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked32ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 32u);
}

/**
 * Address: 0x004FA650 (FUN_004FA650)
 * Address: 0x006DDC80 (FUN_006DDC80)
 * Address: 0x00704750 (FUN_00704750)
 *
 * What it does:
 * Allocates one checked raw block for 40-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked40ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 40u);
}

/**
 * Address: 0x006DC9D0 (FUN_006DC9D0)
 *
 * What it does:
 * Allocates one checked 40-byte-element block for non-zero `count` and
 * preserves VC8 zero-count behavior by returning `operator new(0)`.
 */
[[maybe_unused]] void* AllocateChecked40ByteElementsZeroAware(const std::uint32_t count)
{
  return count != 0u ? AllocateChecked40ByteElements(count) : ::operator new(0);
}

/**
 * Address: 0x006DC9C0 (FUN_006DC9C0)
 * Address: 0x0078A5C0 (FUN_0078A5C0)
 * Address: 0x0078B5B0 (FUN_0078B5B0)
 *
 * What it does:
 * Releases one vector-runtime storage block through global `operator delete`.
 */
[[maybe_unused]] void DeleteVectorRuntimeStorage(void* const storage) noexcept
{
  ::operator delete(storage);
}

/**
 * Address: 0x005C9F40 (FUN_005C9F40)
 *
 * What it does:
 * Allocates one checked raw block for 52-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked52ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 52u);
}

/**
 * Address: 0x00562850 (FUN_00562850)
 *
 * What it does:
 * Allocates one checked raw block for 120-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked120ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 120u);
}

/**
 * Address: 0x00562770 (FUN_00562770)
 *
 * What it does:
 * Allocates one checked raw block for 216-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked216ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 216u);
}

/**
 * Address: 0x00562700 (FUN_00562700)
 *
 * What it does:
 * Allocates one checked raw block for 352-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked352ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 352u);
}

/**
 * Address: 0x005627E0 (FUN_005627E0)
 *
 * What it does:
 * Allocates one checked raw block for 568-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked568ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 568u);
}

/**
 * Address: 0x007419E0 (FUN_007419E0)
 *
 * What it does:
 * Allocates one checked raw block for 712-byte elements using the VC8
 * `_Allocate(count, element*)` overflow guard semantics.
 */
[[maybe_unused]] void* AllocateChecked712ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 712u);
}

[[noreturn]] void ThrowVectorLengthError()
{
  throw std::length_error("vector<T> too long");
}

[[nodiscard]] bool BuyVectorStorageByElementWidth(
  VectorVoidStorageView& storage,
  const std::uint32_t count,
  const std::uint32_t elementSize
)
{
  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;

  if (elementSize == 0u || count > (std::numeric_limits<std::uint32_t>::max() / elementSize)) {
    ThrowVectorLengthError();
  }

  std::byte* const begin = (count != 0u)
    ? static_cast<std::byte*>(AllocateCheckedElementBlock(count, elementSize))
    : static_cast<std::byte*>(::operator new(0));

  const std::size_t byteCount = static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize);
  storage.first = reinterpret_cast<void**>(begin);
  storage.last = storage.first;
  storage.end = reinterpret_cast<void**>(begin + byteCount);
  return true;
}

/**
 * Address: 0x007402B0 (FUN_007402B0)
 *
 * What it does:
 * Allocates one float-vector storage lane of `count` elements, fills every
 * element with `fillValue`, and marks `_Mylast` as fully initialized.
 */
[[maybe_unused]] void FillFloatVectorStorage(
  VectorVoidStorageView& storage,
  const float fillValue,
  const std::uint32_t count
)
{
  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;

  if (count == 0u) {
    return;
  }

  if (count > (std::numeric_limits<std::uint32_t>::max() / sizeof(float))) {
    ThrowVectorLengthError();
  }

  auto* const begin = static_cast<float*>(AllocateCheckedElementBlock(count, static_cast<std::uint32_t>(sizeof(float))));
  const std::size_t byteCount = static_cast<std::size_t>(count) * sizeof(float);
  storage.first = reinterpret_cast<void**>(begin);
  storage.last = storage.first;
  storage.end = reinterpret_cast<void**>(reinterpret_cast<std::byte*>(begin) + byteCount);
  std::fill_n(begin, static_cast<std::size_t>(count), fillValue);
  storage.last = storage.end;
}

/**
 * Address: 0x00507FF0 (FUN_00507FF0)
 * Address: 0x00547BB0 (FUN_00547BB0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 20-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage20Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 20u);
}

/**
 * Address: 0x00547C00 (FUN_00547C00)
 * Address: 0x0057EEC0 (FUN_0057EEC0)
 * Address: 0x0057F830 (FUN_0057F830)
 * Address: 0x005C5F60 (FUN_005C5F60)
 * Address: 0x005DC910 (FUN_005DC910)
 * Address: 0x005DCAB0 (FUN_005DCAB0)
 * Address: 0x005EA9E0 (FUN_005EA9E0)
 * Address: 0x00561340 (FUN_00561340)
 * Address: 0x0067CB50 (FUN_0067CB50)
 * Address: 0x00701F70 (FUN_00701F70)
 * Address: 0x00719990 (FUN_00719990)
 * Address: 0x00740D90 (FUN_00740D90)
 * Address: 0x00740DC0 (FUN_00740DC0)
 * Address: 0x00740DF0 (FUN_00740DF0)
 * Address: 0x00740E60 (FUN_00740E60)
 * Address: 0x007DA1A0 (FUN_007DA1A0)
 * Address: 0x007E37C0 (FUN_007E37C0)
 * Address: 0x007AF380 (FUN_007AF380)
 * Address: 0x007AF5F0 (FUN_007AF5F0)
 * Address: 0x0078A270 (FUN_0078A270)
 *
 * What it does:
 * Releases one owned vector backing block and resets all three runtime
 * storage lanes (`_Myfirst/_Mylast/_Myend`) to null.
 */
[[maybe_unused]] void ReleaseAndResetVectorStorage(VectorVoidStorageView& storage) noexcept
{
  if (storage.first != nullptr) {
    ::operator delete(storage.first);
  }

  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;
}

/**
 * Address: 0x005CA010 (FUN_005CA010)
 * Address: 0x005822B0 (FUN_005822B0)
 * Address: 0x005DF3C0 (FUN_005DF3C0)
 * Address: 0x005DF4F0 (FUN_005DF4F0)
 * Address: 0x0067FA60 (FUN_0067FA60)
 * Address: 0x006528C0 (FUN_006528C0)
 * Address: 0x0066AE90 (FUN_0066AE90)
 * Address: 0x006F9110 (FUN_006F9110)
 * Address: 0x00704500 (FUN_00704500)
 * Address: 0x007DA630 (FUN_007DA630)
 * Address: 0x007E5500 (FUN_007E5500)
 * Address: 0x007B1210 (FUN_007B1210)
 * Address: 0x007B1360 (FUN_007B1360)
 * Address: 0x0087D290 (FUN_0087D290)
 * Address: 0x0087D360 (FUN_0087D360)
 * Address: 0x0087D430 (FUN_0087D430)
 * Address: 0x0088AF20 (FUN_0088AF20)
 * Address: 0x00751D70 (FUN_00751D70)
 * Address: 0x0076CE60 (FUN_0076CE60)
 * Address: 0x0078AE40 (FUN_0078AE40)
 * Address: 0x0078B3E0 (FUN_0078B3E0)
 *
 * What it does:
 * Moves one dword range `[sourceBegin, sourceEnd)` so that it ends at
 * `destinationEnd`, returning the begin pointer of the copied block.
 */
[[maybe_unused]] std::uint32_t* MoveDwordRangeToEnd(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationEnd,
  const std::uint32_t* const sourceBegin
) noexcept
{
  const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
  std::uint32_t* const destinationBegin = destinationEnd - dwordCount;
  if (dwordCount != 0u) {
    const std::size_t byteCount = dwordCount * sizeof(std::uint32_t);
    (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
  }

  return destinationBegin;
}

/**
 * Address: 0x005DF340 (FUN_005DF340)
 * Address: 0x005DF470 (FUN_005DF470)
 * Address: 0x005C9A70 (FUN_005C9A70)
 * Address: 0x00582270 (FUN_00582270)
 * Address: 0x005C9FD0 (FUN_005C9FD0)
 * Address: 0x005CC540 (FUN_005CC540)
 * Address: 0x005DF380 (FUN_005DF380)
 * Address: 0x005DF4B0 (FUN_005DF4B0)
 * Address: 0x005E1220 (FUN_005E1220)
 * Address: 0x005E1280 (FUN_005E1280)
 * Address: 0x005EE6B0 (FUN_005EE6B0)
 * Address: 0x00751CC0 (FUN_00751CC0)
 * Address: 0x0076CE20 (FUN_0076CE20)
 * Address: 0x0078AE00 (FUN_0078AE00)
 * Address: 0x007B11D0 (FUN_007B11D0)
 * Address: 0x007B1320 (FUN_007B1320)
 * Address: 0x007DA5F0 (FUN_007DA5F0)
 * Address: 0x007E54C0 (FUN_007E54C0)
 * Address: 0x00652880 (FUN_00652880)
 * Address: 0x0066AE50 (FUN_0066AE50)
 * Address: 0x0067FB00 (FUN_0067FB00)
 * Address: 0x00681120 (FUN_00681120)
 * Address: 0x006F90D0 (FUN_006F90D0)
 * Address: 0x007044C0 (FUN_007044C0)
 * Address: 0x0078B390 (FUN_0078B390)
 * Address: 0x0078B550 (FUN_0078B550)
 * Address: 0x0078BA30 (FUN_0078BA30)
 * Address: 0x007BCBB0 (FUN_007BCBB0)
 *
 * What it does:
 * Copies one dword range `[sourceBegin, sourceEnd)` into `destinationBegin`
 * and returns one-past the last copied destination lane.
 */
[[maybe_unused]] std::uint32_t* MoveDwordRangeAndReturnEnd(
  const std::uint32_t* const sourceEnd,
  std::uint32_t* const destinationBegin,
  const std::uint32_t* const sourceBegin
) noexcept
{
  const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
  if (dwordCount != 0u) {
    const std::size_t byteCount = dwordCount * sizeof(std::uint32_t);
    (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
  }

  return destinationBegin + dwordCount;
}

/**
 * Address: 0x00AC3AE0 (FUN_00AC3AE0)
 * Address: 0x006E2D40 (FUN_006E2D40)
 * Address: 0x006E34E0 (FUN_006E34E0)
 *
 * What it does:
 * Fills one dword range `[begin,end)` from one fixed source dword lane.
 */
[[maybe_unused]] std::uint32_t* FillDwordRangeFromSingleSource(
  std::uint32_t* begin,
  std::uint32_t* const end,
  const std::uint32_t* const sourceWord
) noexcept
{
  while (begin != end) {
    *begin = *sourceWord;
    ++begin;
  }
  return begin;
}

/**
 * Address: 0x00AC3E90 (FUN_00AC3E90)
 *
 * What it does:
 * Writes `count` dwords from one fixed source lane and returns one-past-end.
 */
[[maybe_unused]] std::uint32_t* FillDwordCountFromSingleSource(
  std::uint32_t* const begin,
  const std::int32_t count,
  const std::uint32_t* const sourceWord
) noexcept
{
  std::uint32_t* cursor = begin;
  std::int32_t remaining = count;
  while (remaining != 0) {
    *cursor = *sourceWord;
    ++cursor;
    --remaining;
  }
  return begin + count;
}

/**
 * Address: 0x00AC3D60 (FUN_00AC3D60)
 * Address: 0x0078ADA0 (FUN_0078ADA0)
 *
 * What it does:
 * Copies one source-first dword range `[sourceBegin, sourceEnd)` into byte
 * destination storage and returns one-past-end destination lane.
 */
[[maybe_unused]] std::uint8_t* MoveDwordRangeSourceFirstAndReturnEnd(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t* const sourceEnd,
  std::uint8_t* const destinationBegin
) noexcept
{
  const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
  if (dwordCount != 0u) {
    const std::size_t byteCount = dwordCount * sizeof(std::uint32_t);
    (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
  }

  return destinationBegin + (dwordCount * sizeof(std::uint32_t));
}

/**
 * Address: 0x0078B580 (FUN_0078B580)
 *
 * What it does:
 * Moves exactly `dwordCount` 32-bit lanes from `sourceBegin` into
 * `destinationBegin` and returns the destination begin lane.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t* MoveFixedDwordCountAndReturnDestination(
  const std::uint32_t* const sourceBegin,
  const std::uint32_t dwordCount,
  std::uint32_t* const destinationBegin
) noexcept
{
  const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
  (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
  return destinationBegin;
}

/**
 * Address: 0x0078B340 (FUN_0078B340)
 *
 * What it does:
 * Moves exactly `dwordCount` 32-bit lanes from `sourceBegin` into
 * `destinationBegin` and returns `passthroughTag` unchanged.
 */
[[maybe_unused]] [[nodiscard]] std::uintptr_t MoveFixedDwordCountAndReturnPassthroughTag(
  const std::uint32_t* const sourceBegin,
  std::uint32_t* const destinationBegin,
  const std::uint32_t dwordCount,
  const std::uintptr_t passthroughTag
) noexcept
{
  (void)MoveFixedDwordCountAndReturnDestination(sourceBegin, dwordCount, destinationBegin);
  return passthroughTag;
}

/**
 * Address: 0x005DD0C0 (FUN_005DD0C0)
 * Address: 0x005DD510 (FUN_005DD510)
 * Address: 0x005C5EC0 (FUN_005C5EC0)
 * Address: 0x005AFF30 (FUN_005AFF30)
 * Address: 0x0074F820 (FUN_0074F820)
 * Address: 0x0076C7F0 (FUN_0076C7F0)
 * Address: 0x0078A1D0 (FUN_0078A1D0)
 *
 * What it does:
 * Relocates one dword tail segment from `sourceBegin` to `destinationBegin`,
 * updates `_Mylast`, and returns `outDestinationBegin`.
 */
[[maybe_unused]] std::uint32_t** RelocateDwordTailAndReturnBegin(
  VectorDwordStorageView& storage,
  std::uint32_t** const outDestinationBegin,
  std::uint32_t* const destinationBegin,
  std::uint32_t* const sourceBegin
) noexcept
{
  if (destinationBegin != sourceBegin) {
    const std::ptrdiff_t dwordCount = storage.last - sourceBegin;
    if (dwordCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
      (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
    }
    storage.last = destinationBegin + dwordCount;
  }

  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x006E30F0 (FUN_006E30F0)
 *
 * What it does:
 * Forward-copies one dword tail segment from `sourceBegin` to `destinationBegin`,
 * updates `_Mylast`, and stores the destination begin lane in output storage.
 */
[[maybe_unused]] std::uint32_t** RelocateDwordTailForwardAndReturnBegin(
  std::uint32_t** const outDestinationBegin,
  VectorDwordStorageView& storage,
  std::uint32_t* const destinationBegin,
  const std::uint32_t* sourceBegin
) noexcept
{
  if (destinationBegin != sourceBegin) {
    std::uint32_t* write = destinationBegin;
    const std::uint32_t* read = sourceBegin;
    const std::uint32_t* const tail = storage.last;
    while (read != tail) {
      *write = *read;
      ++write;
      ++read;
    }
    storage.last = write;
  }

  *outDestinationBegin = destinationBegin;
  return outDestinationBegin;
}

/**
 * Address: 0x0057FF40 (FUN_0057FF40)
 *
 * What it does:
 * Source-first register adapter that relocates one dword tail segment,
 * updates `_Mylast`, and returns the destination begin pointer.
 */
[[maybe_unused]] std::uint32_t* RelocateDwordTailAndReturnDestinationBegin(
  std::uint32_t* const sourceBegin,
  VectorDwordStorageView& storage,
  std::uint32_t* const destinationBegin
) noexcept
{
  std::uint32_t* relocatedBegin = destinationBegin;
  (void)RelocateDwordTailAndReturnBegin(storage, &relocatedBegin, destinationBegin, sourceBegin);
  return relocatedBegin;
}

/**
 * Address: 0x005E0170 (FUN_005E0170)
 * Address: 0x005E01D0 (FUN_005E01D0)
 * Address: 0x005ED4C0 (FUN_005ED4C0)
 * Address: 0x0078A070 (FUN_0078A070)
 *
 * What it does:
 * Clears one dword-vector logical used range by rebinding `_Mylast` to
 * `_Myfirst` while preserving storage allocation.
 */
[[maybe_unused]] void ResetVectorUsedRangeToBegin(VectorDwordStorageView& storage) noexcept
{
  if (storage.first != storage.last) {
    storage.last = storage.first;
  }
}

/**
 * Address: 0x00543480 (FUN_00543480)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 36-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage36Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 36u);
}

/**
 * Address: 0x0074D6C0 (FUN_0074D6C0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 144-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage144Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 144u);
}

/**
 * Address: 0x00510850 (FUN_00510850)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 16-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage16Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 16u);
}

/**
 * Address: 0x005433A0 (FUN_005433A0)
 * Address: 0x005EA4E0 (FUN_005EA4E0)
 * Address: 0x0074DBA0 (FUN_0074DBA0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 32-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage32Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 32u);
}

/**
 * Address: 0x0057EE70 (FUN_0057EE70)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 24-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage24Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 24u);
}

/**
 * Address: 0x005C5530 (FUN_005C5530)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 52-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage52Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 52u);
}

/**
 * Address: 0x00627410 (FUN_00627410)
 * Address: 0x006DBDD0 (FUN_006DBDD0)
 * Address: 0x0074D790 (FUN_0074D790)
 * Address: 0x0074D8C0 (FUN_0074D8C0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 12-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage12Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 12u);
}

/**
 * Address: 0x006DBBB0 (FUN_006DBBB0)
 * Address: 0x00702590 (FUN_00702590)
 * Address: 0x0074DA70 (FUN_0074DA70)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 40-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage40Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 40u);
}

/**
 * Address: 0x00719950 (FUN_00719950)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 56-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage56Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 56u);
}

/**
 * Address: 0x0074D800 (FUN_0074D800)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 8-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage8Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 8u);
}

/**
 * Address: 0x00719EE0 (FUN_00719EE0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 140-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage140Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 140u);
}

/**
 * Address: 0x007406A0 (FUN_007406A0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 712-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage712Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 712u);
}

/**
 * Address: 0x00561300 (FUN_00561300)
 * Address: 0x005C5F10 (FUN_005C5F10)
 * Address: 0x005DC8D0 (FUN_005DC8D0)
 * Address: 0x005DCA70 (FUN_005DCA70)
 * Address: 0x0067CB00 (FUN_0067CB00)
 * Address: 0x006E2140 (FUN_006E2140)
 * Address: 0x00701F30 (FUN_00701F30)
 * Address: 0x0074D730 (FUN_0074D730)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 4-byte element vector
 * lane and initializes the logical range to empty.
 */
[[maybe_unused]] bool BuyVectorStorage4Byte(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageByElementWidth(storage, count, 4u);
}

using CheckedElementAllocatorFn = void* (*)(std::uint32_t);

[[nodiscard]] bool InitializeVectorStorageLanesFromAllocation(
  VectorVoidStorageView& storage,
  void* const begin,
  const std::uint32_t count,
  const std::uint32_t elementSize
) noexcept
{
  auto* const beginBytes = static_cast<std::byte*>(begin);
  storage.first = reinterpret_cast<void**>(beginBytes);
  storage.last = storage.first;
  storage.end = reinterpret_cast<void**>(
    beginBytes + (static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize))
  );
  return true;
}

[[nodiscard]] bool BuyVectorStorageGuardedByMaxCount(
  VectorVoidStorageView& storage,
  const std::uint32_t count,
  const std::uint32_t maxCount,
  const std::uint32_t elementSize,
  CheckedElementAllocatorFn const allocator
)
{
  if (count > maxCount) {
    ThrowVectorLengthError();
  }

  void* const begin = (count != 0u) ? allocator(count) : ::operator new(0);
  return InitializeVectorStorageLanesFromAllocation(storage, begin, count, elementSize);
}

[[nodiscard]] void* AllocateChecked60ByteElements(const std::uint32_t count)
{
  return AllocateCheckedElementBlock(count, 60u);
}

/**
 * Address: 0x006F8720 (FUN_006F8720)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 4-byte element vector
 * lane with legacy max-count guard `0x3FFFFFFF`, preserving the caller's
 * overflow context lanes.
 */
[[maybe_unused]] bool BuyVectorStorage4ByteGuardedWithOverflowContext(
  const std::uint32_t overflowContextA,
  const std::uint32_t overflowContextB,
  VectorVoidStorageView& storage,
  const std::uint32_t count
)
{
  (void)overflowContextA;
  (void)overflowContextB;
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x3FFFFFFFu, 4u, &AllocateChecked4ByteElements);
}

/**
 * Address: 0x007335A0 (FUN_007335A0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 8-byte element vector
 * lane with legacy max-count guard `0x1FFFFFFF`, preserving the caller's
 * overflow context lane.
 */
[[maybe_unused]] bool BuyVectorStorage8ByteGuardedWithOverflowContext(
  const std::uint32_t overflowContext,
  VectorVoidStorageView& storage,
  const std::uint32_t count
)
{
  (void)overflowContext;
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x1FFFFFFFu, 8u, &AllocateChecked8ByteElements);
}

/**
 * Address: 0x0074D390 (FUN_0074D390)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 352-byte element vector
 * lane with legacy max-count guard `0x00BA2E8B`.
 */
[[maybe_unused]] bool BuyVectorStorage352ByteGuarded(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(
    storage,
    count,
    kLegacyVectorStorageGuard352Byte,
    352u,
    &AllocateChecked352ByteElements
  );
}

/**
 * Address: 0x0074D3F0 (FUN_0074D3F0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 12-byte element vector
 * lane with legacy max-count guard `0x15555555`.
 */
[[maybe_unused]] bool BuyVectorStorage12ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x15555555u, 12u, &AllocateChecked12ByteElements);
}

/**
 * Address: 0x0074D460 (FUN_0074D460)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 28-byte element vector
 * lane with legacy max-count guard `0x09249249`.
 */
[[maybe_unused]] bool BuyVectorStorage28ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x09249249u, 28u, &AllocateChecked28ByteElements);
}

/**
 * Address: 0x0074D4C0 (FUN_0074D4C0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 216-byte element vector
 * lane with legacy max-count guard `0x012F684B`.
 */
[[maybe_unused]] bool BuyVectorStorage216ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x012F684Bu, 216u, &AllocateChecked216ByteElements);
}

/**
 * Address: 0x0074D520 (FUN_0074D520)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 568-byte element vector
 * lane with legacy max-count guard `0x0073615A`.
 */
[[maybe_unused]] bool BuyVectorStorage568ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(
    storage,
    count,
    kLegacyVectorStorageGuard568Byte,
    568u,
    &AllocateChecked568ByteElements
  );
}

/**
 * Address: 0x0074D580 (FUN_0074D580)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 4-byte element vector
 * lane with legacy max-count guard `0x3FFFFFFF`.
 */
[[maybe_unused]] bool BuyVectorStorage4ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x3FFFFFFFu, 4u, &AllocateChecked4ByteElements);
}

/**
 * Address: 0x0074D5E0 (FUN_0074D5E0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 60-byte element vector
 * lane with legacy max-count guard `0x04444444`, preserving the caller's
 * overflow context lane.
 */
[[maybe_unused]] bool BuyVectorStorage60ByteGuardedWithOverflowContext(
  const std::uint32_t overflowContext,
  VectorVoidStorageView& storage,
  const std::uint32_t count
)
{
  (void)overflowContext;
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x04444444u, 60u, &AllocateChecked60ByteElements);
}

/**
 * Address: 0x0074D640 (FUN_0074D640)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 120-byte element vector
 * lane with legacy max-count guard `0x02222222`.
 */
[[maybe_unused]] bool BuyVectorStorage120ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x02222222u, 120u, &AllocateChecked120ByteElements);
}

/**
 * Address: 0x00783190 (FUN_00783190)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 8-byte element vector
 * lane with legacy max-count guard `0x1FFFFFFF`.
 */
[[maybe_unused]] bool BuyVectorStorage8ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x1FFFFFFFu, 8u, &AllocateChecked8ByteElements);
}

/**
 * Address: 0x007983B0 (FUN_007983B0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 20-byte element vector
 * lane with legacy max-count guard `0x0CCCCCCC`.
 */
[[maybe_unused]] bool BuyVectorStorage20ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x0CCCCCCCu, 20u, &AllocateChecked20ByteElements);
}

/**
 * Address: 0x007C92B0 (FUN_007C92B0)
 *
 * What it does:
 * Acquires `_Myfirst/_Mylast/_Myend` storage for one 16-byte element vector
 * lane with legacy max-count guard `0x0FFFFFFF`.
 */
[[maybe_unused]] bool BuyVectorStorage16ByteGuardedVariant(VectorVoidStorageView& storage, const std::uint32_t count)
{
  return BuyVectorStorageGuardedByMaxCount(storage, count, 0x0FFFFFFFu, 16u, &AllocateChecked16ByteElements);
}

namespace
{
template <class ElementT>
[[nodiscard]] std::uint32_t VectorElementCount(const VectorVoidStorageView& storage) noexcept
{
  const auto* const first = reinterpret_cast<const ElementT*>(storage.first);
  if (first == nullptr) {
    return 0u;
  }

  const auto* const last = reinterpret_cast<const ElementT*>(storage.last);
  return static_cast<std::uint32_t>(last - first);
}

template <class ElementT>
[[nodiscard]] std::uint32_t VectorElementCapacity(const VectorVoidStorageView& storage) noexcept
{
  const auto* const first = reinterpret_cast<const ElementT*>(storage.first);
  if (first == nullptr) {
    return 0u;
  }

  const auto* const end = reinterpret_cast<const ElementT*>(storage.end);
  return static_cast<std::uint32_t>(end - first);
}

template <class ElementT>
void DestroyObjectRange(ElementT* begin, ElementT* end) noexcept
{
  while (begin != end) {
    begin->~ElementT();
    ++begin;
  }
}

template <class ElementT>
[[nodiscard]] ElementT* CopyAssignObjectRange(
  ElementT* destination,
  const ElementT* sourceBegin,
  const ElementT* sourceEnd
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destination = *sourceBegin;
    ++destination;
    ++sourceBegin;
  }

  return destination;
}

template <class ElementT>
[[nodiscard]] ElementT* UninitializedCopyObjectRange(
  ElementT* destination,
  const ElementT* sourceBegin,
  const ElementT* sourceEnd
)
{
  ElementT* write = destination;
  try {
    for (const ElementT* source = sourceBegin; source != sourceEnd; ++source, ++write) {
      new (write) ElementT(*source);
    }
  } catch (...) {
    DestroyObjectRange(destination, write);
    throw;
  }

  return write;
}

/**
 * Address: 0x005EAC50 (FUN_005EAC50, sub_5EAC50)
 *
 * What it does:
 * Copies one `SAiReservedTransportBone` lane, relinks the destination weak
 * unit lane to the same owner slot chain, and copy-assigns the reserved-bones
 * vector payload.
 */
void CopyAssignReservedTransportBoneLane(
  moho::SAiReservedTransportBone& destination,
  const moho::SAiReservedTransportBone& source
)
{
  destination.transportBoneIndex = source.transportBoneIndex;
  destination.attachBoneIndex = source.attachBoneIndex;
  destination.reservedUnit.ResetFromOwnerLinkSlot(source.reservedUnit.ownerLinkSlot);
  destination.reservedBones = source.reservedBones;
}

[[nodiscard]] moho::SAiReservedTransportBone* CopyAssignReservedTransportBoneRange(
  moho::SAiReservedTransportBone* destination,
  const moho::SAiReservedTransportBone* sourceBegin,
  const moho::SAiReservedTransportBone* sourceEnd
)
{
  while (sourceBegin != sourceEnd) {
    CopyAssignReservedTransportBoneLane(*destination, *sourceBegin);
    ++destination;
    ++sourceBegin;
  }

  return destination;
}

/**
 * Address: 0x005EFF70 (FUN_005EFF70, sub_5EFF70)
 *
 * What it does:
 * Copy-constructs one half-open `SAiReservedTransportBone` range and, on
 * failure, destroys the already-constructed destination prefix before
 * rethrowing.
 */
[[nodiscard]] moho::SAiReservedTransportBone* UninitializedCopyReservedTransportBoneRange(
  moho::SAiReservedTransportBone* destination,
  const moho::SAiReservedTransportBone* sourceBegin,
  const moho::SAiReservedTransportBone* sourceEnd
)
{
  moho::SAiReservedTransportBone* write = destination;
  try {
    for (const moho::SAiReservedTransportBone* source = sourceBegin; source != sourceEnd; ++source, ++write) {
      new (write) moho::SAiReservedTransportBone{};
      CopyAssignReservedTransportBoneLane(*write, *source);
    }
  } catch (...) {
    (void)moho::DestroyReservedTransportBoneRange(destination, write);
    throw;
  }

  return write;
}

/**
 * Address: 0x005EC830 (FUN_005EC830)
 * Address: 0x005EE710 (FUN_005EE710)
 *
 * What it does:
 * Bridges legacy EH/register-shaped caller lanes into the canonical
 * `UninitializedCopyReservedTransportBoneRange` helper.
 */
[[maybe_unused]] [[nodiscard]] moho::SAiReservedTransportBone* UninitializedCopyReservedTransportBoneRangeRegisterAdapter(
  moho::SAiReservedTransportBone* const destinationBegin,
  const moho::SAiReservedTransportBone* const sourceBegin,
  const std::uint32_t /*unusedEhStateLane*/,
  moho::SAiReservedTransportBone* const destinationEnd
)
{
  return UninitializedCopyReservedTransportBoneRange(destinationBegin, sourceBegin, destinationEnd);
}

void CopyEntitySetStorageOnly(
  moho::SEntitySetTemplateUnit& destination,
  const moho::SEntitySetTemplateUnit& source
)
{
  destination.mVec.ResetStorageToInline();
  destination.mVec.reserve(source.mVec.size());
  for (moho::Entity* const entry : source.mVec) {
    destination.mVec.push_back(entry);
  }
}

[[nodiscard]] moho::SEntitySetTemplateUnit* CopyAssignEntitySetRange(
  moho::SEntitySetTemplateUnit* destination,
  const moho::SEntitySetTemplateUnit* sourceBegin,
  const moho::SEntitySetTemplateUnit* sourceEnd
)
{
  while (sourceBegin != sourceEnd) {
    CopyEntitySetStorageOnly(*destination, *sourceBegin);
    ++destination;
    ++sourceBegin;
  }

  return destination;
}

void DestroyEntitySetRange(
  moho::SEntitySetTemplateUnit* begin,
  moho::SEntitySetTemplateUnit* end
) noexcept
{
  while (begin != end) {
    begin->~SEntitySetTemplateUnit();
    ++begin;
  }
}

/**
 * Address: 0x00706900 (FUN_00706900, sub_706900)
 *
 * What it does:
 * Copy-constructs one half-open `SEntitySetTemplateUnit` range and destroys
 * the partially-constructed destination prefix before rethrowing when a copy
 * lane fails.
 */
[[nodiscard]] moho::SEntitySetTemplateUnit* UninitializedCopyEntitySetRange(
  moho::SEntitySetTemplateUnit* destination,
  const moho::SEntitySetTemplateUnit* sourceBegin,
  const moho::SEntitySetTemplateUnit* sourceEnd
)
{
  moho::SEntitySetTemplateUnit* write = destination;
  try {
    for (const moho::SEntitySetTemplateUnit* source = sourceBegin; source != sourceEnd; ++source, ++write) {
      new (write) moho::SEntitySetTemplateUnit(*source);
    }
  } catch (...) {
    DestroyEntitySetRange(destination, write);
    throw;
  }

  return write;
}

/**
 * Address: 0x00706210 (FUN_00706210)
 *
 * What it does:
 * Bridges one legacy register-lane unwind adapter into the canonical
 * `UninitializedCopyEntitySetRange` helper.
 */
[[maybe_unused]] [[nodiscard]] moho::SEntitySetTemplateUnit* UninitializedCopyEntitySetRangeRegisterAdapter(
  moho::SEntitySetTemplateUnit* const destinationBegin,
  const moho::SEntitySetTemplateUnit* const sourceBegin,
  const std::uint32_t /*unusedEhStateLane*/,
  moho::SEntitySetTemplateUnit* const destinationEnd
)
{
  return UninitializedCopyEntitySetRange(destinationBegin, sourceBegin, destinationEnd);
}

void RetainSharedControlRef(volatile long* const control) noexcept
{
  if (control != nullptr) {
    (void)_InterlockedExchangeAdd(control + 1, 1L);
  }
}

void ReleaseSharedControlRef(volatile long* const control) noexcept
{
  if (control == nullptr) {
    return;
  }

  if (_InterlockedExchangeAdd(control + 1, -1L) != 1L) {
    return;
  }

  using SharedControlReleaseFn = void(__thiscall*)(volatile long*);
  auto* const vtable = *reinterpret_cast<SharedControlReleaseFn* const*>(const_cast<long*>(control));
  vtable[1](control);
  if (_InterlockedExchangeAdd(control + 2, -1L) == 1L) {
    vtable[2](control);
  }
}

[[nodiscard]] VectorElement12RefcountedLane* CopyAssignRefcountedLaneRange(
  VectorElement12RefcountedLane* destination,
  const VectorElement12RefcountedLane* sourceBegin,
  const VectorElement12RefcountedLane* sourceEnd
) noexcept
{
  while (sourceBegin != sourceEnd) {
    destination->lane0 = sourceBegin->lane0;
    destination->lane1 = sourceBegin->lane1;
    if (destination->sharedControl != sourceBegin->sharedControl) {
      RetainSharedControlRef(sourceBegin->sharedControl);
      ReleaseSharedControlRef(destination->sharedControl);
      destination->sharedControl = sourceBegin->sharedControl;
    }

    ++destination;
    ++sourceBegin;
  }

  return destination;
}

[[nodiscard]] VectorElement12RefcountedLane* CopyConstructRefcountedLaneRange(
  VectorElement12RefcountedLane* destination,
  const VectorElement12RefcountedLane* sourceBegin,
  const VectorElement12RefcountedLane* sourceEnd
) noexcept
{
  VectorElement12RefcountedLane* write = destination;
  while (sourceBegin != sourceEnd) {
    write->lane0 = sourceBegin->lane0;
    write->lane1 = sourceBegin->lane1;
    write->sharedControl = sourceBegin->sharedControl;
    RetainSharedControlRef(write->sharedControl);
    ++write;
    ++sourceBegin;
  }

  return write;
}

void ReleaseRefcountedLaneRange(
  VectorElement12RefcountedLane* begin,
  VectorElement12RefcountedLane* end
) noexcept
{
  while (begin != end) {
    ReleaseSharedControlRef(begin->sharedControl);
    ++begin;
  }
}

[[nodiscard]] VectorElement40DwordDecupleLane* CopyDwordDecupleLaneRange(
  VectorElement40DwordDecupleLane* destination,
  const VectorElement40DwordDecupleLane* sourceBegin,
  const VectorElement40DwordDecupleLane* sourceEnd
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destination = *sourceBegin;
    ++destination;
    ++sourceBegin;
  }

  return destination;
}

[[nodiscard]] VectorElement28FloatSeptupleLane* CopyFloatSeptupleLaneRange(
  VectorElement28FloatSeptupleLane* destination,
  const VectorElement28FloatSeptupleLane* sourceBegin,
  const VectorElement28FloatSeptupleLane* sourceEnd
) noexcept
{
  while (sourceBegin != sourceEnd) {
    *destination = *sourceBegin;
    ++destination;
    ++sourceBegin;
  }

  return destination;
}

/**
 * Address: 0x007548B0 (FUN_007548B0)
 *
 * What it does:
 * Adapter lane that forwards one refcounted 12-byte copy-assign range
 * `[sourceBegin, sourceEnd)` into the shared range copy helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement12RefcountedLane* CopyAssignRefcountedLaneRangeAdapter(
  const VectorElement12RefcountedLane* sourceBegin,
  const VectorElement12RefcountedLane* sourceEnd,
  VectorElement12RefcountedLane* destination
) noexcept
{
  return CopyAssignRefcountedLaneRange(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x007548E0 (FUN_007548E0)
 *
 * What it does:
 * Adapter lane that forwards one refcounted 12-byte uninitialized copy range
 * `[sourceBegin, sourceEnd)` into the shared copy-construction helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement12RefcountedLane* CopyConstructRefcountedLaneRangeAdapter(
  const VectorElement12RefcountedLane* sourceBegin,
  const VectorElement12RefcountedLane* sourceEnd,
  VectorElement12RefcountedLane* destination
) noexcept
{
  return CopyConstructRefcountedLaneRange(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x00754970 (FUN_00754970)
 *
 * What it does:
 * Adapter lane that forwards one trivial 40-byte copy range
 * `[sourceBegin, sourceEnd)` into the decuple-dword range copy helper.
 */
[[maybe_unused]] [[nodiscard]] VectorElement40DwordDecupleLane* CopyDwordDecupleLaneRangeAdapter(
  const VectorElement40DwordDecupleLane* sourceBegin,
  const VectorElement40DwordDecupleLane* sourceEnd,
  VectorElement40DwordDecupleLane* destination
) noexcept
{
  return CopyDwordDecupleLaneRange(destination, sourceBegin, sourceEnd);
}
} // namespace

/**
 * Address: 0x0051B3D0 (FUN_0051B3D0, sub_51B3D0)
 *
 * What it does:
 * Copy-constructs one half-open `RMeshBlueprintLOD` range and destroys the
 * partially-constructed destination prefix on failure before rethrowing.
 */
[[maybe_unused]] [[nodiscard]] moho::RMeshBlueprintLOD* CopyConstructRMeshBlueprintLodRange(
  moho::RMeshBlueprintLOD* destination,
  const moho::RMeshBlueprintLOD* sourceBegin,
  const moho::RMeshBlueprintLOD* sourceEnd
)
{
  return UninitializedCopyObjectRange(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x0051A5B0 (FUN_0051A5B0)
 * Address: 0x0051AED0 (FUN_0051AED0)
 * Address: 0x0051B050 (FUN_0051B050)
 * Address: 0x0051B1C0 (FUN_0051B1C0)
 * Address: 0x0051B250 (FUN_0051B250)
 *
 * What it does:
 * Bridges legacy EH/register-shaped wrapper lanes into the canonical
 * `CopyConstructRMeshBlueprintLodRange` helper.
 */
[[maybe_unused]] [[nodiscard]] moho::RMeshBlueprintLOD* CopyConstructRMeshBlueprintLodRangeRegisterAdapter(
  moho::RMeshBlueprintLOD* const destinationBegin,
  const moho::RMeshBlueprintLOD* const sourceBegin,
  const std::uint32_t /*unusedEhStateLane*/,
  moho::RMeshBlueprintLOD* const destinationEnd
)
{
  return CopyConstructRMeshBlueprintLodRange(destinationBegin, sourceBegin, destinationEnd);
}

/**
 * Address: 0x00527DD0 (FUN_00527DD0, sub_527DD0)
 * Address: 0x00527F20 (FUN_00527F20, sub_527F20)
 *
 * What it does:
 * Copy-constructs one half-open `RUnitBlueprintWeapon` range and destroys the
 * partially-constructed destination prefix on failure before rethrowing.
 */
[[maybe_unused]] [[nodiscard]] moho::RUnitBlueprintWeapon* CopyConstructRUnitBlueprintWeaponRange(
  moho::RUnitBlueprintWeapon* destination,
  const moho::RUnitBlueprintWeapon* sourceBegin,
  const moho::RUnitBlueprintWeapon* sourceEnd
)
{
  return UninitializedCopyObjectRange(destination, sourceBegin, sourceEnd);
}

/**
 * Address: 0x005261A0 (FUN_005261A0)
 * Address: 0x00526030 (FUN_00526030)
 * Address: 0x00527320 (FUN_00527320)
 * Address: 0x005271D0 (FUN_005271D0)
 * Address: 0x00527650 (FUN_00527650)
 * Address: 0x005279F0 (FUN_005279F0)
 * Address: 0x00527A70 (FUN_00527A70)
 * Address: 0x00527C50 (FUN_00527C50)
 * Address: 0x00527BA0 (FUN_00527BA0)
 *
 * What it does:
 * Bridges legacy EH/register-shaped wrapper lanes into the canonical
 * `CopyConstructRUnitBlueprintWeaponRange` helper.
 */
[[maybe_unused]] [[nodiscard]] moho::RUnitBlueprintWeapon* CopyConstructRUnitBlueprintWeaponRangeRegisterAdapter(
  moho::RUnitBlueprintWeapon* const destinationBegin,
  const moho::RUnitBlueprintWeapon* const sourceBegin,
  const std::uint32_t /*unusedEhStateLane*/,
  moho::RUnitBlueprintWeapon* const destinationEnd
)
{
  return CopyConstructRUnitBlueprintWeaponRange(destinationBegin, sourceBegin, destinationEnd);
}

/**
 * Address: 0x0051A900 (FUN_0051A900)
 *
 * What it does:
 * Copy-assigns one `vector<RMeshBlueprintLOD>` lane with full VC8
 * size/capacity split behavior and string-aware element lifetime management.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignRMeshBlueprintLodVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const moho::RMeshBlueprintLOD*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const moho::RMeshBlueprintLOD*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<moho::RMeshBlueprintLOD>(source);
  auto* destinationBegin = reinterpret_cast<moho::RMeshBlueprintLOD*>(destination.first);
  auto* destinationEnd = reinterpret_cast<moho::RMeshBlueprintLOD*>(destination.last);

  if (sourceCount == 0u) {
    if (destinationBegin != destinationEnd) {
      DestroyObjectRange(destinationBegin, destinationEnd);
      destination.last = reinterpret_cast<void**>(destinationBegin);
    }
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<moho::RMeshBlueprintLOD>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<moho::RMeshBlueprintLOD>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignObjectRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyConstructRMeshBlueprintLodRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      DestroyObjectRange(destinationBegin, destinationEnd);
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (BuyVectorStorageByElementWidth(destination, sourceCount, 204u)) {
      destinationBegin = reinterpret_cast<moho::RMeshBlueprintLOD*>(destination.first);
      destinationEnd = CopyConstructRMeshBlueprintLodRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  const auto* const sourceBound = sourceBegin + sourceCount;
  moho::RMeshBlueprintLOD* const copiedEnd = CopyAssignObjectRange(destinationBegin, sourceBegin, sourceBound);
  DestroyObjectRange(copiedEnd, destinationEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x00526A90 (FUN_00526A90)
 *
 * What it does:
 * Copy-assigns one `vector<RUnitBlueprintWeapon>` lane with destructor-aware
 * trim/reallocate paths matching VC8 vector assignment semantics.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignRUnitBlueprintWeaponVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const moho::RUnitBlueprintWeapon*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const moho::RUnitBlueprintWeapon*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<moho::RUnitBlueprintWeapon>(source);
  auto* destinationBegin = reinterpret_cast<moho::RUnitBlueprintWeapon*>(destination.first);
  auto* destinationEnd = reinterpret_cast<moho::RUnitBlueprintWeapon*>(destination.last);

  if (sourceCount == 0u) {
    if (destinationBegin != destinationEnd) {
      DestroyObjectRange(destinationBegin, destinationEnd);
      destination.last = reinterpret_cast<void**>(destinationBegin);
    }
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<moho::RUnitBlueprintWeapon>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<moho::RUnitBlueprintWeapon>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignObjectRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyConstructRUnitBlueprintWeaponRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      DestroyObjectRange(destinationBegin, destinationEnd);
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (BuyVectorStorageByElementWidth(destination, sourceCount, 388u)) {
      destinationBegin = reinterpret_cast<moho::RUnitBlueprintWeapon*>(destination.first);
      destinationEnd = CopyConstructRUnitBlueprintWeaponRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  const auto* const sourceBound = sourceBegin + sourceCount;
  moho::RUnitBlueprintWeapon* const copiedEnd = CopyAssignObjectRange(destinationBegin, sourceBegin, sourceBound);
  DestroyObjectRange(copiedEnd, destinationEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x00582890 (FUN_00582890)
 *
 * What it does:
 * Copy-assigns one `vector<SPointVector>` lane with the original split between
 * in-place overwrite, append-construct tail, and full reallocate.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignSPointVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const moho::SPointVector*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const moho::SPointVector*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<moho::SPointVector>(source);
  auto* destinationBegin = reinterpret_cast<moho::SPointVector*>(destination.first);
  auto* destinationEnd = reinterpret_cast<moho::SPointVector*>(destination.last);

  if (sourceCount == 0u) {
    destination.last = reinterpret_cast<void**>(destinationBegin);
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<moho::SPointVector>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<moho::SPointVector>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignObjectRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyAssignObjectRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (BuyVectorStorage24Byte(destination, sourceCount)) {
      destinationBegin = reinterpret_cast<moho::SPointVector*>(destination.first);
      destinationEnd = CopyAssignObjectRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  (void)CopyAssignObjectRange(destinationBegin, sourceBegin, sourceEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x005ED370 (FUN_005ED370)
 *
 * What it does:
 * Copy-assigns one `vector<SAiReservedTransportBone>` lane while preserving
 * weak-link relink behavior and reserved-bones subvector ownership rules.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignReservedTransportBoneVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const moho::SAiReservedTransportBone*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const moho::SAiReservedTransportBone*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<moho::SAiReservedTransportBone>(source);
  auto* destinationBegin = reinterpret_cast<moho::SAiReservedTransportBone*>(destination.first);
  auto* destinationEnd = reinterpret_cast<moho::SAiReservedTransportBone*>(destination.last);

  if (sourceCount == 0u) {
    if (destinationBegin != destinationEnd) {
      (void)moho::DestroyReservedTransportBoneRange(destinationBegin, destinationEnd);
      destination.last = reinterpret_cast<void**>(destinationBegin);
    }
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<moho::SAiReservedTransportBone>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<moho::SAiReservedTransportBone>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignReservedTransportBoneRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = UninitializedCopyReservedTransportBoneRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      (void)moho::DestroyReservedTransportBoneRange(destinationBegin, destinationEnd);
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (sourceCount != 0u && BuyVectorStorage32Byte(destination, sourceCount)) {
      destinationBegin = reinterpret_cast<moho::SAiReservedTransportBone*>(destination.first);
      destinationEnd = UninitializedCopyReservedTransportBoneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  const auto* const sourceBound = sourceBegin + sourceCount;
  moho::SAiReservedTransportBone* const copiedEnd =
    CopyAssignReservedTransportBoneRange(destinationBegin, sourceBegin, sourceBound);
  (void)moho::DestroyReservedTransportBoneRange(copiedEnd, destinationEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x00704D80 (FUN_00704D80)
 *
 * What it does:
 * Copy-assigns one `vector<SEntitySetTemplateUnit>` lane, copying only per-set
 * fastvector payload for existing nodes and preserving intrusive list lanes.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignEntitySetTemplateUnitVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const moho::SEntitySetTemplateUnit*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const moho::SEntitySetTemplateUnit*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<moho::SEntitySetTemplateUnit>(source);
  auto* destinationBegin = reinterpret_cast<moho::SEntitySetTemplateUnit*>(destination.first);
  auto* destinationEnd = reinterpret_cast<moho::SEntitySetTemplateUnit*>(destination.last);

  if (sourceCount == 0u) {
    if (destinationBegin != destinationEnd) {
      DestroyEntitySetRange(destinationBegin, destinationEnd);
      destination.last = reinterpret_cast<void**>(destinationBegin);
    }
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<moho::SEntitySetTemplateUnit>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<moho::SEntitySetTemplateUnit>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignEntitySetRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = UninitializedCopyEntitySetRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      DestroyEntitySetRange(destinationBegin, destinationEnd);
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (sourceCount != 0u && BuyVectorStorage40Byte(destination, sourceCount)) {
      destinationBegin = reinterpret_cast<moho::SEntitySetTemplateUnit*>(destination.first);
      destinationEnd = UninitializedCopyEntitySetRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  const auto* const sourceBound = sourceBegin + sourceCount;
  moho::SEntitySetTemplateUnit* const copiedEnd = CopyAssignEntitySetRange(destinationBegin, sourceBegin, sourceBound);
  DestroyEntitySetRange(copiedEnd, destinationEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x00752C50 (FUN_00752C50)
 *
 * What it does:
 * Copy-assigns one 12-byte refcounted lane vector, preserving intrusive
 * shared-control retain/release semantics on every overwrite and trim path.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignRefcountedLaneVector12Storage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const VectorElement12RefcountedLane*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const VectorElement12RefcountedLane*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<VectorElement12RefcountedLane>(source);
  auto* destinationBegin = reinterpret_cast<VectorElement12RefcountedLane*>(destination.first);
  auto* destinationEnd = reinterpret_cast<VectorElement12RefcountedLane*>(destination.last);

  if (sourceCount == 0u) {
    if (destinationBegin != destinationEnd) {
      ReleaseRefcountedLaneRange(destinationBegin, destinationEnd);
      destination.last = reinterpret_cast<void**>(destinationBegin);
    }
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<VectorElement12RefcountedLane>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<VectorElement12RefcountedLane>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyAssignRefcountedLaneRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyConstructRefcountedLaneRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      ReleaseRefcountedLaneRange(destinationBegin, destinationEnd);
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (sourceCount != 0u && BuyVectorStorage12Byte(destination, sourceCount)) {
      destinationBegin = reinterpret_cast<VectorElement12RefcountedLane*>(destination.first);
      destinationEnd = CopyConstructRefcountedLaneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  const auto* const sourceBound = sourceBegin + sourceCount;
  VectorElement12RefcountedLane* const copiedEnd =
    CopyAssignRefcountedLaneRange(destinationBegin, sourceBegin, sourceBound);
  ReleaseRefcountedLaneRange(copiedEnd, destinationEnd);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x00752EA0 (FUN_00752EA0)
 *
 * What it does:
 * Copy-assigns one 40-byte decuple-dword vector lane with VC8-style
 * overwrite/append/reallocate branching and trivial-element clear semantics.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignDwordDecupleVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const VectorElement40DwordDecupleLane*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const VectorElement40DwordDecupleLane*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<VectorElement40DwordDecupleLane>(source);
  auto* destinationBegin = reinterpret_cast<VectorElement40DwordDecupleLane*>(destination.first);
  auto* destinationEnd = reinterpret_cast<VectorElement40DwordDecupleLane*>(destination.last);

  if (sourceCount == 0u) {
    destination.last = reinterpret_cast<void**>(destinationBegin);
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<VectorElement40DwordDecupleLane>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<VectorElement40DwordDecupleLane>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyDwordDecupleLaneRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyDwordDecupleLaneRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (sourceCount != 0u && BuyVectorStorage40Byte(destination, sourceCount)) {
      destinationBegin = reinterpret_cast<VectorElement40DwordDecupleLane*>(destination.first);
      destinationEnd = CopyDwordDecupleLaneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  (void)CopyDwordDecupleLaneRange(destinationBegin, sourceBegin, sourceBegin + sourceCount);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x007525C0 (FUN_007525C0)
 *
 * What it does:
 * Copy-assigns one 28-byte float-septuple vector storage lane with the
 * legacy overwrite/append/reallocate split.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignFloatSeptupleVector28Storage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  const auto* const sourceBegin = reinterpret_cast<const VectorElement28FloatSeptupleLane*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const VectorElement28FloatSeptupleLane*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<VectorElement28FloatSeptupleLane>(source);
  auto* destinationBegin = reinterpret_cast<VectorElement28FloatSeptupleLane*>(destination.first);
  auto* destinationEnd = reinterpret_cast<VectorElement28FloatSeptupleLane*>(destination.last);

  if (sourceCount == 0u) {
    destination.last = reinterpret_cast<void**>(destinationBegin);
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<VectorElement28FloatSeptupleLane>(destination);
  if (sourceCount > destinationCount) {
    const std::uint32_t destinationCapacity = VectorElementCapacity<VectorElement28FloatSeptupleLane>(destination);
    if (sourceCount <= destinationCapacity) {
      const auto* const sourceMiddle = sourceBegin + destinationCount;
      (void)CopyFloatSeptupleLaneRange(destinationBegin, sourceBegin, sourceMiddle);
      destinationEnd = CopyFloatSeptupleLaneRange(destinationEnd, sourceMiddle, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
      return &destination;
    }

    if (destinationBegin != nullptr) {
      ::operator delete(destinationBegin);
    }

    destination.first = nullptr;
    destination.last = nullptr;
    destination.end = nullptr;
    if (sourceCount != 0u && BuyVectorStorageByElementWidth(destination, sourceCount, 28u)) {
      destinationBegin = reinterpret_cast<VectorElement28FloatSeptupleLane*>(destination.first);
      destinationEnd = CopyFloatSeptupleLaneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    }
    return &destination;
  }

  (void)CopyFloatSeptupleLaneRange(destinationBegin, sourceBegin, sourceBegin + sourceCount);
  destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
  return &destination;
}

/**
 * Address: 0x007529A0 (FUN_007529A0)
 *
 * What it does:
 * Copy-constructs one 8-byte dword-pair vector storage lane and replays the
 * legacy overflow-guarded allocation path before copying source lanes.
 */
[[maybe_unused]] VectorVoidStorageView* CopyConstructDwordPairVector8Storage(
  const VectorVoidStorageView& source,
  VectorVoidStorageView& destination
)
{
  destination.first = nullptr;
  destination.last = nullptr;
  destination.end = nullptr;

  const std::uint32_t sourceCount = VectorElementCount<VectorElement8DwordPairLane>(source);
  if (sourceCount == 0u) {
    return &destination;
  }

  if (sourceCount > 0x1FFFFFFFu) {
    ThrowVectorLengthError();
  }

  if (BuyVectorStorage8Byte(destination, sourceCount)) {
    auto* write = reinterpret_cast<VectorElement8DwordPairLane*>(destination.first);
    const auto* sourceCursor = reinterpret_cast<const VectorElement8DwordPairLane*>(source.first);
    const auto* const sourceEnd = reinterpret_cast<const VectorElement8DwordPairLane*>(source.last);

    try {
      while (sourceCursor != sourceEnd) {
        *write = *sourceCursor;
        ++sourceCursor;
        ++write;
      }
      destination.last = reinterpret_cast<void**>(write);
    } catch (...) {
      ReleaseAndResetVectorStorage(destination);
      throw;
    }
  }

  return &destination;
}

/**
 * Address: 0x00752BA0 (FUN_00752BA0)
 *
 * What it does:
 * Copy-constructs one 12-byte refcounted vector lane, preserving shared
 * control retain/release behavior while constructing destination entries.
 */
[[maybe_unused]] VectorVoidStorageView* CopyConstructRefcountedLaneVector12Storage(
  const VectorVoidStorageView& source,
  VectorVoidStorageView& destination
)
{
  destination.first = nullptr;
  destination.last = nullptr;
  destination.end = nullptr;

  const std::uint32_t sourceCount = VectorElementCount<VectorElement12RefcountedLane>(source);
  if (sourceCount != 0u && BuyVectorStorage12Byte(destination, sourceCount)) {
    auto* const destinationBegin = reinterpret_cast<VectorElement12RefcountedLane*>(destination.first);
    auto* constructedEnd = destinationBegin;
    const auto* const sourceBegin = reinterpret_cast<const VectorElement12RefcountedLane*>(source.first);
    const auto* const sourceEnd = reinterpret_cast<const VectorElement12RefcountedLane*>(source.last);

    try {
      constructedEnd = CopyConstructRefcountedLaneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(constructedEnd);
    } catch (...) {
      ReleaseRefcountedLaneRange(destinationBegin, constructedEnd);
      ReleaseAndResetVectorStorage(destination);
      throw;
    }
  }

  return &destination;
}

/**
 * Address: 0x00752DE0 (FUN_00752DE0)
 *
 * What it does:
 * Copy-constructs one 40-byte decuple-dword vector lane from source storage
 * after allocating destination capacity through the legacy vector allocator.
 */
[[maybe_unused]] VectorVoidStorageView* CopyConstructDwordDecupleVector40Storage(
  const VectorVoidStorageView& source,
  VectorVoidStorageView& destination
)
{
  destination.first = nullptr;
  destination.last = nullptr;
  destination.end = nullptr;

  const std::uint32_t sourceCount = VectorElementCount<VectorElement40DwordDecupleLane>(source);
  if (sourceCount != 0u && BuyVectorStorage40Byte(destination, sourceCount)) {
    auto* const destinationBegin = reinterpret_cast<VectorElement40DwordDecupleLane*>(destination.first);
    const auto* const sourceBegin = reinterpret_cast<const VectorElement40DwordDecupleLane*>(source.first);
    const auto* const sourceEnd = reinterpret_cast<const VectorElement40DwordDecupleLane*>(source.last);

    try {
      auto* const destinationEnd = CopyDwordDecupleLaneRange(destinationBegin, sourceBegin, sourceEnd);
      destination.last = reinterpret_cast<void**>(destinationEnd);
    } catch (...) {
      ReleaseAndResetVectorStorage(destination);
      throw;
    }
  }

  return &destination;
}

/**
 * Address: 0x00526870 (FUN_00526870)
 * Address: 0x00753240 (FUN_00753240)
 *
 * What it does:
 * Copy-assigns one 4-byte dword vector storage lane using the legacy
 * overwrite/append/reallocate split and updates `_Mylast` accordingly.
 */
[[maybe_unused]] VectorVoidStorageView* CopyAssignDwordVectorStorage(
  VectorVoidStorageView& destination,
  const VectorVoidStorageView& source
)
{
  if (&destination == &source) {
    return &destination;
  }

  auto* destinationBegin = reinterpret_cast<std::uint32_t*>(destination.first);
  const auto* const sourceBegin = reinterpret_cast<const std::uint32_t*>(source.first);
  const auto* const sourceEnd = reinterpret_cast<const std::uint32_t*>(source.last);
  const std::uint32_t sourceCount = VectorElementCount<std::uint32_t>(source);

  if (sourceCount == 0u) {
    ResetVectorWordStorageLogicalEnd(destination);
    return &destination;
  }

  const std::uint32_t destinationCount = VectorElementCount<std::uint32_t>(destination);
  if (sourceCount <= destinationCount) {
    if (sourceCount != 0u) {
      const std::size_t byteCount = static_cast<std::size_t>(sourceCount) * sizeof(std::uint32_t);
      (void)memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
    }

    destination.last = reinterpret_cast<void**>(destinationBegin + sourceCount);
    return &destination;
  }

  const std::uint32_t destinationCapacity = VectorElementCapacity<std::uint32_t>(destination);
  if (sourceCount <= destinationCapacity) {
    const std::uint32_t prefixCount = destinationCount;
    const auto* const sourceMiddle = sourceBegin + prefixCount;
    if (prefixCount != 0u) {
      const std::size_t prefixBytes = static_cast<std::size_t>(prefixCount) * sizeof(std::uint32_t);
      (void)memmove_s(destinationBegin, prefixBytes, sourceBegin, prefixBytes);
    }

    auto* const destinationMiddle = destinationBegin + prefixCount;
    destination.last = reinterpret_cast<void**>(MoveDwordRangeAndReturnEnd(sourceEnd, destinationMiddle, sourceMiddle));
    return &destination;
  }

  if (destinationBegin != nullptr) {
    ::operator delete(destinationBegin);
  }

  destination.first = nullptr;
  destination.last = nullptr;
  destination.end = nullptr;
  if (sourceCount != 0u && BuyVectorStorage4Byte(destination, sourceCount)) {
    destinationBegin = reinterpret_cast<std::uint32_t*>(destination.first);
    destination.last = reinterpret_cast<void**>(MoveDwordRangeAndReturnEnd(sourceEnd, destinationBegin, sourceBegin));
  }

  return &destination;
}

[[nodiscard]] bool BuyVectorStorageByElementWidthRequireNonZero(
  VectorVoidStorageView& storage,
  const std::uint32_t count,
  const std::uint32_t elementSize
)
{
  storage.first = nullptr;
  storage.last = nullptr;
  storage.end = nullptr;

  if (count == 0u) {
    return false;
  }

  if (elementSize == 0u || count > (std::numeric_limits<std::uint32_t>::max() / elementSize)) {
    ThrowVectorLengthError();
  }

  auto* const begin = static_cast<std::byte*>(AllocateCheckedElementBlock(count, elementSize));
  const std::size_t byteCount = static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize);
  storage.first = reinterpret_cast<void**>(begin);
  storage.last = storage.first;
  storage.end = reinterpret_cast<void**>(begin + byteCount);
  return true;
}

/**
 * Address: 0x00540270 (FUN_00540270)
 * Address: 0x00540640 (FUN_00540640)
 * Address: 0x00848B70 (FUN_00848B70)
 *
 * What it does:
 * Initializes one 4-byte vector storage lane and reports failure when
 * `count == 0`, matching the legacy callsites that treat empty input as
 * a no-op without allocation.
 */
[[maybe_unused]] bool BuyVectorStorage4ByteRequireNonZero(
  VectorVoidStorageView& storage,
  const std::uint32_t count
)
{
  return BuyVectorStorageByElementWidthRequireNonZero(storage, count, 4u);
}

/**
 * Address: 0x005400A0 (FUN_005400A0)
 *
 * What it does:
 * Initializes one 4-byte vector storage lane to `count` elements filled from
 * `*fillValue`, returning false for zero-count inputs without allocating.
 */
[[maybe_unused]] bool InitializeFilled4ByteVectorStorage(
  const std::uint32_t count,
  VectorVoidStorageView& storage,
  const std::uint32_t* const fillValue
)
{
  if (fillValue == nullptr || !BuyVectorStorage4ByteRequireNonZero(storage, count)) {
    return false;
  }

  auto* const begin = reinterpret_cast<std::uint32_t*>(storage.first);
  for (std::uint32_t index = 0; index < count; ++index) {
    begin[index] = *fillValue;
  }

  storage.last = reinterpret_cast<void**>(begin + count);
  return true;
}

/**
 * Address: 0x0053FDA0 (FUN_0053FDA0)
 *
 * What it does:
 * Initializes one 4-byte vector storage lane to `count` elements filled with
 * zero and returns the caller-owned storage lane pointer.
 */
[[maybe_unused]] VectorVoidStorageView* InitializeZeroFilled4ByteVectorStorageLane(
  const std::uint32_t count,
  VectorVoidStorageView* const outStorage
)
{
  std::uint32_t zeroFillValue = 0u;
  (void)InitializeFilled4ByteVectorStorage(count, *outStorage, &zeroFillValue);
  return outStorage;
}

/**
 * Address: 0x00741270 (FUN_00741270)
 *
 * What it does:
 * Initializes one 16-byte vector storage lane and reports failure when
 * `count == 0`, matching the legacy callsites that treat empty input as
 * a no-op without allocation.
 */
[[maybe_unused]] bool BuyVectorStorage16ByteRequireNonZero(
  VectorVoidStorageView& storage,
  const std::uint32_t count
)
{
  return BuyVectorStorageByElementWidthRequireNonZero(storage, count, 16u);
}

/**
 * Address: 0x00561580 (FUN_00561580)
 * Address: 0x00561EB0 (FUN_00561EB0)
 *
 * What it does:
 * Returns the legacy max-count guard for 352-byte vector storage lanes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t GetLegacyVectorStorageGuard352ByteValue() noexcept
{
  return kLegacyVectorStorageGuard352Byte;
}

/**
 * Address: 0x005617B0 (FUN_005617B0)
 * Address: 0x00561ED0 (FUN_00561ED0)
 *
 * What it does:
 * Returns the legacy max-count guard for 568-byte vector storage lanes.
 */
[[maybe_unused]] [[nodiscard]] std::uint32_t GetLegacyVectorStorageGuard568ByteValue() noexcept
{
  return kLegacyVectorStorageGuard568Byte;
}
} // namespace msvc8::detail
