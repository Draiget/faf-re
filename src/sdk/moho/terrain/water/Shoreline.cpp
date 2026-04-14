#include "moho/terrain/water/Shoreline.h"

#include <cstdint>
#include <new>

namespace
{
  using ShoreCellRef = boost::shared_ptr<moho::ShoreCell>;

  /**
   * Address: 0x00814040 (FUN_00814040, sub_814040)
   *
   * What it does:
   * Assign-copies one half-open shoreline-cell shared-pointer range into
   * destination storage and returns the new destination end.
   */
  [[nodiscard]] ShoreCellRef* CopyShoreCellRefRange(
    ShoreCellRef* const destination,
    ShoreCellRef* sourceBegin,
    ShoreCellRef* const sourceEnd
  )
  {
    ShoreCellRef* write = destination;
    while (sourceBegin != sourceEnd) {
      *write = *sourceBegin;
      ++sourceBegin;
      ++write;
    }
    return write;
  }

  /**
   * Address: 0x008140F0 (FUN_008140F0, sub_8140F0)
   *
   * What it does:
   * Releases one half-open shoreline-cell shared-pointer range by resetting each
   * shared owner lane.
   */
  void ReleaseShoreCellRefRange(ShoreCellRef* rangeBegin, ShoreCellRef* const rangeEnd)
  {
    while (rangeBegin != rangeEnd) {
      rangeBegin->reset();
      ++rangeBegin;
    }
  }

  /**
   * Address: 0x00813750 (FUN_00813750, sub_813750)
   *
   * What it does:
   * Erases one half-open shoreline-cell range from the runtime vector by moving
   * tail lanes over the erased range and releasing the trailing stale lanes.
   */
  [[nodiscard]] ShoreCellRef* EraseShoreCellRefRange(
    msvc8::vector<ShoreCellRef>& shorelineCells,
    ShoreCellRef* const eraseBegin,
    ShoreCellRef* const eraseEnd
  )
  {
    if (eraseBegin == eraseEnd) {
      return eraseBegin;
    }

    auto& cellView = msvc8::AsVectorRuntimeView(shorelineCells);
    ShoreCellRef* const previousEnd = cellView.end;
    ShoreCellRef* const newEnd = CopyShoreCellRefRange(eraseBegin, eraseEnd, previousEnd);
    ReleaseShoreCellRefRange(newEnd, previousEnd);
    cellView.end = newEnd;
    return eraseBegin;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00812840 (FUN_00812840, Moho::Shoreline::Shoreline)
   *
   * What it does:
   * Initializes shoreline runtime lanes, including spatial-db entry wrapper,
   * shoreline-cell vector storage, vertex-sheet shared owner, and triangle count.
   */
  Shoreline::Shoreline()
    : mSpatialDbEntry()
    , mUnknown0C_93{}
    , mCells()
    , mVertexSheet()
    , mShorelineTris(0)
  {}

  /**
   * Address: 0x00812E00 (FUN_00812E00, Moho::Shoreline::Destroy)
   *
   * What it does:
   * Releases vertex-sheet ownership, erases shoreline-cell shared-pointer lanes,
   * and clears shoreline triangle-count state.
   */
  void Shoreline::Destroy()
  {
    mVertexSheet.reset();

    auto& cellView = msvc8::AsVectorRuntimeView(mCells);
    (void)EraseShoreCellRefRange(mCells, cellView.begin, cellView.end);

    mShorelineTris = 0;
  }

  /**
   * Address: 0x008128D0 (FUN_008128D0, Moho::Shoreline::~Shoreline)
   *
   * What it does:
   * Destroys shoreline runtime state by calling `Destroy`, releasing shoreline
   * cell storage, and tearing down the spatial-db entry wrapper subobject.
   */
  Shoreline::~Shoreline()
  {
    Destroy();
  }

  /**
   * Address: 0x008128B0 (FUN_008128B0, Moho::Shoreline::dtr)
   *
   * What it does:
   * Runs the non-deleting destructor and conditionally frees `this` when the
   * low delete-flag bit is set.
   */
  Shoreline* Shoreline::DeleteWithFlag(const std::uint8_t deleteFlags)
  {
    this->~Shoreline();
    if ((deleteFlags & 0x1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }
} // namespace moho

