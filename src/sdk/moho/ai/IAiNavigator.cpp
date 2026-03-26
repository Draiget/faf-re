#include "moho/ai/IAiNavigator.h"

#include <algorithm>
#include <cstring>
#include <new>

using namespace moho;

std::size_t SNavPath::Count() const noexcept
{
  if (!start || !finish || finish < start) {
    return 0;
  }
  return static_cast<std::size_t>(finish - start);
}

std::int32_t SNavPath::CountInt() const noexcept
{
  return static_cast<std::int32_t>(Count());
}

std::size_t SNavPath::CapacityCount() const noexcept
{
  if (!start || !capacity || capacity < start) {
    return 0;
  }
  return static_cast<std::size_t>(capacity - start);
}

void SNavPath::ClearContent() noexcept
{
  if (start) {
    finish = start;
  }
}

void SNavPath::FreeStorage() noexcept
{
  if (start) {
    ::operator delete(start);
  }
  reserved0 = 0;
  start = nullptr;
  finish = nullptr;
  capacity = nullptr;
}

void SNavPath::EnsureCapacity(const std::size_t requiredCount)
{
  const std::size_t currentCapacity = CapacityCount();
  if (currentCapacity >= requiredCount) {
    return;
  }

  const std::size_t currentSize = Count();
  const std::size_t newCapacity = std::max(requiredCount, std::max<std::size_t>(4, currentCapacity * 2));
  auto* const storage = static_cast<SOCellPos*>(::operator new(sizeof(SOCellPos) * newCapacity));

  if (start && currentSize > 0) {
    std::memcpy(storage, start, sizeof(SOCellPos) * currentSize);
  }

  if (start) {
    ::operator delete(start);
  }

  start = storage;
  finish = storage + currentSize;
  capacity = storage + newCapacity;
}

void SNavPath::AssignCopy(const SNavPath& src)
{
  const std::size_t count = src.Count();
  if (count == 0) {
    ClearContent();
    return;
  }

  EnsureCapacity(count);
  std::memcpy(start, src.start, sizeof(SOCellPos) * count);
  finish = start + count;
}

void SNavPath::AppendCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::size_t appendCount = static_cast<std::size_t>(end - begin);
  const std::size_t currentCount = Count();
  EnsureCapacity(currentCount + appendCount);

  std::memcpy(start + currentCount, begin, sizeof(SOCellPos) * appendCount);
  finish = start + currentCount + appendCount;
}

void SNavPath::PrependCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::size_t prependCount = static_cast<std::size_t>(end - begin);
  const std::size_t currentCount = Count();
  EnsureCapacity(currentCount + prependCount);

  if (currentCount > 0) {
    std::memmove(start + prependCount, start, sizeof(SOCellPos) * currentCount);
  }
  std::memcpy(start, begin, sizeof(SOCellPos) * prependCount);
  finish = start + currentCount + prependCount;
}

void SNavPath::AppendCell(const SOCellPos& cell)
{
  AppendCells(&cell, &cell + 1);
}

void SNavPath::EraseFrontCell() noexcept
{
  const std::size_t count = Count();
  if (count == 0) {
    return;
  }

  if (count == 1) {
    finish = start;
    return;
  }

  std::memmove(start, start + 1, sizeof(SOCellPos) * (count - 1));
  --finish;
}

void SNavPath::EraseFrontCells(std::int32_t count) noexcept
{
  while (count > 0 && CountInt() > 0) {
    EraseFrontCell();
    --count;
  }
}

gpg::RType* IAiNavigator::sType = nullptr;

/**
 * Address: 0x005A2D30 (FUN_005A2D30, scalar deleting thunk)
 */
IAiNavigator::~IAiNavigator()
{
  mListenerNode.ListUnlink();
}
