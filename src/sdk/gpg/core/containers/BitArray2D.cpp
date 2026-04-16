#include "BitArray2D.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace gpg
{
/**
 * Address: 0x008D81F0 (FUN_008D81F0, ??0BitArray2D@gpg@@QAE@XZ)
 */
BitArray2D::BitArray2D()
    : ptr(nullptr), size(0), width(0), height(0)
{
}

/**
 * Address: 0x008D82F0 (FUN_008D82F0, ??0BitArray2D@gpg@@QAE@II@Z_0)
 */
BitArray2D::BitArray2D(const unsigned int newWidth, const unsigned int newHeight)
  : ptr(nullptr)
  , size(0)
  , width(0)
  , height(0)
{
    Reset(newWidth, newHeight);
}

/**
 * Address: 0x008D8320 (FUN_008D8320, ??0BitArray2D@gpg@@QAE@ABV01@@Z_0)
 */
BitArray2D::BitArray2D(const BitArray2D& other)
  : ptr(nullptr)
  , size(0)
  , width(0)
  , height(0)
{
  Reset(static_cast<unsigned int>(other.width), static_cast<unsigned int>(other.height));
  if (size > 0 && ptr != nullptr && other.ptr != nullptr) {
    std::memcpy(ptr, other.ptr, static_cast<std::size_t>(size) * sizeof(std::int32_t));
  }
}

/**
 * Address: 0x008D8200 (FUN_008D8200, ??1BitArray2D@gpg@@QAE@XZ)
 */
BitArray2D::~BitArray2D()
{
    operator delete(ptr);
}

/**
 * Address: 0x0077FF50 (FUN_0077FF50)
 *
 * What it does:
 * Executes one `BitArray2D` scalar-delete lane by destroying the object and
 * then releasing its storage via global `operator delete`.
 */
BitArray2D* DestroyAndDeleteBitArray2D(BitArray2D* const bitArray)
{
  bitArray->~BitArray2D();
  ::operator delete(bitArray);
  return bitArray;
}

/**
 * Address: 0x008D8210 (FUN_008D8210, ?Reset@BitArray2D@gpg@@QAEXII@Z)
 */
void BitArray2D::Reset(const unsigned int newWidth, const unsigned int newHeight)
{
    const unsigned int wordCount = newWidth * ((newHeight + 31u) >> 5);
    auto* const newWords = static_cast<int32_t*>(operator new(sizeof(int32_t) * wordCount));

    operator delete(ptr);
    ptr = newWords;
    size = static_cast<int32_t>(wordCount);
    width = static_cast<int32_t>(newWidth);
    height = static_cast<int32_t>(newHeight);

    std::memset(newWords, 0, sizeof(int32_t) * wordCount);
}

/**
 * Address: 0x008D8370 (FUN_008D8370, ?FillRect@BitArray2D@gpg@@QAEXHHHH_N@Z)
 */
void BitArray2D::FillRect(int x0, int z0, const int rectWidth, const int rectHeight, const bool fill)
{
    int x1 = x0 + rectWidth;
    int z1 = z0 + rectHeight;

    if (x0 < 0) {
        x0 = 0;
    }
    if (z0 < 0) {
        z0 = 0;
    }
    if (x1 > width) {
        x1 = width;
    }
    if (z1 > height) {
        z1 = height;
    }
    if (x1 <= x0 || z1 <= z0 || !ptr) {
        return;
    }

    const int fillBits = fill ? -1 : 0;
    int word = z0 >> 5;
    const int endWord = (z1 - 1) >> 5;
    int mask = -1 << (z0 & 0x1F);

    while (word <= endWord) {
        if (word == endWord && (z1 & 0x1F) != 0) {
            mask &= ~(-1 << (z1 & 0x1F));
        }

        int* dst = &ptr[x0 + word * width];
        const int setValue = fillBits & mask;
        const int keepMask = ~mask;
        for (int x = x0; x < x1; ++x, ++dst) {
            *dst = setValue | (keepMask & *dst);
        }

        ++word;
        mask = -1;
    }
}

/**
 * Address: 0x008D8270 (FUN_008D8270, ?AnyBitSet@BitArray2D@gpg@@QBE_NPAH0PAI@Z)
 */
bool BitArray2D::AnyBitSet(unsigned int* storeWidth, unsigned int* storeHeight, unsigned int* progress) const
{
    unsigned int curProgress = 0u;
    if (progress && *progress < static_cast<unsigned int>(size)) {
        curProgress = *progress;
    }

    if (size <= 0 || !ptr || !storeWidth || !storeHeight) {
        return false;
    }

    int totalWork = 0;
    while (ptr[curProgress] == 0) {
        ++curProgress;
        if (curProgress == static_cast<unsigned int>(size)) {
            curProgress = 0u;
        }

        ++totalWork;
        if (totalWork == size) {
            return false;
        }
    }

    *storeWidth = curProgress % static_cast<unsigned int>(width);

    unsigned int bitIndex = 0u;
    unsigned int bits = static_cast<unsigned int>(ptr[curProgress]);
    while ((bits & 1u) == 0u) {
        bits >>= 1u;
        ++bitIndex;
    }

    *storeHeight = bitIndex + 32u * (curProgress / static_cast<unsigned int>(width));
    if (progress) {
        *progress = curProgress;
    }
    return true;
}

/**
 * Address: 0x008E3380 (FUN_008E3380)
 *
 * What it does:
 * Clears one packed bit at `(x,z)` and returns the modified backing word lane.
 */
int32_t* BitArray2D::ClearBitAndReturnWord(const int x, const unsigned int z)
{
    const unsigned int wordRow = z >> 5u;
    const int index = x + static_cast<int>(static_cast<unsigned int>(width) * wordRow);
    int32_t* const word = &ptr[index];
    *word &= ~static_cast<int32_t>(1u << (z & 0x1Fu));
    return word;
}

/**
 * Address: 0x008D8460 (FUN_008D8460, ?GetRectOr@BitArray2D@gpg@@QBE_NHHHH_N@Z)
 */
bool BitArray2D::GetRectOr(int x0, int z0, const int w, const int h, const bool disallowNegative) const
{
    int x1 = x0 + w;
    int z1 = z0 + h;

    if (x0 < 0 || z0 < 0 || x1 >= width || z1 >= height) {
        if (disallowNegative && x0 < x1 && z0 < z1) {
            return true;
        }

        if (x0 < 0) {
            x0 = 0;
        }
        if (z0 < 0) {
            z0 = 0;
        }
        if (x1 >= width) {
            x1 = width;
        }
        if (z1 >= height) {
            z1 = height;
        }
    }

    if (x1 <= x0 || z1 <= z0) {
        return false;
    }

    const int endWord = (z1 - 1) >> 5;
    int word = z0 >> 5;
    int rectMask = -1 << (z0 & 0x1F);
    int orBits = 0;

    while (word <= endWord) {
        if (word == endWord && (z1 & 0x1F) != 0) {
            rectMask &= ~(-1 << (z1 & 0x1F));
        }

        int* rowBits = &ptr[x0 + word * width];
        for (int x = x0; x < x1; ++x, ++rowBits) {
            orBits |= rectMask & *rowBits;
        }

        ++word;
        rectMask = -1;
    }

    return orBits != 0;
}

/**
 * Address: 0x00720580 (FUN_00720580, gpg::BitArray2D::GetRectNeg)
 *
 * What it does:
 * Adapts one `Rect2i` lane into `GetRectOr` with strict negative-range
 * handling enabled.
 */
bool BitArray2D::GetRectNeg(const Rect2i& rect) const
{
  return GetRectOr(rect.x0, rect.z0, rect.x1 - rect.x0, rect.z1 - rect.z0, true);
}

/**
 * Address: 0x00720510 (FUN_00720510)
 *
 * What it does:
 * Returns true when the queried bit is set or the coordinates fall outside
 * the logical width/height.
 */
bool BitArray2D::IsBitSetOrOutOfBounds(const unsigned int x, const unsigned int z) const
{
    if (x >= static_cast<unsigned int>(width) || z >= static_cast<unsigned int>(height)) {
        return true;
    }

    const std::size_t index = static_cast<std::size_t>(x) +
                              static_cast<std::size_t>(width) * static_cast<std::size_t>(z >> 5);
    return (static_cast<std::uint32_t>(ptr[index]) & (1u << (z & 0x1Fu))) != 0u;
}
}
